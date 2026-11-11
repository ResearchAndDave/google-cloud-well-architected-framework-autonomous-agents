"""FastAPI Cloud Run Pub/Sub Push Endpoint & ADK Runner for the WAF Auditor."""

import base64
import json
import os
from pathlib import Path
import sys
import uuid
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from google.adk.artifacts import GcsArtifactService, InMemoryArtifactService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService, VertexAiSessionService
from google.genai import types

if "pytest" not in sys.modules:
    load_dotenv(Path(__file__).resolve().parent / ".env", override=False)

from .agent import root_agent
from .config import get_waf_config
from .dashboard import (
    fetch_dashboard_telemetry,
    render_tufte_architecture_html,
    render_tufte_dashboard_html,
)

APP_NAME = "waf_auditor_agent"
_CFG = get_waf_config()
PROJECT_ID = _CFG.project_id
LOCATION = _CFG.location
DEFAULT_ORG_ID = _CFG.target_scope
GCS_ARTIFACT_BUCKET = os.getenv("WAF_GCS_BUCKET", "")
AGENT_ENGINE_ID = os.getenv("VERTEX_AGENT_ENGINE_ID", "")

app = FastAPI(title="Autonomous Google Cloud WAF Auditor")

session_service = (
    VertexAiSessionService(project=PROJECT_ID, location=LOCATION, agent_engine_id=AGENT_ENGINE_ID)
    if AGENT_ENGINE_ID
    else InMemorySessionService()
)
artifact_service = (
    GcsArtifactService(bucket_name=GCS_ARTIFACT_BUCKET)
    if GCS_ARTIFACT_BUCKET
    else InMemoryArtifactService()
)

runner = Runner(
    agent=root_agent,
    app_name=APP_NAME,
    session_service=session_service,
    artifact_service=artifact_service,
)


def _parse_pubsub_envelope(body: dict) -> dict:
    """Decodes base64 Pub/Sub push message data into a dictionary."""
    message = body.get("message", {})
    raw_data = message.get("data", "")
    if not raw_data:
        return {}
    decoded_bytes = base64.b64decode(raw_data)
    return json.loads(decoded_bytes.decode("utf-8"))


@app.get("/", include_in_schema=False)
async def root_redirect():
    """Redirects root URL to the Tufte analytical dashboard."""
    return RedirectResponse(url="/dashboard")


@app.get("/healthz")
async def health_check():
    return {"status": "ok", "app": APP_NAME}


@app.get("/api/dashboard/data")
async def get_dashboard_data(blob: str | None = None):
    """Returns live BigQuery view telemetry and GCS executive report data as JSON."""
    return fetch_dashboard_telemetry(report_blob_name=blob)


@app.get("/dashboard", response_class=HTMLResponse)
async def get_tufte_dashboard(
    blob: str | None = None,
    pillar: str | None = None,
    project: str | None = None,
):
    """Renders the Edward Tufte-inspired analytical WAF posture dashboard."""
    telemetry = fetch_dashboard_telemetry(report_blob_name=blob)
    return HTMLResponse(
        content=render_tufte_dashboard_html(
            telemetry,
            selected_pillar=pillar,
            selected_project=project,
        )
    )


@app.get("/architecture", response_class=HTMLResponse)
async def get_tufte_architecture():
    """Renders the Edward Tufte-inspired System Architecture & Telemetry Flow schematic."""
    return HTMLResponse(content=render_tufte_architecture_html())


@app.post("/pubsub/push")
async def handle_pubsub_push(request: Request):
    """Unified Cloud Run push endpoint for CAI RealTimeFeed (Path A) & Cloud Scheduler (Path B)."""
    try:
        envelope = await request.json()
        payload = _parse_pubsub_envelope(envelope)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Pub/Sub push payload: {exc}")

    if "asset" in payload:
        scan_mode = "REALTIME_DRIFT"
        asset_info = payload["asset"]
        asset_uri = asset_info.get("name", "")
        asset_type = asset_info.get("assetType", "")
        initial_state = {
            "org_id": DEFAULT_ORG_ID,
            "scan_mode": scan_mode,
            "target_asset": json.dumps(asset_info),
            "observed_resource_uris": [asset_uri] if asset_uri else [],
        }
        prompt_text = (
            f"Evaluate real-time Cloud Asset Inventory drift event for `{asset_uri}` "
            f"(type `{asset_type}`) against the Google Cloud Well-Architected Framework."
        )
    else:
        scan_mode = payload.get("scan_mode", "NIGHTLY_SWEEP")
        org_id = payload.get("org_id", DEFAULT_ORG_ID)
        initial_state = {
            "org_id": org_id,
            "scan_mode": scan_mode,
            "target_asset": "ALL_ORG_ASSETS",
            "observed_resource_uris": [],
        }
        prompt_text = payload.get(
            "prompt",
            (
                f"Execute a full organizational Well-Architected Framework baseline sweep "
                f"across `{org_id}` covering all 6 WAF pillars (SECURITY, RELIABILITY, "
                f"COST_OPTIMIZATION, PERFORMANCE_OPTIMIZATION, OPERATIONAL_EXCELLENCE, and SUSTAINABILITY). "
                f"Each pillar specialist MUST call `search_org_assets` on `{org_id}` to discover live "
                f"resources across multiple projects and produce at least 1 concrete NON_COMPLIANT "
                f"finding using an exact `resource_uri` returned by `search_org_assets`, complete with "
                f"valid Terraform HCL remediation and `estimated_monthly_savings_usd` where applicable."
            ),
        )

    session_id = f"waf-{scan_mode.lower()}-{uuid.uuid4().hex[:10]}"
    user_id = "system-scheduler"

    await session_service.create_session(
        app_name=APP_NAME,
        user_id=user_id,
        session_id=session_id,
        state=initial_state,
    )

    user_message = types.Content(
        role="user",
        parts=[types.Part.from_text(text=prompt_text)],
    )

    async for _ in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=user_message,
    ):
        pass

    updated_session = await session_service.get_session(
        app_name=APP_NAME, user_id=user_id, session_id=session_id
    )
    final_report = updated_session.state.get("final_org_report") or updated_session.state.get("draft_org_report")
    if final_report and final_report.get("executive_markdown"):
        md_bytes = final_report["executive_markdown"].encode("utf-8")
        try:
            await artifact_service.save_artifact(
                app_name=APP_NAME,
                user_id=user_id,
                session_id=session_id,
                filename="waf_executive_summary.md",
                artifact=types.Part.from_bytes(data=md_bytes, mime_type="text/markdown"),
            )
        except Exception:
            pass

    return {
        "status": "COMPLETED",
        "session_id": session_id,
        "scan_mode": scan_mode,
        "findings_committed": len(final_report.get("validated_findings", [])) if final_report else 0,
    }
