"""Integration tests for the FastAPI /pubsub/push endpoint (Path A: CAI RealTimeFeed & Path B: Nightly Sweep)."""

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import APP_NAME, app, session_service

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "cai_drift_samples.json"


def _make_pubsub_envelope(payload: dict) -> dict:
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    return {
        "message": {
            "data": encoded,
            "messageId": "1001",
            "publishTime": "2026-10-22T14:00:00Z",
        },
        "subscription": "projects/waf-compliance-hub/subscriptions/waf-auditor-push-sub",
    }


@pytest.mark.anyio
async def test_healthz_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "app": APP_NAME}


@pytest.mark.anyio
async def test_pubsub_push_path_a_realtime_drift_firewall():
    """Verifies Path A (CAI RealTimeFeed) decodes the asset, pre-seeds observed URIs, and saves GCS/memory artifact."""
    fixtures = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
    cai_event = fixtures["open_ssh_firewall"]
    expected_uri = cai_event["asset"]["name"]

    mock_final_report = {
        "org_id": "organizations/123456789",
        "scan_mode": "REALTIME_DRIFT",
        "evaluation_timestamp": "2026-10-22T14:00:05Z",
        "overall_waf_score": 85,
        "pillar_scores": {"SECURITY": 85},
        "top_architectural_risks": ["Open SSH 0.0.0.0/0 on allow-ssh-world"],
        "total_projected_monthly_savings_usd": 0.0,
        "validated_findings": [
            {
                "resource_uri": expected_uri,
                "project_id": "waf-compliance-hub",
                "folder_id": "folders/11223344",
                "waf_pillar": "SECURITY",
                "waf_principle": "Implement zero trust",
                "severity": "CRITICAL",
                "compliance_status": "NON_COMPLIANT",
                "rationale": "Firewall allows ingress from 0.0.0.0/0 on TCP port 22 without IAP.",
                "terraform_remediation": 'resource "google_compute_firewall" "fix" {}',
                "estimated_monthly_savings_usd": 0.0,
            }
        ],
        "executive_markdown": "# WAF Executive Summary\n- **Overall Score:** 85/100\n",
    }

    async def fake_run_async(*, user_id: str, session_id: str, new_message):
        # Verify initial session state was pre-seeded with the CAI drift asset and URI
        session = await session_service.get_session(
            app_name=APP_NAME, user_id=user_id, session_id=session_id
        )
        assert session.state["scan_mode"] == "REALTIME_DRIFT"
        assert session.state["observed_resource_uris"] == [expected_uri]
        assert "allow-ssh-world" in session.state["target_asset"]

        # Simulate the LoopAgent approving and writing final_org_report into the underlying session store
        internal_session = session_service.sessions[APP_NAME][user_id][session_id]
        internal_session.state["final_org_report"] = mock_final_report
        yield SimpleNamespace(is_final_response=lambda: True, Author="WAF_Auditor_Pipeline")

    with patch("app.main.runner.run_async", side_effect=fake_run_async):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/pubsub/push", json=_make_pubsub_envelope(cai_event))

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["scan_mode"] == "REALTIME_DRIFT"
    assert body["findings_committed"] == 1


@pytest.mark.anyio
async def test_pubsub_push_path_b_nightly_sweep():
    """Verifies Path B (Cloud Scheduler Nightly Sweep) sets ALL_ORG_ASSETS scope and executes full sweep."""
    scheduler_payload = {
        "scan_mode": "NIGHTLY_SWEEP",
        "org_id": "organizations/123456789",
    }

    async def fake_run_async(*, user_id: str, session_id: str, new_message):
        session = await session_service.get_session(
            app_name=APP_NAME, user_id=user_id, session_id=session_id
        )
        assert session.state["scan_mode"] == "NIGHTLY_SWEEP"
        assert session.state["target_asset"] == "ALL_ORG_ASSETS"
        assert session.state["org_id"] == "organizations/123456789"
        yield SimpleNamespace(is_final_response=lambda: True, Author="WAF_Auditor_Pipeline")

    with patch("app.main.runner.run_async", side_effect=fake_run_async):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/pubsub/push", json=_make_pubsub_envelope(scheduler_payload))

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["scan_mode"] == "NIGHTLY_SWEEP"


@pytest.mark.anyio
async def test_tufte_dashboard_endpoint():
    """Verifies GET /dashboard renders Edward Tufte small multiples, sparklines, and drift ledger."""
    sample_telemetry = {
        "project_id": "legacy-waf-compliance-0",
        "dataset_id": "org_compliance",
        "gcs_bucket": "legacy-waf-compliance-0-waf-artifacts",
        "generated_at": "2026-10-23 16:00:00 UTC",
        "overall_waf_score": 98,
        "total_active_findings": 1,
        "total_monthly_savings_usd": 0.0,
        "pillar_scores": [
            {
                "waf_pillar": "SECURITY",
                "pillar_score_0_to_100": 93,
                "active_finding_count": 1,
                "critical_count": 0,
                "high_count": 1,
                "medium_count": 0,
                "low_count": 0,
                "potential_monthly_savings_usd": 0.0,
            }
        ],
        "current_findings": [
            {
                "evaluation_timestamp": "2026-10-23T15:29:36+00:00",
                "org_id": "123456789012",
                "scan_mode": "REALTIME_DRIFT",
                "resource_uri": "//compute.googleapis.com/projects/agent-dlp/global/firewalls/default-allow-ssh",
                "project_id": "agent-dlp",
                "folder_id": None,
                "waf_pillar": "SECURITY",
                "waf_principle": "Implement security by design",
                "severity": "HIGH",
                "compliance_status": "NON_COMPLIANT",
                "rationale": "Open SSH port 22.",
                "terraform_remediation": 'resource "google_compute_firewall" "fix" {}',
                "estimated_monthly_savings_usd": 0.0,
                "gitops_plan": {
                    "fingerprint": "a1b2c3d4e5f6",
                    "branch_name": "waf-remediation/agent-dlp/security-a1b2c3d4e5f6",
                    "target_tf_path": "remediations/agent-dlp/security_a1b2c3d4e5f6.tf",
                },
            }
        ],
        "drift_velocity": [
            {
                "audit_date": "2026-10-23",
                "waf_pillar": "SECURITY",
                "non_compliant_count": 1,
                "high_risk_count": 1,
                "daily_net_drift": 0,
                "seven_day_drift_velocity": 0,
            }
        ],
        "heatmap_rows": [
            {
                "folder_id": "folders/UNASSIGNED_ROOT",
                "project_id": "agent-dlp",
                "waf_pillar": "SECURITY",
                "total_findings": 1,
                "critical_findings": 0,
                "high_findings": 1,
                "monthly_savings_opportunity_usd": 0.0,
                "last_evaluated_at": "2026-10-23T15:29:36+00:00",
            }
        ],
        "executive_markdown": "# Executive Summary\nScore: 98/100",
        "available_reports": [
            {"name": "reports/waf_executive_summary.md", "updated": "2026-10-23T16:01:53Z", "size_bytes": "1200"}
        ],
        "selected_blob": "reports/waf_executive_summary.md",
    }

    with patch("app.main.fetch_dashboard_telemetry", return_value=sample_telemetry):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/dashboard")
            filtered_match = await client.get("/dashboard?project=agent-dlp&pillar=SECURITY")
            filtered_empty = await client.get("/dashboard?pillar=COST_OPTIMIZATION")
            arch_resp = await client.get("/architecture")

    assert resp.status_code == 200
    assert "Six-Pillar Small Multiples" in resp.text
    assert 'class="sparkline"' in resp.text
    assert 'class="bullet-bar"' in resp.text
    assert "agent-dlp" in resp.text

    assert filtered_match.status_code == 200
    assert "Showing <strong>1</strong> of 1 findings" in filtered_match.text
    assert "default-allow-ssh" in filtered_match.text
    assert "auto-PR eligible" in filtered_match.text

    assert filtered_empty.status_code == 200
    assert "Showing <strong>0</strong> of 1 findings" in filtered_empty.text
    assert "default-allow-ssh" not in filtered_empty.text

    assert arch_resp.status_code == 200
    assert "Multivariate System Topology" in arch_resp.text
    assert "WAF_Six_Pillar_FanOut" in arch_resp.text
