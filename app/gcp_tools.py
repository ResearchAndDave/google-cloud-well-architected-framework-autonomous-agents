"""Deterministic Google Cloud telemetry tools and Critic HCL/URI validation tools."""

import json
import os
import re
from datetime import datetime, timezone
from typing import Optional
import urllib.request

import google.auth
import google.auth.transport.requests
import hcl2
from google.adk.agents.callback_context import CallbackContext
from google.adk.tools import ToolContext
from google.api_core import exceptions as gcp_exceptions
from google.api_core.client_options import ClientOptions
from google.api_core.gapic_v1.client_info import ClientInfo
from google.cloud import asset_v1, bigquery, recommender_v1, securitycenter_v2, storage
from google.protobuf.json_format import MessageToDict

from .config import get_waf_config, normalize_scope
from .gitops import gitops_thresholds_from_env, select_findings_for_gitops

CAI_URI_PATTERN = re.compile(r"^//[a-z0-9-]+\.googleapis\.com/.+$")
PROJECT_SLUG_PATTERN = re.compile(r"/projects/([a-z][a-z0-9-]{4,29})(?:/|$)")
RPC_TIMEOUT_SECONDS = float(os.getenv("WAF_GCP_RPC_TIMEOUT", "15.0"))


def _resolve_human_project_id(
    raw_project: str,
    resource_uri: str = "",
    parent_uri: str = "",
    uri_project_map: Optional[dict[str, str]] = None,
) -> str:
    """Resolves human-readable GCP project_id from CAI parent/resource URIs instead of numeric project numbers."""
    if uri_project_map and resource_uri in uri_project_map:
        return uri_project_map[resource_uri]
    for candidate in (parent_uri, resource_uri):
        match = PROJECT_SLUG_PATTERN.search(candidate or "")
        if match:
            return match.group(1)
    cleaned = (raw_project or "").removeprefix("projects/").strip()
    return cleaned or "unknown-project"

RECOMMENDER_MAP = {
    "SECURITY": ["google.iam.policy.Recommender"],
    "RELIABILITY": ["google.cloudsql.instance.ReliabilityRecommender"],
    "COST": [
        "google.compute.instance.IdleResourceRecommender",
        "google.compute.disk.IdleResourceRecommender",
        "google.compute.commitment.UsageCommitmentRecommender",
        "google.cloudsql.instance.IdleRecommender",
    ],
    "PERFORMANCE": [
        "google.compute.instance.MachineTypeRecommender",
        "google.cloudsql.instance.OverprovisionedRecommender",
    ],
}


def _client_info(skill_name: str = "google-cloud-waf-security") -> ClientInfo:
    """Returns Google Cloud SDK ClientInfo with official skill usage attribution."""
    return ClientInfo(user_agent=f"agent-skills/1.0 (skill:{skill_name})")


def _client_options() -> ClientOptions:
    """Returns Google Cloud SDK ClientOptions with dynamic quota project for ADC."""
    quota_project = get_waf_config().quota_project_id
    return ClientOptions(quota_project_id=quota_project)


def search_org_assets(
    scope: str,
    asset_types: list[str],
    query: str = "",
    page_size: int = 50,
    tool_context: Optional[ToolContext] = None,
) -> dict:
    """Searches resources across the Organization or Project using Cloud Asset Inventory.

    Args:
        scope: Organization or Project scope, e.g. 'organizations/123456789' or 'projects/golden-path-demo'.
        asset_types: List of CAI asset types, e.g. ['compute.googleapis.com/Instance', 'sqladmin.googleapis.com/Instance'].
        query: Optional CAI query filter, e.g. 'NOT labels.env:*' or 'location:us-central1'.
        page_size: Max records to return (capped at 50 to protect LLM context window).
    """
    client = asset_v1.AssetServiceClient(
        client_info=_client_info(),
        client_options=_client_options(),
    )
    request = asset_v1.SearchAllResourcesRequest(
        scope=scope,
        asset_types=asset_types,
        query=query,
        page_size=min(page_size, 50),
    )

    results = []
    known_uris = set(tool_context.state.get("observed_resource_uris", [])) if tool_context else set()
    observed_locations = set(tool_context.state.get("observed_locations", [])) if tool_context else set()
    uri_project_map = dict(tool_context.state.get("uri_to_project_id", {})) if tool_context else {}

    try:
        for resource in client.search_all_resources(request=request, timeout=RPC_TIMEOUT_SECONDS):
            human_project_id = _resolve_human_project_id(
                raw_project=resource.project,
                resource_uri=resource.name,
                parent_uri=getattr(resource, "parent_full_resource_name", ""),
            )
            uri_project_map[resource.name] = human_project_id
            if resource.location:
                observed_locations.add(resource.location)
            results.append({
                "resource_uri": resource.name,
                "asset_type": resource.asset_type,
                "project": human_project_id,
                "project_id": human_project_id,
                "folders": list(resource.folders),
                "location": resource.location,
                "labels": dict(resource.labels),
                "state": resource.state,
            })
            known_uris.add(resource.name)
            if len(results) >= min(page_size, 50):
                break
    except Exception as exc:
        return {"count": 0, "resources": [], "warning": f"Cloud Asset Inventory query failed: {exc}"}

    if tool_context is not None:
        tool_context.state["observed_resource_uris"] = list(known_uris)
        tool_context.state["observed_locations"] = list(observed_locations)
        tool_context.state["uri_to_project_id"] = uri_project_map

    return {"count": len(results), "resources": results}


def inspect_resource_configuration(
    scope: str,
    resource_uris: list[str],
    content_type: str = "RESOURCE",
) -> dict:
    """Fetches full configuration or IAM policy for specific resource URIs via CAI BatchGetAssetsHistory."""
    client = asset_v1.AssetServiceClient(
        client_info=_client_info(),
        client_options=_client_options(),
    )
    enum_map = {
        "RESOURCE": asset_v1.ContentType.RESOURCE,
        "IAM_POLICY": asset_v1.ContentType.IAM_POLICY,
        "ORG_POLICY": asset_v1.ContentType.ORG_POLICY,
    }
    try:
        response = client.batch_get_assets_history(
            request=asset_v1.BatchGetAssetsHistoryRequest(
                parent=scope,
                asset_names=resource_uris[:20],
                content_type=enum_map.get(content_type, asset_v1.ContentType.RESOURCE),
            ),
            timeout=RPC_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        return {"inspected_count": 0, "configurations": [], "warning": f"CAI inspection failed: {exc}"}

    configs = []
    for temporal_asset in response.assets:
        asset_dict = MessageToDict(temporal_asset.asset._pb)
        configs.append({
            "resource_uri": temporal_asset.asset.name,
            "asset_type": temporal_asset.asset.asset_type,
            "resource_data": asset_dict.get("resource", {}).get("data", {}),
            "iam_policy": asset_dict.get("iamPolicy", {}),
        })
    return {"inspected_count": len(configs), "configurations": configs}


def get_active_scc_findings(
    org_id: str,
    min_severity: str = "HIGH",
    max_results: int = 50,
    tool_context: Optional[ToolContext] = None,
) -> dict:
    """Queries active Security Command Center (SCC v2) findings across an Organization, Folder, or Project."""
    cfg = get_waf_config()
    normalized_scope = normalize_scope(org_id, fallback_project=cfg.project_id)
    parent = f"{normalized_scope}/sources/-/locations/global"
    client = securitycenter_v2.SecurityCenterClient(
        client_info=_client_info("google-cloud-waf-security"),
        client_options=_client_options(),
    )

    severity_filter = (
        'severity="CRITICAL"'
        if min_severity == "CRITICAL"
        else '(severity="CRITICAL" OR severity="HIGH")'
    )
    filter_str = f'state="ACTIVE" AND {severity_filter}'

    findings = []
    known_uris = set(tool_context.state.get("observed_resource_uris", [])) if tool_context else set()

    request = securitycenter_v2.ListFindingsRequest(
        parent=parent,
        filter=filter_str,
        page_size=min(max_results, 50),
    )
    try:
        for item in client.list_findings(request=request, timeout=RPC_TIMEOUT_SECONDS):
            finding = item.finding
            known_uris.add(finding.resource_name)
            findings.append({
                "finding_name": finding.name,
                "category": finding.category,
                "finding_class": finding.finding_class.name,
                "severity": finding.severity.name,
                "resource_uri": finding.resource_name,
                "description": finding.description,
                "next_steps": finding.next_steps,
            })
            if len(findings) >= min(max_results, 50):
                break
    except Exception as exc:
        return {"active_findings_count": 0, "findings": [], "warning": f"SCC v2 query failed: {exc}"}

    if tool_context is not None:
        tool_context.state["observed_resource_uris"] = list(known_uris)

    return {"active_findings_count": len(findings), "findings": findings}


def fetch_project_recommendations(
    project_id: str,
    pillar_category: str,
    locations: list[str] = ["global", "us-central1", "us-east1"],
    tool_context: Optional[ToolContext] = None,
) -> dict:
    """Fetches Active Assist recommendations for a project mapped to a WAF pillar category."""
    client = recommender_v1.RecommenderClient(
        client_info=_client_info(),
        client_options=_client_options(),
    )
    recommender_ids = RECOMMENDER_MAP.get(pillar_category.upper(), [])
    recommendations = []
    known_uris = set(tool_context.state.get("observed_resource_uris", [])) if tool_context else set()
    observed_locs = list(tool_context.state.get("observed_locations", [])) if tool_context else []

    merged_locations: list[str] = []
    for loc in [*(locations or []), *get_waf_config().recommender_locations, *observed_locs]:
        if loc and loc not in merged_locations:
            merged_locations.append(loc)

    for loc in merged_locations:
        for rec_id in recommender_ids:
            parent = f"projects/{project_id}/locations/{loc}/recommenders/{rec_id}"
            try:
                for rec in client.list_recommendations(parent=parent, timeout=RPC_TIMEOUT_SECONDS):
                    if rec.state_info.state != recommender_v1.RecommendationStateInfo.State.ACTIVE:
                        continue
                    impact = rec.primary_impact
                    cost_usd = None
                    if impact.cost_projection and impact.cost_projection.cost:
                        cost_usd = abs(
                            impact.cost_projection.cost.units
                            + impact.cost_projection.cost.nanos / 1e9
                        )
                    target_resources = list(rec.content.overview.get("resourceNames", []))
                    for uri in target_resources:
                        known_uris.add(uri)

                    recommendations.append({
                        "recommender_id": rec_id,
                        "description": rec.description,
                        "recommender_subtype": rec.recommender_subtype,
                        "priority": rec.priority.name,
                        "target_resources": target_resources,
                        "estimated_monthly_savings_usd": cost_usd,
                    })
            except Exception:
                continue

    if tool_context is not None:
        tool_context.state["observed_resource_uris"] = list(known_uris)

    return {"count": len(recommendations), "recommendations": recommendations}


def query_carbon_footprint_summary(
    billing_export_table: str = "",
    months_lookback: int = 3,
) -> dict:
    """Queries the Google Cloud Carbon Footprint BigQuery export grouped by project, service, and region."""
    cfg = get_waf_config()
    resolved_table = (billing_export_table or cfg.carbon_export_table).strip()
    if not resolved_table:
        return {
            "hotspot_count": 0,
            "carbon_hotspots": [],
            "warning": (
                "Carbon Footprint BigQuery export table is not configured (set WAF_CARBON_EXPORT_TABLE). "
                "Evaluate sustainability posture using resource locations (CFE%), idle resource signals, "
                "and architecture configurations returned by search_org_assets."
            ),
        }

    try:
        bq_client = bigquery.Client(client_info=_client_info("google-cloud-waf-sustainability"))
        query = f"""
            SELECT
                project.id AS project_id,
                service.description AS service_name,
                location.region AS region,
                ROUND(SUM(carbon_footprint_total_kgCO2e.location_based), 2) AS location_based_kg_co2e,
                ROUND(SUM(carbon_footprint_total_kgCO2e.market_based), 2) AS market_based_kg_co2e
            FROM `{resolved_table}`
            WHERE usage_month >= DATE_SUB(DATE_TRUNC(CURRENT_DATE(), MONTH), INTERVAL @months MONTH)
            GROUP BY 1, 2, 3
            ORDER BY location_based_kg_co2e DESC
            LIMIT 50
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("months", "INT64", months_lookback)]
        )
        rows = [dict(row) for row in bq_client.query(query, job_config=job_config).result()]
        return {"hotspot_count": len(rows), "carbon_hotspots": rows}
    except Exception as exc:
        return {
            "hotspot_count": 0,
            "carbon_hotspots": [],
            "warning": (
                f"Carbon Footprint BigQuery query skipped ({exc}). "
                "Evaluate sustainability posture using resource locations (CFE%), idle resource signals, "
                "and architecture configurations returned by search_org_assets."
            ),
        }


def validate_terraform_and_uri(
    resource_uri: str,
    terraform_hcl: str,
    tool_context: ToolContext,
) -> dict:
    """Deterministically validates a WAFFinding's CAI resource URI and parses its Terraform HCL AST."""
    errors = []

    if not CAI_URI_PATTERN.match(resource_uri):
        errors.append(
            f"Invalid CAI URI format '{resource_uri}'. Must start with '//<service>.googleapis.com/'."
        )
    observed = set(tool_context.state.get("observed_resource_uris", []))
    if observed and resource_uri not in observed:
        errors.append(
            f"Hallucinated URI '{resource_uri}': resource was not returned by any CAI, SCC, or Recommender tool call."
        )

    if "agent-skills/1.0" in terraform_hcl or "CLOUDSDK_METRICS_REQUEST_ATTRIBUTION" in terraform_hcl:
        errors.append("Forbidden attribution tag found inside generated Terraform HCL.")

    try:
        parsed = hcl2.loads(terraform_hcl)
        if not parsed:
            errors.append("Terraform HCL parsed to an empty block.")
    except Exception as exc:
        errors.append(f"Terraform HCL syntax error: {exc}")

    return {"is_valid": len(errors) == 0, "errors": errors}


def _publish_gitops_plans_to_pubsub(topic_path: str, plans: list[dict]) -> int:
    """Publishes qualified GitOps PR plans to Cloud Pub/Sub REST endpoint."""
    import base64

    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    auth_req = google.auth.transport.requests.Request()
    credentials.refresh(auth_req)

    url = f"https://pubsub.googleapis.com/v1/{topic_path}:publish"
    messages = [
        {
            "data": base64.b64encode(json.dumps(plan).encode("utf-8")).decode("utf-8"),
            "attributes": {
                "fingerprint": plan["fingerprint"],
                "branch_name": plan["branch_name"],
                "target_tf_path": plan["target_tf_path"],
            },
        }
        for plan in plans
    ]
    req = urllib.request.Request(
        url,
        data=json.dumps({"messages": messages}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {credentials.token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=RPC_TIMEOUT_SECONDS) as resp:
        resp.read()
    return len(messages)


def commit_findings_to_bigquery_and_gcs(callback_context: CallbackContext) -> None:
    """Root SequentialAgent after_agent_callback: writes validated findings to BigQuery, Markdown to GCS, and GitOps PR plans."""
    report = callback_context.state.get("final_org_report") or callback_context.state.get("draft_org_report")
    if not report:
        return

    cfg = get_waf_config()
    bq_table = cfg.bq_table
    gcs_bucket_name = cfg.gcs_bucket
    gitops_topic = os.getenv("WAF_GITOPS_PUBSUB_TOPIC", "")
    now_iso = datetime.now(timezone.utc).isoformat()

    findings = report.get("validated_findings", [])
    uri_project_map = dict(callback_context.state.get("uri_to_project_id", {}))
    for f in findings:
        f["project_id"] = _resolve_human_project_id(
            raw_project=f.get("project_id", ""),
            resource_uri=f.get("resource_uri", ""),
            uri_project_map=uri_project_map,
        )

    if findings and os.getenv("WAF_ENABLE_BQ_WRITE", "FALSE") == "TRUE":
        bq_project = bq_table.split(".")[0] if "." in bq_table else None
        bq_client = bigquery.Client(project=bq_project)
        rows_to_insert = [
            {
                "evaluation_timestamp": now_iso,
                "org_id": report.get("org_id", ""),
                "scan_mode": report.get("scan_mode", "NIGHTLY_SWEEP"),
                "resource_uri": f["resource_uri"],
                "project_id": f["project_id"],
                "folder_id": f.get("folder_id"),
                "waf_pillar": f["waf_pillar"],
                "waf_principle": f["waf_principle"],
                "severity": f["severity"],
                "compliance_status": f["compliance_status"],
                "rationale": f["rationale"],
                "terraform_remediation": f["terraform_remediation"],
                "estimated_monthly_savings_usd": f.get("estimated_monthly_savings_usd"),
            }
            for f in findings
        ]
        errors = bq_client.insert_rows_json(bq_table, rows_to_insert)
        callback_context.state["bq_insert_status"] = (
            {"status": "SUCCESS", "rows_inserted": len(rows_to_insert), "table": bq_table}
            if not errors
            else {"status": "ERROR", "errors": errors, "table": bq_table}
        )

    exec_md = report.get("executive_markdown", "")
    if exec_md and gcs_bucket_name and os.getenv("WAF_ENABLE_GCS_WRITE", "FALSE") == "TRUE":
        now_dt = datetime.now(timezone.utc)
        scan_mode_slug = report.get("scan_mode", "NIGHTLY_SWEEP").lower()
        date_prefix = now_dt.strftime("%Y/%m/%d")
        ts_slug = now_dt.strftime("%Y%m%dT%H%M%SZ")
        archive_blob_path = f"reports/{date_prefix}/waf_report_{scan_mode_slug}_{ts_slug}.md"
        latest_blob_path = "reports/waf_executive_summary.md"

        storage_client = storage.Client(project=os.getenv("GOOGLE_CLOUD_QUOTA_PROJECT") or None)
        bucket = storage_client.bucket(gcs_bucket_name)
        for path in (latest_blob_path, archive_blob_path):
            blob = bucket.blob(path)
            blob.upload_from_string(exec_md, content_type="text/markdown")
        callback_context.state["gcs_upload_status"] = {
            "status": "SUCCESS",
            "bucket": gcs_bucket_name,
            "blobs": [
                f"gs://{gcs_bucket_name}/{latest_blob_path}",
                f"gs://{gcs_bucket_name}/{archive_blob_path}",
            ],
        }

    # Sink 3 (Phase 4): Generate & optionally publish deduplicated GitOps Pull Request plans
    if findings:
        thresholds = gitops_thresholds_from_env()
        max_prs = int(os.getenv("WAF_GITOPS_MAX_PRS_PER_RUN", "5"))
        existing_fps = set(callback_context.state.get("dispatched_gitops_fingerprints", []))
        # Select ALL eligible candidates first; the per-run cap is applied after durable-ledger
        # filtering so already-dispatched findings never crowd out new ones.
        candidates = select_findings_for_gitops(
            findings=findings,
            existing_fingerprints=existing_fps,
            min_severity=thresholds["min_severity"],
            min_cost_savings_usd=thresholds["min_cost_savings_usd"],
            max_prs_per_run=len(findings),
        )

        publish_enabled = bool(gitops_topic) and os.getenv("WAF_ENABLE_GITOPS_PR", "FALSE") == "TRUE"
        if publish_enabled:
            ledger_bucket_name = os.getenv("WAF_GITOPS_LEDGER_BUCKET", gcs_bucket_name)
            storage_client = storage.Client(project=os.getenv("GOOGLE_CLOUD_QUOTA_PROJECT") or None)
            ledger_bucket = storage_client.bucket(ledger_bucket_name)
            gitops_plans, claimed_blobs, skipped = [], [], 0
            for plan in candidates:
                if len(gitops_plans) >= max_prs:
                    break
                blob = _claim_gitops_fingerprint(ledger_bucket, plan)
                if blob is None:
                    skipped += 1
                    continue
                gitops_plans.append(plan)
                claimed_blobs.append(blob)

            if gitops_plans:
                try:
                    _publish_gitops_plans_to_pubsub(gitops_topic, gitops_plans)
                except Exception:
                    # Release claims so the next run can retry these fingerprints.
                    for blob in claimed_blobs:
                        try:
                            blob.delete()
                        except Exception:
                            pass
                    raise
            callback_context.state["gitops_ledger_status"] = {
                "bucket": ledger_bucket_name,
                "dispatched": len(gitops_plans),
                "skipped_already_dispatched": skipped,
            }
        else:
            gitops_plans = candidates[:max_prs]

        callback_context.state["gitops_pr_plans"] = gitops_plans
        callback_context.state["dispatched_gitops_fingerprints"] = list(
            existing_fps | {p["fingerprint"] for p in gitops_plans}
        )


def _claim_gitops_fingerprint(bucket: "storage.Bucket", plan: dict):
    """Atomically claims a fingerprint in the durable GCS dispatch ledger.

    Uses `if_generation_match=0` (create-only precondition) so concurrent Cloud Run instances
    processing overlapping drift events can never both dispatch the same PR. Returns the
    created blob on success, or None if the fingerprint was already dispatched by a prior run.
    """
    blob = bucket.blob(f"gitops/dispatched/{plan['fingerprint']}.json")
    record = {
        "fingerprint": plan["fingerprint"],
        "branch_name": plan["branch_name"],
        "target_tf_path": plan["target_tf_path"],
        "pr_title": plan["pr_title"],
        "dispatched_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        blob.upload_from_string(json.dumps(record), content_type="application/json", if_generation_match=0)
    except gcp_exceptions.PreconditionFailed:
        return None
    return blob
