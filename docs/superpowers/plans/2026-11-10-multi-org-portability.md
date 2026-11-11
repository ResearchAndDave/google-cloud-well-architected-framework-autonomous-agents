# Multi-Organization Portability & Turnkey Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple the Autonomous Google Cloud Well-Architected Framework (WAF) Auditor from hardcoded organization/project identifiers so it can be deployed turnkey into any GCP Organization, Folder, or Project—creating a dedicated WAF Compliance Host Project in a user-specified folder by default.

**Architecture:** Introduce a centralized runtime configuration module (`app/config.py`) that normalizes Organization/Folder/Project scopes and derives BigQuery/GCS resource identifiers dynamically from `GOOGLE_CLOUD_PROJECT`. Make the telemetry tools (`app/gcp_tools.py`) scope-polymorphic and resilient when optional enterprise services (SCC v2, Carbon Footprint export) are unconfigured. Refactor the flat `terraform/` root module to create a dedicated WAF Compliance Host Project by default (`create_compliance_project = true`) under `parent_folder_id`, automatically enable host APIs and Artifact Registry (`terraform/services.tf`), bind IAM and CAI feeds polymorphically across `ORGANIZATION`/`FOLDER`/`PROJECT` scopes, make Phase 4 GitOps opt-in (`enable_gitops = false`), and provide a two-stage bootstrap script (`scripts/deploy.sh`) plus `terraform/terraform.tfvars.example`.

**Tech Stack:** Python 3.12 (`google-adk`, `google-cloud-*`, `fastapi`, `pytest`), Terraform `>= 1.5` (`hashicorp/google ~> 6.0`, `hashicorp/google-beta ~> 6.0`, `hashicorp/random ~> 3.6`), Bash (`gcloud`, `terraform`).

---

## File Structure

- **Create:**
  - `app/config.py` — Centralized `WAFConfig` frozen dataclass, `get_waf_config()`, and `normalize_scope()` helper.
  - `tests/test_multi_org_portability.py` — Unit tests for `normalize_scope`, `get_waf_config`, multi-scope SCC v2, graceful Carbon Footprint fallback, dynamic Recommender locations, and dashboard config wiring.
  - `terraform/project.tf` — Input variables (`create_compliance_project`, `compliance_project_id`, `parent_folder_id`, `billing_account_id`, `scope_type`, `scope_id`, `org_id`, `region`, `enable_realtime_feeds`, `enable_gitops`, `carbon_export_table`), `random_id.project_suffix`, `google_project.waf_compliance`, and scope/project resolution `locals`.
  - `terraform/services.tf` — `google_project_service.required_apis` and `google_artifact_registry_repository.waf_auditor`.
  - `terraform/outputs.tf` — Terraform outputs (`compliance_project_id`, `region`, `canonical_scope`, `artifact_registry_image`, `cloud_run_service_uri`, `bigquery_dataset`, `gcs_artifact_bucket`).
  - `terraform/terraform.tfvars.example` — Copy-pasteable presets for Default (New WAF Project in Folder + Org Audit), Folder-Scoped Audit, and Existing Host Project modes.
  - `scripts/deploy.sh` — Executable two-stage bootstrap script (Stage 1: Project/APIs/AR -> Stage 2: Cloud Build / Docker push -> Stage 3: Full Terraform Apply).
- **Modify:**
  - `app/gcp_tools.py` — Replace hardcoded project/bucket defaults with `get_waf_config()`, make `get_active_scc_findings` support `organizations/*`, `folders/*`, and `projects/*` parents, make `query_carbon_footprint_summary` degrade gracefully with a warning when unconfigured, and merge `observed_locations` in `fetch_project_recommendations`.
  - `app/main.py` — Wire `get_waf_config()` for `PROJECT_ID`, `LOCATION`, and `DEFAULT_ORG_ID`.
  - `app/dashboard.py` — Replace hardcoded `legacy-waf-compliance-0` and `organizations/123456789012` strings in `fetch_dashboard_telemetry` and `render_tufte_architecture_html` with `get_waf_config()`.
  - `app/skill_loader.py` — Use `get_waf_config().target_scope` as fallback in `build_pillar_instruction_provider` and clarify multi-scope & optional telemetry fallback rules.
  - `scripts/replay_drift.py` — Use `get_waf_config()` for default `--org-id` and Pub/Sub subscription project slug.
  - `terraform/versions.tf` — Add `hashicorp/random` (`~> 3.6`) provider and remove static `project = var.compliance_project_id` from provider blocks so `google_project.waf_compliance` can be created when `compliance_project_id` is generated.
  - `terraform/iam.tf` — Remove duplicate variable declarations (moved to `terraform/project.tf`), reference `local.effective_project_id`, and add `google_organization_iam_member`, `google_folder_iam_member`, and `google_project_iam_member` conditional bindings based on `var.scope_type`.
  - `terraform/pubsub_cai.tf` — Reference `local.effective_project_id` and conditionally provision `google_cloud_asset_organization_feed`, `google_cloud_asset_folder_feed`, or `google_cloud_asset_project_feed` when `var.enable_realtime_feeds` is `true`.
  - `terraform/bigquery.tf` — Reference `local.effective_project_id`.
  - `terraform/cloud_run.tf` — Reference `local.effective_project_id`, `local.canonical_scope`, and `var.carbon_export_table`.
  - `terraform/gitops_cloudbuild.tf` — Gate all Phase 4 GitOps resources behind `count = var.enable_gitops ? 1 : 0` and reference `local.effective_project_id`.
  - `README.md` — Document multi-org / folder / project deployment presets and `scripts/deploy.sh`.

---

### Task 1: Centralized Runtime Configuration Module (`app/config.py`)

**Files:**
- Create: `app/config.py`
- Test: `tests/test_multi_org_portability.py`

- [ ] **Step 1: Write the failing unit tests for `normalize_scope` and `get_waf_config`**

Create `tests/test_multi_org_portability.py`:

```python
"""Unit tests for multi-organization portability, scope normalization, and graceful telemetry degradation."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.config import WAFConfig, get_waf_config, normalize_scope


def test_normalize_scope_variants():
    assert normalize_scope("organizations/123456789") == "organizations/123456789"
    assert normalize_scope("123456789") == "organizations/123456789"
    assert normalize_scope("folders/987654321") == "folders/987654321"
    assert normalize_scope("projects/my-custom-proj") == "projects/my-custom-proj"
    assert normalize_scope("my-custom-proj") == "projects/my-custom-proj"
    assert normalize_scope("", fallback_project="host-proj-1") == "projects/host-proj-1"


def test_get_waf_config_derives_defaults_from_project(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "acme-waf-hub-01")
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "europe-west1")
    monkeypatch.setenv("WAF_TARGET_SCOPE", "folders/44556677")
    monkeypatch.delenv("WAF_BQ_TABLE", raising=False)
    monkeypatch.delenv("WAF_GCS_BUCKET", raising=False)
    monkeypatch.delenv("WAF_CARBON_EXPORT_TABLE", raising=False)

    cfg = get_waf_config()
    assert isinstance(cfg, WAFConfig)
    assert cfg.project_id == "acme-waf-hub-01"
    assert cfg.quota_project_id == "acme-waf-hub-01"
    assert cfg.location == "europe-west1"
    assert cfg.target_scope == "folders/44556677"
    assert cfg.bq_table == "acme-waf-hub-01.org_compliance.waf_findings"
    assert cfg.gcs_bucket == "acme-waf-hub-01-waf-artifacts"
    assert "europe-west1" in cfg.recommender_locations
    assert "global" in cfg.recommender_locations
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/test_multi_org_portability.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.config'`

- [ ] **Step 3: Implement `app/config.py`**

Create `app/config.py`:

```python
"""Centralized runtime configuration and scope normalization for the WAF Auditor."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re

NUMERIC_ID_PATTERN = re.compile(r"^\d+$")
DEFAULT_RECOMMENDER_LOCATIONS = "global,us-central1,us-east1,europe-west1,asia-east1"


def normalize_scope(raw_scope: str | None, fallback_project: str = "waf-compliance-hub") -> str:
    """Normalizes an audit scope string into canonical CAI parent format.

    Supports:
      - 'organizations/<id>' or bare numeric '<id>' -> 'organizations/<id>'
      - 'folders/<id>' -> 'folders/<id>'
      - 'projects/<id>' or bare project slug '<slug>' -> 'projects/<slug>'
      - Empty/None -> 'projects/<fallback_project>'
    """
    cleaned = (raw_scope or "").strip().rstrip("/")
    if not cleaned:
        return f"projects/{fallback_project}"
    if cleaned.startswith(("organizations/", "folders/", "projects/")):
        return cleaned
    if NUMERIC_ID_PATTERN.match(cleaned):
        return f"organizations/{cleaned}"
    return f"projects/{cleaned}"


@dataclass(frozen=True)
class WAFConfig:
    """Resolved runtime configuration for a WAF Auditor deployment."""

    project_id: str
    quota_project_id: str
    location: str
    target_scope: str
    bq_table: str
    gcs_bucket: str
    carbon_export_table: str
    recommender_locations: list[str]


def get_waf_config() -> WAFConfig:
    """Resolves WAFConfig from environment variables with zero hardcoded org lock-in."""
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "waf-compliance-hub").strip() or "waf-compliance-hub"
    quota_project_id = (os.getenv("GOOGLE_CLOUD_QUOTA_PROJECT") or project_id).strip()
    location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1").strip() or "us-central1"

    raw_scope = os.getenv("WAF_TARGET_SCOPE") or os.getenv("WAF_ORG_ID", "organizations/123456789")
    target_scope = normalize_scope(raw_scope, fallback_project=project_id)

    bq_table = (
        os.getenv("WAF_BQ_TABLE", "").strip()
        or f"{project_id}.org_compliance.waf_findings"
    )
    gcs_bucket = (
        os.getenv("WAF_GCS_BUCKET", "").strip()
        or f"{project_id}-waf-artifacts"
    )
    carbon_export_table = os.getenv("WAF_CARBON_EXPORT_TABLE", "").strip()

    raw_locs = os.getenv("WAF_RECOMMENDER_LOCATIONS", DEFAULT_RECOMMENDER_LOCATIONS)
    loc_list: list[str] = []
    for item in ["global", location, *[x.strip() for x in raw_locs.split(",") if x.strip()]]:
        if item and item not in loc_list:
            loc_list.append(item)

    return WAFConfig(
        project_id=project_id,
        quota_project_id=quota_project_id,
        location=location,
        target_scope=target_scope,
        bq_table=bq_table,
        gcs_bucket=gcs_bucket,
        carbon_export_table=carbon_export_table,
        recommender_locations=loc_list,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra dev pytest tests/test_multi_org_portability.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add app/config.py tests/test_multi_org_portability.py
git commit -m "feat(config): add centralized WAFConfig and multi-scope normalization"
```

---

### Task 2: Scope-Aware & Gracefully Degrading Telemetry Tools (`app/gcp_tools.py`)

**Files:**
- Modify: `app/gcp_tools.py:1-135`, `app/gcp_tools.py:170-305`, `app/gcp_tools.py:365-380`
- Test: `tests/test_multi_org_portability.py`

- [ ] **Step 1: Add failing unit tests for multi-scope SCC v2, graceful Carbon Footprint fallback, and dynamic Recommender locations**

Append to `tests/test_multi_org_portability.py`:

```python
from app.gcp_tools import (
    fetch_project_recommendations,
    get_active_scc_findings,
    query_carbon_footprint_summary,
)


def test_scc_findings_supports_folder_and_project_scopes():
    with patch("app.gcp_tools.securitycenter_v2.SecurityCenterClient") as mock_cls:
        mock_client = MagicMock()
        mock_client.list_findings.return_value = []
        mock_cls.return_value = mock_client

        res_folder = get_active_scc_findings(org_id="folders/55667788")
        assert res_folder["active_findings_count"] == 0
        call_req = mock_client.list_findings.call_args.kwargs["request"]
        assert call_req.parent == "folders/55667788/sources/-/locations/global"

        res_proj = get_active_scc_findings(org_id="projects/my-sec-proj")
        call_req_proj = mock_client.list_findings.call_args.kwargs["request"]
        assert call_req_proj.parent == "projects/my-sec-proj/sources/-/locations/global"


def test_carbon_footprint_degrades_gracefully_when_unconfigured(monkeypatch):
    monkeypatch.delenv("WAF_CARBON_EXPORT_TABLE", raising=False)
    result = query_carbon_footprint_summary(billing_export_table="")
    assert result["hotspot_count"] == 0
    assert result["carbon_hotspots"] == []
    assert "warning" in result

    with patch("app.gcp_tools.bigquery.Client") as mock_bq_cls:
        mock_bq = MagicMock()
        mock_bq.query.side_effect = RuntimeError("404 Not found: Table billing.carbon_footprint")
        mock_bq_cls.return_value = mock_bq

        res_err = query_carbon_footprint_summary(billing_export_table="missing-proj.billing.carbon")
        assert res_err["hotspot_count"] == 0
        assert res_err["carbon_hotspots"] == []
        assert "warning" in res_err


def test_recommender_merges_observed_locations_from_state(monkeypatch):
    monkeypatch.setenv("WAF_RECOMMENDER_LOCATIONS", "global,us-central1")
    ctx = SimpleNamespace(state={"observed_resource_uris": [], "observed_locations": ["europe-west4"]})
    queried_parents = []

    with patch("app.gcp_tools.recommender_v1.RecommenderClient") as mock_rec_cls:
        mock_client = MagicMock()

        def _fake_list(parent, timeout=None):
            queried_parents.append(parent)
            return []

        mock_client.list_recommendations.side_effect = _fake_list
        mock_rec_cls.return_value = mock_client

        fetch_project_recommendations(
            project_id="demo-proj",
            pillar_category="SECURITY",
            locations=["global"],
            tool_context=ctx,
        )

    assert any("/locations/europe-west4/" in p for p in queried_parents)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --extra dev pytest tests/test_multi_org_portability.py -v`
Expected: FAIL (`call_req.parent` is `'organizations/folders/55667788/sources/-/locations/global'` and `query_carbon_footprint_summary` fails when `billing_export_table=""`)

- [ ] **Step 3: Update `app/gcp_tools.py` to use `get_waf_config()` and `normalize_scope()`**

Modify `app/gcp_tools.py`:

1. Import `get_waf_config` and `normalize_scope` from `.config`:
```python
from .config import get_waf_config, normalize_scope
from .gitops import gitops_thresholds_from_env, select_findings_for_gitops
```

2. Update `_client_options()` in `app/gcp_tools.py`:
```python
def _client_options() -> ClientOptions:
    """Returns Google Cloud SDK ClientOptions with dynamic quota project for ADC."""
    quota_project = get_waf_config().quota_project_id
    return ClientOptions(quota_project_id=quota_project)
```

3. Track `observed_locations` in `search_org_assets` (`app/gcp_tools.py`):
```python
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
```

4. Update `get_active_scc_findings` in `app/gcp_tools.py` to support `organizations/*`, `folders/*`, and `projects/*`:
```python
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
```

5. Update `fetch_project_recommendations` and `query_carbon_footprint_summary` in `app/gcp_tools.py`:
```python
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
```

6. Update `commit_findings_to_bigquery_and_gcs` in `app/gcp_tools.py` to use `get_waf_config()` instead of hardcoded `legacy-waf-compliance-0`:
```python
    cfg = get_waf_config()
    bq_table = cfg.bq_table
    gcs_bucket_name = cfg.gcs_bucket
    gitops_topic = os.getenv("WAF_GITOPS_PUBSUB_TOPIC", "")
    now_iso = datetime.now(timezone.utc).isoformat()
```

- [ ] **Step 4: Run unit tests to verify they pass**

Run: `uv run --extra dev pytest tests/test_multi_org_portability.py tests/test_critic_validation.py tests/test_gitops_pr.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/gcp_tools.py tests/test_multi_org_portability.py
git commit -m "feat(telemetry): support folder/project SCC scopes and graceful carbon/recommender fallbacks"
```

---

### Task 3: Wire `app/main.py`, `app/dashboard.py`, `app/skill_loader.py`, and `scripts/replay_drift.py` to `WAFConfig`

**Files:**
- Modify: `app/main.py:20-46`
- Modify: `app/dashboard.py:20-58`, `app/dashboard.py:1018-1025`, `app/dashboard.py:1275-1283`, `app/dashboard.py:1416-1422`, `app/dashboard.py:1576-1612`
- Modify: `app/skill_loader.py:43-72`
- Modify: `scripts/replay_drift.py:39-80`
- Test: `tests/test_multi_org_portability.py`

- [ ] **Step 1: Add failing test verifying `render_tufte_architecture_html()` and `build_pillar_instruction_provider()` reflect configured project/scope with zero hardcoded `legacy-waf-compliance-0` strings**

Append to `tests/test_multi_org_portability.py`:

```python
from app.dashboard import render_tufte_architecture_html
from app.skill_loader import build_pillar_instruction_provider


def test_architecture_html_uses_dynamic_waf_config(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "globex-waf-compliance")
    monkeypatch.setenv("WAF_TARGET_SCOPE", "folders/88990011")
    monkeypatch.delenv("WAF_BQ_TABLE", raising=False)
    monkeypatch.delenv("WAF_GCS_BUCKET", raising=False)

    html_out = render_tufte_architecture_html()
    assert "globex-waf-compliance" in html_out
    assert "folders/88990011" in html_out
    assert "legacy-waf-compliance-0" not in html_out
    assert "123456789012" not in html_out


def test_instruction_provider_uses_configured_scope(monkeypatch):
    monkeypatch.setenv("WAF_TARGET_SCOPE", "folders/11223344")
    provider = build_pillar_instruction_provider("google-cloud-waf-security")
    ctx = SimpleNamespace(state={})
    prompt = provider(ctx)
    assert "folders/11223344" in prompt
    assert "123456789012" not in prompt
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/test_multi_org_portability.py -v`
Expected: FAIL (`assert "globex-waf-compliance" in html_out` fails because `render_tufte_architecture_html()` has hardcoded `legacy-waf-compliance-0` and `123456789012`)

- [ ] **Step 3: Update `app/main.py`, `app/dashboard.py`, `app/skill_loader.py`, and `scripts/replay_drift.py`**

1. In `app/main.py`, import `get_waf_config` and update module-level config initialization:
```python
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
```

2. In `app/dashboard.py`:
- Import `get_waf_config` from `.config`:
```python
from .config import get_waf_config
from .gitops import build_gitops_pr_plan, gitops_ineligibility_reason, gitops_thresholds_from_env
```
- Update `fetch_dashboard_telemetry`:
```python
def fetch_dashboard_telemetry(report_blob_name: str | None = None) -> dict[str, Any]:
    """Queries the 4 Looker Studio BigQuery views and GCS Executive Markdown reports, with automatic local cache fallback if ADC expires."""
    cfg = get_waf_config()
    bq_table = cfg.bq_table
    parts = bq_table.split(".")
    project_id = parts[0] if len(parts) == 3 else cfg.project_id
    dataset_id = parts[1] if len(parts) == 3 else "org_compliance"
    gcs_bucket_name = cfg.gcs_bucket
    selected_blob = report_blob_name or "reports/waf_executive_summary.md"
```
- Update `render_tufte_architecture_html()` in `app/dashboard.py` to resolve `cfg = get_waf_config()` at the start of the function and substitute `cfg.target_scope`, `cfg.project_id`, `cfg.quota_project_id`, `cfg.bq_table`, and `cfg.gcs_bucket` in place of the hardcoded `organizations/123456789012`, `legacy-waf-compliance-0`, and `legacy-ai-inference-dev-0` strings:
```python
def render_tufte_architecture_html() -> str:
    """Renders an Edward Tufte-inspired Architectural Overview & Multivariate System Schematic."""
    cfg = get_waf_config()
    scope_esc = html.escape(cfg.target_scope)
    proj_esc = html.escape(cfg.project_id)
    quota_esc = html.escape(cfg.quota_project_id)
    bq_esc = html.escape(cfg.bq_table)
    gcs_esc = html.escape(cfg.gcs_bucket)
    html_template = """<!DOCTYPE html>
...
```
And replace the 5 hardcoded occurrences inside `render_tufte_architecture_html()` using `.replace()`:
```python
    return (
        html_template.replace("__WAF_TARGET_SCOPE__", scope_esc)
        .replace("__WAF_PROJECT_ID__", proj_esc)
        .replace("__WAF_QUOTA_PROJECT_ID__", quota_esc)
        .replace("__WAF_BQ_TABLE__", bq_esc)
        .replace("__WAF_GCS_BUCKET__", gcs_esc)
    )
```

3. In `app/skill_loader.py`:
- Import `get_waf_config` from `.config`:
```python
from .config import get_waf_config
```
- Update `build_pillar_instruction_provider`:
```python
def build_pillar_instruction_provider(skill_dir_name: str) -> Callable[[ReadonlyContext], str]:
    """Builds an ADK InstructionProvider that injects SKILL.md + runtime session.state context."""

    def instruction_provider(ctx: ReadonlyContext) -> str:
        metadata, skill_markdown = WAFSkillLoader.load_skill(skill_dir_name)
        cfg = get_waf_config()
        org_id = ctx.state.get("org_id", cfg.target_scope)
        scan_mode = ctx.state.get("scan_mode", "NIGHTLY_SWEEP")
        target_asset = ctx.state.get("target_asset", ctx.state.get("target_scope", "ALL_ORG_ASSETS"))

        return f"""You are an autonomous Google Cloud Well-Architected Framework (WAF) Auditor Agent
operating under skill `{metadata.get('name', skill_dir_name)}` (v{metadata.get('metadata', {}).get('version', '1.0')}).

### RUNTIME EXECUTION CONTEXT
- Organization / Hierarchy Scope: `{org_id}`
- Scan Mode: `{scan_mode}`
- Target Asset Filter: `{target_asset}`

### AUTONOMOUS OPERATING RULES
1. DO NOT ask interactive questions. Infer workload criticality and environment from GCP resource labels (`env`, `tier`, `cost-center`), folders, and project naming conventions.
2. If `Scan Mode` is `REALTIME_DRIFT`, evaluate ONLY the mutated resource in `Target Asset Filter`. If the mutated asset type is not relevant to your pillar, return `findings=[]` and `pillar_score=100` immediately without calling unnecessary tools.
3. Every `waf_principle` you cite in a `WAFFinding` MUST match one of the exact bolded Core Principles in the Official Skill Rubric below.
4. When you need deeper architectural guidance on a specific principle URL (`https://docs.cloud.google.com/architecture/framework/.../*.md.txt`) or a specialized workload skill (e.g., `gke-reliability/SKILL.md`), call `read_waf_skill_reference`.
5. If optional organization telemetry tools (`get_active_scc_findings` or `query_carbon_footprint_summary`) return a `warning`, rely on `search_org_assets` and `inspect_resource_configuration` to evaluate resources directly.
6. Produce valid, self-contained Terraform HCL in `terraform_remediation`. NEVER include `CLOUDSDK_METRICS_REQUEST_ATTRIBUTION` or `agent-skills/1.0` tracking tags inside generated Terraform HCL code.

### OFFICIAL SKILL RUBRIC ({skill_dir_name})
{skill_markdown}
"""

    return instruction_provider
```

4. In `scripts/replay_drift.py`, use `os.getenv("GOOGLE_CLOUD_PROJECT", "waf-compliance-hub")` for the synthetic Pub/Sub subscription name and `os.getenv("WAF_TARGET_SCOPE") or os.getenv("WAF_ORG_ID", "organizations/123456789")` for the default `--org-id`.

- [ ] **Step 4: Run all Python unit and async integration tests**

Run:
```bash
uv run --extra dev pytest -v -k "not asyncio"
uv run --extra dev pytest tests/test_pubsub_push.py tests/test_critic_loop.py -v -k "asyncio"
```
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app/main.py app/dashboard.py app/skill_loader.py scripts/replay_drift.py tests/test_multi_org_portability.py
git commit -m "feat(app): unify runtime scope and project configuration across main, dashboard, and skill loader"
```

---

### Task 4: Refactor Terraform for Dedicated Host Project Creation, Host API Bootstrap & Polymorphic Scope (`terraform/`)

**Files:**
- Create: `terraform/project.tf`
- Create: `terraform/services.tf`
- Create: `terraform/outputs.tf`
- Create: `terraform/terraform.tfvars.example`
- Modify: `terraform/versions.tf`
- Modify: `terraform/iam.tf`
- Modify: `terraform/pubsub_cai.tf`
- Modify: `terraform/bigquery.tf`
- Modify: `terraform/cloud_run.tf`
- Modify: `terraform/gitops_cloudbuild.tf`

- [ ] **Step 1: Update `terraform/versions.tf` to add `hashicorp/random` and use `local.effective_project_id`**

Modify `terraform/versions.tf`:

```hcl
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "google" {
  region = var.region
}

provider "google-beta" {
  region = var.region
}
```

- [ ] **Step 2: Create `terraform/project.tf` for dedicated WAF Compliance Host Project creation in a user-specified folder and polymorphic scope resolution**

Create `terraform/project.tf`:

```hcl
variable "create_compliance_project" {
  type        = bool
  default     = true
  description = "When true (default), creates a dedicated GCP project for the WAF Auditor inside var.parent_folder_id (or var.org_id). Set to false to deploy into an existing project."
}

variable "compliance_project_id" {
  type        = string
  default     = ""
  description = "Custom GCP Project ID to create (when create_compliance_project = true) or existing Project ID to use (when create_compliance_project = false). If empty and create_compliance_project = true, generates waf-compliance-<hex>."
}

variable "compliance_project_name" {
  type        = string
  default     = "WAF Compliance Hub"
  description = "Display name for the created WAF Compliance Host Project."
}

variable "parent_folder_id" {
  type        = string
  default     = ""
  description = "GCP Folder ID (e.g., '987654321098' or 'folders/987654321098') where the dedicated WAF Compliance Project will be created."
}

variable "billing_account_id" {
  type        = string
  default     = ""
  description = "Billing Account ID (e.g., '012345-6789AB-CDEF01') attached to the created WAF Compliance Project when create_compliance_project = true."
}

variable "org_id" {
  type        = string
  default     = ""
  description = "Optional numeric Google Cloud Organization ID. Used as fallback project parent if parent_folder_id is empty, and as fallback scope_id when scope_type = 'ORGANIZATION'."
}

variable "scope_type" {
  type        = string
  default     = "ORGANIZATION"
  description = "Target hierarchy level to audit: 'ORGANIZATION', 'FOLDER', or 'PROJECT'."

  validation {
    condition     = contains(["ORGANIZATION", "FOLDER", "PROJECT"], upper(var.scope_type))
    error_message = "scope_type must be one of: ORGANIZATION, FOLDER, PROJECT."
  }
}

variable "scope_id" {
  type        = string
  default     = ""
  description = "Target audit scope identifier (numeric Org ID, numeric Folder ID, or Project ID). Falls back to var.org_id, var.parent_folder_id, or the compliance project ID."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "Primary GCP region for Cloud Run, BigQuery, Artifact Registry, and Cloud Scheduler."
}

variable "enable_realtime_feeds" {
  type        = bool
  default     = true
  description = "Enables Cloud Asset Inventory RealTimeFeeds (RESOURCE and IAM_POLICY) at the target audit scope."
}

variable "enable_gitops" {
  type        = bool
  default     = false
  description = "Enables Phase 4 GitOps Pull Request Cloud Build worker, Pub/Sub topic, and Secret Manager secret."
}

variable "carbon_export_table" {
  type        = string
  default     = ""
  description = "Optional BigQuery table ID (project.dataset.carbon_footprint) for the Sustainability pillar."
}

resource "random_id" "project_suffix" {
  count       = var.create_compliance_project && var.compliance_project_id == "" ? 1 : 0
  byte_length = 3
}

locals {
  normalized_scope_type  = upper(var.scope_type)
  clean_parent_folder_id = replace(var.parent_folder_id, "folders/", "")
  clean_org_id           = replace(var.org_id, "organizations/", "")

  generated_project_id = (
    var.compliance_project_id != ""
    ? var.compliance_project_id
    : "waf-compliance-${coalesce(one(random_id.project_suffix[*].hex), "000000")}"
  )
}

resource "google_project" "waf_compliance" {
  count           = var.create_compliance_project ? 1 : 0
  name            = var.compliance_project_name
  project_id      = local.generated_project_id
  folder_id       = local.clean_parent_folder_id != "" ? local.clean_parent_folder_id : null
  org_id          = local.clean_parent_folder_id == "" && local.clean_org_id != "" ? local.clean_org_id : null
  billing_account = var.billing_account_id != "" ? var.billing_account_id : null
  deletion_policy = "PREVENT"
}

locals {
  effective_project_id = (
    var.create_compliance_project
    ? google_project.waf_compliance[0].project_id
    : var.compliance_project_id
  )

  raw_scope_id = (
    var.scope_id != "" ? var.scope_id : (
      local.normalized_scope_type == "ORGANIZATION" ? local.clean_org_id : (
        local.normalized_scope_type == "FOLDER" ? local.clean_parent_folder_id : local.effective_project_id
      )
    )
  )

  clean_scope_id = replace(
    replace(replace(local.raw_scope_id, "organizations/", ""), "folders/", ""),
    "projects/",
    ""
  )

  scope_prefix_map = {
    ORGANIZATION = "organizations"
    FOLDER       = "folders"
    PROJECT      = "projects"
  }

  canonical_scope = "${local.scope_prefix_map[local.normalized_scope_type]}/${local.clean_scope_id}"
}
```

- [ ] **Step 3: Create `terraform/services.tf` for host project API enablement and Artifact Registry provisioning**

Create `terraform/services.tf`:

```hcl
locals {
  core_apis = [
    "serviceusage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "run.googleapis.com",
    "cloudasset.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "aiplatform.googleapis.com",
    "pubsub.googleapis.com",
    "cloudscheduler.googleapis.com",
    "artifactregistry.googleapis.com",
    "recommender.googleapis.com",
    "cloudbuild.googleapis.com",
  ]

  gitops_apis = var.enable_gitops ? ["secretmanager.googleapis.com"] : []

  required_apis = toset(concat(local.core_apis, local.gitops_apis))
}

resource "google_project_service" "required_apis" {
  for_each           = local.required_apis
  project            = local.effective_project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "waf_auditor" {
  project       = local.effective_project_id
  location      = var.region
  repository_id = "waf-auditor"
  description   = "Container images for the Autonomous Google Cloud WAF Auditor"
  format        = "DOCKER"

  depends_on = [
    google_project_service.required_apis["artifactregistry.googleapis.com"],
  ]
}
```

- [ ] **Step 4: Update `terraform/iam.tf`, `terraform/pubsub_cai.tf`, `terraform/bigquery.tf`, `terraform/cloud_run.tf`, and `terraform/gitops_cloudbuild.tf`, and create `terraform/outputs.tf`**

1. Update `terraform/iam.tf`:
```hcl
locals {
  org_readonly_roles = toset([
    "roles/cloudasset.viewer",
    "roles/securitycenter.findingsViewer",
    "roles/recommender.viewer",
    "roles/monitoring.viewer",
    "roles/cloudconfig.viewer",
    "roles/browser",
  ])
}

resource "google_service_account" "waf_auditor_sa" {
  project      = local.effective_project_id
  account_id   = "waf-auditor-sa"
  display_name = "Autonomous WAF Auditor Runtime SA"

  depends_on = [
    google_project_service.required_apis["iam.googleapis.com"],
  ]
}

resource "google_organization_iam_member" "org_readonly" {
  for_each = local.normalized_scope_type == "ORGANIZATION" ? local.org_readonly_roles : toset([])
  org_id   = local.clean_scope_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_folder_iam_member" "folder_readonly" {
  for_each = local.normalized_scope_type == "FOLDER" ? local.org_readonly_roles : toset([])
  folder   = "folders/${local.clean_scope_id}"
  role     = each.value
  member   = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_project_iam_member" "project_readonly" {
  for_each = local.normalized_scope_type == "PROJECT" ? local.org_readonly_roles : toset([])
  project  = local.clean_scope_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_project_iam_member" "vertex_ai_user" {
  project = local.effective_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_bigquery_dataset_iam_member" "bq_dataset_writer" {
  project    = local.effective_project_id
  dataset_id = google_bigquery_dataset.org_compliance.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_project_iam_member" "bq_job_user" {
  project = local.effective_project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_storage_bucket" "waf_artifacts" {
  project                     = local.effective_project_id
  name                        = "${local.effective_project_id}-waf-artifacts"
  location                    = var.region
  uniform_bucket_level_access = true
  versioning {
    enabled = true
  }

  depends_on = [
    google_project_service.required_apis["storage.googleapis.com"],
  ]
}

resource "google_storage_bucket_iam_member" "gcs_artifact_admin" {
  bucket = google_storage_bucket.waf_artifacts.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}
```

2. Update `terraform/pubsub_cai.tf` to support Organization, Folder, and Project feeds:
```hcl
locals {
  high_risk_asset_types = [
    "compute.googleapis.com/Firewall",
    "container.googleapis.com/Cluster",
    "sqladmin.googleapis.com/Instance",
  ]

  iam_policy_asset_types = [
    "cloudresourcemanager.googleapis.com/Project",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Organization",
  ]
}

resource "google_pubsub_topic" "waf_audit_triggers" {
  project = local.effective_project_id
  name    = "waf-audit-triggers"

  depends_on = [
    google_project_service.required_apis["pubsub.googleapis.com"],
  ]
}

resource "google_project_service_identity" "cai_identity" {
  provider = google-beta
  project  = local.effective_project_id
  service  = "cloudasset.googleapis.com"

  depends_on = [
    google_project_service.required_apis["cloudasset.googleapis.com"],
  ]
}

resource "google_pubsub_topic_iam_member" "cai_publisher" {
  project = local.effective_project_id
  topic   = google_pubsub_topic.waf_audit_triggers.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_project_service_identity.cai_identity.email}"
}

# --- ORGANIZATION SCOPE FEEDS ---
resource "google_cloud_asset_organization_feed" "high_risk_resources" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "ORGANIZATION" ? 1 : 0
  billing_project = local.effective_project_id
  org_id          = local.clean_scope_id
  feed_id         = "waf-high-risk-resource-drift"
  content_type    = "RESOURCE"
  asset_types     = local.high_risk_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Exclude deleted resources"
    expression = "!temporal_asset.deleted"
  }
}

resource "google_cloud_asset_organization_feed" "iam_policy_drift" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "ORGANIZATION" ? 1 : 0
  billing_project = local.effective_project_id
  org_id          = local.clean_scope_id
  feed_id         = "waf-iam-policy-drift"
  content_type    = "IAM_POLICY"
  asset_types     = local.iam_policy_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Active IAM policy changes only"
    expression = "!temporal_asset.deleted"
  }
}

# --- FOLDER SCOPE FEEDS ---
resource "google_cloud_asset_folder_feed" "high_risk_resources_folder" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "FOLDER" ? 1 : 0
  billing_project = local.effective_project_id
  folder          = local.clean_scope_id
  feed_id         = "waf-high-risk-resource-drift"
  content_type    = "RESOURCE"
  asset_types     = local.high_risk_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Exclude deleted resources"
    expression = "!temporal_asset.deleted"
  }
}

resource "google_cloud_asset_folder_feed" "iam_policy_drift_folder" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "FOLDER" ? 1 : 0
  billing_project = local.effective_project_id
  folder          = local.clean_scope_id
  feed_id         = "waf-iam-policy-drift"
  content_type    = "IAM_POLICY"
  asset_types     = local.iam_policy_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Active IAM policy changes only"
    expression = "!temporal_asset.deleted"
  }
}

# --- PROJECT SCOPE FEEDS ---
resource "google_cloud_asset_project_feed" "high_risk_resources_project" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "PROJECT" ? 1 : 0
  billing_project = local.effective_project_id
  project         = local.clean_scope_id
  feed_id         = "waf-high-risk-resource-drift"
  content_type    = "RESOURCE"
  asset_types     = local.high_risk_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Exclude deleted resources"
    expression = "!temporal_asset.deleted"
  }
}

resource "google_cloud_asset_project_feed" "iam_policy_drift_project" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "PROJECT" ? 1 : 0
  billing_project = local.effective_project_id
  project         = local.clean_scope_id
  feed_id         = "waf-iam-policy-drift"
  content_type    = "IAM_POLICY"
  asset_types     = local.iam_policy_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Active IAM policy changes only"
    expression = "!temporal_asset.deleted"
  }
}
```

3. Replace `var.compliance_project_id` with `local.effective_project_id` in `terraform/bigquery.tf`, `terraform/cloud_run.tf`, and `terraform/gitops_cloudbuild.tf`. In `terraform/cloud_run.tf`, set `WAF_TARGET_SCOPE` and `WAF_ORG_ID` to `local.canonical_scope`, and add `WAF_CARBON_EXPORT_TABLE = var.carbon_export_table`. In `terraform/gitops_cloudbuild.tf`, gate all resources with `count = var.enable_gitops ? 1 : 0`.

4. Create `terraform/outputs.tf`:
```hcl
output "compliance_project_id" {
  description = "Effective GCP Project ID hosting the WAF Auditor infrastructure."
  value       = local.effective_project_id
}

output "region" {
  description = "Deployed GCP region."
  value       = var.region
}

output "canonical_scope" {
  description = "Canonical Cloud Asset Inventory audit scope (organizations/*, folders/*, or projects/*)."
  value       = local.canonical_scope
}

output "artifact_registry_image" {
  description = "Target container image URI in Artifact Registry."
  value       = "${var.region}-docker.pkg.dev/${local.effective_project_id}/${google_artifact_registry_repository.waf_auditor.repository_id}/agent:latest"
}

output "cloud_run_service_uri" {
  description = "Deployed Cloud Run v2 service URL."
  value       = google_cloud_run_v2_service.waf_auditor.uri
}

output "bigquery_dataset" {
  description = "BigQuery compliance dataset identifier."
  value       = "${local.effective_project_id}.${google_bigquery_dataset.org_compliance.dataset_id}"
}

output "gcs_artifact_bucket" {
  description = "GCS bucket storing executive Markdown reports and GitOps dispatch ledger."
  value       = google_storage_bucket.waf_artifacts.name
}
```

5. Create `terraform/terraform.tfvars.example` with presets for Preset A (Default: create dedicated WAF project in a specified folder and audit Organization), Preset B (Create dedicated WAF project in a folder and audit Folder), and Preset C (Use existing project).

- [ ] **Step 5: Run `terraform fmt -check`, `terraform init -backend=false`, and `terraform validate`**

Run:
```bash
cd terraform && terraform fmt && terraform init -backend=false && terraform validate
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 6: Commit**

```bash
git add terraform/
git commit -m "feat(terraform): create dedicated WAF host project in folder by default and support org/folder/project scopes"
```

---

### Task 5: Turnkey Two-Stage Deployment Script (`scripts/deploy.sh`) & Documentation (`README.md`)

**Files:**
- Create: `scripts/deploy.sh`
- Modify: `README.md`
- Test: `tests/test_multi_org_portability.py`

- [ ] **Step 1: Write a unit test verifying `scripts/deploy.sh` syntax and `--help` output**

Append to `tests/test_multi_org_portability.py`:

```python
import subprocess
from pathlib import Path


def test_deploy_script_syntax_and_help():
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "deploy.sh"
    assert script_path.exists()
    syntax_check = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True)
    assert syntax_check.returncode == 0, syntax_check.stderr

    help_check = subprocess.run(["bash", str(script_path), "--help"], capture_output=True, text=True)
    assert help_check.returncode == 0
    assert "Stage 1" in help_check.stdout
    assert "terraform.tfvars" in help_check.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/test_multi_org_portability.py::test_deploy_script_syntax_and_help -v`
Expected: FAIL (`assert script_path.exists()` is False)

- [ ] **Step 3: Create `scripts/deploy.sh` and update `README.md`**

Create `scripts/deploy.sh` (`chmod +x scripts/deploy.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="${ROOT_DIR}/terraform"
TFVARS_FILE="${TF_DIR}/terraform.tfvars"
USE_LOCAL_DOCKER="false"
PLAN_ONLY="false"

usage() {
  cat <<EOF
Usage: ./scripts/deploy.sh [options]

Turnkey multi-stage deployment for the Autonomous Google Cloud WAF Auditor:
  Stage 1: Bootstrap dedicated WAF Host Project (or attach existing), enable APIs & create Artifact Registry
  Stage 2: Build and push the WAF Auditor container image via Cloud Build (or --local-docker)
  Stage 3: Converge full Terraform stack (BigQuery, GCS, Scope IAM, CAI Feeds, Cloud Run, Scheduler)

Options:
  --tfvars <path>    Path to terraform.tfvars file (default: terraform/terraform.tfvars)
  --local-docker     Build and push container image using local Docker instead of Cloud Build
  --plan-only        Run terraform init & plan without applying changes
  -h, --help         Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tfvars)
      TFVARS_FILE="$2"
      shift 2
      ;;
    --local-docker)
      USE_LOCAL_DOCKER="true"
      shift
      ;;
    --plan-only)
      PLAN_ONLY="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "${TFVARS_FILE}" ]]; then
  echo "Error: tfvars file not found at ${TFVARS_FILE}" >&2
  echo "Copy terraform/terraform.tfvars.example to terraform/terraform.tfvars and fill in your values." >&2
  exit 1
fi

echo "==> Initializing Terraform in ${TF_DIR} ..."
terraform -chdir="${TF_DIR}" init

if [[ "${PLAN_ONLY}" == "true" ]]; then
  terraform -chdir="${TF_DIR}" plan -var-file="${TFVARS_FILE}"
  exit 0
fi

echo "==> Stage 1: Bootstrapping WAF Compliance Host Project, APIs & Artifact Registry ..."
terraform -chdir="${TF_DIR}" apply -auto-approve \
  -var-file="${TFVARS_FILE}" \
  -target=random_id.project_suffix \
  -target=google_project.waf_compliance \
  -target=google_project_service.required_apis \
  -target=google_artifact_registry_repository.waf_auditor

PROJECT_ID="$(terraform -chdir="${TF_DIR}" output -raw compliance_project_id)"
REGION="$(terraform -chdir="${TF_DIR}" output -raw region)"
IMAGE_URI="$(terraform -chdir="${TF_DIR}" output -raw artifact_registry_image)"

echo "==> Stage 2: Building and pushing container image ${IMAGE_URI} ..."
if [[ "${USE_LOCAL_DOCKER}" == "true" ]]; then
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
  docker build -t "${IMAGE_URI}" "${ROOT_DIR}"
  docker push "${IMAGE_URI}"
else
  gcloud builds submit "${ROOT_DIR}" \
    --project="${PROJECT_ID}" \
    --tag="${IMAGE_URI}"
fi

echo "==> Stage 3: Applying full WAF Auditor infrastructure stack ..."
terraform -chdir="${TF_DIR}" apply -auto-approve -var-file="${TFVARS_FILE}"

SERVICE_URI="$(terraform -chdir="${TF_DIR}" output -raw cloud_run_service_uri)"
SCOPE="$(terraform -chdir="${TF_DIR}" output -raw canonical_scope)"
BQ_DATASET="$(terraform -chdir="${TF_DIR}" output -raw bigquery_dataset)"
GCS_BUCKET="$(terraform -chdir="${TF_DIR}" output -raw gcs_artifact_bucket)"

cat <<EOF

================================================================================
WAF Auditor Deployment Complete!
================================================================================
  Compliance Host Project : ${PROJECT_ID}
  Target Audit Scope      : ${SCOPE}
  Cloud Run Service URL   : ${SERVICE_URI}
  BigQuery Dataset        : ${BQ_DATASET}
  GCS Artifact Bucket     : gs://${GCS_BUCKET}
================================================================================
EOF
```

Update `README.md` to document the multi-org / folder / project deployment workflow, `terraform/terraform.tfvars.example`, and `./scripts/deploy.sh`.

- [ ] **Step 4: Run full test suite and Terraform validation**

Run:
```bash
uv run --extra dev pytest -v -k "not asyncio"
uv run --extra dev pytest tests/test_pubsub_push.py tests/test_critic_loop.py -v -k "asyncio"
cd terraform && terraform fmt -check && terraform validate
```
Expected: All tests and Terraform checks PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/deploy.sh README.md tests/test_multi_org_portability.py
git commit -m "feat(deploy): add turnkey multi-stage deploy.sh script and multi-org documentation"
```
