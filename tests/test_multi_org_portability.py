"""Unit tests for multi-organization portability, scope normalization, and graceful telemetry degradation."""

from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.config import WAFConfig, get_waf_config, normalize_scope
from app.dashboard import render_tufte_architecture_html
from app.gcp_tools import (
    fetch_project_recommendations,
    get_active_scc_findings,
    query_carbon_footprint_summary,
)
from app.skill_loader import build_pillar_instruction_provider


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


def test_deploy_script_syntax_and_help():
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "deploy.sh"
    assert script_path.exists()
    syntax_check = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True)
    assert syntax_check.returncode == 0, syntax_check.stderr

    help_check = subprocess.run(["bash", str(script_path), "--help"], capture_output=True, text=True)
    assert help_check.returncode == 0
    assert "Stage 1" in help_check.stdout
    assert "terraform.tfvars" in help_check.stdout


