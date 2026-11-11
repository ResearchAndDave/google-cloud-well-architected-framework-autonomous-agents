"""Unit tests for Phase 4 GitOps Auto-Remediation PR planning, deduplication, and guardrails."""

from types import SimpleNamespace
import hcl2
from app.gcp_tools import commit_findings_to_bigquery_and_gcs
from app.gitops import (
    build_gitops_pr_plan,
    compute_finding_fingerprint,
    select_findings_for_gitops,
    should_open_gitops_pr,
)

SAMPLE_CRITICAL_SECURITY_FINDING = {
    "resource_uri": "//compute.googleapis.com/projects/golden-path-demo/global/firewalls/allow-ssh-world",
    "project_id": "golden-path-demo",
    "waf_pillar": "SECURITY",
    "waf_principle": "Implement zero trust",
    "severity": "CRITICAL",
    "compliance_status": "NON_COMPLIANT",
    "rationale": "Unrestricted 0.0.0.0/0 SSH ingress.",
    "terraform_remediation": """
resource "google_compute_firewall" "allow_ssh_iap" {
  name          = "allow-ssh-world"
  project       = "golden-path-demo"
  network       = "prod-vpc"
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
""",
    "estimated_monthly_savings_usd": None,
}

SAMPLE_MEDIUM_COST_FINDING_HIGH_SAVINGS = {
    "resource_uri": "//compute.googleapis.com/projects/golden-path-demo/zones/us-central1-a/instances/idle-gpu-vm",
    "project_id": "golden-path-demo",
    "waf_pillar": "COST",
    "waf_principle": "Optimize resource usage",
    "severity": "MEDIUM",
    "compliance_status": "NON_COMPLIANT",
    "rationale": "Idle n1-standard-8 VM with attached GPU.",
    "terraform_remediation": 'resource "google_compute_instance" "rightsized" { machine_type = "e2-medium" }',
    "estimated_monthly_savings_usd": 420.50,
}

SAMPLE_LOW_OPS_FINDING = {
    "resource_uri": "//storage.googleapis.com/projects/_/buckets/demo-logs-bucket",
    "project_id": "golden-path-demo",
    "waf_pillar": "OPS",
    "waf_principle": "Ensure operational readiness",
    "severity": "LOW",
    "compliance_status": "WARNING",
    "rationale": "Missing cost-center label.",
    "terraform_remediation": 'resource "google_storage_bucket" "labeled" { name = "demo-logs-bucket" }',
    "estimated_monthly_savings_usd": 0.0,
}


def test_deterministic_fingerprint():
    fp1 = compute_finding_fingerprint(SAMPLE_CRITICAL_SECURITY_FINDING)
    fp2 = compute_finding_fingerprint(SAMPLE_CRITICAL_SECURITY_FINDING)
    assert fp1 == fp2
    assert len(fp1) == 12


def test_should_open_gitops_pr_guardrails():
    # CRITICAL Security finding qualifies
    assert should_open_gitops_pr(SAMPLE_CRITICAL_SECURITY_FINDING) is True
    # MEDIUM Cost finding with $420.50/mo savings (>= $100 threshold) qualifies
    assert should_open_gitops_pr(SAMPLE_MEDIUM_COST_FINDING_HIGH_SAVINGS) is True
    # LOW Ops finding with $0 savings does NOT qualify for auto-PR
    assert should_open_gitops_pr(SAMPLE_LOW_OPS_FINDING) is False


def test_build_gitops_pr_plan_generates_valid_hcl_file():
    plan = build_gitops_pr_plan(SAMPLE_CRITICAL_SECURITY_FINDING)
    fp = plan["fingerprint"]
    assert plan["branch_name"] == f"waf-remediation/golden-path-demo/security-{fp}"
    assert plan["target_tf_path"] == f"remediations/golden-path-demo/security_{fp}.tf"
    assert "Implement zero trust" in plan["pr_body"]
    # Verify the generated .tf file (including header comments) parses cleanly with python-hcl2
    parsed = hcl2.loads(plan["file_content"])
    assert "resource" in parsed


def test_select_findings_deduplicates_and_respects_max_prs():
    findings = [
        SAMPLE_LOW_OPS_FINDING,
        SAMPLE_MEDIUM_COST_FINDING_HIGH_SAVINGS,
        SAMPLE_CRITICAL_SECURITY_FINDING,
        SAMPLE_CRITICAL_SECURITY_FINDING,  # Duplicate finding
    ]
    selected = select_findings_for_gitops(findings, max_prs_per_run=5)
    # Only the CRITICAL security finding and high-savings COST finding should be selected (deduplicated to 2)
    assert len(selected) == 2
    # CRITICAL finding must be prioritized first
    assert "SECURITY" in selected[0]["pr_title"]
    assert "COST" in selected[1]["pr_title"]


def test_commit_findings_callback_populates_gitops_pr_plans(monkeypatch):
    """Verifies that the root after_agent_callback populates session.state['gitops_pr_plans'] and deduplicates across runs."""
    monkeypatch.setenv("WAF_ENABLE_BQ_WRITE", "FALSE")
    monkeypatch.setenv("WAF_ENABLE_GCS_WRITE", "FALSE")
    monkeypatch.setenv("WAF_ENABLE_GITOPS_PR", "FALSE")
    ctx = SimpleNamespace(
        state={
            "final_org_report": {
                "org_id": "organizations/123456789",
                "scan_mode": "REALTIME_DRIFT",
                "validated_findings": [
                    SAMPLE_CRITICAL_SECURITY_FINDING,
                    SAMPLE_LOW_OPS_FINDING,
                ],
                "executive_markdown": "# Summary",
            }
        }
    )
    commit_findings_to_bigquery_and_gcs(ctx)
    assert len(ctx.state["gitops_pr_plans"]) == 1
    assert len(ctx.state["dispatched_gitops_fingerprints"]) == 1

    # Running callback a second time with the exact same finding should produce 0 new PR plans
    commit_findings_to_bigquery_and_gcs(ctx)
    assert len(ctx.state["gitops_pr_plans"]) == 0


def test_fingerprint_ignores_principle_and_matches_bq_dedup_key():
    """Same resource + pillar cited under a different principle must map to the same PR."""
    alt_principle = dict(SAMPLE_CRITICAL_SECURITY_FINDING, waf_principle="Implement security by design")
    assert compute_finding_fingerprint(alt_principle) == compute_finding_fingerprint(
        SAMPLE_CRITICAL_SECURITY_FINDING
    )
    other_pillar = dict(SAMPLE_CRITICAL_SECURITY_FINDING, waf_pillar="RELIABILITY")
    assert compute_finding_fingerprint(other_pillar) != compute_finding_fingerprint(
        SAMPLE_CRITICAL_SECURITY_FINDING
    )


def test_ineligibility_reason():
    from app.gitops import gitops_ineligibility_reason

    assert gitops_ineligibility_reason(SAMPLE_CRITICAL_SECURITY_FINDING) is None
    reason = gitops_ineligibility_reason(SAMPLE_LOW_OPS_FINDING)
    assert reason is not None and "LOW" in reason and "HIGH" in reason


class _FakeBlob:
    def __init__(self, store: dict, name: str):
        self._store, self.name = store, name

    def upload_from_string(self, data, content_type=None, if_generation_match=None):
        from google.api_core import exceptions as gcp_exceptions

        if if_generation_match == 0 and self.name in self._store:
            raise gcp_exceptions.PreconditionFailed("object exists")
        self._store[self.name] = data

    def delete(self):
        self._store.pop(self.name, None)


class _FakeBucket:
    def __init__(self, store: dict):
        self._store = store

    def blob(self, name: str):
        return _FakeBlob(self._store, name)


def _ctx(findings):
    return SimpleNamespace(
        state={
            "final_org_report": {
                "org_id": "organizations/123456789",
                "scan_mode": "NIGHTLY_SWEEP",
                "validated_findings": findings,
                "executive_markdown": "# Summary",
            }
        }
    )


def test_durable_ledger_dedups_across_independent_runs(monkeypatch):
    """Two separate sessions (fresh state) must not dispatch the same PR twice."""
    from unittest.mock import patch

    monkeypatch.setenv("WAF_ENABLE_BQ_WRITE", "FALSE")
    monkeypatch.setenv("WAF_ENABLE_GCS_WRITE", "FALSE")
    monkeypatch.setenv("WAF_ENABLE_GITOPS_PR", "TRUE")
    monkeypatch.setenv("WAF_GITOPS_PUBSUB_TOPIC", "projects/p/topics/waf-gitops-remediation")

    store: dict = {}
    published: list = []
    fake_client = SimpleNamespace(bucket=lambda _name: _FakeBucket(store))

    with patch("app.gcp_tools.storage.Client", return_value=fake_client), patch(
        "app.gcp_tools._publish_gitops_plans_to_pubsub",
        side_effect=lambda _topic, plans: published.extend(plans) or len(plans),
    ):
        run1 = _ctx([SAMPLE_CRITICAL_SECURITY_FINDING, SAMPLE_MEDIUM_COST_FINDING_HIGH_SAVINGS])
        commit_findings_to_bigquery_and_gcs(run1)
        assert run1.state["gitops_ledger_status"]["dispatched"] == 2
        assert len(published) == 2

        run2 = _ctx([SAMPLE_CRITICAL_SECURITY_FINDING, SAMPLE_MEDIUM_COST_FINDING_HIGH_SAVINGS])
        commit_findings_to_bigquery_and_gcs(run2)
        assert run2.state["gitops_ledger_status"]["dispatched"] == 0
        assert run2.state["gitops_ledger_status"]["skipped_already_dispatched"] == 2
        assert run2.state["gitops_pr_plans"] == []
        assert len(published) == 2


def test_ledger_releases_claims_when_publish_fails(monkeypatch):
    from unittest.mock import patch
    import pytest

    monkeypatch.setenv("WAF_ENABLE_BQ_WRITE", "FALSE")
    monkeypatch.setenv("WAF_ENABLE_GCS_WRITE", "FALSE")
    monkeypatch.setenv("WAF_ENABLE_GITOPS_PR", "TRUE")
    monkeypatch.setenv("WAF_GITOPS_PUBSUB_TOPIC", "projects/p/topics/waf-gitops-remediation")

    store: dict = {}
    fake_client = SimpleNamespace(bucket=lambda _name: _FakeBucket(store))
    with patch("app.gcp_tools.storage.Client", return_value=fake_client), patch(
        "app.gcp_tools._publish_gitops_plans_to_pubsub", side_effect=RuntimeError("pubsub down")
    ):
        with pytest.raises(RuntimeError):
            commit_findings_to_bigquery_and_gcs(_ctx([SAMPLE_CRITICAL_SECURITY_FINDING]))
    assert store == {}


def test_per_run_cap_applies_after_ledger_filtering(monkeypatch):
    """Already-dispatched findings must not consume the per-run PR budget."""
    from unittest.mock import patch

    monkeypatch.setenv("WAF_ENABLE_BQ_WRITE", "FALSE")
    monkeypatch.setenv("WAF_ENABLE_GCS_WRITE", "FALSE")
    monkeypatch.setenv("WAF_ENABLE_GITOPS_PR", "TRUE")
    monkeypatch.setenv("WAF_GITOPS_PUBSUB_TOPIC", "projects/p/topics/waf-gitops-remediation")
    monkeypatch.setenv("WAF_GITOPS_MAX_PRS_PER_RUN", "1")

    store: dict = {}
    fake_client = SimpleNamespace(bucket=lambda _name: _FakeBucket(store))
    with patch("app.gcp_tools.storage.Client", return_value=fake_client), patch(
        "app.gcp_tools._publish_gitops_plans_to_pubsub", return_value=1
    ):
        both = [SAMPLE_CRITICAL_SECURITY_FINDING, SAMPLE_MEDIUM_COST_FINDING_HIGH_SAVINGS]
        run1 = _ctx(both)
        commit_findings_to_bigquery_and_gcs(run1)
        run2 = _ctx(both)
        commit_findings_to_bigquery_and_gcs(run2)

    assert "SECURITY" in run1.state["gitops_pr_plans"][0]["pr_title"]
    assert "COST" in run2.state["gitops_pr_plans"][0]["pr_title"]
