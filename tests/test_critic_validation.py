"""Unit tests for Critic URI verification, Terraform HCL AST validation, and WAFSkillLoader."""

from types import SimpleNamespace
import pytest
from app.gcp_tools import validate_terraform_and_uri
from app.skill_loader import WAFSkillLoader, read_waf_skill_reference


class DummyToolContext:
    def __init__(self, observed_uris: list[str]):
        self.state = {"observed_resource_uris": observed_uris}
        self.actions = SimpleNamespace(escalate=False)


VALID_URI = "//compute.googleapis.com/projects/golden-path-demo/global/firewalls/allow-ssh-world"

VALID_HCL = """
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

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
"""


def test_valid_finding_passes_critic():
    ctx = DummyToolContext(observed_uris=[VALID_URI])
    result = validate_terraform_and_uri(VALID_URI, VALID_HCL, ctx)
    assert result["is_valid"] is True
    assert result["errors"] == []


def test_hallucinated_uri_rejected():
    ctx = DummyToolContext(observed_uris=[VALID_URI])
    hallucinated = "//compute.googleapis.com/projects/golden-path-demo/global/firewalls/non-existent-fw"
    result = validate_terraform_and_uri(hallucinated, VALID_HCL, ctx)
    assert result["is_valid"] is False
    assert any("Hallucinated URI" in err for err in result["errors"])


def test_broken_terraform_hcl_rejected():
    ctx = DummyToolContext(observed_uris=[VALID_URI])
    broken_hcl = 'resource "google_compute_firewall" "broken" { name = "unclosed"'
    result = validate_terraform_and_uri(VALID_URI, broken_hcl, ctx)
    assert result["is_valid"] is False
    assert any("Terraform HCL syntax error" in err for err in result["errors"])


def test_leaked_attribution_tag_rejected():
    ctx = DummyToolContext(observed_uris=[VALID_URI])
    leaked_hcl = f"# agent-skills/1.0 (skill:google-cloud-waf-security)\n{VALID_HCL}"
    result = validate_terraform_and_uri(VALID_URI, leaked_hcl, ctx)
    assert result["is_valid"] is False
    assert any("Forbidden attribution tag" in err for err in result["errors"])


@pytest.mark.parametrize(
    "skill_name",
    [
        "google-cloud-waf-security",
        "google-cloud-waf-reliability",
        "google-cloud-waf-cost-optimization",
        "google-cloud-waf-performance-optimization",
        "google-cloud-waf-operational-excellence",
        "google-cloud-waf-sustainability",
    ],
)
def test_waf_skill_loader_loads_all_six_pillars(skill_name: str):
    metadata, body = WAFSkillLoader.load_skill(skill_name)
    assert metadata["name"] == skill_name
    assert "## Core principles" in body
    assert "## Workload assessment questions" not in body


def test_read_waf_skill_reference_loads_vendored_sibling_skill():
    res = read_waf_skill_reference("gke-reliability/SKILL.md")
    assert res["status"] == "OK"
    assert res["source"] == "vendored_skill"
    assert "GKE" in res["content"] or "reliability" in res["content"].lower()
