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
