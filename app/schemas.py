"""Pydantic data contracts for the Autonomous Google Cloud WAF Auditor."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class WAFPillar(str, Enum):
    SECURITY = "SECURITY"
    RELIABILITY = "RELIABILITY"
    COST = "COST"
    PERFORMANCE = "PERFORMANCE"
    OPS = "OPS"
    SUSTAINABILITY = "SUSTAINABILITY"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ComplianceStatus(str, Enum):
    NON_COMPLIANT = "NON_COMPLIANT"
    WARNING = "WARNING"


class WAFFinding(BaseModel):
    resource_uri: str = Field(
        description="Canonical Cloud Asset Inventory URI (e.g., //compute.googleapis.com/projects/p/zones/z/instances/i)"
    )
    project_id: str = Field(description="Owning GCP project ID")
    folder_id: Optional[str] = Field(default=None, description="Owning GCP folder ID if applicable")
    waf_pillar: WAFPillar
    waf_principle: str = Field(description="Exact core principle cited from the official SKILL.md")
    severity: Severity
    compliance_status: ComplianceStatus
    rationale: str = Field(
        description="Architectural explanation contextualized by resource configuration, labels, and environment"
    )
    terraform_remediation: str = Field(
        description="Valid, self-contained Terraform HCL resource/patch block to remediate the finding"
    )
    estimated_monthly_savings_usd: Optional[float] = Field(
        default=None, description="Projected monthly savings in USD (populated by Cost/Performance pillars)"
    )


class PillarEvaluationReport(BaseModel):
    waf_pillar: WAFPillar
    pillar_score: int = Field(ge=0, le=100, description="0-100 posture score for this pillar")
    evaluated_resource_count: int = Field(ge=0)
    findings: List[WAFFinding] = Field(default_factory=list)
    summary_notes: str


class PillarScores(BaseModel):
    SECURITY: int = Field(ge=0, le=100)
    RELIABILITY: int = Field(ge=0, le=100)
    COST: int = Field(ge=0, le=100)
    PERFORMANCE: int = Field(ge=0, le=100)
    OPS: int = Field(ge=0, le=100)
    SUSTAINABILITY: int = Field(ge=0, le=100)


class OrganizationWAFReport(BaseModel):
    org_id: str
    scan_mode: str = Field(description="REALTIME_DRIFT | NIGHTLY_SWEEP")
    evaluation_timestamp: str
    overall_waf_score: int = Field(ge=0, le=100)
    pillar_scores: PillarScores
    top_architectural_risks: List[str]
    total_projected_monthly_savings_usd: float
    validated_findings: List[WAFFinding]
    executive_markdown: str = Field(description="Full Markdown narrative for GCS waf_executive_summary.md")
