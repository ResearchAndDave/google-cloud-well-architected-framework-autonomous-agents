"""ADK Multi-Agent Pipeline (ParallelAgent 6-Pillar Fan-Out + LoopAgent Synthesizer/Critic)."""

import os

from google.adk.agents import LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
from google.adk.models import Gemini
from google.adk.tools import ToolContext
from google.genai import types

from .gcp_tools import (
    commit_findings_to_bigquery_and_gcs,
    fetch_project_recommendations,
    get_active_scc_findings,
    inspect_resource_configuration,
    query_carbon_footprint_summary,
    search_org_assets,
    validate_terraform_and_uri,
)
from .schemas import OrganizationWAFReport, PillarEvaluationReport
from .skill_loader import build_pillar_instruction_provider, read_waf_skill_reference

DEFAULT_PILLAR_MODEL = os.environ.get("WAF_PILLAR_MODEL", "gemini-2.5-pro")
DEFAULT_SYNTHESIS_MODEL = os.environ.get("WAF_SYNTHESIS_MODEL", "gemini-2.5-pro")
DEFAULT_FAST_MODEL = os.environ.get("WAF_FAST_MODEL", "gemini-2.5-flash")

VERTEX_RETRY_OPTIONS = types.HttpRetryOptions(
    attempts=6,
    initial_delay=3.0,
    max_delay=45.0,
    exp_base=2.0,
    jitter=1.0,
    http_status_codes=[429, 500, 502, 503, 504],
)


def _resilient_gemini(model_name: str) -> Gemini:
    """Wraps a Gemini model identifier with exponential backoff for 429 TPM rate limits."""
    return Gemini(model=model_name, retry_options=VERTEX_RETRY_OPTIONS)


def approve_org_report(tool_context: ToolContext) -> dict:
    """Called by Compliance_Critic when all findings and HCL blocks pass validation."""
    tool_context.state["final_org_report"] = tool_context.state.get("draft_org_report")
    tool_context.actions.escalate = True
    return {"status": "APPROVED", "message": "Exiting critic loop."}


def create_pillar_agent(
    name: str,
    model: str,
    skill_dir_name: str,
    tools: list,
    output_key: str,
) -> LlmAgent:
    return LlmAgent(
        name=name,
        model=_resilient_gemini(model),
        instruction=build_pillar_instruction_provider(skill_dir_name),
        tools=tools,
        output_schema=PillarEvaluationReport,
        output_key=output_key,
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
    )


waf_six_pillar_fanout = ParallelAgent(
    name="WAF_Six_Pillar_FanOut",
    sub_agents=[
        create_pillar_agent(
            name="WAF_Security_Agent",
            model=DEFAULT_PILLAR_MODEL,
            skill_dir_name="google-cloud-waf-security",
            tools=[
                get_active_scc_findings,
                search_org_assets,
                inspect_resource_configuration,
                fetch_project_recommendations,
                read_waf_skill_reference,
            ],
            output_key="security_report",
        ),
        create_pillar_agent(
            name="WAF_Reliability_Agent",
            model=DEFAULT_PILLAR_MODEL,
            skill_dir_name="google-cloud-waf-reliability",
            tools=[
                search_org_assets,
                inspect_resource_configuration,
                fetch_project_recommendations,
                read_waf_skill_reference,
            ],
            output_key="reliability_report",
        ),
        create_pillar_agent(
            name="WAF_Cost_Agent",
            model=DEFAULT_PILLAR_MODEL,
            skill_dir_name="google-cloud-waf-cost-optimization",
            tools=[
                fetch_project_recommendations,
                search_org_assets,
                read_waf_skill_reference,
            ],
            output_key="cost_report",
        ),
        create_pillar_agent(
            name="WAF_Performance_Agent",
            model=DEFAULT_PILLAR_MODEL,
            skill_dir_name="google-cloud-waf-performance-optimization",
            tools=[
                fetch_project_recommendations,
                search_org_assets,
                inspect_resource_configuration,
                read_waf_skill_reference,
            ],
            output_key="performance_report",
        ),
        create_pillar_agent(
            name="WAF_Operational_Excellence_Agent",
            model=DEFAULT_PILLAR_MODEL,
            skill_dir_name="google-cloud-waf-operational-excellence",
            tools=[
                search_org_assets,
                inspect_resource_configuration,
                read_waf_skill_reference,
            ],
            output_key="ops_report",
        ),
        create_pillar_agent(
            name="WAF_Sustainability_Agent",
            model=DEFAULT_FAST_MODEL,
            skill_dir_name="google-cloud-waf-sustainability",
            tools=[
                query_carbon_footprint_summary,
                search_org_assets,
                read_waf_skill_reference,
            ],
            output_key="sustainability_report",
        ),
    ],
)

report_synthesizer = LlmAgent(
    name="Report_Synthesizer",
    model=_resilient_gemini(DEFAULT_SYNTHESIS_MODEL),
    instruction="""You are the Lead Cloud Architect Synthesizer.
Combine the six pillar reports from session state:
- Security: {security_report?}
- Reliability: {reliability_report?}
- Cost: {cost_report?}
- Performance: {performance_report?}
- Operational Excellence: {ops_report?}
- Sustainability: {sustainability_report?}

If critic feedback is present in {critic_feedback?}, resolve every flagged URI or Terraform HCL error.
Produce a unified OrganizationWAFReport.""",
    output_schema=OrganizationWAFReport,
    output_key="draft_org_report",
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
)

compliance_critic = LlmAgent(
    name="Compliance_Critic",
    model=_resilient_gemini(DEFAULT_FAST_MODEL),
    instruction="""You are the WAF Compliance Critic.
Inspect {draft_org_report?}.
1. Call `validate_terraform_and_uri` for each finding in `validated_findings`.
2. Verify that every `waf_principle` matches an authentic principle from the pillar reports.
3. If ALL findings pass validation, call `approve_org_report` immediately.
4. Otherwise, summarize the exact errors so Report_Synthesizer can fix them on the next iteration.""",
    tools=[validate_terraform_and_uri, approve_org_report],
    output_key="critic_feedback",
)

synthesis_loop = LoopAgent(
    name="WAF_Synthesis_Critic_Loop",
    sub_agents=[report_synthesizer, compliance_critic],
    max_iterations=3,
)

root_agent = SequentialAgent(
    name="WAF_Auditor_Pipeline",
    sub_agents=[waf_six_pillar_fanout, synthesis_loop],
    after_agent_callback=commit_findings_to_bigquery_and_gcs,
)
