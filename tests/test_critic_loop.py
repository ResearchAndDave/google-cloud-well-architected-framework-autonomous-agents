"""Integration test for the ADK LoopAgent self-correcting Synthesis + Critic loop."""

from typing import AsyncGenerator
import pytest
from google.adk.agents import BaseAgent, LoopAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from types import SimpleNamespace

from app.agent import approve_org_report
from app.gcp_tools import validate_terraform_and_uri

VALID_URI = "//compute.googleapis.com/projects/golden-path-demo/global/firewalls/allow-ssh-world"

BROKEN_HCL = 'resource "google_compute_firewall" "allow_ssh_iap" { name = "unclosed"'

FIXED_HCL = """
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
"""


class SimulatedSynthesizerAgent(BaseAgent):
    """Simulates Report_Synthesizer: emits broken HCL on Iteration 1, then fixes it on Iteration 2 after Critic feedback."""

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        iteration = ctx.session.state.get("synth_iteration", 0) + 1

        feedback = ctx.session.state.get("critic_feedback")
        hcl_to_emit = BROKEN_HCL if not feedback else FIXED_HCL

        draft_report = {
            "org_id": "organizations/123456789",
            "scan_mode": "REALTIME_DRIFT",
            "evaluation_timestamp": "2026-10-22T14:00:00Z",
            "overall_waf_score": 85,
            "pillar_scores": {"SECURITY": 85},
            "top_architectural_risks": ["Open SSH 0.0.0.0/0"],
            "total_projected_monthly_savings_usd": 0.0,
            "validated_findings": [
                {
                    "resource_uri": VALID_URI,
                    "project_id": "golden-path-demo",
                    "waf_pillar": "SECURITY",
                    "waf_principle": "Implement zero trust",
                    "severity": "CRITICAL",
                    "compliance_status": "NON_COMPLIANT",
                    "rationale": "Open SSH to 0.0.0.0/0",
                    "terraform_remediation": hcl_to_emit,
                }
            ],
            "executive_markdown": f"# Iteration {iteration}",
        }

        yield Event(
            author=self.name,
            actions=EventActions(
                state_delta={
                    "synth_iteration": iteration,
                    "draft_org_report": draft_report,
                }
            ),
            content=types.Content(
                role="model",
                parts=[types.Part.from_text(text=f"Synthesized draft report (iteration {iteration})")],
            ),
        )


class SimulatedCriticAgent(BaseAgent):
    """Executes the real deterministic `validate_terraform_and_uri` and `approve_org_report` tools inside ADK LoopAgent."""

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        draft = ctx.session.state.get("draft_org_report", {})
        findings = draft.get("validated_findings", [])

        state_delta = {}
        actions = EventActions(state_delta=state_delta)
        tool_ctx = SimpleNamespace(
            state=ctx.session.state,
            actions=actions,
        )

        all_errors = []
        for f in findings:
            res = validate_terraform_and_uri(
                resource_uri=f["resource_uri"],
                terraform_hcl=f["terraform_remediation"],
                tool_context=tool_ctx,
            )
            if not res["is_valid"]:
                all_errors.extend(res["errors"])

        if not all_errors:
            approve_org_report(tool_ctx)
            yield Event(
                author=self.name,
                actions=EventActions(
                    escalate=True,
                    state_delta={
                        "final_org_report": draft,
                        "critic_feedback": "APPROVED",
                    },
                ),
                content=types.Content(
                    role="model",
                    parts=[types.Part.from_text(text="All findings valid. Escalating loop.")],
                ),
            )
        else:
            error_msg = "; ".join(all_errors)
            yield Event(
                author=self.name,
                actions=EventActions(
                    state_delta={"critic_feedback": error_msg},
                ),
                content=types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=f"Rejected draft: {error_msg}")],
                ),
            )


@pytest.mark.anyio
async def test_loop_agent_self_corrects_on_iteration_2_and_exits_early():
    """Proves that LoopAgent (max_iterations=3) rejects broken HCL on pass 1, fixes it on pass 2, and exits early without running pass 3."""
    loop = LoopAgent(
        name="Test_WAF_Synthesis_Critic_Loop",
        sub_agents=[
            SimulatedSynthesizerAgent(name="Report_Synthesizer"),
            SimulatedCriticAgent(name="Compliance_Critic"),
        ],
        max_iterations=3,
    )

    session_service = InMemorySessionService()
    runner = Runner(
        agent=loop,
        app_name="test_loop_app",
        session_service=session_service,
    )

    await session_service.create_session(
        app_name="test_loop_app",
        user_id="tester",
        session_id="loop-session-1",
        state={"observed_resource_uris": [VALID_URI]},
    )

    events = []
    async for event in runner.run_async(
        user_id="tester",
        session_id="loop-session-1",
        new_message=types.Content(role="user", parts=[types.Part.from_text(text="Run synthesis loop")]),
    ):
        events.append(event)

    internal_session = session_service.sessions["test_loop_app"]["tester"]["loop-session-1"]

    # 1. Verify Synthesizer ran exactly twice (not 3 times, because Critic escalated on iteration 2)
    assert internal_session.state["synth_iteration"] == 2
    assert len(events) == 4  # Synth(1) -> Critic(1: Reject) -> Synth(2) -> Critic(2: Approve & Escalate)

    # 2. Verify final_org_report was promoted and contains valid HCL
    final_report = internal_session.state.get("final_org_report")
    assert final_report is not None
    assert final_report["executive_markdown"] == "# Iteration 2"
    assert "35.235.240.0/20" in final_report["validated_findings"][0]["terraform_remediation"]
