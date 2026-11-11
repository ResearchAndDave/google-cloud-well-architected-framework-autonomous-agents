"""Skill loader and progressive disclosure reader for official Google Cloud WAF skills."""

import os
import re
import urllib.request
from pathlib import Path
from typing import Callable
import frontmatter
from google.adk.agents.readonly_context import ReadonlyContext

from .config import get_waf_config

SKILLS_ROOT = Path(os.getenv("WAF_SKILLS_DIR", Path(__file__).resolve().parent.parent / "agent" / "skills"))
GROUNDING_CACHE_DIR = SKILLS_ROOT / ".grounding_cache"
ALLOWED_GROUNDING_PREFIX = "https://docs.cloud.google.com/architecture/framework/"


class WAFSkillLoader:
    """Loads, parses, and transforms official Google Cloud WAF skills for autonomous ADK execution."""

    _skill_cache: dict[str, tuple[dict, str]] = {}

    @classmethod
    def load_skill(cls, skill_dir_name: str) -> tuple[dict, str]:
        if skill_dir_name in cls._skill_cache:
            return cls._skill_cache[skill_dir_name]

        skill_path = SKILLS_ROOT / skill_dir_name / "SKILL.md"
        if not skill_path.exists():
            raise FileNotFoundError(f"Skill file not found: {skill_path}")

        post = frontmatter.load(skill_path)
        meta = dict(post.metadata)
        meta.setdefault("name", skill_dir_name)
        autonomous_body = re.sub(
            r"## Workload assessment questions.*?(?=\n## |\Z)",
            "",
            post.content,
            flags=re.DOTALL,
        )
        cls._skill_cache[skill_dir_name] = (meta, autonomous_body.strip())
        return cls._skill_cache[skill_dir_name]


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


def read_waf_skill_reference(reference_target: str) -> dict:
    """Progressive disclosure tool for sub-agents to fetch WAF grounding docs or specialized sibling skills.

    Args:
        reference_target: Either a grounding document URL from SKILL.md starting with
            'https://docs.cloud.google.com/architecture/framework/' and ending with '.md.txt',
            or a relative path inside the vendored skills directory (e.g., 'gke-reliability/SKILL.md').
    """
    if reference_target.startswith("https://"):
        if not reference_target.startswith(ALLOWED_GROUNDING_PREFIX) or not reference_target.endswith(".md.txt"):
            return {
                "status": "ERROR",
                "error": f"URL must start with {ALLOWED_GROUNDING_PREFIX} and end with .md.txt",
            }
        GROUNDING_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_key = reference_target.replace(ALLOWED_GROUNDING_PREFIX, "").replace("/", "__")
        cache_file = GROUNDING_CACHE_DIR / cache_key

        if cache_file.exists():
            return {"status": "OK", "source": "cache", "content": cache_file.read_text(encoding="utf-8")[:15000]}

        req = urllib.request.Request(
            reference_target,
            headers={"User-Agent": "WAF-Auditor-Agent/1.0 agent-skills/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8")
            cache_file.write_text(text, encoding="utf-8")
            return {"status": "OK", "source": "remote", "content": text[:15000]}

    safe_rel_path = Path(reference_target.lstrip("/"))
    resolved_path = (SKILLS_ROOT / safe_rel_path).resolve()
    if not str(resolved_path).startswith(str(SKILLS_ROOT.resolve())) or not resolved_path.is_file():
        return {"status": "ERROR", "error": f"Reference '{reference_target}' not found in vendored skills."}

    return {
        "status": "OK",
        "source": "vendored_skill",
        "content": resolved_path.read_text(encoding="utf-8")[:15000],
    }
