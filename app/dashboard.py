"""Edward Tufte-inspired Analytical Dashboard for Google Cloud Well-Architected Framework Telemetry.

Implements core principles from Edward R. Tufte's *The Visual Display of Quantitative Information* (1983),
*Envisioning Information* (1990), and *Beautiful Evidence* (2006):
  1. Maximize Data-Ink Ratio: eliminate chartjunk, circular gauges, drop shadows, and vertical table rules.
  2. Small Multiples & Sparklines: word-sized inline SVG time-series graphics embedded directly in booktabs tables.
  3. Range-Frame / Bullet Micro-Bars: compact horizontal posture bars with explicit deficit encoding.
  4. Zero-Suppressed Typographic Matrix: quiet middle dots ('·') for zero-risk cells so anomalies stand out immediately.
  5. Sidenotes & Integrated Evidence: words, numbers, and graphics woven together on a single warm-ivory page (#fffff8).
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from google.cloud import bigquery, storage

from .config import get_waf_config
from .gitops import build_gitops_pr_plan, gitops_ineligibility_reason, gitops_thresholds_from_env

CACHE_PATH = Path(__file__).resolve().parent / ".dashboard_cache.json"

PILLAR_ORDER = [
    "SECURITY",
    "RELIABILITY",
    "COST",
    "PERFORMANCE",
    "OPS",
    "SUSTAINABILITY",
]

PILLAR_LABELS = {
    "SECURITY": "Security, Identity & Compliance",
    "RELIABILITY": "Reliability & Resiliency",
    "COST": "Cost Optimization (FinOps)",
    "PERFORMANCE": "Performance Optimization",
    "OPS": "Operational Excellence",
    "SUSTAINABILITY": "Sustainability (Carbon)",
}


def fetch_dashboard_telemetry(report_blob_name: str | None = None) -> dict[str, Any]:
    """Queries the 4 Looker Studio BigQuery views and GCS Executive Markdown reports, with automatic local cache fallback if ADC expires."""
    cfg = get_waf_config()
    bq_table = cfg.bq_table
    parts = bq_table.split(".")
    project_id = parts[0] if len(parts) == 3 else cfg.project_id
    dataset_id = parts[1] if len(parts) == 3 else "org_compliance"
    gcs_bucket_name = cfg.gcs_bucket
    selected_blob = report_blob_name or "reports/waf_executive_summary.md"

    try:
        bq_client = bigquery.Client(project=project_id)

        # 1. View: v_pillar_posture_scores
        scores_sql = f"""
            SELECT
              waf_pillar,
              pillar_score_0_to_100,
              active_finding_count,
              critical_count,
              high_count,
              medium_count,
              low_count,
              potential_monthly_savings_usd
            FROM `{project_id}.{dataset_id}.v_pillar_posture_scores`
        """
        raw_scores = {row["waf_pillar"]: dict(row) for row in bq_client.query(scores_sql).result()}
        pillar_scores = []
        for p in PILLAR_ORDER:
            row = raw_scores.get(
                p,
                {
                    "waf_pillar": p,
                    "pillar_score_0_to_100": 100,
                    "active_finding_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "potential_monthly_savings_usd": 0.0,
                },
            )
            pillar_scores.append(row)

        # 2. View: v_current_waf_posture
        posture_sql = f"""
            SELECT
              evaluation_timestamp,
              org_id,
              scan_mode,
              resource_uri,
              project_id,
              folder_id,
              waf_pillar,
              waf_principle,
              severity,
              compliance_status,
              rationale,
              terraform_remediation,
              estimated_monthly_savings_usd
            FROM `{project_id}.{dataset_id}.v_current_waf_posture`
            ORDER BY
              CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
              END,
              evaluation_timestamp DESC
        """
        current_findings = []
        for row in bq_client.query(posture_sql).result():
            item = dict(row)
            if isinstance(item.get("evaluation_timestamp"), datetime):
                item["evaluation_timestamp"] = item["evaluation_timestamp"].isoformat()
            item["gitops_plan"] = build_gitops_pr_plan(item)
            current_findings.append(item)

        # 3. View: v_pillar_drift_velocity
        velocity_sql = f"""
            SELECT
              audit_date,
              waf_pillar,
              non_compliant_count,
              high_risk_count,
              daily_net_drift,
              seven_day_drift_velocity
            FROM `{project_id}.{dataset_id}.v_pillar_drift_velocity`
            ORDER BY audit_date ASC, waf_pillar ASC
        """
        drift_velocity = []
        for row in bq_client.query(velocity_sql).result():
            item = dict(row)
            item["audit_date"] = str(item["audit_date"])
            drift_velocity.append(item)

        # 4. View: v_folder_project_heatmap
        heatmap_sql = f"""
            SELECT
              folder_id,
              project_id,
              waf_pillar,
              total_findings,
              critical_findings,
              high_findings,
              monthly_savings_opportunity_usd,
              last_evaluated_at
            FROM `{project_id}.{dataset_id}.v_folder_project_heatmap`
            ORDER BY total_findings DESC, project_id ASC
        """
        heatmap_rows = []
        for row in bq_client.query(heatmap_sql).result():
            item = dict(row)
            if isinstance(item.get("last_evaluated_at"), datetime):
                item["last_evaluated_at"] = item["last_evaluated_at"].isoformat()
            heatmap_rows.append(item)

        # 5. GCS Executive Markdown Reports
        executive_markdown = ""
        available_reports: list[dict[str, str]] = []
        try:
            storage_client = storage.Client(project=project_id)
            bucket = storage_client.bucket(gcs_bucket_name)
            blobs = list(bucket.list_blobs(prefix="reports/"))
            for b in sorted(blobs, key=lambda x: x.updated or datetime.min.replace(tzinfo=timezone.utc), reverse=True):
                if b.name.endswith(".md"):
                    available_reports.append(
                        {
                            "name": b.name,
                            "updated": b.updated.isoformat() if b.updated else "",
                            "size_bytes": str(b.size or 0),
                        }
                    )
            target_blob = bucket.blob(selected_blob)
            if target_blob.exists():
                executive_markdown = target_blob.download_as_text(encoding="utf-8")
        except Exception as exc:
            executive_markdown = f"*Unable to load GCS executive summary from `gs://{gcs_bucket_name}/{selected_blob}`: {exc}*"

        overall_score = round(
            sum(int(r["pillar_score_0_to_100"]) for r in pillar_scores) / max(len(pillar_scores), 1)
        )
        total_active = sum(int(r["active_finding_count"]) for r in pillar_scores)
        total_savings = sum(float(r["potential_monthly_savings_usd"] or 0.0) for r in pillar_scores)

        telemetry = {
            "project_id": project_id,
            "dataset_id": dataset_id,
            "gcs_bucket": gcs_bucket_name,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "overall_waf_score": overall_score,
            "total_active_findings": total_active,
            "total_monthly_savings_usd": round(total_savings, 2),
            "pillar_scores": pillar_scores,
            "current_findings": current_findings,
            "drift_velocity": drift_velocity,
            "heatmap_rows": heatmap_rows,
            "executive_markdown": executive_markdown,
            "available_reports": available_reports,
            "selected_blob": selected_blob,
        }
        try:
            CACHE_PATH.write_text(json.dumps(telemetry, indent=2), encoding="utf-8")
        except Exception:
            pass
        return telemetry

    except Exception as exc:
        if CACHE_PATH.exists():
            cached = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            for item in cached.get("current_findings", []):
                # Always rebuild so cached plans pick up the current fingerprint scheme.
                item["gitops_plan"] = build_gitops_pr_plan(item)
            cached["selected_blob"] = selected_blob
            cached["auth_warning"] = (
                f"Local Google Cloud ADC session expired ({type(exc).__name__}). "
                f"Serving cached snapshot from {cached.get('generated_at', 'last sweep')} — "
                f"run `gcloud auth application-default login` in your terminal to resume live BigQuery queries."
            )
            return cached
        raise


def _render_sparkline_svg(series: list[int], width: int = 80, height: int = 20) -> str:
    """Renders a Tufte word-sized inline SVG sparkline with a terminal value dot and direct numeral."""
    if not series:
        series = [0, 0]
    elif len(series) == 1:
        series = [series[0], series[0]]

    min_v = min(series)
    max_v = max(series)
    span = max(max_v - min_v, 1)
    pad_x = 4
    pad_y = 4
    plot_w = width - 2 * pad_x
    plot_h = height - 2 * pad_y

    coords = []
    for idx, val in enumerate(series):
        x = pad_x + (idx / (len(series) - 1)) * plot_w
        y = pad_y + plot_h - ((val - min_v) / span) * plot_h
        coords.append((round(x, 1), round(y, 1)))

    points_attr = " ".join(f"{x},{y}" for x, y in coords)
    last_x, last_y = coords[-1]
    dot_color = "#991b1b" if series[-1] > 0 else "#2f5233"

    return (
        f'<svg class="sparkline" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'aria-label="14-day drift sparkline">'
        f'<line x1="{pad_x}" y1="{pad_y + plot_h}" x2="{width - pad_x}" y2="{pad_y + plot_h}" '
        f'stroke="#e2dfd7" stroke-width="0.75" />'
        f'<polyline fill="none" stroke="#333333" stroke-width="1.15" points="{points_attr}" />'
        f'<circle cx="{last_x}" cy="{last_y}" r="2.3" fill="{dot_color}" />'
        f"</svg>"
    )


def _render_tufte_bullet_svg(score: int, width: int = 104, height: int = 12) -> str:
    """Renders a high-data-ink horizontal bullet/horizon bar showing 0..100 posture and deficit."""
    clamped = max(0, min(100, int(score)))
    fill_w = round((clamped / 100.0) * width, 1)
    deficit_w = round(width - fill_w, 1)
    bar_color = "#222222" if clamped == 100 else "#8b1e1e"

    deficit_rect = (
        f'<rect x="{fill_w}" y="3" width="{deficit_w}" height="6" fill="#f3d8d8" />'
        if deficit_w > 0
        else ""
    )
    return (
        f'<svg class="bullet-bar" width="{width + 4}" height="{height}" viewBox="0 0 {width + 4} {height}">'
        f'<rect x="0" y="3" width="{fill_w}" height="6" fill="{bar_color}" />'
        f"{deficit_rect}"
        f'<line x1="{width}" y1="1" x2="{width}" y2="11" stroke="#111111" stroke-width="1.2" />'
        f"</svg>"
    )


def _build_filter_href(
    pillar: str | None = None,
    project: str | None = None,
    blob: str | None = None,
) -> str:
    params = []
    if pillar:
        params.append(f"pillar={html.escape(pillar)}")
    if project:
        params.append(f"project={html.escape(project)}")
    if blob and blob != "reports/waf_executive_summary.md":
        params.append(f"blob={html.escape(blob)}")
    query = ("?" + "&".join(params)) if params else ""
    return f"/dashboard{query}#drift-ledger"


def render_tufte_dashboard_html(
    data: dict[str, Any],
    selected_pillar: str | None = None,
    selected_project: str | None = None,
) -> str:
    """Renders a complete Edward Tufte analytical report HTML document."""
    project_id = html.escape(data["project_id"])
    dataset_id = html.escape(data["dataset_id"])
    gcs_bucket = html.escape(data["gcs_bucket"])
    generated_at = html.escape(data["generated_at"])
    overall_score = int(data["overall_waf_score"])
    total_active = int(data["total_active_findings"])
    total_savings = float(data["total_monthly_savings_usd"])
    current_blob = data.get("selected_blob")
    active_pillar = selected_pillar.upper() if selected_pillar else None
    active_project = selected_project if selected_project else None

    # Build per-pillar time series for sparklines
    series_by_pillar: dict[str, list[int]] = {p: [] for p in PILLAR_ORDER}
    net_drift_by_pillar: dict[str, int] = {p: 0 for p in PILLAR_ORDER}
    for row in data["drift_velocity"]:
        p = row.get("waf_pillar", "")
        if p in series_by_pillar:
            series_by_pillar[p].append(int(row.get("non_compliant_count") or 0))
            net_drift_by_pillar[p] = int(row.get("seven_day_drift_velocity") or 0)

    # 1. Small Multiples Table Rows (v_pillar_posture_scores + v_pillar_drift_velocity)
    pillar_rows_html = []
    for row in data["pillar_scores"]:
        pillar = row["waf_pillar"]
        score = int(row["pillar_score_0_to_100"])
        active = int(row["active_finding_count"])
        crit = int(row["critical_count"])
        high = int(row["high_count"])
        med = int(row["medium_count"])
        low = int(row["low_count"])
        savings = float(row["potential_monthly_savings_usd"] or 0.0)
        deficit = 100 - score

        spark_svg = _render_sparkline_svg(series_by_pillar.get(pillar, []))
        bullet_svg = _render_tufte_bullet_svg(score)
        drift_7d = net_drift_by_pillar.get(pillar, 0)
        drift_str = f"+{drift_7d}" if drift_7d > 0 else ("0" if drift_7d == 0 else str(drift_7d))

        fmt_count = lambda n: f'<span class="nonzero">{n}</span>' if n > 0 else '<span class="zero-dot">·</span>'
        savings_str = f"${savings:,.2f}" if savings > 0 else '<span class="zero-dot">·</span>'
        deficit_str = f"−{deficit} pts" if deficit > 0 else '<span class="zero-dot">0</span>'

        next_pillar = None if active_pillar == pillar else pillar
        pillar_href = _build_filter_href(pillar=next_pillar, project=active_project, blob=current_blob)
        row_cls = ' class="active-filter-row"' if active_pillar == pillar else ""

        pillar_rows_html.append(
            f"""
            <tr{row_cls}>
              <td class="col-pillar">
                <a class="filter-link" href="{pillar_href}" title="Filter ledger by {html.escape(pillar)}"><strong>{html.escape(pillar)}</strong></a>
                <div class="sub-label">{html.escape(PILLAR_LABELS.get(pillar, pillar))}</div>
              </td>
              <td class="num score-cell">{score}</td>
              <td class="bullet-cell">{bullet_svg}</td>
              <td class="num">{deficit_str}</td>
              <td class="spark-cell">{spark_svg} <span class="spark-meta">({drift_str})</span></td>
              <td class="num">{fmt_count(crit)}</td>
              <td class="num">{fmt_count(high)}</td>
              <td class="num">{fmt_count(med)}</td>
              <td class="num">{fmt_count(low)}</td>
              <td class="num">{savings_str}</td>
            </tr>
            """
        )

    # 2. Zero-Suppressed Folder/Project Risk Concentration Matrix (v_folder_project_heatmap)
    projects_map: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for h in data["heatmap_rows"]:
        key = (str(h.get("folder_id") or "folders/UNASSIGNED_ROOT"), str(h.get("project_id") or "unknown"))
        projects_map.setdefault(key, {})[str(h.get("waf_pillar"))] = h

    heatmap_rows_html = []
    if not projects_map:
        heatmap_rows_html.append(
            '<tr><td colspan="8" class="empty-row">No active non-compliant findings across organization projects.</td></tr>'
        )
    else:
        for (folder_id, proj_id), pillar_dict in sorted(projects_map.items()):
            cells = []
            row_total = 0
            for p in PILLAR_ORDER:
                entry = pillar_dict.get(p)
                if not entry or int(entry.get("total_findings") or 0) == 0:
                    cells.append('<td class="num matrix-zero">·</td>')
                else:
                    cnt = int(entry["total_findings"])
                    crit_c = int(entry.get("critical_findings") or 0)
                    high_c = int(entry.get("high_findings") or 0)
                    row_total += cnt
                    intensity_cls = "matrix-crit" if crit_c > 0 else ("matrix-high" if high_c > 0 else "matrix-med")
                    cell_href = _build_filter_href(pillar=p, project=proj_id, blob=current_blob)
                    cells.append(
                        f'<td class="num {intensity_cls}" title="Critical: {crit_c}, High: {high_c} — Click to filter">'
                        f'<a class="filter-link" href="{cell_href}">{cnt}</a></td>'
                    )
            next_proj = None if active_project == proj_id else proj_id
            proj_href = _build_filter_href(pillar=active_pillar, project=next_proj, blob=current_blob)
            proj_row_cls = ' class="active-filter-row"' if active_project == proj_id else ""
            heatmap_rows_html.append(
                f"""
                <tr{proj_row_cls}>
                  <td class="mono">
                    <a class="filter-link" href="{proj_href}" title="Filter ledger by project {html.escape(proj_id)}">{html.escape(proj_id)}</a>
                    <div class="sub-label">{html.escape(folder_id)}</div>
                  </td>
                  {"".join(cells)}
                  <td class="num"><strong>{row_total}</strong></td>
                </tr>
                """
            )

    # 3. Active Architectural Drift Ledger (v_current_waf_posture)
    all_findings = data["current_findings"]
    filtered_findings = [
        f
        for f in all_findings
        if (not active_pillar or str(f.get("waf_pillar") or "").upper() == active_pillar)
        and (not active_project or str(f.get("project_id") or "") == active_project)
    ]

    filter_banner_html = ""
    if active_pillar or active_project:
        chips = []
        if active_project:
            chips.append(f"project = <code>{html.escape(active_project)}</code>")
        if active_pillar:
            chips.append(f"pillar = <code>{html.escape(active_pillar)}</code>")
        clear_href = _build_filter_href(pillar=None, project=None, blob=current_blob)
        filter_banner_html = (
            f'<div class="filter-banner">'
            f'Showing <strong>{len(filtered_findings)}</strong> of {len(all_findings)} findings · '
            f'Filtered by {" &amp; ".join(chips)} · '
            f'<a href="{clear_href}" class="clear-filter-link">Reset filter ×</a>'
            f"</div>"
        )

    findings_html = []
    gitops_thresholds = gitops_thresholds_from_env()
    for idx, f in enumerate(filtered_findings, start=1):
        uri = html.escape(str(f.get("resource_uri") or ""))
        proj = html.escape(str(f.get("project_id") or ""))
        pillar = html.escape(str(f.get("waf_pillar") or ""))
        principle = html.escape(str(f.get("waf_principle") or ""))
        sev = html.escape(str(f.get("severity") or ""))
        ts = html.escape(str(f.get("evaluation_timestamp") or "")[:19].replace("T", " "))
        rationale = html.escape(str(f.get("rationale") or ""))
        tf_code = html.escape(str(f.get("terraform_remediation") or ""))
        gitops = f.get("gitops_plan", {})
        fp = html.escape(str(gitops.get("fingerprint") or ""))
        branch = html.escape(str(gitops.get("branch_name") or ""))
        tf_path = html.escape(str(gitops.get("target_tf_path") or ""))
        ineligible_reason = gitops_ineligibility_reason(f, **gitops_thresholds)
        if ineligible_reason is None:
            gitops_sidenote = (
                f'<strong>Phase 4 GitOps Plan</strong> · <span class="nonzero">auto-PR eligible</span><br/>'
                f'Fingerprint: <code class="mono">{fp}</code><br/>'
                f'Project: <code class="mono">{proj}</code><br/>'
                f'Branch: <code class="mono">{branch}</code><br/>'
                f'Target HCL: <code class="mono">{tf_path}</code>'
            )
        else:
            gitops_sidenote = (
                f'<strong>Phase 4 GitOps Plan</strong> · <span class="zero-dot">manual remediation</span><br/>'
                f'No auto-PR: {html.escape(ineligible_reason)}.<br/>'
                f'Fingerprint: <code class="mono">{fp}</code><br/>'
                f'Project: <code class="mono">{proj}</code>'
            )

        findings_html.append(
            f"""
            <article class="finding-entry">
              <div class="finding-header">
                <span class="finding-index">§ {idx}</span>
                <span class="sev-tag sev-{sev.lower()}">{sev}</span>
                <span class="pillar-tag">{pillar} · <em>{principle}</em></span>
                <span class="finding-ts">{ts} UTC</span>
              </div>
              <div class="finding-uri mono">{uri}</div>
              <div class="finding-body-grid">
                <div>
                  <p class="finding-rationale">{rationale}</p>
                  <details class="hcl-details" open>
                    <summary>Validated Terraform HCL Remediation (<code class="mono">{tf_path}</code>)</summary>
                    <pre class="hcl-block"><code>{tf_code}</code></pre>
                  </details>
                </div>
                <div class="sidenote">
                  {gitops_sidenote}
                </div>
              </div>
            </article>
            """
        )

    if not findings_html:
        findings_html.append('<p>No active architectural drift findings in the last 30 days.</p>')

    # 4. GCS Report Selector options
    report_options = []
    for r in data["available_reports"]:
        name = r["name"]
        selected_attr = "selected" if name == data["selected_blob"] else ""
        label = f"{name} ({r['updated'][:19].replace('T', ' ')} UTC)"
        report_options.append(f'<option value="{html.escape(name)}" {selected_attr}>{html.escape(label)}</option>')

    exec_md_escaped = html.escape(data["executive_markdown"])
    auth_warning = data.get("auth_warning")
    auth_banner_html = (
        f'<div class="filter-banner" style="margin-bottom:1.25rem;">'
        f"<strong>Cached Snapshot Mode:</strong> {html.escape(str(auth_warning))}"
        f"</div>"
        if auth_warning
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Google Cloud Well-Architected Posture — Tufte Analytical Ledger</title>
  <style>
    /* Edward Tufte Analytical Typography & High Data-Ink Layout */
    :root {{
      --paper: #fffff8;
      --ink: #111111;
      --muted: #555550;
      --hairline: #d4d0c8;
      --accent-crimson: #8b1e1e;
      --accent-crimson-bg: #f9ebeb;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      background-color: var(--paper);
      color: var(--ink);
      font-family: "ETBembo", "Palatino Linotype", "Palatino", "Book Antiqua", Georgia, serif;
      font-size: 16px;
      line-height: 1.55;
      margin: 0;
      padding: 2.2rem 3rem 5rem 3rem;
      max-width: 1460px;
      margin-left: auto;
      margin-right: auto;
      -webkit-font-smoothing: antialiased;
    }}

    /* Layout grid: 76% main column + 20% right-hand Tufte sidenote margin with 4% gap */
    .tufte-grid {{
      display: grid;
      grid-template-columns: minmax(0, 76%) minmax(200px, 20%);
      column-gap: 4%;
      align-items: start;
    }}

    .tufte-grid > main {{
      min-width: 0;
      padding-right: 1rem;
    }}

    .tufte-grid > aside {{
      min-width: 0;
    }}

    header.report-masthead {{
      border-bottom: 1.5px solid var(--ink);
      padding-bottom: 1rem;
      margin-bottom: 2rem;
    }}

    h1 {{
      font-weight: 400;
      font-size: 2.1rem;
      letter-spacing: -0.01em;
      margin: 0 0 0.35rem 0;
    }}

    .subtitle {{
      font-style: italic;
      color: var(--muted);
      font-size: 1.05rem;
      margin: 0;
    }}

    h2 {{
      font-weight: 400;
      font-style: italic;
      font-size: 1.4rem;
      margin: 2.4rem 0 0.6rem 0;
      border-bottom: 0.5px solid var(--hairline);
      padding-bottom: 0.25rem;
    }}

    .mono, code, pre {{
      font-family: "JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.82rem;
    }}

    .num {{
      font-family: "JetBrains Mono", "SFMono-Regular", Menlo, monospace;
      font-variant-numeric: tabular-nums;
      text-align: right;
      font-size: 0.85rem;
    }}

    /* Horizon Summary Strip: Direct Quantitative Numerals without Box Borders */
    .summary-strip {{
      display: flex;
      gap: 3.5rem;
      align-items: baseline;
      margin: 0.5rem 0 1.8rem 0;
      padding: 0.5rem 0;
      border-bottom: 0.5px solid var(--hairline);
    }}

    .metric-unit .metric-value {{
      font-family: "JetBrains Mono", Menlo, monospace;
      font-variant-numeric: tabular-nums;
      font-size: 1.85rem;
      font-weight: 500;
      color: var(--ink);
    }}

    .metric-unit .metric-label {{
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      display: block;
    }}

    /* Booktabs Tables: Top & Bottom Horizontal Hairlines Only, Zero Vertical Lines */
    table.booktabs {{
      width: 100%;
      table-layout: auto;
      border-collapse: collapse;
      border-top: 1.5px solid var(--ink);
      border-bottom: 1.5px solid var(--ink);
      margin: 0.75rem 0 1.75rem 0;
    }}

    table.booktabs thead th {{
      font-family: "ETBembo", Georgia, serif;
      font-weight: 600;
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
      padding: 0.42rem 0.35rem;
      border-bottom: 1px solid var(--ink);
      text-align: left;
      white-space: nowrap;
    }}

    table.booktabs thead th.num {{
      text-align: right;
    }}

    table.booktabs tbody td {{
      padding: 0.45rem 0.35rem;
      border-bottom: 0.5px solid #ebe8df;
      vertical-align: middle;
    }}

    table.booktabs tbody tr:last-child td {{
      border-bottom: none;
    }}

    .sub-label {{
      font-size: 0.78rem;
      color: var(--muted);
      font-style: italic;
    }}

    .score-cell {{
      font-weight: 600;
      font-size: 0.95rem;
    }}

    .bullet-cell {{
      width: 120px;
      white-space: nowrap;
    }}

    .spark-cell {{
      white-space: nowrap;
    }}

    .sparkline, .bullet-bar {{
      vertical-align: middle;
    }}

    .spark-meta {{
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.74rem;
      color: var(--muted);
      margin-left: 0.25rem;
    }}

    .zero-dot, .matrix-zero {{
      color: #b5b2a8;
      font-weight: 400;
    }}

    .nonzero {{
      color: var(--accent-crimson);
      font-weight: 600;
    }}

    /* Zero-Suppressed Risk Matrix Cells */
    .matrix-crit {{
      background-color: #f3d2d2;
      color: #6b1111;
      font-weight: 700;
    }}

    .matrix-high {{
      background-color: var(--accent-crimson-bg);
      color: var(--accent-crimson);
      font-weight: 600;
    }}

    .matrix-med {{
      background-color: #f4f1e6;
      color: var(--ink);
    }}

    /* Click-to-Filter Interactive Links & Active Row Highlighting */
    a.filter-link {{
      color: inherit;
      text-decoration: none;
      border-bottom: 1px dotted #9a968c;
      transition: border-color 0.12s ease, color 0.12s ease;
    }}

    a.filter-link:hover {{
      color: var(--accent-crimson);
      border-bottom: 1px solid var(--accent-crimson);
    }}

    tr.active-filter-row td {{
      background-color: #f6f2e4;
    }}

    .filter-banner {{
      font-size: 0.86rem;
      background-color: #f6f2e4;
      border-left: 2.5px solid var(--accent-crimson);
      padding: 0.45rem 0.75rem;
      margin: 0.4rem 0 0.9rem 0;
    }}

    a.clear-filter-link {{
      color: var(--accent-crimson);
      font-weight: 600;
      text-decoration: none;
      border-bottom: 1px solid var(--accent-crimson);
    }}

    /* Margin Sidenotes */
    .margin-note {{
      font-size: 0.84rem;
      line-height: 1.45;
      color: var(--muted);
      border-left: 1px solid var(--hairline);
      padding-left: 0.9rem;
      margin-bottom: 1.5rem;
    }}

    .margin-note strong {{
      color: var(--ink);
      font-weight: 600;
    }}

    /* Findings Ledger */
    .finding-entry {{
      padding: 1.1rem 0;
      border-bottom: 0.5px solid var(--hairline);
      position: relative;
    }}

    .finding-header {{
      display: flex;
      gap: 0.75rem;
      align-items: baseline;
      margin-bottom: 0.25rem;
    }}

    .finding-index {{
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.82rem;
      color: var(--muted);
    }}

    .sev-tag {{
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.73rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.05rem 0.35rem;
      border-bottom: 1.5px solid var(--accent-crimson);
      color: var(--accent-crimson);
      font-weight: 600;
    }}

    .finding-ts {{
      margin-left: auto;
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.76rem;
      color: var(--muted);
    }}

    .finding-uri {{
      color: var(--ink);
      font-weight: 500;
      margin-bottom: 0.45rem;
      word-break: break-all;
    }}

    .finding-body-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 250px;
      column-gap: 1.5rem;
      align-items: start;
    }}

    .finding-rationale {{
      margin: 0.2rem 0 0.75rem 0;
      text-align: justify;
    }}

    .sidenote {{
      font-size: 0.78rem;
      line-height: 1.45;
      color: var(--muted);
      border-left: 1px solid var(--hairline);
      padding-left: 0.8rem;
      word-break: break-word;
    }}

    details.hcl-details summary {{
      cursor: pointer;
      font-size: 0.86rem;
      color: var(--muted);
      user-select: none;
    }}

    pre.hcl-block {{
      background-color: #f7f5ee;
      border-left: 2px solid var(--ink);
      padding: 0.75rem 1rem;
      overflow-x: auto;
      margin: 0.4rem 0 0.2rem 0;
      line-height: 1.4;
    }}

    pre.md-archive {{
      background-color: #faf8f0;
      border-top: 1px solid var(--ink);
      border-bottom: 1px solid var(--ink);
      padding: 1rem 1.2rem;
      white-space: pre-wrap;
      font-family: "ETBembo", Georgia, serif;
      font-size: 0.96rem;
      line-height: 1.55;
    }}

    select.report-picker {{
      background: var(--paper);
      border: 1px solid var(--ink);
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.78rem;
      padding: 0.25rem 0.5rem;
      color: var(--ink);
    }}

    @media (max-width: 1024px) {{
      body {{
        padding: 1.5rem;
      }}
      .tufte-grid {{
        grid-template-columns: 1fr;
      }}
      .sidenote {{
        float: none;
        margin-right: 0;
        width: 100%;
        display: block;
        margin-top: 0.5rem;
      }}
    }}
  </style>
</head>
<body>
  <header class="report-masthead">
    <h1>Google Cloud Well-Architected Framework Posture</h1>
    <p class="subtitle">
      Organization Telemetry Sink: <span class="mono">{project_id}.{dataset_id}</span> ·
      Artifact Archive: <span class="mono">gs://{gcs_bucket}</span> ·
      Evaluated: <span class="mono">{generated_at}</span> ·
      <a href="/architecture" class="filter-link" style="font-style:normal;font-weight:600;">§ System Architecture Schematic →</a>
    </p>
  </header>
  {auth_banner_html}

  <div class="tufte-grid">
    <main>
      <div class="summary-strip">
        <div class="metric-unit">
          <span class="metric-value">{overall_score}<span style="font-size:1rem;color:#666">/100</span></span>
          <span class="metric-label">Composite WAF Index</span>
        </div>
        <div class="metric-unit">
          <span class="metric-value">{total_active}</span>
          <span class="metric-label">Active Non-Compliant Drift Items</span>
        </div>
        <div class="metric-unit">
          <span class="metric-value">${total_savings:,.2f}</span>
          <span class="metric-label">Projected Monthly FinOps Savings</span>
        </div>
      </div>

      <h2>I. Six-Pillar Small Multiples &amp; 14-Day Drift Sparklines</h2>
      <table class="booktabs">
        <thead>
          <tr>
            <th>WAF Pillar</th>
            <th class="num">Score</th>
            <th>Posture Range (0–100)</th>
            <th class="num">Deficit</th>
            <th>14d Drift Sparkline (Δ7d)</th>
            <th class="num">Crit</th>
            <th class="num">High</th>
            <th class="num">Med</th>
            <th class="num">Low</th>
            <th class="num">Est. Savings/mo</th>
          </tr>
        </thead>
        <tbody>
          {"".join(pillar_rows_html)}
        </tbody>
      </table>

      <h2>II. Project × Pillar Risk Concentration Matrix (Zero-Suppressed)</h2>
      <table class="booktabs">
        <thead>
          <tr>
            <th>Project / Folder Scope</th>
            <th class="num">SEC</th>
            <th class="num">REL</th>
            <th class="num">COST</th>
            <th class="num">PERF</th>
            <th class="num">OPS</th>
            <th class="num">SUST</th>
            <th class="num">Total</th>
          </tr>
        </thead>
        <tbody>
          {"".join(heatmap_rows_html)}
        </tbody>
      </table>

      <h2 id="drift-ledger">III. Deduplicated Architectural Drift Ledger &amp; Phase 4 GitOps Plans</h2>
      {filter_banner_html}
      {"".join(findings_html)}

      <h2>IV. Archived Executive Markdown Narrative (<span class="mono">gs://{gcs_bucket}</span>)</h2>
      <form method="get" action="/dashboard" style="margin-bottom:0.75rem;">
        {f'<input type="hidden" name="pillar" value="{html.escape(active_pillar)}" />' if active_pillar else ""}
        {f'<input type="hidden" name="project" value="{html.escape(active_project)}" />' if active_project else ""}
        <label for="report-select" style="font-size:0.85rem;color:var(--muted);">Select GCS Archive Snapshot: </label>
        <select id="report-select" name="blob" class="report-picker" onchange="this.form.submit()">
          {"".join(report_options)}
        </select>
      </form>
      <pre class="md-archive">{exec_md_escaped}</pre>
    </main>

    <aside>
      <div class="margin-note">
        <strong>§ Deterministic Scoring Rubric</strong><br/>
        Source: <span class="mono">v_pillar_posture_scores</span><br/>
        Each pillar starts at <span class="mono">100</span> and deducts:<br/>
        · <span class="mono">CRITICAL</span>: −15 pts<br/>
        · <span class="mono">HIGH</span>: −7 pts<br/>
        · <span class="mono">MEDIUM</span>: −3 pts<br/>
        · <span class="mono">LOW</span>: −1 pt<br/>
        Deduplicated over a rolling 30-day window via <span class="mono">QUALIFY ROW_NUMBER() OVER (PARTITION BY resource_uri, waf_pillar) = 1</span>.
      </div>
      <div class="margin-note">
        <strong>§ Live BigQuery Views</strong><br/>
        1. <span class="mono">v_pillar_posture_scores</span><br/>
        2. <span class="mono">v_pillar_drift_velocity</span><br/>
        3. <span class="mono">v_folder_project_heatmap</span><br/>
        4. <span class="mono">v_current_waf_posture</span><br/><br/>
        JSON API endpoint:<br/>
        <a href="/api/dashboard/data" class="mono" style="color:var(--ink);">GET /api/dashboard/data</a><br/><br/>
        Architecture blueprint:<br/>
        <a href="/architecture" class="mono" style="color:var(--ink);">GET /architecture</a>
      </div>
    </aside>
  </div>
</body>
</html>"""


def render_tufte_architecture_html() -> str:
    """Renders an Edward Tufte-inspired Architectural Overview & Multivariate System Schematic."""
    cfg = get_waf_config()
    template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Autonomous Google Cloud WAF Auditor — Tufte Architectural Overview</title>
  <style>
    :root {
      --paper: #fffff8;
      --ink: #111111;
      --muted: #555550;
      --hairline: #d4d0c8;
      --accent-crimson: #8b1e1e;
      --accent-crimson-bg: #f9ebeb;
    }
    * { box-sizing: border-box; }
    body {
      background-color: var(--paper);
      color: var(--ink);
      font-family: "ETBembo", "Palatino Linotype", "Palatino", "Book Antiqua", Georgia, serif;
      font-size: 16px;
      line-height: 1.55;
      margin: 0;
      padding: 2.2rem 3rem 5rem 3rem;
      max-width: 1460px;
      margin-left: auto;
      margin-right: auto;
      -webkit-font-smoothing: antialiased;
    }
    .tufte-grid {
      display: grid;
      grid-template-columns: minmax(0, 76%) minmax(200px, 20%);
      column-gap: 4%;
      align-items: start;
    }
    .tufte-grid > main { min-width: 0; padding-right: 1rem; }
    .tufte-grid > aside { min-width: 0; }
    header.report-masthead {
      border-bottom: 1.5px solid var(--ink);
      padding-bottom: 1rem;
      margin-bottom: 1.8rem;
    }
    h1 {
      font-weight: 400;
      font-size: 2.1rem;
      letter-spacing: -0.01em;
      margin: 0 0 0.35rem 0;
    }
    .subtitle {
      font-style: italic;
      color: var(--muted);
      font-size: 1.05rem;
      margin: 0;
    }
    h2 {
      font-weight: 400;
      font-style: italic;
      font-size: 1.4rem;
      margin: 2.2rem 0 0.6rem 0;
      border-bottom: 0.5px solid var(--hairline);
      padding-bottom: 0.25rem;
    }
    .mono, code, pre {
      font-family: "JetBrains Mono", "SFMono-Regular", Consolas, Menlo, monospace;
      font-size: 0.80rem;
    }
    .num {
      font-family: "JetBrains Mono", Menlo, monospace;
      font-variant-numeric: tabular-nums;
      text-align: right;
      font-size: 0.82rem;
    }
    a.filter-link {
      color: inherit;
      text-decoration: none;
      border-bottom: 1px dotted #9a968c;
    }
    a.filter-link:hover {
      color: var(--accent-crimson);
      border-bottom: 1px solid var(--accent-crimson);
    }
    table.booktabs {
      width: 100%;
      border-collapse: collapse;
      border-top: 1.5px solid var(--ink);
      border-bottom: 1.5px solid var(--ink);
      margin: 0.75rem 0 1.75rem 0;
    }
    table.booktabs thead th {
      font-family: "ETBembo", Georgia, serif;
      font-weight: 600;
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
      padding: 0.42rem 0.4rem;
      border-bottom: 1px solid var(--ink);
      text-align: left;
    }
    table.booktabs tbody td {
      padding: 0.48rem 0.4rem;
      border-bottom: 0.5px solid #ebe8df;
      vertical-align: top;
      font-size: 0.92rem;
    }
    table.booktabs tbody tr:last-child td { border-bottom: none; }
    .sub-label {
      font-size: 0.78rem;
      color: var(--muted);
      font-style: italic;
    }
    .margin-note {
      font-size: 0.84rem;
      line-height: 1.45;
      color: var(--muted);
      border-left: 1px solid var(--hairline);
      padding-left: 0.9rem;
      margin-bottom: 1.5rem;
    }
    .margin-note strong { color: var(--ink); font-weight: 600; }
    .schematic-frame {
      margin: 0.75rem 0 1.75rem 0;
      padding: 1rem 0;
      border-top: 1.5px solid var(--ink);
      border-bottom: 1.5px solid var(--ink);
    }
    .flow-grid {
      display: grid;
      grid-template-columns: 1fr 28px 1.25fr 28px 1.1fr 28px 1.2fr;
      align-items: stretch;
      gap: 0;
    }
    .flow-col {
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
      min-width: 0;
    }
    .flow-stage-title {
      font-style: italic;
      font-size: 0.86rem;
      color: var(--muted);
      border-bottom: 0.75px solid var(--ink);
      padding-bottom: 0.25rem;
      margin-bottom: 0.15rem;
    }
    .flow-arrow-gutter {
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 1.15rem;
      color: var(--ink);
      user-select: none;
      padding-top: 1.6rem;
    }
    .node-card {
      background-color: #faf8f0;
      border: 1px solid var(--ink);
      padding: 0.55rem 0.65rem;
      font-size: 0.82rem;
      line-height: 1.38;
      overflow-wrap: anywhere;
    }
    .node-card.white {
      background-color: var(--paper);
    }
    .node-card.crimson {
      background-color: var(--accent-crimson-bg);
      border-color: var(--accent-crimson);
    }
    .node-title {
      font-family: "ETBembo", Georgia, serif;
      font-weight: 700;
      font-size: 0.94rem;
      color: var(--ink);
      margin-bottom: 0.2rem;
    }
    .node-card.crimson .node-title {
      color: var(--accent-crimson);
    }
    .node-meta {
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.73rem;
      color: var(--muted);
      display: block;
    }
    .node-highlight {
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.73rem;
      color: var(--accent-crimson);
      display: block;
      margin-top: 0.15rem;
    }
    .pillar-list {
      list-style: none;
      margin: 0.35rem 0 0 0;
      padding: 0;
      border-top: 0.5px solid var(--hairline);
    }
    .pillar-list li {
      padding: 0.28rem 0;
      border-bottom: 0.5px solid #ebe8df;
      font-size: 0.78rem;
      line-height: 1.32;
    }
    .pillar-list li:last-child {
      border-bottom: none;
    }
    .loop-connector {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.72rem;
      padding: 0.15rem 0.35rem;
      color: var(--muted);
    }
    .Down-connector {
      text-align: center;
      font-family: "JetBrains Mono", Menlo, monospace;
      font-size: 0.78rem;
      color: var(--muted);
      padding: 0.55rem 0 0.35rem 0;
      letter-spacing: 0.03em;
    }
    .presentation-band {
      background-color: #faf8f0;
      border: 1.2px solid var(--ink);
      padding: 0.7rem 0.95rem;
    }
    .presentation-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.9rem;
      margin-top: 0.35rem;
      font-size: 0.80rem;
      line-height: 1.38;
    }
    @media (max-width: 1100px) {
      .flow-grid {
        grid-template-columns: 1fr;
        gap: 0.75rem;
      }
      .flow-arrow-gutter {
        padding-top: 0;
        transform: rotate(90deg);
      }
      .presentation-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <header class="report-masthead">
    <h1>Autonomous Google Cloud Well-Architected Framework Auditor — System Architecture</h1>
    <p class="subtitle">
      Organization Scope: <span class="mono">__TARGET_SCOPE__</span> ·
      Compliance Hub: <span class="mono">__PROJECT_ID__</span> ·
      Inference Host: <span class="mono">__QUOTA_PROJECT_ID__</span> ·
      <a href="/dashboard" class="filter-link" style="font-style:normal;font-weight:600;">← Return to Live Posture Dashboard</a>
    </p>
  </header>

  <div class="tufte-grid">
    <main>
      <h2>I. Multivariate System Topology &amp; Telemetry Flow Schematic</h2>
      <p style="margin-top:0.2rem;color:var(--muted);font-size:0.95rem;">
        End-to-end execution path from Cloud Asset Inventory real-time drift and scheduled organization sweeps through the 8-agent <span class="mono">google-adk</span> hierarchy into BigQuery, Cloud Storage, and zero-trust GitOps Pull Request remediation.
      </p>

      <div class="schematic-frame" aria-label="Tufte Multivariate System Architecture Schematic">
        <div class="flow-grid">
          <!-- STAGE 1: Event Ingestion -->
          <div class="flow-col">
            <div class="flow-stage-title">§ 1. Dual-Mode Ingestion</div>
            <div class="node-card">
              <div class="node-title">Path A: Real-Time Drift</div>
              <span class="node-meta">CAI RealTimeFeed (Org-level)</span>
              <span class="node-meta">RESOURCE + IAM_POLICY (&lt;60s)</span>
              <span class="node-highlight">scan_mode = REALTIME_DRIFT</span>
            </div>
            <div class="node-card">
              <div class="node-title">Path B: Nightly Baseline</div>
              <span class="node-meta">Cloud Scheduler (0 2 * * * UTC)</span>
              <span class="node-highlight">scan_mode = NIGHTLY_SWEEP</span>
            </div>
            <div class="Loop-connector" style="justify-content:center;font-family:Menlo,monospace;font-size:0.75rem;color:var(--ink);">↓ Pub/Sub Push</div>
            <div class="node-card white">
              <div class="node-title">Cloud Run Push Endpoint</div>
              <span class="node-meta">POST /pubsub/push (OIDC)</span>
              <span class="node-meta">SA: waf-pubsub-invoker-sa</span>
              <span class="node-meta">Backoff: 10s–600s · DLQ: 5 tries</span>
              <span class="node-highlight">Seeds: observed_resource_uris</span>
            </div>
          </div>

          <div class="flow-arrow-gutter" aria-hidden="true">→</div>

          <!-- STAGE 2: 6-Pillar ParallelAgent -->
          <div class="flow-col">
            <div class="flow-stage-title">§ 2. 6-Pillar Parallel Fan-Out</div>
            <div class="node-card white" style="flex:1;">
              <div class="node-title">ParallelAgent: WAF_Six_Pillar_FanOut</div>
              <span class="node-meta">Model: gemini-2.5-flash · 429 Backoff: 5x</span>
              <ul class="pillar-list">
                <li>
                  <strong>1. SECURITY</strong> <span class="node-meta">→ state['security_report']</span>
                  <div class="sub-label">Skill: google-cloud-waf-security · CAI + SCC v2</div>
                </li>
                <li>
                  <strong>2. RELIABILITY</strong> <span class="node-meta">→ state['reliability_report']</span>
                  <div class="sub-label">Skill: google-cloud-waf-reliability · PromQL SLOs</div>
                </li>
                <li>
                  <strong>3. COST (FinOps)</strong> <span class="node-meta">→ state['cost_report']</span>
                  <div class="sub-label">Skill: google-cloud-waf-cost-optimization · Recommender</div>
                </li>
                <li>
                  <strong>4. PERFORMANCE</strong> <span class="node-meta">→ state['performance_report']</span>
                  <div class="sub-label">Skill: google-cloud-waf-performance-optimization</div>
                </li>
                <li>
                  <strong>5. OPS EXCELLENCE</strong> <span class="node-meta">→ state['ops_report']</span>
                  <div class="sub-label">Skill: google-cloud-waf-operational-excellence · LQL</div>
                </li>
                <li>
                  <strong>6. SUSTAINABILITY</strong> <span class="node-meta">→ state['sustainability_report']</span>
                  <div class="sub-label">Skill: google-cloud-waf-sustainability · Carbon BQ</div>
                </li>
              </ul>
              <div style="border-top:0.75px solid var(--ink);margin-top:0.35rem;padding-top:0.3rem;">
                <span class="node-highlight">Anti-Hallucination Tool Ledger:</span>
                <span class="node-meta">· state['observed_resource_uris']</span>
                <span class="node-meta">· state['uri_to_project_id']</span>
              </div>
            </div>
          </div>

          <div class="flow-arrow-gutter" aria-hidden="true">→</div>

          <!-- STAGE 3: Synthesis & Critic Loop -->
          <div class="flow-col">
            <div class="flow-stage-title">§ 3. Synthesis &amp; Critic Loop</div>
            <div class="node-card">
              <div class="node-title">LoopAgent (max_iterations=3)</div>
              <span class="node-meta" style="margin-bottom:0.35rem;">Synthesis_And_Critic_Loop</span>

              <div class="node-card white" style="margin-bottom:0.3rem;">
                <div class="node-title">Chief Architect Synthesizer</div>
                <span class="node-meta">Model: gemini-2.5-pro</span>
                <span class="node-meta">Schema: OrgWAFReport</span>
                <span class="node-meta">Merges &amp; deduplicates 6 reports</span>
                <span class="node-highlight">→ state['draft_org_report']</span>
              </div>

              <div class="loop-connector">
                <span>↓ evaluate draft</span>
                <span style="color:var(--accent-crimson);">↑ fix HCL / URI</span>
              </div>

              <div class="node-card crimson">
                <div class="node-title">WAF Critic Verifier</div>
                <span class="node-meta">Tool: validate_terraform_and_uri</span>
                <span class="node-meta">1. Regex ^//[a-z0-9-]+\.googleapis</span>
                <span class="node-meta">2. URI ∈ observed_resource_uris</span>
                <span class="node-meta">3. python-hcl2 AST syntax check</span>
                <span class="node-highlight">Pass → approve_and_exit_loop()</span>
              </div>
            </div>

            <div class="loop-connector" style="justify-content:center;color:var(--ink);">↓ on loop exit</div>

            <div class="node-card white">
              <div class="node-title">Root after_agent_callback</div>
              <span class="node-meta">commit_findings_to_bigquery_and_gcs</span>
              <span class="node-meta">SA: waf-auditor-sa</span>
            </div>
          </div>

          <div class="flow-arrow-gutter" aria-hidden="true">→</div>

          <!-- STAGE 4: Three Telemetry Sinks -->
          <div class="flow-col">
            <div class="flow-stage-title">§ 4. Telemetry &amp; GitOps Sinks</div>
            <div class="node-card white">
              <div class="node-title">Sink 1: BigQuery Warehouse</div>
              <span class="node-meta">org_compliance.waf_findings</span>
              <span class="node-meta">PARTITION BY DATE(eval_timestamp)</span>
              <span class="node-meta">CLUSTER BY pillar, project, severity</span>
              <span class="node-highlight">+ 4 Analytical SQL Views:</span>
              <span class="node-meta">v_current_waf_posture · v_pillar_scores</span>
              <span class="node-meta">v_pillar_drift_velocity · v_heatmap</span>
            </div>

            <div class="node-card white">
              <div class="node-title">Sink 2: Hardened GCS Archive</div>
              <span class="node-meta">gs://__GCS_BUCKET__</span>
              <span class="node-meta">UBLA · PAP Enforced · 7d Soft Delete</span>
              <span class="node-meta">Object Versioning · Timestamped .md</span>
            </div>

            <div class="node-card crimson">
              <div class="node-title">Sink 3: Zero-Trust GitOps PRs</div>
              <span class="node-meta">Topic: waf-gitops-remediation</span>
              <span class="node-meta">SHA-256: resource_uri | waf_pillar</span>
              <span class="node-meta">Cloud Build: waf-gitops-worker-sa</span>
              <span class="node-highlight">Secret: github-pat-waf-bot (isolated)</span>
              <span class="node-meta">remediations/&lt;proj&gt;/&lt;pillar&gt;_&lt;fp&gt;.tf</span>
            </div>
          </div>
        </div>

        <div class="Down-connector">
          ↓ Sink 1 (4 BigQuery Views) &amp; Sink 2 (GCS Markdown Snapshots) feed the Analytical Presentation Layer ↓
        </div>

        <div class="presentation-band">
          <div class="node-title">§ 5. Analytical Presentation &amp; Executive Reporting Layer (<span class="mono">GET /dashboard</span> &amp; Looker Studio)</div>
          <div class="presentation-grid">
            <div>
              <strong>Section I: Small Multiples</strong><br/>
              <span class="node-meta">v_pillar_posture_scores + v_pillar_drift_velocity</span>
              Range-frame bullet bars (0–100), severity breakdown, and word-sized 14-day drift sparklines (<span class="mono">Δ7d</span>).
            </div>
            <div>
              <strong>Section II: Risk Matrix</strong><br/>
              <span class="node-meta">v_folder_project_heatmap</span>
              Zero-suppressed <span class="mono">Project × Pillar</span> table (<span class="mono">· = 0</span>) with click-to-filter links (<span class="mono">?pillar=...&amp;project=...</span>).
            </div>
            <div>
              <strong>Sections III &amp; IV: Evidence Ledger</strong><br/>
              <span class="node-meta">v_current_waf_posture + GCS Archive</span>
              Deduplicated findings with validated HCL, Phase 4 GitOps sidenotes, and historical snapshot picker.
            </div>
          </div>
        </div>
      </div>

      <h2>II. Multi-Agent Hierarchy, Grounding Skills &amp; Tool Matrix (<span class="mono">app/agent.py</span>)</h2>
      <table class="booktabs">
        <thead>
          <tr>
            <th>Agent Name &amp; ADK Class</th>
            <th>Vertex AI Model</th>
            <th>Grounding Skill (<span class="mono">.agents/skills/</span>)</th>
            <th>Deterministic Read/Verify Tools</th>
            <th>Session State Contract</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <strong>WAF_Auditor_Pipeline</strong>
              <div class="sub-label">SequentialAgent (Root)</div>
            </td>
            <td class="mono">—</td>
            <td class="mono">Orchestrates Fan-Out → Critic Loop → Callback</td>
            <td class="mono">commit_findings_to_bigquery_and_gcs</td>
            <td class="mono">bq_insert_status<br/>gcs_upload_status<br/>gitops_pr_plans</td>
          </tr>
          <tr>
            <td>
              <strong>WAF_Security_Auditor</strong>
              <div class="sub-label">LlmAgent (Branch 1)</div>
            </td>
            <td class="mono">gemini-2.5-flash</td>
            <td class="mono">google-cloud-waf-security</td>
            <td class="mono">search_org_assets<br/>inspect_resource_configuration<br/>fetch_scc_findings<br/>fetch_active_recommendations</td>
            <td class="mono">security_report<br/>(PillarAuditReport)</td>
          </tr>
          <tr>
            <td>
              <strong>WAF_Reliability_Auditor</strong>
              <div class="sub-label">LlmAgent (Branch 2)</div>
            </td>
            <td class="mono">gemini-2.5-flash</td>
            <td class="mono">google-cloud-waf-reliability</td>
            <td class="mono">search_org_assets<br/>inspect_resource_configuration<br/>fetch_active_recommendations<br/>query_cloud_monitoring_promql</td>
            <td class="mono">reliability_report<br/>(PillarAuditReport)</td>
          </tr>
          <tr>
            <td>
              <strong>WAF_Cost_Auditor</strong>
              <div class="sub-label">LlmAgent (Branch 3)</div>
            </td>
            <td class="mono">gemini-2.5-flash</td>
            <td class="mono">google-cloud-waf-cost-optimization</td>
            <td class="mono">search_org_assets<br/>fetch_active_recommendations<br/>query_cloud_monitoring_promql</td>
            <td class="mono">cost_report<br/>(PillarAuditReport)</td>
          </tr>
          <tr>
            <td>
              <strong>WAF_Performance_Auditor</strong>
              <div class="sub-label">LlmAgent (Branch 4)</div>
            </td>
            <td class="mono">gemini-2.5-flash</td>
            <td class="mono">google-cloud-waf-performance-optimization</td>
            <td class="mono">search_org_assets<br/>inspect_resource_configuration<br/>fetch_active_recommendations<br/>query_cloud_monitoring_promql</td>
            <td class="mono">performance_report<br/>(PillarAuditReport)</td>
          </tr>
          <tr>
            <td>
              <strong>WAF_Ops_Excellence_Auditor</strong>
              <div class="sub-label">LlmAgent (Branch 5)</div>
            </td>
            <td class="mono">gemini-2.5-flash</td>
            <td class="mono">google-cloud-waf-operational-excellence</td>
            <td class="mono">search_org_assets<br/>inspect_resource_configuration<br/>query_cloud_logging_lql</td>
            <td class="mono">ops_report<br/>(PillarAuditReport)</td>
          </tr>
          <tr>
            <td>
              <strong>WAF_Sustainability_Auditor</strong>
              <div class="sub-label">LlmAgent (Branch 6)</div>
            </td>
            <td class="mono">gemini-2.5-flash</td>
            <td class="mono">google-cloud-waf-sustainability</td>
            <td class="mono">search_org_assets<br/>fetch_active_recommendations<br/>query_carbon_footprint_bq</td>
            <td class="mono">sustainability_report<br/>(PillarAuditReport)</td>
          </tr>
          <tr>
            <td>
              <strong>WAF_Chief_Architect_Synthesizer</strong>
              <div class="sub-label">LlmAgent (Loop Step 1)</div>
            </td>
            <td class="mono">gemini-2.5-pro</td>
            <td class="mono">Cross-Pillar Trade-Off Resolution</td>
            <td class="mono">Reads all 6 {*_report?} state keys + {critic_feedback?}</td>
            <td class="mono">draft_org_report<br/>(OrgWAFReport)</td>
          </tr>
          <tr>
            <td>
              <strong>WAF_Critic_Verifier</strong>
              <div class="sub-label">LlmAgent (Loop Step 2)</div>
            </td>
            <td class="mono">gemini-2.5-pro</td>
            <td class="mono">Deterministic URI &amp; HCL AST Gatekeeper</td>
            <td class="mono">validate_terraform_and_uri<br/>approve_and_exit_loop</td>
            <td class="mono">critic_feedback →<br/>final_org_report</td>
          </tr>
        </tbody>
      </table>

      <h2>III. Telemetry Sinks, Analytical Views &amp; Reporting Pipeline</h2>
      <table class="booktabs">
        <thead>
          <tr>
            <th>Telemetry Sink / View</th>
            <th>GCP Resource Identifier</th>
            <th>Partitioning / Deduplication Logic</th>
            <th>Dashboard &amp; Looker Studio Role</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Raw Audit Ledger Table</strong></td>
            <td class="mono">__BQ_TABLE__</td>
            <td class="mono">PARTITION BY DATE(evaluation_timestamp)<br/>CLUSTER BY waf_pillar, project_id, severity</td>
            <td>Immutable append-only history of every real-time drift and nightly sweep finding.</td>
          </tr>
          <tr>
            <td><strong>View 1: Current Posture</strong></td>
            <td class="mono">org_compliance.v_current_waf_posture</td>
            <td class="mono">QUALIFY ROW_NUMBER() OVER (PARTITION BY resource_uri, waf_pillar ORDER BY evaluation_timestamp DESC) = 1</td>
            <td>Powers <strong>Section III</strong> (Deduplicated Drift Ledger) and filters out superseded evaluations.</td>
          </tr>
          <tr>
            <td><strong>View 2: Pillar Scores</strong></td>
            <td class="mono">org_compliance.v_pillar_posture_scores</td>
            <td class="mono">100 − (15×CRIT + 7×HIGH + 3×MED + 1×LOW)</td>
            <td>Powers the <strong>Horizon Summary Strip</strong> and <strong>Section I</strong> (6-Pillar Small Multiples &amp; Bullet Bars).</td>
          </tr>
          <tr>
            <td><strong>View 3: Drift Velocity</strong></td>
            <td class="mono">org_compliance.v_pillar_drift_velocity</td>
            <td class="mono">COALESCE(LAG(non_compliant_count, 1) OVER (...))</td>
            <td>Powers the word-sized <strong>14-Day Drift Sparklines</strong> and 7-day net velocity (<span class="mono">Δ7d</span>) in Section I.</td>
          </tr>
          <tr>
            <td><strong>View 4: Project × Pillar Matrix</strong></td>
            <td class="mono">org_compliance.v_folder_project_heatmap</td>
            <td class="mono">GROUP BY folder_id, project_id, waf_pillar</td>
            <td>Powers <strong>Section II</strong> (Zero-Suppressed Risk Concentration Matrix with click-to-filter links).</td>
          </tr>
          <tr>
            <td><strong>Hardened Markdown Archive</strong></td>
            <td class="mono">gs://__GCS_BUCKET__</td>
            <td class="mono">reports/waf_executive_summary.md<br/>reports/YYYY/MM/DD/waf_report_&lt;mode&gt;_&lt;ts&gt;.md</td>
            <td>Powers <strong>Section IV</strong> (Historical GCS Snapshot Picker &amp; Executive Narrative).</td>
          </tr>
        </tbody>
      </table>

      <h2>IV. Zero-Trust Identity &amp; Secret Isolation Matrix (<span class="mono">terraform/iam.tf</span> &amp; <span class="mono">gitops_cloudbuild.tf</span>)</h2>
      <table class="booktabs">
        <thead>
          <tr>
            <th>Principal / Secret</th>
            <th>Execution Boundary</th>
            <th>Granted IAM Roles</th>
            <th>Explicitly Denied / Isolated Capabilities</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="mono"><strong>waf-pubsub-invoker-sa</strong></td>
            <td>Pub/Sub Push Subscription OIDC Envelope</td>
            <td class="mono">roles/run.invoker (on waf-auditor-service only)</td>
            <td>Zero access to Cloud Asset Inventory, BigQuery, GCS, or Secret Manager.</td>
          </tr>
          <tr>
            <td class="mono"><strong>waf-auditor-sa</strong></td>
            <td>Cloud Run ADK Multi-Agent Runtime</td>
            <td class="mono">roles/cloudasset.viewer, roles/securitycenter.findingsViewer, roles/recommender.viewer, roles/monitoring.viewer, roles/logging.viewer (Org); roles/bigquery.dataEditor, roles/storage.objectUser, roles/pubsub.publisher (Hub)</td>
            <td><strong>Read-only across Organization</strong>; cannot mutate live GCP infrastructure or read <span class="mono">github-pat-waf-bot</span>.</td>
          </tr>
          <tr>
            <td class="mono"><strong>waf-gitops-worker-sa</strong></td>
            <td>Cloud Build Ephemeral GitOps Worker</td>
            <td class="mono">roles/secretmanager.secretAccessor (on github-pat-waf-bot only); roles/logging.logWriter</td>
            <td><strong>Zero Organization IAM roles</strong>; cannot query CAI/SCC or modify BigQuery compliance tables.</td>
          </tr>
          <tr>
            <td class="mono"><strong>github-pat-waf-bot</strong></td>
            <td>Secret Manager (<span class="mono">available_secrets</span> in Cloud Build)</td>
            <td class="mono">Scoped strictly to IaC Git repository Pull Request creation</td>
            <td>Never mounted into the LLM/ADK Cloud Run container; immune to prompt-injection exfiltration.</td>
          </tr>
        </tbody>
      </table>
    </main>

    <aside>
      <div class="margin-note">
        <strong>§ Progressive Skill Disclosure</strong><br/>
        Instead of stuffing 60,000+ tokens of WAF documentation into system prompts, each pillar agent uses ADK’s <span class="mono">SkillToolset</span>:<br/>
        · <strong>L1</strong>: YAML frontmatter (~100 tokens)<br/>
        · <strong>L2</strong>: <span class="mono">SKILL.md</span> core rubric (~2k tokens)<br/>
        · <strong>L3</strong>: On-demand <span class="mono">references/*.md</span>
      </div>
      <div class="margin-note">
        <strong>§ Anti-Hallucination Invariant</strong><br/>
        Every <span class="mono">search_org_assets</span>, <span class="mono">fetch_scc_findings</span>, and <span class="mono">fetch_active_recommendations</span> call appends discovered URIs to <span class="mono">state['observed_resource_uris']</span>. <span class="mono">validate_terraform_and_uri</span> rejects any finding whose <span class="mono">resource_uri</span> was not observed in live tool output.
      </div>
      <div class="margin-note">
        <strong>§ Navigation</strong><br/>
        · <a href="/dashboard" class="mono" style="color:var(--ink);">GET /dashboard</a> (Live Posture)<br/>
        · <a href="/architecture" class="mono" style="color:var(--ink);">GET /architecture</a> (This Blueprint)<br/>
        · <a href="/api/dashboard/data" class="mono" style="color:var(--ink);">GET /api/dashboard/data</a> (JSON API)
      </div>
    </aside>
  </div>
</body>
</html>"""
    return (
        template.replace("__TARGET_SCOPE__", html.escape(cfg.target_scope))
        .replace("__PROJECT_ID__", html.escape(cfg.project_id))
        .replace("__QUOTA_PROJECT_ID__", html.escape(cfg.quota_project_id))
        .replace("__BQ_TABLE__", html.escape(cfg.bq_table))
        .replace("__GCS_BUCKET__", html.escape(cfg.gcs_bucket))
    )

