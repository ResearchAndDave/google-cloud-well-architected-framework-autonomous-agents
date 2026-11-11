resource "google_bigquery_dataset" "org_compliance" {
  project                    = local.effective_project_id
  dataset_id                 = "org_compliance"
  friendly_name              = "Organization WAF Compliance Telemetry"
  location                   = var.region
  delete_contents_on_destroy = false

  depends_on = [
    google_project_service.required_apis["bigquery.googleapis.com"],
  ]
}

resource "google_bigquery_table" "waf_findings" {
  project             = local.effective_project_id
  dataset_id          = google_bigquery_dataset.org_compliance.dataset_id
  table_id            = "waf_findings"
  deletion_protection = true

  time_partitioning {
    type  = "DAY"
    field = "evaluation_timestamp"
  }

  clustering = ["waf_pillar", "project_id", "severity"]

  schema = jsonencode([
    { name = "evaluation_timestamp", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "org_id", type = "STRING", mode = "REQUIRED" },
    { name = "scan_mode", type = "STRING", mode = "REQUIRED" },
    { name = "resource_uri", type = "STRING", mode = "REQUIRED" },
    { name = "project_id", type = "STRING", mode = "REQUIRED" },
    { name = "folder_id", type = "STRING", mode = "NULLABLE" },
    { name = "waf_pillar", type = "STRING", mode = "REQUIRED" },
    { name = "waf_principle", type = "STRING", mode = "REQUIRED" },
    { name = "severity", type = "STRING", mode = "REQUIRED" },
    { name = "compliance_status", type = "STRING", mode = "REQUIRED" },
    { name = "rationale", type = "STRING", mode = "REQUIRED" },
    { name = "terraform_remediation", type = "STRING", mode = "REQUIRED" },
    { name = "estimated_monthly_savings_usd", type = "FLOAT64", mode = "NULLABLE" }
  ])
}

resource "google_bigquery_table" "v_current_waf_posture" {
  project             = local.effective_project_id
  dataset_id          = google_bigquery_dataset.org_compliance.dataset_id
  table_id            = "v_current_waf_posture"
  deletion_protection = false

  view {
    use_legacy_sql = false
    query          = <<-SQL
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
        COALESCE(estimated_monthly_savings_usd, 0.0) AS estimated_monthly_savings_usd
      FROM `${local.effective_project_id}.${google_bigquery_dataset.org_compliance.dataset_id}.${google_bigquery_table.waf_findings.table_id}`
      WHERE evaluation_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
      QUALIFY ROW_NUMBER() OVER (
        PARTITION BY resource_uri, waf_pillar
        ORDER BY evaluation_timestamp DESC
      ) = 1
    SQL
  }
}

resource "google_bigquery_table" "v_pillar_posture_scores" {
  project             = local.effective_project_id
  dataset_id          = google_bigquery_dataset.org_compliance.dataset_id
  table_id            = "v_pillar_posture_scores"
  deletion_protection = false

  view {
    use_legacy_sql = false
    query          = <<-SQL
      WITH all_pillars AS (
        SELECT waf_pillar
        FROM UNNEST(['SECURITY', 'RELIABILITY', 'COST', 'PERFORMANCE', 'OPS', 'SUSTAINABILITY']) AS waf_pillar
      ),
      active_penalties AS (
        SELECT
          waf_pillar,
          COUNT(*) AS active_finding_count,
          COUNTIF(severity = 'CRITICAL') AS critical_count,
          COUNTIF(severity = 'HIGH') AS high_count,
          COUNTIF(severity = 'MEDIUM') AS medium_count,
          COUNTIF(severity = 'LOW') AS low_count,
          SUM(
            CASE severity
              WHEN 'CRITICAL' THEN 15
              WHEN 'HIGH' THEN 7
              WHEN 'MEDIUM' THEN 3
              WHEN 'LOW' THEN 1
              ELSE 0
            END
          ) AS penalty_points,
          ROUND(SUM(COALESCE(estimated_monthly_savings_usd, 0.0)), 2) AS potential_monthly_savings_usd
        FROM `${local.effective_project_id}.${google_bigquery_dataset.org_compliance.dataset_id}.${google_bigquery_table.v_current_waf_posture.table_id}`
        WHERE compliance_status = 'NON_COMPLIANT'
        GROUP BY waf_pillar
      )
      SELECT
        p.waf_pillar,
        GREATEST(0, 100 - COALESCE(a.penalty_points, 0)) AS pillar_score_0_to_100,
        COALESCE(a.active_finding_count, 0) AS active_finding_count,
        COALESCE(a.critical_count, 0) AS critical_count,
        COALESCE(a.high_count, 0) AS high_count,
        COALESCE(a.medium_count, 0) AS medium_count,
        COALESCE(a.low_count, 0) AS low_count,
        COALESCE(a.potential_monthly_savings_usd, 0.0) AS potential_monthly_savings_usd
      FROM all_pillars p
      LEFT JOIN active_penalties a USING (waf_pillar)
    SQL
  }
}

resource "google_bigquery_table" "v_pillar_drift_velocity" {
  project             = local.effective_project_id
  dataset_id          = google_bigquery_dataset.org_compliance.dataset_id
  table_id            = "v_pillar_drift_velocity"
  deletion_protection = false

  view {
    use_legacy_sql = false
    query          = <<-SQL
      WITH daily_snapshots AS (
        SELECT
          DATE(evaluation_timestamp) AS audit_date,
          waf_pillar,
          severity,
          resource_uri,
          waf_principle,
          compliance_status
        FROM `${local.effective_project_id}.${google_bigquery_dataset.org_compliance.dataset_id}.${google_bigquery_table.waf_findings.table_id}`
        WHERE evaluation_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 14 DAY)
        QUALIFY ROW_NUMBER() OVER (
          PARTITION BY DATE(evaluation_timestamp), resource_uri, waf_pillar, waf_principle
          ORDER BY evaluation_timestamp DESC
        ) = 1
      ),
      daily_counts AS (
        SELECT
          audit_date,
          waf_pillar,
          COUNTIF(compliance_status = 'NON_COMPLIANT') AS non_compliant_count,
          COUNTIF(compliance_status = 'NON_COMPLIANT' AND severity IN ('CRITICAL', 'HIGH')) AS high_risk_count
        FROM daily_snapshots
        GROUP BY 1, 2
      )
      SELECT
        audit_date,
        waf_pillar,
        non_compliant_count,
        high_risk_count,
        non_compliant_count - COALESCE(
          LAG(non_compliant_count, 1) OVER (PARTITION BY waf_pillar ORDER BY audit_date),
          non_compliant_count
        ) AS daily_net_drift,
        non_compliant_count - COALESCE(
          LAG(non_compliant_count, 7) OVER (PARTITION BY waf_pillar ORDER BY audit_date),
          non_compliant_count
        ) AS seven_day_drift_velocity
      FROM daily_counts
      ORDER BY audit_date DESC, waf_pillar
    SQL
  }
}

resource "google_bigquery_table" "v_folder_project_heatmap" {
  project             = local.effective_project_id
  dataset_id          = google_bigquery_dataset.org_compliance.dataset_id
  table_id            = "v_folder_project_heatmap"
  deletion_protection = false

  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT
        COALESCE(folder_id, 'folders/UNASSIGNED_ROOT') AS folder_id,
        project_id,
        waf_pillar,
        COUNT(*) AS total_findings,
        COUNTIF(severity = 'CRITICAL') AS critical_findings,
        COUNTIF(severity = 'HIGH') AS high_findings,
        ROUND(SUM(COALESCE(estimated_monthly_savings_usd, 0.0)), 2) AS monthly_savings_opportunity_usd,
        MAX(evaluation_timestamp) AS last_evaluated_at
      FROM `${local.effective_project_id}.${google_bigquery_dataset.org_compliance.dataset_id}.${google_bigquery_table.v_current_waf_posture.table_id}`
      GROUP BY 1, 2, 3
    SQL
  }
}
