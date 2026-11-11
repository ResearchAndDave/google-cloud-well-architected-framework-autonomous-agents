resource "google_cloud_run_v2_service" "waf_auditor" {
  project  = local.effective_project_id
  name     = "waf-auditor-agent"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  depends_on = [
    google_project_service.required_apis["run.googleapis.com"],
  ]

  template {
    service_account = google_service_account.waf_auditor_sa.email
    timeout         = "600s"

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${local.effective_project_id}/waf-auditor/agent:latest"

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
        cpu_idle = false
      }

      env {
        name  = "GOOGLE_GENAI_USE_VERTEXAI"
        value = "TRUE"
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = local.effective_project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "WAF_TARGET_SCOPE"
        value = local.canonical_scope
      }
      env {
        name  = "WAF_ORG_ID"
        value = local.canonical_scope
      }
      env {
        name  = "WAF_BQ_TABLE"
        value = "${local.effective_project_id}.${google_bigquery_dataset.org_compliance.dataset_id}.${google_bigquery_table.waf_findings.table_id}"
      }
      env {
        name  = "WAF_GCS_BUCKET"
        value = google_storage_bucket.waf_artifacts.name
      }
      env {
        name  = "WAF_CARBON_EXPORT_TABLE"
        value = var.carbon_export_table
      }
      env {
        name  = "WAF_ENABLE_BQ_WRITE"
        value = "TRUE"
      }
      env {
        name  = "WAF_ENABLE_GCS_WRITE"
        value = "TRUE"
      }
    }
  }
}

resource "google_service_account" "waf_invoker_sa" {
  project      = local.effective_project_id
  account_id   = "waf-pubsub-invoker-sa"
  display_name = "WAF Auditor Cloud Run Push Invoker"

  depends_on = [
    google_project_service.required_apis["iam.googleapis.com"],
  ]
}

resource "google_cloud_run_v2_service_iam_member" "allow_pubsub_invoker" {
  project  = local.effective_project_id
  location = var.region
  name     = google_cloud_run_v2_service.waf_auditor.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.waf_invoker_sa.email}"
}

resource "google_pubsub_subscription" "waf_push_sub" {
  project              = local.effective_project_id
  name                 = "waf-auditor-push-sub"
  topic                = google_pubsub_topic.waf_audit_triggers.name
  ack_deadline_seconds = 600

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.waf_auditor.uri}/pubsub/push"
    oidc_token {
      service_account_email = google_service_account.waf_invoker_sa.email
    }
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

resource "google_cloud_scheduler_job" "nightly_waf_sweep" {
  project   = local.effective_project_id
  name      = "waf-nightly-baseline-sweep"
  region    = var.region
  schedule  = "0 2 * * *"
  time_zone = "Etc/UTC"

  depends_on = [
    google_project_service.required_apis["cloudscheduler.googleapis.com"],
  ]

  pubsub_target {
    topic_name = google_pubsub_topic.waf_audit_triggers.id
    data = base64encode(jsonencode({
      scan_mode = "NIGHTLY_SWEEP"
      org_id    = local.canonical_scope
    }))
  }
}
