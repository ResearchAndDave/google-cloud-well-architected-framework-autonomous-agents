locals {
  org_readonly_roles = toset([
    "roles/cloudasset.viewer",
    "roles/securitycenter.findingsViewer",
    "roles/recommender.viewer",
    "roles/monitoring.viewer",
    "roles/cloudconfig.viewer",
    "roles/browser",
  ])
}

resource "google_service_account" "waf_auditor_sa" {
  project      = local.effective_project_id
  account_id   = "waf-auditor-sa"
  display_name = "Autonomous WAF Auditor Runtime SA"

  depends_on = [
    google_project_service.required_apis["iam.googleapis.com"],
  ]
}

resource "google_organization_iam_member" "org_readonly" {
  for_each = local.normalized_scope_type == "ORGANIZATION" ? local.org_readonly_roles : toset([])
  org_id   = local.clean_scope_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_folder_iam_member" "folder_readonly" {
  for_each = local.normalized_scope_type == "FOLDER" ? local.org_readonly_roles : toset([])
  folder   = "folders/${local.clean_scope_id}"
  role     = each.value
  member   = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_project_iam_member" "project_readonly" {
  for_each = local.normalized_scope_type == "PROJECT" ? local.org_readonly_roles : toset([])
  project  = local.clean_scope_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_project_iam_member" "vertex_ai_user" {
  project = local.effective_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_bigquery_dataset_iam_member" "bq_dataset_writer" {
  project    = local.effective_project_id
  dataset_id = google_bigquery_dataset.org_compliance.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_project_iam_member" "bq_job_user" {
  project = local.effective_project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

resource "google_storage_bucket" "waf_artifacts" {
  project                     = local.effective_project_id
  name                        = "${local.effective_project_id}-waf-artifacts"
  location                    = var.region
  uniform_bucket_level_access = true
  versioning {
    enabled = true
  }

  depends_on = [
    google_project_service.required_apis["storage.googleapis.com"],
  ]
}

resource "google_storage_bucket_iam_member" "gcs_artifact_admin" {
  bucket = google_storage_bucket.waf_artifacts.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}
