output "compliance_project_id" {
  description = "Effective GCP Project ID hosting the WAF Auditor infrastructure."
  value       = local.effective_project_id
}

output "region" {
  description = "Deployed GCP region."
  value       = var.region
}

output "canonical_scope" {
  description = "Canonical Cloud Asset Inventory audit scope (organizations/*, folders/*, or projects/*)."
  value       = local.canonical_scope
}

output "artifact_registry_image" {
  description = "Target container image URI in Artifact Registry."
  value       = "${var.region}-docker.pkg.dev/${local.effective_project_id}/${google_artifact_registry_repository.waf_auditor.repository_id}/agent:latest"
}

output "cloud_run_service_uri" {
  description = "Deployed Cloud Run v2 service URL."
  value       = google_cloud_run_v2_service.waf_auditor.uri
}

output "bigquery_dataset" {
  description = "BigQuery compliance dataset identifier."
  value       = "${local.effective_project_id}.${google_bigquery_dataset.org_compliance.dataset_id}"
}

output "gcs_artifact_bucket" {
  description = "GCS bucket storing executive Markdown reports and GitOps dispatch ledger."
  value       = google_storage_bucket.waf_artifacts.name
}
