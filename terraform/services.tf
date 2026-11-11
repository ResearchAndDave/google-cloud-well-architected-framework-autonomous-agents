locals {
  core_apis = [
    "serviceusage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "run.googleapis.com",
    "cloudasset.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "aiplatform.googleapis.com",
    "pubsub.googleapis.com",
    "cloudscheduler.googleapis.com",
    "artifactregistry.googleapis.com",
    "recommender.googleapis.com",
    "cloudbuild.googleapis.com",
  ]

  gitops_apis = var.enable_gitops ? ["secretmanager.googleapis.com"] : []

  required_apis = toset(concat(local.core_apis, local.gitops_apis))
}

resource "google_project_service" "required_apis" {
  for_each           = local.required_apis
  project            = local.effective_project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "waf_auditor" {
  project       = local.effective_project_id
  location      = var.region
  repository_id = "waf-auditor"
  description   = "Container images for the Autonomous Google Cloud WAF Auditor"
  format        = "DOCKER"

  depends_on = [
    google_project_service.required_apis["artifactregistry.googleapis.com"],
  ]
}
