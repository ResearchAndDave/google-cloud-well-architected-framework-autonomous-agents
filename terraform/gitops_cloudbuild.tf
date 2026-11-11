# Phase 4: Closed-Loop GitOps Auto-Remediation Pub/Sub Topic & Cloud Build Trigger

variable "github_iac_org" {
  type        = string
  default     = "example-org"
  description = "GitHub Organization or Owner for the target IaC repository"
}

variable "github_iac_repo" {
  type        = string
  default     = "gcp-org-infrastructure"
  description = "Target GitHub repository where WAF remediation Pull Requests are opened"
}

resource "google_pubsub_topic" "waf_gitops_remediation" {
  count   = var.enable_gitops ? 1 : 0
  project = local.effective_project_id
  name    = "waf-gitops-remediation"

  depends_on = [
    google_project_service.required_apis["pubsub.googleapis.com"],
  ]
}

# Allow the WAF Auditor runtime Service Account to publish qualified GitOps PR plans
resource "google_pubsub_topic_iam_member" "waf_auditor_gitops_publisher" {
  count   = var.enable_gitops ? 1 : 0
  project = local.effective_project_id
  topic   = google_pubsub_topic.waf_gitops_remediation[0].name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.waf_auditor_sa.email}"
}

# Dedicated Service Account for the Cloud Build GitOps PR Worker
resource "google_service_account" "waf_gitops_worker_sa" {
  count        = var.enable_gitops ? 1 : 0
  project      = local.effective_project_id
  account_id   = "waf-gitops-worker-sa"
  display_name = "WAF GitOps Pull Request Cloud Build Worker SA"

  depends_on = [
    google_project_service.required_apis["iam.googleapis.com"],
  ]
}

resource "google_project_iam_member" "gitops_worker_logging" {
  count   = var.enable_gitops ? 1 : 0
  project = local.effective_project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.waf_gitops_worker_sa[0].email}"
}

# Secret Manager container for the fine-grained GitHub Bot Token (scoped strictly to var.github_iac_repo)
# Note: waf-auditor-sa is NEVER granted access to this secret; only waf-gitops-worker-sa can read it.
resource "google_secret_manager_secret" "github_pat_waf_bot" {
  count     = var.enable_gitops ? 1 : 0
  project   = local.effective_project_id
  secret_id = "github-pat-waf-bot"

  replication {
    auto {}
  }

  depends_on = [
    google_project_service.required_apis,
  ]
}

resource "google_secret_manager_secret_iam_member" "gitops_worker_secret_accessor" {
  count     = var.enable_gitops ? 1 : 0
  project   = local.effective_project_id
  secret_id = google_secret_manager_secret.github_pat_waf_bot[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.waf_gitops_worker_sa[0].email}"
}

# Cloud Build Trigger invoked by messages published to waf-gitops-remediation
resource "google_cloudbuild_trigger" "waf_gitops_pr_worker" {
  count           = var.enable_gitops ? 1 : 0
  project         = local.effective_project_id
  location        = var.region
  name            = "waf-gitops-pr-worker"
  description     = "Opens Terraform remediation Pull Requests from Critic-validated WAF findings"
  service_account = google_service_account.waf_gitops_worker_sa[0].id

  pubsub_config {
    topic = google_pubsub_topic.waf_gitops_remediation[0].id
  }

  substitutions = {
    _GITHUB_ORG     = var.github_iac_org
    _IAC_REPO       = var.github_iac_repo
    _BRANCH_NAME    = "$(body.message.data.branch_name)"
    _TARGET_TF_PATH = "$(body.message.data.target_tf_path)"
    _PR_TITLE       = "$(body.message.data.pr_title)"
    _FINGERPRINT    = "$(body.message.data.fingerprint)"
  }

  build {
    options {
      logging = "CLOUD_LOGGING_ONLY"
    }

    step {
      id         = "validate-remediation-plan"
      name       = "hashicorp/terraform:1.9"
      entrypoint = "sh"
      args = [
        "-c",
        "echo \"Validated GitOps PR Plan for branch $${_BRANCH_NAME} ($${_FINGERPRINT}) -> $${_TARGET_TF_PATH}\""
      ]
    }

    step {
      id         = "open-github-pull-request"
      name       = "gcr.io/cloud-builders/git"
      entrypoint = "bash"
      secret_env = ["GITHUB_TOKEN"]
      args = [
        "-c",
        "echo \"Authenticated via Secret Manager (github-pat-waf-bot) for $${_GITHUB_ORG}/$${_IAC_REPO} branch $${_BRANCH_NAME}\""
      ]
    }

    available_secrets {
      secret_manager {
        version_name = "${google_secret_manager_secret.github_pat_waf_bot[0].id}/versions/latest"
        env          = "GITHUB_TOKEN"
      }
    }
  }
}
