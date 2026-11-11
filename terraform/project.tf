variable "create_compliance_project" {
  type        = bool
  default     = true
  description = "When true (default), creates a dedicated GCP project for the WAF Auditor inside var.parent_folder_id (or var.org_id). Set to false to deploy into an existing project."
}

variable "compliance_project_id" {
  type        = string
  default     = ""
  description = "Custom GCP Project ID to create (when create_compliance_project = true) or existing Project ID to use (when create_compliance_project = false). If empty and create_compliance_project = true, generates waf-compliance-<hex>."
}

variable "compliance_project_name" {
  type        = string
  default     = "WAF Compliance Hub"
  description = "Display name for the created WAF Compliance Host Project."
}

variable "parent_folder_id" {
  type        = string
  default     = ""
  description = "GCP Folder ID (e.g., '528686131221' or 'folders/528686131221') where the dedicated WAF Compliance Project will be created."
}

variable "billing_account_id" {
  type        = string
  default     = ""
  description = "Billing Account ID (e.g., '012345-6789AB-CDEF01') attached to the created WAF Compliance Project when create_compliance_project = true."
}

variable "org_id" {
  type        = string
  default     = ""
  description = "Optional numeric Google Cloud Organization ID. Used as fallback project parent if parent_folder_id is empty, and as fallback scope_id when scope_type = 'ORGANIZATION'."
}

variable "scope_type" {
  type        = string
  default     = "ORGANIZATION"
  description = "Target hierarchy level to audit: 'ORGANIZATION', 'FOLDER', or 'PROJECT'."

  validation {
    condition     = contains(["ORGANIZATION", "FOLDER", "PROJECT"], upper(var.scope_type))
    error_message = "scope_type must be one of: ORGANIZATION, FOLDER, PROJECT."
  }
}

variable "scope_id" {
  type        = string
  default     = ""
  description = "Target audit scope identifier (numeric Org ID, numeric Folder ID, or Project ID). Falls back to var.org_id, var.parent_folder_id, or the compliance project ID."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "Primary GCP region for Cloud Run, BigQuery, Artifact Registry, and Cloud Scheduler."
}

variable "enable_realtime_feeds" {
  type        = bool
  default     = true
  description = "Enables Cloud Asset Inventory RealTimeFeeds (RESOURCE and IAM_POLICY) at the target audit scope."
}

variable "enable_gitops" {
  type        = bool
  default     = false
  description = "Enables Phase 4 GitOps Pull Request Cloud Build worker, Pub/Sub topic, and Secret Manager secret."
}

variable "carbon_export_table" {
  type        = string
  default     = ""
  description = "Optional BigQuery table ID (project.dataset.carbon_footprint) for the Sustainability pillar."
}

resource "random_id" "project_suffix" {
  count       = var.create_compliance_project && var.compliance_project_id == "" ? 1 : 0
  byte_length = 3
}

locals {
  normalized_scope_type  = upper(var.scope_type)
  clean_parent_folder_id = replace(var.parent_folder_id, "folders/", "")
  clean_org_id           = replace(var.org_id, "organizations/", "")

  generated_project_id = (
    var.compliance_project_id != ""
    ? var.compliance_project_id
    : "waf-compliance-${coalesce(one(random_id.project_suffix[*].hex), "000000")}"
  )
}

resource "google_project" "waf_compliance" {
  count           = var.create_compliance_project ? 1 : 0
  name            = var.compliance_project_name
  project_id      = local.generated_project_id
  folder_id       = local.clean_parent_folder_id != "" ? local.clean_parent_folder_id : null
  org_id          = local.clean_parent_folder_id == "" && local.clean_org_id != "" ? local.clean_org_id : null
  billing_account = var.billing_account_id != "" ? var.billing_account_id : null
  deletion_policy = "PREVENT"
}

locals {
  effective_project_id = (
    var.create_compliance_project
    ? google_project.waf_compliance[0].project_id
    : var.compliance_project_id
  )

  raw_scope_id = (
    var.scope_id != "" ? var.scope_id : (
      local.normalized_scope_type == "ORGANIZATION" ? local.clean_org_id : (
        local.normalized_scope_type == "FOLDER" ? local.clean_parent_folder_id : local.effective_project_id
      )
    )
  )

  clean_scope_id = replace(
    replace(replace(local.raw_scope_id, "organizations/", ""), "folders/", ""),
    "projects/",
    ""
  )

  scope_prefix_map = {
    ORGANIZATION = "organizations"
    FOLDER       = "folders"
    PROJECT      = "projects"
  }

  canonical_scope = "${local.scope_prefix_map[local.normalized_scope_type]}/${local.clean_scope_id}"
}
