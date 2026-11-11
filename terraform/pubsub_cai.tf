locals {
  high_risk_asset_types = [
    "compute.googleapis.com/Firewall",
    "container.googleapis.com/Cluster",
    "sqladmin.googleapis.com/Instance",
  ]

  iam_policy_asset_types = [
    "cloudresourcemanager.googleapis.com/Project",
    "cloudresourcemanager.googleapis.com/Folder",
    "cloudresourcemanager.googleapis.com/Organization",
  ]
}

resource "google_pubsub_topic" "waf_audit_triggers" {
  project = local.effective_project_id
  name    = "waf-audit-triggers"

  depends_on = [
    google_project_service.required_apis["pubsub.googleapis.com"],
  ]
}

resource "google_project_service_identity" "cai_identity" {
  provider = google-beta
  project  = local.effective_project_id
  service  = "cloudasset.googleapis.com"

  depends_on = [
    google_project_service.required_apis["cloudasset.googleapis.com"],
  ]
}

resource "google_pubsub_topic_iam_member" "cai_publisher" {
  project = local.effective_project_id
  topic   = google_pubsub_topic.waf_audit_triggers.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_project_service_identity.cai_identity.email}"
}

# --- ORGANIZATION SCOPE FEEDS ---
resource "google_cloud_asset_organization_feed" "high_risk_resources" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "ORGANIZATION" ? 1 : 0
  billing_project = local.effective_project_id
  org_id          = local.clean_scope_id
  feed_id         = "waf-high-risk-resource-drift"
  content_type    = "RESOURCE"
  asset_types     = local.high_risk_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Exclude deleted resources"
    expression = "!temporal_asset.deleted"
  }
}

resource "google_cloud_asset_organization_feed" "iam_policy_drift" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "ORGANIZATION" ? 1 : 0
  billing_project = local.effective_project_id
  org_id          = local.clean_scope_id
  feed_id         = "waf-iam-policy-drift"
  content_type    = "IAM_POLICY"
  asset_types     = local.iam_policy_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Active IAM policy changes only"
    expression = "!temporal_asset.deleted"
  }
}

# --- FOLDER SCOPE FEEDS ---
resource "google_cloud_asset_folder_feed" "high_risk_resources_folder" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "FOLDER" ? 1 : 0
  billing_project = local.effective_project_id
  folder          = local.clean_scope_id
  feed_id         = "waf-high-risk-resource-drift"
  content_type    = "RESOURCE"
  asset_types     = local.high_risk_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Exclude deleted resources"
    expression = "!temporal_asset.deleted"
  }
}

resource "google_cloud_asset_folder_feed" "iam_policy_drift_folder" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "FOLDER" ? 1 : 0
  billing_project = local.effective_project_id
  folder          = local.clean_scope_id
  feed_id         = "waf-iam-policy-drift"
  content_type    = "IAM_POLICY"
  asset_types     = local.iam_policy_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Active IAM policy changes only"
    expression = "!temporal_asset.deleted"
  }
}

# --- PROJECT SCOPE FEEDS ---
resource "google_cloud_asset_project_feed" "high_risk_resources_project" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "PROJECT" ? 1 : 0
  billing_project = local.effective_project_id
  project         = local.clean_scope_id
  feed_id         = "waf-high-risk-resource-drift"
  content_type    = "RESOURCE"
  asset_types     = local.high_risk_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Exclude deleted resources"
    expression = "!temporal_asset.deleted"
  }
}

resource "google_cloud_asset_project_feed" "iam_policy_drift_project" {
  count           = var.enable_realtime_feeds && local.normalized_scope_type == "PROJECT" ? 1 : 0
  billing_project = local.effective_project_id
  project         = local.clean_scope_id
  feed_id         = "waf-iam-policy-drift"
  content_type    = "IAM_POLICY"
  asset_types     = local.iam_policy_asset_types

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.waf_audit_triggers.id
    }
  }

  condition {
    title      = "Active IAM policy changes only"
    expression = "!temporal_asset.deleted"
  }
}
