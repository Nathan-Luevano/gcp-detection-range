terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "logging.googleapis.com",
    "bigquery.googleapis.com",
    "artifactregistry.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "dns.googleapis.com",
    "pubsub.googleapis.com",
  ])
  service            = each.key
  disable_on_destroy = false
}

# Telemetry warehouse
resource "google_bigquery_dataset" "telemetry" {
  dataset_id                 = "telemetry"
  location                   = "US"
  delete_contents_on_destroy = false
  depends_on                 = [google_project_service.apis]
}

# 3 sinks for audit, flows, and dns logs to bigquery
# just makes the normalizaaiton layer far cleaner than on giant OR filter
locals {
  sinks = {
    audit = "logName:\"cloudaudit.googleapis.com\""
    flows = "logName:\"compute.googleapis.com%2Fvpc_flows\""
    dns   = "logName:\"dns.googleapis.com%2Fdns_queries\""
  }
}

resource "google_logging_project_sink" "to_bq" {
  for_each               = local.sinks
  name                   = "${each.key}-to-bq"
  destination            = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.telemetry.dataset_id}"
  filter                 = each.value
  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true # not optional otherwise quieres scan entire table everytime and big bill lol
  }
}

resource "google_bigquery_dataset_iam_member" "sink_writers" {
  for_each   = google_logging_project_sink.to_bq
  dataset_id = google_bigquery_dataset.telemetry.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = each.value.writer_identity
}

# Data access audit logs are disabled by default
resource "google_project_iam_audit_config" "data_access" {
  for_each = toset([
    # need to be scoped to these in order to prevent noise and ingestion cost
    "storage.googleapis.com",
    "container.googleapis.com",
    "iam.googleapis.com",
    "artifactregistry.googleapis.com",
  ])
  project = var.project_id
  service = each.key

  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}