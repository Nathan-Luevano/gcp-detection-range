terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_compute_network" "vpc" {
  name                    = "range-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "range-subnet"
  network       = google_compute_network.vpc.id
  region        = var.region
  ip_cidr_range = "10.10.0.0/20"

  log_config {
    flow_sampling        = 0.1
    aggregation_interval = "INTERVAL_5_SEC"
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_dns_policy" "query_logging" {
  name           = "range-dns-policy"
  enable_logging = true

  networks {
    network_url = google_compute_network.vpc.id
  }
}

resource "google_service_account" "gke_node_sa" {
  account_id   = "range-gke-node"
  display_name = "Range GKE node SA, deliberately over-privileged"
}

# scenario 2 target: this SA has project-wide editor, far more than a node needs
resource "google_project_iam_member" "gke_node_sa_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.gke_node_sa.email}"
}

resource "google_container_cluster" "range" {
  name       = "range-gke"
  location   = var.zone
  network    = google_compute_network.vpc.id
  subnetwork = google_compute_subnetwork.subnet.id

  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = false
}

resource "google_container_node_pool" "range_nodes" {
  name     = "range-node-pool"
  cluster  = google_container_cluster.range.name
  location = var.zone

  node_count = 2

  node_config {
    machine_type    = "e2-small"
    spot            = true
    service_account = google_service_account.gke_node_sa.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}

resource "google_artifact_registry_repository" "range" {
  location      = var.region
  repository_id = "range-repo"
  format        = "DOCKER"
}

resource "google_storage_bucket" "sensitive" {
  name                        = "${var.project_id}-sensitive-data"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_object" "fake_secrets" {
  name    = "customer_records.csv"
  bucket  = google_storage_bucket.sensitive.name
  content = "id,name,ssn\n1,Jane Doe,000-00-0000\n2,John Smith,111-11-1111\n"
}
