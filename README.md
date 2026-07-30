# GCP Detection Range

An offline, $0 GCP threat-hunting and detection-engineering range. It generates realistic cloud attacks, normalizes telemetry into one schema, and validates behavioral detections against captured attack traces — entirely with local fixtures and a free-tier BigQuery sandbox, no live infrastructure required.

![Terraform](https://img.shields.io/badge/Terraform-1.15-844FBA?logo=terraform&logoColor=white)
![Google Cloud](https://img.shields.io/badge/Google%20Cloud-BigQuery%20%7C%20GKE%20%7C%20IAM-4285F4?logo=googlecloud&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10-3776AB?logo=python&logoColor=white)
![pytest](https://img.shields.io/badge/pytest-9.1-0A9EDC?logo=pytest&logoColor=white)
![NetworkX](https://img.shields.io/badge/NetworkX-3.4-2E8B57)
![Ollama](https://img.shields.io/badge/Ollama-local%20LLM-000000?logo=ollama&logoColor=white)

## Overview

Every telemetry source is flattened into one normalized schema — `timestamp, actor, actor_type, source_ip, action, resource, resource_type, outcome, raw` — and every detection reads only from that schema, never from raw logs. Six chained attack scenarios exercise the full pipeline: attack simulation → normalization → BigQuery detection → cross-event correlation → dry-run remediation → AI-assisted detection generation gated by a four-part verifier → evaluation metrics.

## Attack Scenarios

| # | Scenario | Detection Signal |
|---|---|---|
| 1 | Service account key used from an unexpected IP | SA identity authenticating outside the range's VPC CIDR |
| 2 | IAM privilege escalation (`SetIamPolicy` / `actAs` abuse) | SA performing IAM operations no workload identity should |
| 3 | GKE service-account token abuse from inside a pod | Stolen token used for Kubernetes RBAC escalation |
| 4 | Privileged / hostPath container creation | Pod spec requesting `privileged: true` or a `hostPath` volume |
| 5 | Unapproved container image deployed | Image outside the approved Artifact Registry path |
| 6 | Storage enumeration + bulk read (exfiltration) | Object-read volume by one actor crossing a threshold in a time window |

## Pipeline

```
terraform/persistent/  →  BigQuery dataset, 3 log sinks, Data Access audit config (validate-only)
terraform/range/       →  VPC, GKE, over-privileged SA, Artifact Registry, seeded bucket (validate-only)
attacks/                →  fabricate raw log rows per scenario, no live API calls
pipeline/               →  normalize raw rows into the 9-column schema
detections/             →  BigQuery Standard SQL, tested against attack + benign fixtures
correlation/            →  NetworkX entity graph, reconstructs the full chained attack path
remediation/            →  three dry-run response actions, no real API calls
ai/                     →  local-LLM candidate detections, gated by a 4-check verifier
eval/                   →  precision/recall, attack-path recall, latency, degradation test
```

## Getting Started

```bash
# Terraform (validate only — no billing required)
cd terraform/persistent && terraform init && terraform validate
cd terraform/range && terraform init && terraform validate

# Normalization tests
python3 -m pytest pipeline/ -v

# Run one attack scenario end-to-end
python3 attacks/01_sa_key_from_unexpected_ip.py
python3 detections/build_normalized_ndjson.py attack_01
bq load --project_id=<PROJECT_ID> --replace --source_format=NEWLINE_DELIMITED_JSON \
  --schema=timestamp:TIMESTAMP,actor:STRING,actor_type:STRING,source_ip:STRING,action:STRING,resource:STRING,resource_type:STRING,outcome:STRING,raw:STRING \
  detection_range_test.normalized_events fixtures/normalized_test.ndjson
bq query --project_id=<PROJECT_ID> --use_legacy_sql=false "$(cat detections/01_sa_key_from_unexpected_ip.sql)"

# Full-day false-positive check
python3 pipeline/generate_benign_day.py
python3 detections/run_benign_day_fp_report.py

# Reconstruct the chained attack path
python3 correlation/build_graph.py

# AI-assisted detection generation + verification (requires Ollama running locally)
python3 -u ai/main.py

# Evaluation metrics
python3 eval/compute_metrics.py
```