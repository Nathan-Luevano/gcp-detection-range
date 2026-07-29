import json
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "attack_01")

SERVICE_ACCOUNT = "range-gke-node@detection-range-b9298c.iam.gserviceaccount.com"
EXPECTED_IP = "10.10.0.5"
ATTACKER_IP = "185.220.101.7"


def make_row(timestamp, caller_ip, method, resource_name, resource_type):
    return {
        "logName": "projects/detection-range-b9298c/logs/cloudaudit.googleapis.com%2Fdata_access",
        "timestamp": timestamp,
        "resource": {"type": resource_type, "labels": {}},
        "protopayload_auditlog": {
            "serviceName": "storage.googleapis.com",
            "methodName": method,
            "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": SERVICE_ACCOUNT},
            "requestMetadata": {"callerIp": caller_ip},
            "status": {},
        },
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = [
        make_row(
            "2026-07-29T09:00:00.000Z",
            EXPECTED_IP,
            "storage.objects.list",
            "projects/_/buckets/detection-range-b9298c-sensitive-data",
            "gcs_bucket",
        ),
        make_row(
            "2026-07-29T09:15:32.000Z",
            ATTACKER_IP,
            "storage.objects.get",
            "projects/_/buckets/detection-range-b9298c-sensitive-data/objects/customer_records.csv",
            "gcs_bucket",
        ),
    ]

    for i, row in enumerate(rows, start=1):
        path = os.path.join(OUTPUT_DIR, f"{i:02d}.json")
        with open(path, "w") as f:
            json.dump(row, f, indent=2)
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
