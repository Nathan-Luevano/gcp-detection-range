import json
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "attack_02")

COMPROMISED_SA = "range-gke-node@detection-range-b9298c.iam.gserviceaccount.com"
TARGET_SA = "priv-detonator@detection-range-b9298c.iam.gserviceaccount.com"
ATTACKER_IP = "185.220.101.7"


def make_row(timestamp, service_name, method, resource_name, resource_type):
    return {
        "logName": "projects/detection-range-b9298c/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": timestamp,
        "resource": {"type": resource_type, "labels": {}},
        "protopayload_auditlog": {
            "serviceName": service_name,
            "methodName": method,
            "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": COMPROMISED_SA},
            "requestMetadata": {"callerIp": ATTACKER_IP},
            "status": {},
        },
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = [
        make_row(
            "2026-07-29T09:20:05.000Z",
            "cloudresourcemanager.googleapis.com",
            "SetIamPolicy",
            "projects/detection-range-b9298c",
            "project",
        ),
        make_row(
            "2026-07-29T09:21:47.000Z",
            "iamcredentials.googleapis.com",
            "GenerateAccessToken",
            f"projects/-/serviceAccounts/{TARGET_SA}",
            "service_account",
        ),
    ]

    for i, row in enumerate(rows, start=1):
        path = os.path.join(OUTPUT_DIR, f"{i:02d}.json")
        with open(path, "w") as f:
            json.dump(row, f, indent=2)
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
