import json
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "attack_03")

COMPROMISED_SA = "range-gke-node@detection-range-b9298c.iam.gserviceaccount.com"
POD_IP = "10.10.0.5"


def make_row(timestamp, method, resource_name, resource_type):
    return {
        "logName": "projects/detection-range-b9298c/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": timestamp,
        "resource": {"type": resource_type, "labels": {}},
        "protopayload_auditlog": {
            "serviceName": "container.googleapis.com",
            "methodName": method,
            "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": COMPROMISED_SA},
            "requestMetadata": {"callerIp": POD_IP},
            "status": {},
        },
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = [
        make_row(
            "2026-07-29T09:25:12.000Z",
            "io.k8s.authorization.rbac.v1.clusterrolebindings.create",
            "clusterrolebindings/attacker-cluster-admin-binding",
            "k8s_rbac",
        ),
        make_row(
            "2026-07-29T09:26:03.000Z",
            "io.k8s.core.v1.secrets.list",
            "namespaces/_/secrets",
            "k8s_secret",
        ),
    ]

    for i, row in enumerate(rows, start=1):
        path = os.path.join(OUTPUT_DIR, f"{i:02d}.json")
        with open(path, "w") as f:
            json.dump(row, f, indent=2)
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
