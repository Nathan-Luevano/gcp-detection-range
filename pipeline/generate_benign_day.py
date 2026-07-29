import json
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "benign_day")

NODE_SA = "range-gke-node@detection-range-b9298c.iam.gserviceaccount.com"
BUCKET = "detection-range-b9298c-sensitive-data"


def make_row(timestamp, service_name, method, resource_name, resource_type, actor, caller_ip, request=None):
    payload = {
        "serviceName": service_name,
        "methodName": method,
        "resourceName": resource_name,
        "authenticationInfo": {"principalEmail": actor},
        "requestMetadata": {"callerIp": caller_ip},
        "status": {},
    }
    if request is not None:
        payload["request"] = request

    return {
        "logName": "projects/detection-range-b9298c/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": timestamp,
        "resource": {"type": resource_type, "labels": {}},
        "protopayload_auditlog": payload,
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    rows = []

    rows.append(make_row(
        "2026-07-29T08:15:00.000Z", "storage.googleapis.com", "storage.objects.get",
        f"projects/_/buckets/{BUCKET}/objects/quarterly_report.csv", "gcs_bucket",
        "analyst1@example.com", "203.0.113.10",
    ))
    rows.append(make_row(
        "2026-07-29T11:40:00.000Z", "storage.googleapis.com", "storage.objects.get",
        f"projects/_/buckets/{BUCKET}/objects/onboarding_notes.csv", "gcs_bucket",
        "analyst2@example.com", "203.0.113.11",
    ))
    rows.append(make_row(
        "2026-07-29T14:05:00.000Z", "storage.googleapis.com", "storage.objects.get",
        f"projects/_/buckets/{BUCKET}/objects/quarterly_report.csv", "gcs_bucket",
        "analyst1@example.com", "203.0.113.10",
    ))

    rows.append(make_row(
        "2026-07-29T09:30:00.000Z", "cloudresourcemanager.googleapis.com", "SetIamPolicy",
        "projects/detection-range-b9298c", "project", "admin@example.com", "203.0.113.20",
    ))
    rows.append(make_row(
        "2026-07-29T16:00:00.000Z", "cloudresourcemanager.googleapis.com", "SetIamPolicy",
        "projects/detection-range-b9298c", "project", "admin@example.com", "203.0.113.20",
    ))

    for hour in (8, 10, 12, 14, 16):
        rows.append(make_row(
            f"2026-07-29T{hour:02d}:00:00.000Z", "storage.googleapis.com", "storage.objects.list",
            f"projects/_/buckets/{BUCKET}", "gcs_bucket", NODE_SA, "10.10.0.5",
        ))
        rows.append(make_row(
            f"2026-07-29T{hour:02d}:02:00.000Z", "storage.googleapis.com", "storage.objects.get",
            f"projects/_/buckets/{BUCKET}/objects/inventory_{hour:02d}.csv", "gcs_bucket", NODE_SA, "10.10.0.5",
        ))

    for hour in (9, 13, 17):
        rows.append(make_row(
            f"2026-07-29T{hour:02d}:15:00.000Z", "container.googleapis.com", "io.k8s.core.v1.pods.list",
            "namespaces/default/pods", "k8s_cluster", NODE_SA, "10.10.0.5",
        ))

    for i, hour in enumerate((10, 15), start=1):
        rows.append(make_row(
            f"2026-07-29T{hour:02d}:30:00.000Z", "container.googleapis.com", "io.k8s.core.v1.pods.create",
            f"namespaces/default/pods/worker-{i}", "k8s_pod", NODE_SA, "10.10.0.5",
            request={"spec": {"containers": [{
                "name": "worker",
                "image": "us-east4-docker.pkg.dev/detection-range-b9298c/range-repo/worker:v1",
                "securityContext": {"privileged": False},
            }], "volumes": []}},
        ))

    for i, row in enumerate(rows, start=1):
        path = os.path.join(OUTPUT_DIR, f"{i:02d}.json")
        with open(path, "w") as f:
            json.dump(row, f, indent=2)

    print(f"wrote {len(rows)} fixtures to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
