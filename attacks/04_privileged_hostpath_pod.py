import json
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "attack_04")

COMPROMISED_SA = "range-gke-node@detection-range-b9298c.iam.gserviceaccount.com"
POD_IP = "10.10.0.5"


def make_row(timestamp, pod_name, containers, volumes):
    return {
        "logName": "projects/detection-range-b9298c/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": timestamp,
        "resource": {"type": "k8s_pod", "labels": {}},
        "protopayload_auditlog": {
            "serviceName": "container.googleapis.com",
            "methodName": "io.k8s.core.v1.pods.create",
            "resourceName": f"namespaces/default/pods/{pod_name}",
            "authenticationInfo": {"principalEmail": COMPROMISED_SA},
            "requestMetadata": {"callerIp": POD_IP},
            "status": {},
            "request": {"spec": {"containers": containers, "volumes": volumes}},
        },
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = [
        make_row(
            "2026-07-29T09:30:00.000Z",
            "innocuous-looking-app",
            [{"name": "app", "image": "us-east4-docker.pkg.dev/detection-range-b9298c/range-repo/alpine-debug:v1", "securityContext": {"privileged": True}}],
            [],
        ),
        make_row(
            "2026-07-29T09:31:15.000Z",
            "log-collector",
            [{"name": "collector", "image": "us-east4-docker.pkg.dev/detection-range-b9298c/range-repo/alpine-debug:v1", "volumeMounts": [{"name": "host-root", "mountPath": "/host"}]}],
            [{"name": "host-root", "hostPath": {"path": "/"}}],
        ),
    ]

    for i, row in enumerate(rows, start=1):
        path = os.path.join(OUTPUT_DIR, f"{i:02d}.json")
        with open(path, "w") as f:
            json.dump(row, f, indent=2)
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
