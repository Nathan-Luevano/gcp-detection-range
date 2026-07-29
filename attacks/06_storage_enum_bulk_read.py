import datetime
import json
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "attack_06")

COMPROMISED_SA = "range-gke-node@detection-range-b9298c.iam.gserviceaccount.com"
ATTACKER_IP = "185.220.101.7"
BUCKET = "detection-range-b9298c-sensitive-data"
START_TIME = datetime.datetime(2026, 7, 29, 10, 0, 0)


def make_row(timestamp, method, resource_name):
    return {
        "logName": "projects/detection-range-b9298c/logs/cloudaudit.googleapis.com%2Fdata_access",
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resource": {"type": "gcs_bucket", "labels": {"bucket_name": BUCKET}},
        "protopayload_auditlog": {
            "serviceName": "storage.googleapis.com",
            "methodName": method,
            "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": COMPROMISED_SA},
            "requestMetadata": {"callerIp": ATTACKER_IP},
            "status": {},
        },
    }


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = [make_row(START_TIME, "storage.objects.list", f"projects/_/buckets/{BUCKET}")]

    for i in range(1, 13):
        t = START_TIME + datetime.timedelta(seconds=5 * i)
        resource_name = f"projects/_/buckets/{BUCKET}/objects/record_{i:03d}.csv"
        rows.append(make_row(t, "storage.objects.get", resource_name))

    for i, row in enumerate(rows, start=1):
        path = os.path.join(OUTPUT_DIR, f"{i:02d}.json")
        with open(path, "w") as f:
            json.dump(row, f, indent=2)
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
