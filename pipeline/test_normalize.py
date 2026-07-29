import json
import os

from normalize import normalize

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")

EXPECTED_COLUMNS = {
    "timestamp",
    "actor",
    "actor_type",
    "source_ip",
    "action",
    "resource",
    "resource_type",
    "outcome",
    "raw",
}


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def test_normalize_bucket_read():
    raw = load_fixture("benign_bucket_read.json")
    row = normalize(raw)

    assert set(row.keys()) == EXPECTED_COLUMNS
    assert row["actor"] == "analyst@detection-range-b9298c.iam.gserviceaccount.com"
    assert row["actor_type"] == "service_account"
    assert row["source_ip"] == "73.202.11.44"
    assert row["action"] == "storage.objects.get"
    assert row["resource_type"] == "gcs_bucket"
    assert row["outcome"] == "success"


def test_normalize_iam_change():
    raw = load_fixture("benign_iam_change.json")
    row = normalize(raw)

    assert set(row.keys()) == EXPECTED_COLUMNS
    assert row["actor"] == "admin@example.com"
    assert row["actor_type"] == "user"
    assert row["source_ip"] == "203.0.113.5"
    assert row["action"] == "SetIamPolicy"
    assert row["resource_type"] == "project"
    assert row["outcome"] == "success"
