import glob
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from normalize import normalize

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")
DETECTIONS_DIR = os.path.dirname(__file__)
NDJSON_PATH = os.path.join(FIXTURES_DIR, "normalized_benign_day.ndjson")
PROJECT_ID = "detection-range-b9298c"
TABLE = "detection_range_test.normalized_events"
SCHEMA = "timestamp:TIMESTAMP,actor:STRING,actor_type:STRING,source_ip:STRING,action:STRING,resource:STRING,resource_type:STRING,outcome:STRING,raw:STRING"


def build_ndjson():
    files = sorted(glob.glob(os.path.join(FIXTURES_DIR, "benign_day", "*.json")))
    with open(NDJSON_PATH, "w") as out:
        for path in files:
            with open(path) as f:
                raw = json.load(f)
            row = normalize(raw)
            row["raw"] = json.dumps(row["raw"])
            out.write(json.dumps(row) + "\n")
    return len(files)


def load_table():
    subprocess.run(
        [
            "bq", "load", f"--project_id={PROJECT_ID}", "--replace",
            "--source_format=NEWLINE_DELIMITED_JSON", f"--schema={SCHEMA}",
            TABLE, NDJSON_PATH,
        ],
        check=True,
        capture_output=True,
    )


def run_detection(sql_path):
    with open(sql_path) as f:
        query = f.read()
    result = subprocess.run(
        ["bq", "query", f"--project_id={PROJECT_ID}", "--use_legacy_sql=false", "--format=csv", query],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = [line for line in result.stdout.strip().splitlines() if line]
    return max(len(lines) - 1, 0)


def main():
    count = build_ndjson()
    print(f"loaded {count} benign_day fixtures")
    load_table()

    for sql_path in sorted(glob.glob(os.path.join(DETECTIONS_DIR, "0*.sql"))):
        name = os.path.basename(sql_path)
        fp_count = run_detection(sql_path)
        print(f"{name}: {fp_count} false positives")


if __name__ == "__main__":
    main()
