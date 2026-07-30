import glob
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from normalize import normalize

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")
PROJECT_ID = "detection-range-b9298c"
TABLE = "detection_range_test.normalized_events"
SCHEMA = "timestamp:TIMESTAMP,actor:STRING,actor_type:STRING,source_ip:STRING,action:STRING,resource:STRING,resource_type:STRING,outcome:STRING,raw:STRING"
NDJSON_PATH = os.path.join(FIXTURES_DIR, "normalized_verify.ndjson")


def dry_run_check(sql):
    result = subprocess.run(
        ["bq", "query", f"--project_id={PROJECT_ID}", "--use_legacy_sql=false", "--dry_run", sql],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True, True, None

    output = result.stdout + result.stderr
    if "Unrecognized name" in output:
        return True, False, output
    return False, False, output


def load_fixtures(dir_names):
    files = []
    for d in dir_names:
        files.extend(sorted(glob.glob(os.path.join(FIXTURES_DIR, d, "*.json"))))

    with open(NDJSON_PATH, "w") as out:
        for path in files:
            with open(path) as f:
                raw = json.load(f)
            row = normalize(raw)
            row["raw"] = json.dumps(row["raw"])
            out.write(json.dumps(row) + "\n")

    subprocess.run(
        [
            "bq", "load", f"--project_id={PROJECT_ID}", "--replace",
            "--source_format=NEWLINE_DELIMITED_JSON", f"--schema={SCHEMA}",
            TABLE, NDJSON_PATH,
        ],
        check=True,
        capture_output=True,
    )


def run_query(sql):
    result = subprocess.run(
        ["bq", "query", f"--project_id={PROJECT_ID}", "--use_legacy_sql=false", "--format=csv", sql],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = [line for line in result.stdout.strip().splitlines() if line]
    return max(len(lines) - 1, 0)


def verify(sql, attack_dir):
    parses, fields_valid, error = dry_run_check(sql)
    gates = {"parses": parses, "fields_valid": fields_valid}

    if not (parses and fields_valid):
        gates["fires_on_attack"] = False
        gates["silent_on_benign"] = False
        return {"accepted": False, "gates": gates, "error": error}

    load_fixtures([attack_dir])
    attack_count = run_query(sql)
    gates["fires_on_attack"] = attack_count >= 1

    load_fixtures(["benign_day"])
    benign_count = run_query(sql)
    gates["silent_on_benign"] = benign_count == 0

    accepted = gates["fires_on_attack"] and gates["silent_on_benign"]
    return {"accepted": accepted, "gates": gates}
