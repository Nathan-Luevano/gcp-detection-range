import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from normalize import normalize

from generate_candidate import generate_candidate
from verify import verify

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")

SCHEMA_DESCRIPTION = """Table: detection_range_test.normalized_events
Columns:
  timestamp     TIMESTAMP
  actor         STRING   (email of the human user or service account)
  actor_type    STRING   ("user" or "service_account")
  source_ip     STRING
  action        STRING   (an audit log method name, e.g. "storage.objects.get")
  resource      STRING
  resource_type STRING
  outcome       STRING   ("success" or "failure")
  raw           STRING   (never use this column in a detection)
"""


def load_attack_trace(attack_dir):
    rows = []
    for name in sorted(os.listdir(os.path.join(FIXTURES_DIR, attack_dir))):
        with open(os.path.join(FIXTURES_DIR, attack_dir, name)) as f:
            raw = json.load(f)
        row = normalize(raw)
        del row["raw"]
        rows.append(row)
    return rows


def extract_sql(text):
    match = re.search(r"```(?:sql)?\s*(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def build_prompt(trace_rows):
    trace_text = json.dumps(trace_rows, indent=2)
    return f"""You are writing a BigQuery Standard SQL detection query.

{SCHEMA_DESCRIPTION}
Here is a normalized event trace from one attack scenario. One row is the actor's
normal behavior, one row is the attack itself (a service account authenticating
from an IP address outside the range's VPC CIDR 10.10.0.0/20):

{trace_text}

Write a single SELECT query against `detection_range_test.normalized_events`
that returns only the anomalous row(s), using only the columns listed above,
never the raw column. Reply with only the SQL query in a single sql code block.
"""


def main():
    attack_dir = "attack_01"
    trace_rows = load_attack_trace(attack_dir)
    prompt = build_prompt(trace_rows)

    print("=== calling local model for candidate detection ===")
    response = generate_candidate(prompt)
    candidate_sql = extract_sql(response)

    print("=== candidate SQL ===")
    print(candidate_sql)

    result = verify(candidate_sql, attack_dir)
    print("=== verifier result (model candidate) ===")
    print(json.dumps(result, indent=2))

    if result["accepted"]:
        out_path = os.path.join(os.path.dirname(__file__), "accepted_01.sql")
        with open(out_path, "w") as f:
            f.write(candidate_sql + "\n")
        print(f"saved accepted candidate to {out_path}")
    else:
        print("candidate rejected, not saved")

    print()
    print("=== demonstrating rejection: a deliberately bad candidate ===")
    bad_sql = "SELECT * FROM `detection_range_test.normalized_events` WHERE nonexistent_column = 'x'"
    print(bad_sql)
    bad_result = verify(bad_sql, attack_dir)
    print(json.dumps(bad_result, indent=2))

    print()
    print("=== demonstrating acceptance: our known-good hand-written detection ===")
    good_sql_path = os.path.join(
        os.path.dirname(__file__), "..", "detections", "01_sa_key_from_unexpected_ip.sql"
    )
    with open(good_sql_path) as f:
        good_sql = f.read()
    print(good_sql)
    good_result = verify(good_sql, attack_dir)
    print(json.dumps(good_result, indent=2))


if __name__ == "__main__":
    main()
