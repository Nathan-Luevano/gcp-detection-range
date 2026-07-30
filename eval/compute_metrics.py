import glob
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from normalize import normalize

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "correlation"))
import build_graph

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")
DETECTIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "detections")
PROJECT_ID = "detection-range-b9298c"
TABLE = "detection_range_test.normalized_events"
SCHEMA = "timestamp:TIMESTAMP,actor:STRING,actor_type:STRING,source_ip:STRING,action:STRING,resource:STRING,resource_type:STRING,outcome:STRING,raw:STRING"
NDJSON_PATH = os.path.join(FIXTURES_DIR, "normalized_eval.ndjson")

BENIGN_FIXTURES = [
    "benign_bucket_read.json",
    "benign_iam_change.json",
    "benign_gke_activity.json",
    "benign_pod_creation.json",
]

SCENARIOS = {
    1: {
        "sql": "01_sa_key_from_unexpected_ip.sql",
        "attack_dir": "attack_01",
        "positive_files": ["02.json"],
        "aggregated": False,
    },
    2: {
        "sql": "02_iam_privilege_escalation.sql",
        "attack_dir": "attack_02",
        "positive_files": ["01.json", "02.json"],
        "aggregated": False,
    },
    3: {
        "sql": "03_gke_sa_token_abuse.sql",
        "attack_dir": "attack_03",
        "positive_files": ["01.json", "02.json"],
        "aggregated": False,
    },
    4: {
        "sql": "04_privileged_hostpath_pod.sql",
        "attack_dir": "attack_04",
        "positive_files": ["01.json", "02.json"],
        "aggregated": False,
    },
    5: {
        "sql": "05_unapproved_container_image.sql",
        "attack_dir": "attack_05",
        "positive_files": ["01.json"],
        "aggregated": False,
    },
    6: {
        "sql": "06_storage_enum_bulk_read.sql",
        "attack_dir": "attack_06",
        "positive_files": [f"{i:02d}.json" for i in range(2, 14)],
        "aggregated": True,
    },
}


def normalize_file(path):
    with open(path) as f:
        raw = json.load(f)
    return normalize(raw)


def load_scenario_events(attack_dir):
    events = {}

    for name in BENIGN_FIXTURES:
        events[("benign", name)] = normalize_file(os.path.join(FIXTURES_DIR, name))

    for name in sorted(os.listdir(os.path.join(FIXTURES_DIR, "benign_day"))):
        events[("benign_day", name)] = normalize_file(os.path.join(FIXTURES_DIR, "benign_day", name))

    for name in sorted(os.listdir(os.path.join(FIXTURES_DIR, attack_dir))):
        events[("attack", name)] = normalize_file(os.path.join(FIXTURES_DIR, attack_dir, name))

    return events


def load_table(events):
    with open(NDJSON_PATH, "w") as out:
        for row in events.values():
            row = dict(row)
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


def run_detection(sql_path):
    with open(sql_path) as f:
        sql = f.read()

    start = time.time()
    result = subprocess.run(
        ["bq", "query", f"--project_id={PROJECT_ID}", "--use_legacy_sql=false", "--format=json", sql],
        capture_output=True,
        text=True,
        check=True,
    )
    latency = time.time() - start

    rows = json.loads(result.stdout) if result.stdout.strip() else []
    return rows, latency


def evaluate_scenario(n, config):
    events = load_scenario_events(config["attack_dir"])
    load_table(events)

    sql_path = os.path.join(DETECTIONS_DIR, config["sql"])
    rows, latency = run_detection(sql_path)

    positive_resources = {
        events[("attack", name)]["resource"] for name in config["positive_files"]
    }

    if config["aggregated"]:
        total_positive = len(positive_resources)
        tp = total_positive if rows else 0
        fn = 0 if rows else total_positive
        fp = 0
        for row in rows:
            if row.get("actor") not in {events[("attack", name)]["actor"] for name in config["positive_files"]}:
                fp += 1
    else:
        returned_resources = {row["resource"] for row in rows}
        tp = len(positive_resources & returned_resources)
        fn = len(positive_resources - returned_resources)
        fp = len(returned_resources - positive_resources)

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")

    return {
        "scenario": n,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "latency_sec": latency,
    }


def attack_path_recall():
    events = build_graph.load_events()
    graph = build_graph.build_graph(events)
    actor, edges = build_graph.find_attack_path(graph)

    if actor is None:
        return 0.0

    stages_found = set()
    for _, stages, _, _ in edges:
        stages_found |= stages

    return len(stages_found) / len(build_graph.STAGE_NAMES)


def flow_log_degradation_check():
    flow_fixtures = []
    for path in glob.glob(os.path.join(FIXTURES_DIR, "**", "*.json"), recursive=True):
        with open(path) as f:
            raw = json.load(f)
        if "vpc_flows" in raw.get("logName", ""):
            flow_fixtures.append(path)
    return flow_fixtures


def main():
    print(f"{'scenario':8} {'tp':>3} {'fp':>3} {'fn':>3} {'precision':>10} {'recall':>8} {'latency_s':>10}")
    for n in sorted(SCENARIOS):
        metrics = evaluate_scenario(n, SCENARIOS[n])
        print(
            f"{n:<8} {metrics['tp']:>3} {metrics['fp']:>3} {metrics['fn']:>3} "
            f"{metrics['precision']:>10.2f} {metrics['recall']:>8.2f} {metrics['latency_sec']:>10.2f}"
        )

    recall = attack_path_recall()
    print(f"\nattack-path recall: {recall:.2f} ({int(recall * 6)}/6 stages reconstructed)")

    flow_fixtures = flow_log_degradation_check()
    print(f"\ndegradation test: {len(flow_fixtures)} fixtures use the VPC flow log sink")
    if not flow_fixtures:
        print(
            "no detection currently derives any signal from VPC flow log data "
            "(all six read only from the audit-log-shaped normalized schema), "
            "so removing flow fixtures changes nothing today -- this is a real coverage gap, not a passing result"
        )


if __name__ == "__main__":
    main()
