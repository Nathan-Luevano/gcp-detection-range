import datetime
import glob
import ipaddress
import json
import os
import sys

import networkx as nx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from normalize import normalize

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")
RANGE_CIDR = ipaddress.ip_network("10.10.0.0/20")
WINDOW = datetime.timedelta(hours=6)

STAGE_NAMES = {
    1: "sa_key_from_unexpected_ip",
    2: "iam_privilege_escalation",
    3: "gke_sa_token_abuse",
    4: "privileged_hostpath_pod",
    5: "unapproved_container_image",
    6: "storage_enum_bulk_read",
}


def load_events():
    events = []
    for i in range(1, 7):
        for path in sorted(glob.glob(os.path.join(FIXTURES_DIR, f"attack_{i:02d}", "*.json"))):
            with open(path) as f:
                raw = json.load(f)
            row = normalize(raw)
            row["timestamp"] = datetime.datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
            events.append(row)
    return events


def bulk_read_counts(events):
    counts = {}
    for row in events:
        if row["action"] != "storage.objects.get":
            continue
        key = (row["actor"], row["timestamp"].replace(minute=0, second=0, microsecond=0))
        counts[key] = counts.get(key, 0) + 1
    return counts


def classify(row, counts):
    stages = set()

    if row["actor_type"] == "service_account" and ipaddress.ip_address(row["source_ip"]) not in RANGE_CIDR:
        stages.add(1)

    if row["actor_type"] == "service_account" and row["action"] in ("SetIamPolicy", "GenerateAccessToken"):
        stages.add(2)

    if row["actor_type"] == "service_account" and row["action"] in (
        "io.k8s.authorization.rbac.v1.clusterrolebindings.create",
        "io.k8s.core.v1.secrets.list",
    ):
        stages.add(3)

    if ".privileged" in row["action"]:
        stages.add(4)

    if ".unapproved_image" in row["action"]:
        stages.add(5)

    if row["action"] == "storage.objects.get":
        key = (row["actor"], row["timestamp"].replace(minute=0, second=0, microsecond=0))
        if counts.get(key, 0) >= 10:
            stages.add(6)

    return stages


def build_graph(events):
    graph = nx.MultiDiGraph()
    counts = bulk_read_counts(events)

    for row in events:
        stages = classify(row, counts)
        if not stages:
            continue
        graph.add_node(row["actor"], kind="actor")
        graph.add_node(row["resource"], kind="resource")
        graph.add_edge(
            row["actor"], row["resource"],
            action=row["action"], timestamp=row["timestamp"], stages=stages,
        )

    return graph


def find_attack_path(graph):
    for actor in graph.nodes:
        if graph.nodes[actor].get("kind") != "actor":
            continue

        edges = []
        for _, resource, data in graph.out_edges(actor, data=True):
            edges.append((data["timestamp"], data["stages"], data["action"], resource))

        if not edges:
            continue

        edges.sort()
        distinct_stages = set()
        for _, stages, _, _ in edges:
            distinct_stages |= stages

        if len(distinct_stages) < 3:
            continue

        span = edges[-1][0] - edges[0][0]
        if span > WINDOW:
            continue

        return actor, edges

    return None, None


def main():
    events = load_events()
    graph = build_graph(events)
    actor, edges = find_attack_path(graph)

    if actor is None:
        print("no chained attack path found")
        return

    print(f"chained attack path for actor: {actor}")
    for timestamp, stages, action, resource in edges:
        stage_labels = ", ".join(f"stage {s} ({STAGE_NAMES[s]})" for s in sorted(stages))
        print(f"  {timestamp}  {action:55s} -> {resource}   [{stage_labels}]")


if __name__ == "__main__":
    main()
