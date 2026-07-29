import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from normalize import normalize

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")
OUTPUT_PATH = os.path.join(FIXTURES_DIR, "normalized_test.ndjson")

FIXTURE_FILES = [
    "benign_bucket_read.json",
    "benign_iam_change.json",
    "attack_01/01.json",
    "attack_01/02.json",
]


def main():
    with open(OUTPUT_PATH, "w") as out:
        for name in FIXTURE_FILES:
            with open(os.path.join(FIXTURES_DIR, name)) as f:
                raw = json.load(f)
            row = normalize(raw)
            row["raw"] = json.dumps(row["raw"])
            out.write(json.dumps(row) + "\n")

    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
