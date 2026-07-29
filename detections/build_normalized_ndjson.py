import glob
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pipeline"))
from normalize import normalize

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")
OUTPUT_PATH = os.path.join(FIXTURES_DIR, "normalized_test.ndjson")


def main():
    attack_dir = sys.argv[1]

    benign_files = sorted(glob.glob(os.path.join(FIXTURES_DIR, "benign_*.json")))
    attack_files = sorted(glob.glob(os.path.join(FIXTURES_DIR, attack_dir, "*.json")))

    with open(OUTPUT_PATH, "w") as out:
        for path in benign_files + attack_files:
            with open(path) as f:
                raw = json.load(f)
            row = normalize(raw)
            row["raw"] = json.dumps(row["raw"])
            out.write(json.dumps(row) + "\n")

    print(f"wrote {OUTPUT_PATH} ({len(benign_files)} benign, {len(attack_files)} attack)")


if __name__ == "__main__":
    main()
