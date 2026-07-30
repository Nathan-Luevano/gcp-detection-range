import sys

SA_EMAIL = "range-gke-node@detection-range-b9298c.iam.gserviceaccount.com"
KEY_ID = "abcd1234efgh5678"


def disable_sa_key(sa_email, key_id, approved):
    if not approved:
        print(f"DRY RUN: would disable key {key_id} for service account {sa_email}")
        return
    print(
        f"APPROVED: would run 'gcloud iam service-accounts keys disable {key_id} "
        f"--iam-account={sa_email}' (not executed, no live cloud wired up)"
    )


def main():
    approved = "--approve" in sys.argv
    disable_sa_key(SA_EMAIL, KEY_ID, approved)


if __name__ == "__main__":
    main()
