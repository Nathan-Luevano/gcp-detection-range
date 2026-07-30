import sys

PROJECT_ID = "detection-range-b9298c"
ROLE = "roles/owner"
MEMBER = "serviceAccount:range-gke-node@detection-range-b9298c.iam.gserviceaccount.com"


def remove_iam_binding(project_id, role, member, approved):
    if not approved:
        print(f"DRY RUN: would remove binding {role} -> {member} on project {project_id}")
        return
    print(
        f"APPROVED: would run 'gcloud projects remove-iam-policy-binding {project_id} "
        f"--role={role} --member={member}' (not executed, no live cloud wired up)"
    )


def main():
    approved = "--approve" in sys.argv
    remove_iam_binding(PROJECT_ID, ROLE, MEMBER, approved)


if __name__ == "__main__":
    main()
