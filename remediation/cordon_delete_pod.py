import sys

NODE_NAME = "gke-range-gke-range-node-pool-abc12345-xyz9"
NAMESPACE = "default"
POD_NAME = "backdoor"


def cordon_and_delete_pod(node_name, namespace, pod_name, approved):
    if not approved:
        print(f"DRY RUN: would cordon node {node_name} and delete pod {namespace}/{pod_name}")
        return
    print(
        f"APPROVED: would run 'kubectl cordon {node_name}' and "
        f"'kubectl delete pod {pod_name} -n {namespace}' (not executed, no live cloud wired up)"
    )


def main():
    approved = "--approve" in sys.argv
    cordon_and_delete_pod(NODE_NAME, NAMESPACE, POD_NAME, approved)


if __name__ == "__main__":
    main()
