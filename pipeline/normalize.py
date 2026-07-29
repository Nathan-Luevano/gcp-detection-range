def _is_privileged_pod(payload):
    spec = payload.get("request", {}).get("spec", {})

    for container in spec.get("containers", []):
        if container.get("securityContext", {}).get("privileged"):
            return True

    for volume in spec.get("volumes", []):
        if "hostPath" in volume:
            return True

    return False


def normalize(raw):
    payload = raw["protopayload_auditlog"]
    principal_email = payload["authenticationInfo"]["principalEmail"]

    if principal_email.endswith(".gserviceaccount.com"):
        actor_type = "service_account"
    else:
        actor_type = "user"

    if payload.get("status", {}).get("code"):
        outcome = "failure"
    else:
        outcome = "success"

    action = payload["methodName"]
    if action == "io.k8s.core.v1.pods.create" and _is_privileged_pod(payload):
        action += ".privileged"

    return {
        "timestamp": raw["timestamp"],
        "actor": principal_email,
        "actor_type": actor_type,
        "source_ip": payload["requestMetadata"]["callerIp"],
        "action": action,
        "resource": payload["resourceName"],
        "resource_type": raw["resource"]["type"],
        "outcome": outcome,
        "raw": raw,
    }
