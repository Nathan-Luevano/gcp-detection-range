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

    return {
        "timestamp": raw["timestamp"],
        "actor": principal_email,
        "actor_type": actor_type,
        "source_ip": payload["requestMetadata"]["callerIp"],
        "action": payload["methodName"],
        "resource": payload["resourceName"],
        "resource_type": raw["resource"]["type"],
        "outcome": outcome,
        "raw": raw,
    }
