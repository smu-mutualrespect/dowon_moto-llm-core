from __future__ import annotations

import os


_DEFAULT_SERVICES = "sts,iam,s3,secretsmanager,ssm"


def should_intercept_native(service: str | None, action: str | None = None) -> bool:
    if os.getenv("HONEYPOT_INTERCEPT_NATIVE", "true").lower() in {"0", "false", "no"}:
        return False
    if not service:
        return False
    services = {
        item.strip().lower()
        for item in os.getenv("HONEYPOT_INTERCEPT_NATIVE_SERVICES", _DEFAULT_SERVICES).split(",")
        if item.strip()
    }
    return service.lower() in services
