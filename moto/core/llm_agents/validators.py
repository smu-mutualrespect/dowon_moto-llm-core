from __future__ import annotations

import json
from typing import Any


def validate_input(schema: dict[str, Any] | None, body: dict[str, Any]) -> tuple[bool, str]:
    if not schema:
        return True, ""
    if not body:
        return True, ""
    normalized_keys = {_normalize_key(name) for name in body}
    missing = [
        name
        for name in schema.get("required_input", [])
        if name not in body and _normalize_key(name) not in normalized_keys
    ]
    if missing:
        return False, f"Missing required parameter: {missing[0]}"
    return True, ""


def aws_error_response(service: str, action: str, message: str, protocol: str = "json") -> str:
    if protocol in ("query", "ec2", "rest-xml"):
        code = "ValidationError"
        return (
            f"<ErrorResponse><Error><Type>Sender</Type><Code>{code}</Code>"
            f"<Message>{_xml_escape(message)}</Message></Error>"
            f"<RequestId>00000000-0000-0000-0000-000000000000</RequestId></ErrorResponse>"
        )
    return json.dumps(
        {
            "__type": f"{service}#{action}ValidationException",
            "message": message,
        },
        separators=(",", ":"),
    )


def validate_generated_response(body: str, schema: dict[str, Any] | None) -> bool:
    if not body:
        return False
    if not schema:
        return True
    protocol = schema.get("protocol")
    if protocol in ("query", "ec2", "rest-xml"):
        return body.lstrip().startswith("<")
    try:
        parsed = json.loads(body)
    except Exception:
        return False
    expected = schema.get("output_schema")
    if isinstance(expected, dict) and isinstance(parsed, dict):
        return set(parsed).issubset(set(expected))
    return True


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _normalize_key(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())
