from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlparse


def parse_request(url: str, headers: dict[str, str], body: Any) -> tuple[str, str, dict[str, Any]]:
    service = "unknown"
    action = "unknown"
    parsed_body: dict[str, Any] = {}

    hostname = urlparse(url).hostname or ""
    match = re.match(r"^([a-z0-9-]+)\.amazonaws\.com$", hostname)
    if match:
        service = match.group(1)

    if service == "unknown":
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        match = re.search(r"Credential=[^/]+/\d+/[^/]+/([a-z0-9-]+)/aws4_request", auth, re.IGNORECASE)
        if match:
            service = match.group(1).lower()

    if isinstance(body, dict):
        parsed_body = dict(body)
        raw_body = ""
    else:
        raw_body = body if isinstance(body, str) else (body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else "")
        try:
            parsed_body = json.loads(raw_body) if raw_body.lstrip().startswith("{") else {}
        except Exception:
            parsed_body = {}
        if not parsed_body and "=" in raw_body:
            parsed_body = {
                key: values[0] if values else ""
                for key, values in parse_qs(raw_body, keep_blank_values=True).items()
            }

    query = parse_qs(urlparse(url).query)
    for key, values in query.items():
        if key not in parsed_body and values:
            parsed_body[key] = unquote_plus(values[0])
    if "Action" in query:
        action = query["Action"][0]
    elif "Action=" in raw_body:
        match = re.search(r"Action=([A-Za-z0-9]+)", raw_body)
        if match:
            action = match.group(1)
    elif "Action" in parsed_body:
        action = str(parsed_body["Action"])
    else:
        target = headers.get("X-Amz-Target") or headers.get("x-amz-target") or ""
        if target:
            action = target.split(".")[-1] if "." in target else target
        else:
            path = urlparse(url).path.strip("/")
            if path:
                action = path.split("/")[-1]

    return service, action, parsed_body
