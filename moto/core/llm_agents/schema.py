from __future__ import annotations

import logging
import re
import threading
from functools import lru_cache
from typing import Any, Optional

logger = logging.getLogger("turn_agent")


_PROTOCOL_CONTENT_TYPE = {
    "json": "application/x-amz-json-{ver}",
    "rest-json": "application/json",
    "rest-xml": "application/xml",
    "query": "text/xml",
    "ec2": "text/xml",
}

XML_SERVICES = {"iam", "sts", "s3", "ec2", "sqs", "sns", "cloudformation", "elasticloadbalancing"}

_session_lock = threading.RLock()
_botocore_session = None


def protocol_to_content_type(protocol: str, json_version: str = "1.1") -> str:
    template = _PROTOCOL_CONTENT_TYPE.get(protocol, "application/json")
    return template.format(ver=json_version)


@lru_cache(maxsize=2048)
def get_service_schema(
    service: str,
    action: str,
    url_path: str = "",
    method: str | None = None,
) -> Optional[dict[str, Any]]:
    if not service or service == "unknown":
        return None
    try:
        model = _get_botocore_session().get_service_model(service)
    except Exception as e:
        logger.debug("service_model lookup failed for %s: %s", service, e)
        return None

    op_name = _normalize_operation_name(model, action) if action and action != "unknown" else None
    if not op_name:
        op_name = _match_operation_by_uri(model, url_path or "", method)
    if not op_name:
        return None

    try:
        op = model.operation_model(op_name)
        protocol = model.metadata.get("protocol", "json")
        json_version = model.metadata.get("jsonVersion", "1.1")
        api_version = model.metadata.get("apiVersion", "")
        endpoint_prefix = model.metadata.get("endpointPrefix", service)
        if protocol == "ec2":
            xmlns = f"http://ec2.amazonaws.com/doc/{api_version}/"
        elif protocol in ("query", "rest-xml"):
            xmlns = f"https://{endpoint_prefix}.amazonaws.com/doc/{api_version}/"
        else:
            xmlns = ""
        output_schema = _shape_to_dict(op.output_shape)
        input_schema = _shape_to_dict(op.input_shape, max_depth=3)
        required = list(getattr(op.input_shape, "required_members", []) or []) if op.input_shape else []
        return {
            "protocol": protocol,
            "content_type": protocol_to_content_type(protocol, json_version),
            "operation_name": op_name,
            "output_schema": output_schema,
            "input_schema": input_schema,
            "required_input": required,
            "schema_prompt": _compact_schema_prompt(output_schema),
            "xmlns": xmlns,
        }
    except Exception as e:
        logger.debug("operation_model failed for %s/%s: %s", service, action, e)
        return None


def _get_botocore_session():
    global _botocore_session
    with _session_lock:
        if _botocore_session is None:
            import botocore.session

            _botocore_session = botocore.session.Session()
        return _botocore_session


def _normalize_operation_name(model, action: str) -> Optional[str]:
    try:
        op_names = model.operation_names
    except Exception:
        return None
    if action in op_names:
        return action
    if "-" in action:
        pascal = "".join(part.capitalize() for part in action.split("-"))
        if pascal in op_names:
            return pascal
    lower = action.lower().replace("_", "")
    for op in op_names:
        if op.lower().replace("_", "") == lower:
            return op
    return None


def _match_operation_by_uri(model, url_path: str, method: str | None = None) -> Optional[str]:
    if not url_path:
        return None
    try:
        op_names = list(model.operation_names)
    except Exception:
        return None
    candidates: list[tuple[int, str]] = []
    for op_name in op_names:
        try:
            op = model.operation_model(op_name)
        except Exception:
            continue
        http = op.http or {}
        op_method = http.get("method")
        op_uri = (http.get("requestUri") or "").split("?")[0]
        if not op_uri:
            continue
        if method and op_method and method.upper() != op_method.upper():
            continue
        pattern = "^" + re.sub(r"\{[^}]+\}", r"[^/]+", op_uri) + "$"
        if re.match(pattern, url_path):
            specificity = op_uri.count("/") - op_uri.count("{")
            candidates.append((specificity, op_name))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _shape_to_dict(shape, depth: int = 0, max_depth: int = 4) -> Any:
    if shape is None:
        return {}
    if depth > max_depth:
        return "..."
    try:
        type_name = shape.type_name
        if type_name == "structure":
            return {
                name: _shape_to_dict(member, depth + 1, max_depth)
                for name, member in shape.members.items()
            }
        if type_name == "list":
            return [_shape_to_dict(shape.member, depth + 1, max_depth)]
        if type_name == "map":
            return {"<key>": _shape_to_dict(shape.key, depth + 1, max_depth), "<value>": _shape_to_dict(shape.value, depth + 1, max_depth)}
        return type_name
    except Exception:
        return "..."


def _compact_schema_prompt(schema: Any, max_chars: int = 1800) -> str:
    import json

    compact = json.dumps(schema, ensure_ascii=False, separators=(",", ":"))
    if len(compact) <= max_chars:
        return compact
    pruned = _prune_schema(schema, max_depth=3, max_members=8)
    compact = json.dumps(pruned, ensure_ascii=False, separators=(",", ":"))
    if len(compact) <= max_chars:
        return compact
    if isinstance(schema, dict):
        summary = {
            "_schema_compacted": True,
            "top_level_fields": list(schema.keys()),
            "note": "Use only these top-level fields; keep nested values minimal and plausible.",
        }
        return json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
    return '{"_schema_compacted":true}'


def _prune_schema(value: Any, depth: int = 0, max_depth: int = 3, max_members: int = 8) -> Any:
    if depth >= max_depth:
        return "..."
    if isinstance(value, dict):
        items = list(value.items())[:max_members]
        result = {k: _prune_schema(v, depth + 1, max_depth, max_members) for k, v in items}
        if len(value) > max_members:
            result["_omitted_optional_fields"] = f"{len(value) - max_members} fields omitted"
        return result
    if isinstance(value, list):
        return [_prune_schema(value[0], depth + 1, max_depth, max_members)] if value else []
    return value
