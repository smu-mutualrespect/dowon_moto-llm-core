from __future__ import annotations

import json
from typing import Any


def maybe_convert_to_xml(body: Any, schema: dict[str, Any] | None) -> str:
    """JSON 응답 바디를 protocol에 맞는 XML로 변환. 이미 XML이면 그대로 반환."""
    if not body or not schema:
        return body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    if isinstance(body, dict):
        data = body
        protocol = schema.get("protocol")
        if protocol not in ("query", "ec2"):
            return json.dumps(data, ensure_ascii=False)
        operation = schema.get("operation_name", "Response")
        xmlns = schema.get("xmlns", "")
        if protocol == "query":
            return _to_query_xml(operation, data, xmlns)
        return _to_ec2_xml(operation, data, xmlns)
    protocol = schema.get("protocol")
    if protocol not in ("query", "ec2"):
        return body
    if body.lstrip().startswith("<"):
        return body  # 이미 XML

    try:
        data = json.loads(body)
    except Exception:
        return body
    if not isinstance(data, dict):
        return body

    operation = schema.get("operation_name", "Response")
    xmlns = schema.get("xmlns", "")

    if protocol == "query":
        return _to_query_xml(operation, data, xmlns)
    else:  # ec2
        return _to_ec2_xml(operation, data, xmlns)


def _to_query_xml(operation: str, data: dict, xmlns: str) -> str:
    inner = _children(data)
    xmlns_attr = f' xmlns="{xmlns}"' if xmlns else ""
    result_block = f"<{operation}Result>{inner}</{operation}Result>" if inner else f"<{operation}Result/>"
    return (
        f"<{operation}Response{xmlns_attr}>"
        f"{result_block}"
        f"<ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata>"
        f"</{operation}Response>"
    )


def _to_ec2_xml(operation: str, data: dict, xmlns: str) -> str:
    inner = _children(data)
    xmlns_attr = f' xmlns="{xmlns}"' if xmlns else ""
    return (
        f"<{operation}Response{xmlns_attr}>"
        f"<requestId>00000000-0000-0000-0000-000000000000</requestId>"
        f"{inner}"
        f"</{operation}Response>"
    )


def _children(data: Any) -> str:
    if isinstance(data, dict):
        return "".join(f"<{k}>{_children(v)}</{k}>" for k, v in data.items())
    if isinstance(data, list):
        return "".join(f"<member>{_children(item)}</member>" for item in data)
    if isinstance(data, bool):
        return "true" if data else "false"
    if data is None:
        return ""
    return _esc(str(data))


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
