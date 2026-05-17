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
        loc_map = schema.get("xml_location_names", {})
        if protocol == "query":
            return _to_query_xml(operation, data, xmlns, loc_map)
        return _to_ec2_xml(operation, data, xmlns, loc_map)
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
    loc_map = schema.get("xml_location_names", {})

    if protocol == "query":
        return _to_query_xml(operation, data, xmlns, loc_map)
    else:  # ec2
        return _to_ec2_xml(operation, data, xmlns, loc_map)


def _to_query_xml(operation: str, data: dict, xmlns: str, loc_map: dict) -> str:
    inner = _children(data, list_tag="member", loc_map=loc_map)
    xmlns_attr = f' xmlns="{xmlns}"' if xmlns else ""
    result_block = f"<{operation}Result>{inner}</{operation}Result>" if inner else f"<{operation}Result/>"
    return (
        f"<{operation}Response{xmlns_attr}>"
        f"{result_block}"
        f"<ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata>"
        f"</{operation}Response>"
    )


def _to_ec2_xml(operation: str, data: dict, xmlns: str, loc_map: dict) -> str:
    inner = _children(data, list_tag="item", loc_map=loc_map)
    xmlns_attr = f' xmlns="{xmlns}"' if xmlns else ""
    return (
        f"<{operation}Response{xmlns_attr}>"
        f"<requestId>00000000-0000-0000-0000-000000000000</requestId>"
        f"{inner}"
        f"</{operation}Response>"
    )


def _children(data: Any, list_tag: str = "member", loc_map: dict | None = None) -> str:
    if isinstance(data, dict):
        parts = []
        for k, v in data.items():
            entry = (loc_map or {}).get(k, {}) if loc_map else {}
            xml_name = entry.get("_loc", k) if entry else k
            if isinstance(v, list):
                item_tag = entry.get("__item_tag", list_tag) if entry else list_tag
                item_map = entry.get("__item_children") if entry else None
                parts.append(f"<{xml_name}>{_children(v, item_tag, item_map)}</{xml_name}>")
            else:
                child_map = entry.get("_children") if entry else None
                parts.append(f"<{xml_name}>{_children(v, list_tag, child_map)}</{xml_name}>")
        return "".join(parts)
    if isinstance(data, list):
        return "".join(f"<{list_tag}>{_children(item, list_tag, loc_map)}</{list_tag}>" for item in data)
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
