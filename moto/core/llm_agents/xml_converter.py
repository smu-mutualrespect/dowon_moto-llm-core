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
        if protocol not in ("query", "ec2", "rest-xml"):
            return json.dumps(data, ensure_ascii=False)
        return _dict_to_xml(data, schema)

    protocol = schema.get("protocol")
    if protocol not in ("query", "ec2", "rest-xml"):
        return body
    if body.lstrip().startswith("<"):
        return body  # 이미 XML

    try:
        data = json.loads(body)
    except Exception:
        return body
    if not isinstance(data, dict):
        return body

    return _dict_to_xml(data, schema)


def _dict_to_xml(data: dict[str, Any], schema: dict[str, Any]) -> str:
    operation = schema.get("operation_name", "Response")
    xmlns = schema.get("xmlns", "")
    location_names = schema.get("xml_location_names", {})
    protocol = schema.get("protocol")
    if protocol == "query":
        return _to_query_xml(operation, data, xmlns, location_names)
    if protocol == "ec2":
        return _to_ec2_xml(operation, data, xmlns, location_names)
    return _to_rest_xml(operation, data, xmlns, location_names)


def _to_query_xml(
    operation: str,
    data: dict[str, Any],
    xmlns: str,
    location_names: dict[str, Any] | None = None,
) -> str:
    inner = _children(data, location_names or {}, list_item_tag="member")
    xmlns_attr = f' xmlns="{xmlns}"' if xmlns else ""
    result_block = f"<{operation}Result>{inner}</{operation}Result>" if inner else f"<{operation}Result/>"
    return (
        f"<{operation}Response{xmlns_attr}>"
        f"{result_block}"
        f"<ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata>"
        f"</{operation}Response>"
    )


def _to_ec2_xml(
    operation: str,
    data: dict[str, Any],
    xmlns: str,
    location_names: dict[str, Any] | None = None,
) -> str:
    inner = _children(data, location_names or {}, list_item_tag="item")
    xmlns_attr = f' xmlns="{xmlns}"' if xmlns else ""
    return (
        f"<{operation}Response{xmlns_attr}>"
        f"<requestId>00000000-0000-0000-0000-000000000000</requestId>"
        f"{inner}"
        f"</{operation}Response>"
    )


def _to_rest_xml(
    operation: str,
    data: dict[str, Any],
    xmlns: str,
    location_names: dict[str, Any] | None = None,
) -> str:
    location_names = location_names or {}
    root_name = location_names.get("_name") or operation
    xmlns_attr = f' xmlns="{xmlns}"' if xmlns else ""
    return f"<{root_name}{xmlns_attr}>{_children(data, location_names, list_item_tag='member')}</{root_name}>"


def _children(data: Any, location_names: Any = None, *, list_item_tag: str = "member") -> str:
    if isinstance(data, dict):
        return "".join(
            _element(
                _xml_name(k, _child_location(location_names, k)),
                _children(v, _child_location(location_names, k), list_item_tag=list_item_tag),
            )
            for k, v in data.items()
        )
    if isinstance(data, list):
        member_location = _member_location(location_names)
        tag = _xml_name(list_item_tag, member_location)
        return "".join(
            _element(tag, _children(item, member_location, list_item_tag=list_item_tag))
            for item in data
        )
    if isinstance(data, bool):
        return "true" if data else "false"
    if data is None:
        return ""
    return _esc(str(data))


def _element(name: str, inner: str) -> str:
    return f"<{name}>{inner}</{name}>"


def _xml_name(default: str, location: Any) -> str:
    if isinstance(location, dict) and location.get("_name"):
        return str(location["_name"])
    return default


def _child_location(location_names: Any, key: str) -> Any:
    if isinstance(location_names, dict):
        return location_names.get(key, {})
    return {}


def _member_location(location_names: Any) -> Any:
    if isinstance(location_names, dict):
        return location_names.get("_member", {})
    return {}


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
