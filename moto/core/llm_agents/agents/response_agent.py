from __future__ import annotations

import json
import os
import uuid
from typing import Any, Optional
from xml.etree.ElementTree import Element, SubElement, tostring

import botocore.session as _botocore_session

from moto.core.llm_agents.providers import LLMResult, call_gpt_api

_schema_cache: dict[str, str] = {}
_service_meta_cache: dict[str, dict] = {}

_XML_PROTOCOLS = {"query", "rest-xml"}


def _get_service_meta(service: str) -> dict:
    if service in _service_meta_cache:
        return _service_meta_cache[service]
    try:
        model = _botocore_session.get_session().get_service_model(service)
        meta = {
            "protocol": model.protocol,
            "xmlns": model.metadata.get("xmlNamespace", ""),
        }
    except Exception:
        meta = {"protocol": "json", "xmlns": ""}
    _service_meta_cache[service] = meta
    return meta


def _to_pascal(snake: str) -> str:
    return "".join(w.capitalize() for w in snake.split("_"))


def _json_to_query_xml(action: str, data: dict, xmlns: str) -> str:
    # Converts a JSON dict to AWS query-protocol XML format
    # <ActionResponse xmlns="..."><ActionResult>...</ActionResult><ResponseMetadata>...</ResponseMetadata></ActionResponse>
    pascal_action = _to_pascal(action)
    root = Element(f"{pascal_action}Response")
    if xmlns:
        root.set("xmlns", xmlns)

    result_el = SubElement(root, f"{pascal_action}Result")
    _dict_to_xml(result_el, data)

    meta_el = SubElement(root, "ResponseMetadata")
    req_el = SubElement(meta_el, "RequestId")
    req_el.text = str(uuid.uuid4())

    return tostring(root, encoding="unicode", xml_declaration=False)


def _dict_to_xml(parent: Element, data: Any) -> None:
    if isinstance(data, dict):
        for key, val in data.items():
            child = SubElement(parent, key)
            _dict_to_xml(child, val)
    elif isinstance(data, list):
        for item in data:
            member = SubElement(parent, "member")
            _dict_to_xml(member, item)
    elif data is None:
        pass
    else:
        parent.text = str(data).lower() if isinstance(data, bool) else str(data)


def generate(
    service: str,
    action: str,
    body: Any,
    bait_instructions: Optional[str] = None,
    bait_markers: Optional[list] = None,
) -> LLMResult:
    llm_model = os.getenv("MOTO_LLM_OPENAI_MODEL", "gpt-4o-mini")
    extra = ""
    if bait_instructions:
        extra += f"\n\nADDITIONAL INSTRUCTION: {bait_instructions}"
    if bait_markers:
        marker_lines = "\n".join(
            f"  - {m['type']}: \"{m['value']}\"" for m in bait_markers
        )
        extra += f"\n\nYou MUST include these exact values in your response:\n{marker_lines}"

    meta = _get_service_meta(service)
    is_xml = meta["protocol"] in _XML_PROTOCOLS

    schema, schema_in_tok, schema_out_tok = _get_schema(service, action, llm_model)

    response_prompt = f"""You are an AWS API simulator. Generate a realistic fake response for the following AWS API request.

AWS service: {service}
AWS action: {action}
Request body: {body}

The response must follow this exact schema:
{schema}

Rules:
- Output ONLY a raw JSON object. No markdown, no code fences, no explanation.
- {"Follow the schema field names and types as closely as possible, but you MAY embed bait values naturally inside existing string fields. The bait values below take priority over strict schema conformance." if bait_markers else "Follow the schema field names and types exactly. Do NOT add any fields that are not in the schema."}
- Use realistic fake values (fake ARNs, UUIDs, timestamps).
- Validate input parameter formats only. If any input format is invalid, return: {{"__type": "<AWSErrorCode>", "message": "<error message>"}}
- If inputs are valid, always return a successful response. Never return resource-not-found errors — assume all referenced resources exist.{extra}"""

    result = call_gpt_api(response_prompt, model=llm_model)

    if is_xml:
        try:
            data = json.loads(result.text)
            xml_text = _json_to_query_xml(action, data, meta["xmlns"])
        except Exception:
            try:
                fixed = result.text.replace('\\\\"', '\\"').replace("\\\\'", "\\'")
                data = json.loads(fixed)
                xml_text = _json_to_query_xml(action, data, meta["xmlns"])
            except Exception:
                xml_text = result.text
        return LLMResult(
            text=xml_text,
            input_tokens=schema_in_tok + result.input_tokens,
            output_tokens=schema_out_tok + result.output_tokens,
        )

    return LLMResult(
        text=result.text,
        input_tokens=schema_in_tok + result.input_tokens,
        output_tokens=schema_out_tok + result.output_tokens,
    )


def _get_schema(service: str, action: str, model: str) -> tuple[str, int, int]:
    cache_key = f"{service}.{action}"
    if cache_key in _schema_cache:
        return _schema_cache[cache_key], 0, 0

    schema_prompt = f"""What fields does the real AWS {service} {action} API response contain?
Return ONLY the fields that are documented in the official AWS API reference for this action.
Do NOT add any fields that you are not 100% certain are in the official response schema. If unsure about a field, omit it.
Use placeholder values like "<string>", "<integer>", "<boolean>", ["<item>"], etc.
No explanation, no markdown, no code fences. Raw JSON only."""

    result = call_gpt_api(schema_prompt, model=model)
    _schema_cache[cache_key] = result.text
    return result.text, result.input_tokens, result.output_tokens
