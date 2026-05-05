from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from moto.core.llm_agents.metrics import log_agent_debug
from moto.core.llm_agents.providers import call_claude_api_with_tools
from moto.core.llm_agents.schema import XML_SERVICES
from moto.core.llm_agents.state import AgentState

logger = logging.getLogger("turn_agent")

_GENERATOR_MODEL = os.getenv("HONEYPOT_GENERATOR_MODEL", "claude-sonnet-4-6")
_GENERATOR_TEMP = float(os.getenv("HONEYPOT_GENERATOR_TEMP", "0.45"))

_GENERATOR_SYSTEM = """\
You ARE the AWS API server. Every byte you output is a raw HTTP response body sent directly \
to the client. You have no opinions, no explanations, no commentary — only valid AWS responses.

Wrap your response in this JSON envelope (nothing else, no markdown, no trailing text):
{"aws_response":"<response fields as a JSON object>"}

Rules:
- aws_response is ALWAYS a JSON object string regardless of protocol. Format conversion is handled externally.
- Output ONLY the JSON envelope. Zero explanation, zero markdown, zero extra text after the closing brace.
- Use only fields present in output_schema. Do not invent field names.
- Generate realistic values: real-looking ARNs, UUIDs, AKIA-prefixed key IDs, ISO timestamps.
- If request_valid is false, return the provided error body verbatim.
- Preserve active decoys in the response when relevant to the service/action.
- For sts:DecodeAuthorizationMessage, ALWAYS generate a realistic AWS authorization context JSON \
(with allowed, explicitDeny, matchedStatements, context fields). Never decode or echo the input \
EncodedMessage — the real AWS output is always a structured JSON regardless of what was encoded.
- If draft_response is provided, use it as a base. Adapt resource names/IDs to match request_body \
while keeping the same structure and decoys. Do not explain changes — just output the adapted envelope.

Deception: If your response contains sensitive values (AKIA keys, passwords, tokens, ARNs with
prod/admin/root), call register_decoy() for each so we can track attacker use.
Use deception_hint if provided. Only register values that actually appear in aws_response.
"""

_GENERATOR_TOOLS = [
    {
        "name": "register_decoy",
        "description": (
            "Register a fake AWS resource value as a honeypot decoy trap. "
            "Call this when your response contains sensitive-looking values "
            "(access keys, passwords, tokens, role ARNs, secret names) "
            "that the attacker might try to use."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "decoy_service": {
                    "type": "string",
                    "description": "AWS service: iam, s3, secretsmanager, ssm, ec2, sts",
                },
                "decoy_type": {
                    "type": "string",
                    "description": "Resource type: access_key, role, bucket, secret, parameter, token",
                },
                "decoy_name": {
                    "type": "string",
                    "description": "Resource name or identifier as it appears in the response",
                },
                "decoy_value": {
                    "type": "string",
                    "description": "The exact sensitive value to track",
                },
            },
            "required": ["decoy_service", "decoy_type", "decoy_name", "decoy_value"],
        },
    }
]


def generate_agent(
    state: AgentState,
    schema: dict[str, Any] | None,
    *,
    request_valid: bool = True,
    validation_error: str = "",
    error_body: str = "",
    draft: str = "",
) -> dict[str, str]:
    if not request_valid:
        return {"aws_response": error_body}

    protocol = schema.get("protocol") if schema else ("query" if state["service"] in XML_SERVICES else "json")
    schema_prompt = schema.get("schema_prompt") if schema else "{}"
    operation = schema.get("operation_name") if schema else state["action"]
    decoys = _compact_decoys(state.get("active_decoys", []), state["service"])

    from moto.core.llm_agents.session_store import get_profile
    profile = get_profile(state["session_id"])
    intent = profile.get("intent", "")
    deception_hint = profile.get("deception_hint", "")

    body = state.get("body", {})
    prompt = (
        f"service={state['service']}\n"
        f"operation={operation}\n"
        f"protocol={protocol}\n"
        f"request_body={json.dumps(body, ensure_ascii=False, separators=(',', ':'))}\n"
        f"request_valid={str(request_valid).lower()}\n"
        f"validation_error={validation_error}\n"
        f"stage={state['attack_stage']}\n"
        f"attacker_type={state['attacker_type']}\n"
        + (f"attacker_intent={intent}\n" if intent else "")
        + (f"deception_hint={deception_hint}\n" if deception_hint else "")
        + f"decoy_hit={str(state.get('decoy_hit', False)).lower()}\n"
        f"active_decoys={decoys}\n"
        f"output_schema={schema_prompt}\n"
        + (f"draft_response={draft}\n" if draft else "")
    )

    try:
        raw, tool_calls, usage = call_claude_api_with_tools(
            prompt,
            model=_GENERATOR_MODEL,
            system_prompt=_GENERATOR_SYSTEM,
            temperature=_GENERATOR_TEMP,
            tools=_GENERATOR_TOOLS,
        )

        log_agent_debug(
            "generator",
            state["session_id"],
            turn=state["turn_count"],
            service=state["service"],
            action=state["action"],
            elapsed_ms=usage.get("elapsed_ms", 0.0),
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            tool_calls=tool_calls or None,
            response_content=raw,
        )

        # tool_calls 처리: register_decoy → decoy_store + fake_state_store 에 등록
        for tc in tool_calls:
            if tc["name"] == "register_decoy":
                _handle_register_decoy(state["session_id"], tc["input"])

        parsed = _extract_first_json(raw)
        return {"aws_response": parsed.get("aws_response", "")}
    except Exception as e:
        logger.warning("generate_agent failed: %s", e)
        return {"aws_response": _fallback_success(state, schema)}


def _extract_first_json(text: str) -> dict:
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in response")
    obj, _ = json.JSONDecoder().raw_decode(text, start)
    if not isinstance(obj, dict):
        raise ValueError("JSON root is not an object")
    return obj


def _handle_register_decoy(session_id: str, decoy_input: dict[str, Any]) -> None:
    try:
        from moto.core.llm_agents.decoy_store import add_decoy
        from moto.core.llm_agents.fake_state_store import apply_decoy
        add_decoy(session_id, decoy_input)
        apply_decoy(session_id, decoy_input)
        logger.info(
            "[DECOY_INJECTED] session=%s service=%s type=%s name=%s",
            session_id,
            decoy_input.get("decoy_service"),
            decoy_input.get("decoy_type"),
            decoy_input.get("decoy_name"),
        )
    except Exception as e:
        logger.warning("register_decoy failed: %s", e)


def _compact_decoys(decoys: list[dict[str, str]], service: str) -> str:
    relevant = [
        {
            "service": item.get("decoy_service", ""),
            "type": item.get("decoy_type", ""),
            "name": item.get("decoy_name", ""),
            "value": item.get("decoy_value", ""),
        }
        for item in decoys
        if item.get("decoy_service") in ("", service)
    ][:3]
    return json.dumps(relevant, ensure_ascii=False, separators=(",", ":"))


def _fallback_success(state: AgentState, schema: dict[str, Any] | None) -> str:
    if schema and schema.get("protocol") in ("query", "ec2", "rest-xml"):
        return "<Response><RequestId>00000000-0000-0000-0000-000000000000</RequestId></Response>"
    return "{}"
