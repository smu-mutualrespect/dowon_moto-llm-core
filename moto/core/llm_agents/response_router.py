from __future__ import annotations

import os
import time
from typing import Any

from moto.core.llm_agents.agents import generate_agent
from moto.core.llm_agents.metrics import log_metric
from moto.core.llm_agents.response_cache import get_cached_response
from moto.core.llm_agents.state_renderer import render_state_response
from moto.core.llm_agents.state import AgentState
from moto.core.llm_agents.templates import render_template_response
from moto.core.llm_agents.validators import validate_generated_response
from moto.core.llm_agents.xml_converter import maybe_convert_to_xml


_TEMPLATE_FIRST = os.getenv("HONEYPOT_TEMPLATE_FIRST", "true").lower() not in {"0", "false", "no"}


def route_response(
    state: AgentState,
    schema: dict[str, Any] | None,
    *,
    request_valid: bool,
    validation_error: str,
    error_body: str,
) -> tuple[str, str]:
    start = time.perf_counter()
    source = "error"
    if not request_valid:
        return error_body, source

    rendered = render_state_response(state, schema)
    if rendered and validate_generated_response(rendered, schema):
        source = "state"
        _log_route(state, source, start)
        return rendered, source

    if _TEMPLATE_FIRST:
        templated = render_template_response(state, schema)
        if templated and validate_generated_response(templated, schema):
            source = "template"
            _log_route(state, source, start)
            return templated, source

    draft = get_cached_response(state, schema)
    source = "draft" if draft else "llm"

    generated = generate_agent(
        state,
        schema,
        request_valid=request_valid,
        validation_error=validation_error,
        error_body=error_body,
        draft=draft or "",
    ).get("aws_response", "")
    generated = maybe_convert_to_xml(generated, schema)
    if generated and validate_generated_response(generated, schema):
        _log_route(state, source, start)
        return generated, source

    fallback = "{}" if state["content_type"] != "text/xml" else "<Response />"
    source = "fallback"
    _log_route(state, source, start)
    return fallback, source


def _log_route(state: AgentState, source: str, start: float) -> None:
    log_metric(
        "route",
        session=state["session_id"],
        turn=state["turn_count"],
        service=state["service"],
        action=state["action"],
        source=source,
        elapsed_ms=round((time.perf_counter() - start) * 1000, 2),
        stage=state["attack_stage"],
        attacker_type=state["attacker_type"],
        decoy_hit=state.get("decoy_hit", False),
    )
