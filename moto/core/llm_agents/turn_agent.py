from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse

from moto.core.llm_agents.agents import analyst_agent, generate_agent, strategy_agent
from moto.core.llm_agents.agents.analyst import llm_analyst_agent
from moto.core.llm_agents.decoy_store import add_decoy, detect_decoy_hit, list_decoys
from moto.core.llm_agents.fake_state_store import apply_decoy
from moto.core.llm_agents.metrics import log_metric
from moto.core.llm_agents.request_parser import parse_request
from moto.core.llm_agents.response_cache import get_cached_response, set_cached_response
from moto.core.llm_agents.response_router import route_response
from moto.core.llm_agents.schema import get_service_schema
from moto.core.llm_agents.session_store import (
    append_history,
    clear_strategy_inflight,
    get_history,
    get_profile,
    mark_strategy_inflight,
    update_profile,
)
from moto.core.llm_agents.state import AgentState
from moto.core.llm_agents.validators import aws_error_response, validate_generated_response, validate_input


logger = logging.getLogger("turn_agent")
logger.setLevel(logging.DEBUG)

_log_path = os.path.join(os.path.dirname(__file__), "turn_agent.log")
if not logger.handlers:
    _fh = logging.FileHandler(_log_path)
    _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(_fh)


_BACKGROUND_AFTER_TURNS = int(os.getenv("HONEYPOT_BACKGROUND_AFTER_TURNS", "5"))
_PREGEN_MIN_CONFIDENCE = float(os.getenv("HONEYPOT_PREGEN_MIN_CONFIDENCE", "0.6"))


def run(
    url: str,
    headers: dict[str, str],
    body: Any,
    source: str = "unknown",
    service: Optional[str] = None,
    action: Optional[str] = None,
    method: Optional[str] = None,
) -> tuple[dict[str, str], str]:
    request_start = time.perf_counter()
    parsed_service, parsed_action, parsed_body = parse_request(url, headers, body)
    service = service or parsed_service
    action = action or parsed_action
    session_id = source or "unknown"

    history_before = get_history(session_id)
    profile = get_profile(session_id)
    url_path = urlparse(url).path
    schema = get_service_schema(service, action, url_path=url_path, method=method)
    if schema:
        action = schema["operation_name"]
        content_type = schema["content_type"]
    else:
        content_type = "application/json"

    active_decoys = list_decoys(session_id)
    decoy_hit = detect_decoy_hit(session_id, service, action, parsed_body)
    state: AgentState = {
        "session_id": session_id,
        "service": service,
        "action": action,
        "body": parsed_body,
        "history": history_before,
        "turn_count": len(history_before) + 1,
        "attack_stage": profile["attack_stage"],
        "attacker_type": profile["attacker_type"],
        "response": "",
        "decoy_placed": bool(active_decoys),
        "decoy_hit": decoy_hit,
        "content_type": content_type,
        "active_decoys": active_decoys,
        "source": source,
    }

    valid, validation_error = validate_input(schema, parsed_body)
    error_body = ""
    if not valid:
        error_body = aws_error_response(service, action, validation_error, (schema or {}).get("protocol", "json"))

    resp_body, response_source = route_response(
        state,
        schema,
        request_valid=valid,
        validation_error=validation_error,
        error_body=error_body,
    )

    history_after = append_history(session_id, service, action)

    # 빠른 규칙 기반 분석 (동기, 즉시)
    rule_profile = analyst_agent(session_id, history_after, parsed_body)
    update_profile(session_id, rule_profile)

    # 백그라운드: LLM analyst + pre-generation + strategy
    _schedule_background_jobs(session_id, history_after, parsed_body, state, schema)

    logger.info(
        "[EVENT] session=%s turn=%d service=%s action=%s stage=%s attacker=%s decoy=%s hit=%s",
        session_id,
        len(history_after),
        service,
        action,
        state["attack_stage"],
        state["attacker_type"],
        bool(active_decoys),
        decoy_hit,
    )
    log_metric(
        "request",
        session=session_id,
        turn=len(history_after),
        service=service,
        action=action,
        source=response_source,
        elapsed_ms=round((time.perf_counter() - request_start) * 1000, 2),
        content_type=content_type,
        body_bytes=len(resp_body.encode("utf-8")),
    )
    return {"Content-Type": content_type}, resp_body


def _schedule_background_jobs(
    session_id: str,
    history: list[str],
    body: dict[str, Any],
    base_state: AgentState,
    schema: Any,
) -> None:
    worker = threading.Thread(
        target=_run_analysis_job,
        args=(session_id, list(history), body, dict(base_state)),
        daemon=True,
        name=f"hpot-analysis-{session_id}",
    )
    worker.start()

    # strategy는 별도 조건 충족 시만 실행
    profile = get_profile(session_id)
    if (
        len(history) >= _BACKGROUND_AFTER_TURNS
        and profile["attack_stage"] in ("cred_access", "privesc", "exfil")
        and mark_strategy_inflight(session_id)
    ):
        strat_worker = threading.Thread(
            target=_run_strategy_job,
            args=(session_id, list(history), profile),
            daemon=True,
            name=f"hpot-strategy-{session_id}",
        )
        strat_worker.start()


def _run_analysis_job(
    session_id: str,
    history: list[str],
    body: dict[str, Any],
    base_state: dict,
) -> None:
    """[방법 1] LLM analyst → 프로파일 업데이트
       [방법 3] predicted_next 기반 pre-generation"""
    try:
        # 방법 1: LLM analyst
        llm_profile = llm_analyst_agent(session_id, history, body)
        update_profile(session_id, llm_profile)
        logger.info(
            "[LLM_ANALYST] session=%s intent=%s predicted=%s hint=%s",
            session_id,
            llm_profile.get("intent", ""),
            llm_profile.get("predicted_next", []),
            llm_profile.get("deception_hint", ""),
        )

        # 방법 3: pre-generation
        if llm_profile.get("confidence", 0) >= _PREGEN_MIN_CONFIDENCE:
            predicted = llm_profile.get("predicted_next", [])
            for op in predicted[:2]:
                if ":" in op:
                    svc, act = op.split(":", 1)
                    _pregen_operation(session_id, svc, act, base_state, llm_profile)

    except Exception as e:
        logger.warning("analysis job failed: %s", e)


def _pregen_operation(
    session_id: str,
    service: str,
    action: str,
    base_state: dict,
    profile: dict,
) -> None:
    """예측된 다음 operation을 미리 LLM 호출해서 캐시에 저장."""
    try:
        schema = get_service_schema(service, action)
        if not schema:
            return

        pred_state: AgentState = {
            "session_id": session_id,
            "service": service,
            "action": schema["operation_name"],
            "body": {},
            "history": base_state.get("history", []),
            "turn_count": base_state.get("turn_count", 1) + 1,
            "attack_stage": profile["attack_stage"],
            "attacker_type": profile["attacker_type"],
            "response": "",
            "decoy_placed": base_state.get("decoy_placed", False),
            "decoy_hit": False,
            "content_type": schema["content_type"],
            "active_decoys": base_state.get("active_decoys", []),
            "source": base_state.get("source", "unknown"),
        }

        # 이미 캐시에 있으면 생성 불필요
        if get_cached_response(pred_state, schema):
            return

        result = generate_agent(pred_state, schema, request_valid=True, validation_error="", error_body="")
        body = result.get("aws_response", "")
        if body and validate_generated_response(body, schema):
            set_cached_response(pred_state, schema, body)
            logger.info("[PREGEN] session=%s predicted=%s:%s cached", session_id, service, action)

    except Exception as e:
        logger.warning("pregen failed %s:%s — %s", service, action, e)


def _run_strategy_job(session_id: str, history: list[str], profile) -> None:
    try:
        decoy = strategy_agent(session_id, history, profile)
        if decoy:
            decoys = _expand_decoys(decoy)
            for item in decoys:
                add_decoy(session_id, item)
                apply_decoy(session_id, item)
            logger.info(
                "[DECOY_SPEC] session=%s count=%d reasoning=%s",
                session_id,
                len(decoys),
                decoy.get("reasoning", "?"),
            )
    finally:
        clear_strategy_inflight(session_id)


def _expand_decoys(raw: dict[str, str]) -> list[dict[str, str]]:
    grouped: dict[str, dict[str, str]] = {}
    for key, value in raw.items():
        if not key.startswith("decoys."):
            continue
        _, idx, field = key.split(".", 2)
        grouped.setdefault(idx, {})[field] = value
    if grouped:
        return [item for _, item in sorted(grouped.items()) if item]
    if raw.get("decoy_service") and raw.get("decoy_type"):
        return [raw]
    return []
