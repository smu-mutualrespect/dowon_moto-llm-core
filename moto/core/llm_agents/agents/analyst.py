from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from moto.core.llm_agents.metrics import log_agent_debug, log_metric
from moto.core.llm_agents.providers import call_gpt_api
from moto.core.llm_agents.session_store import analyze_session
from moto.core.llm_agents.state import SessionProfile

logger = logging.getLogger("turn_agent")

_ANALYST_MODEL = os.getenv("HONEYPOT_ANALYST_MODEL", "gpt-5.4-mini")
_ANALYST_TEMP = float(os.getenv("HONEYPOT_ANALYST_TEMP", "0.2"))

_ANALYST_SYSTEM = """\
You are a cybersecurity analyst monitoring an AWS API honeypot.
Analyze the session history to understand the attacker's intent and predict their next move.

Output ONLY valid JSON:
{
  "attack_stage": "recon|cred_access|privesc|exfil",
  "attacker_type": "unknown|script_kiddie|insider|apt",
  "confidence": 0.0,
  "intent": "<one sentence: what the attacker specifically wants to achieve>",
  "predicted_next": ["service:OperationName"],
  "deception_hint": "<one sentence: what fake resource to plant to trap this attacker>",
  "summary": "<brief 1-2 sentence analysis>"
}

Guidelines:
- predicted_next: 1-2 most likely next AWS API calls based on the pattern
- deception_hint: be specific (e.g. "plant a fake RDS password in secretsmanager named prod/rds/master")
- attacker_type: script_kiddie=broad scanning, insider=uses internal resource names, apt=stealthy focused
"""


def analyst_agent(
    session_id: str,
    history: list[str],
    current_body: dict[str, Any] | None = None,
) -> SessionProfile:
    profile = analyze_session(history, current_body)
    log_metric(
        "analyst",
        session=session_id,
        turn=len(history),
        attack_stage=profile["attack_stage"],
        attacker_type=profile["attacker_type"],
        confidence=profile["confidence"],
        summary=profile["summary"],
        source="rules",
    )
    return profile


def llm_analyst_agent(
    session_id: str,
    history: list[str],
    current_body: dict[str, Any] | None = None,
) -> SessionProfile:
    base = analyze_session(history, current_body)
    if not history:
        return base

    prompt = (
        f"session_id={session_id}\n"
        f"history={json.dumps(history[-15:], ensure_ascii=False, separators=(',', ':'))}\n"
        f"current_body={json.dumps(current_body or {}, ensure_ascii=False, separators=(',', ':'))}\n"
        f"rule_stage={base['attack_stage']}\n"
        f"rule_attacker_type={base['attacker_type']}\n"
    )

    try:
        raw, usage = call_gpt_api(
            prompt,
            model=_ANALYST_MODEL,
            system_prompt=_ANALYST_SYSTEM,
            temperature=_ANALYST_TEMP,
            timeout=20.0,
        )
        start = raw.find("{")
        if start == -1:
            raise ValueError("No JSON in analyst response")
        parsed, _ = json.JSONDecoder().raw_decode(raw, start)

        profile: SessionProfile = {
            "attack_stage": str(parsed.get("attack_stage", base["attack_stage"])),
            "attacker_type": str(parsed.get("attacker_type", base["attacker_type"])),
            "confidence": float(parsed.get("confidence", base["confidence"])),
            "summary": str(parsed.get("summary", base["summary"])),
            "intent": str(parsed.get("intent", "")),
            "predicted_next": [str(x) for x in parsed.get("predicted_next", [])],
            "deception_hint": str(parsed.get("deception_hint", "")),
        }
        log_metric(
            "analyst",
            session=session_id,
            turn=len(history),
            attack_stage=profile["attack_stage"],
            attacker_type=profile["attacker_type"],
            confidence=profile["confidence"],
            summary=profile["summary"],
            source="llm",
            intent=profile["intent"],
            predicted_next=profile["predicted_next"],
        )
        log_agent_debug(
            "llm_analyst",
            session_id,
            turn=len(history),
            elapsed_ms=usage.get("elapsed_ms", 0.0),
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            response_content=raw,
            extra={
                "attack_stage": profile["attack_stage"],
                "attacker_type": profile["attacker_type"],
                "intent": profile["intent"],
            },
        )
        return profile

    except Exception as e:
        logger.warning("llm_analyst_agent failed: %s", e)
        return base
