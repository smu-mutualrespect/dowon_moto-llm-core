from __future__ import annotations

import re
import threading
from collections import defaultdict
from typing import Any

from moto.core.llm_agents.state import SessionProfile


_lock = threading.RLock()
_history: dict[str, list[str]] = defaultdict(list)
_profiles: dict[str, SessionProfile] = {}
_inflight_strategy: set[str] = set()


_CRED_ACTIONS = {
    "createaccesskey",
    "listaccesskeys",
    "getsecretvalue",
    "listsecrets",
    "getparameter",
    "getparameters",
    "getparametersbypath",
}
_PRIVESC_ACTIONS = {
    "assumerole",
    "attachuserpolicy",
    "attachrolepolicy",
    "putuserpolicy",
    "putrolepolicy",
    "createpolicyversion",
    "simulateprincipalpolicy",
}
_EXFIL_ACTIONS = {
    "getobject",
    "selectobjectcontent",
    "startqueryexecution",
    "createdataexport",
    "exportfindings",
}


def get_history(session_id: str) -> list[str]:
    with _lock:
        return list(_history.get(session_id, []))


def append_history(session_id: str, service: str, action: str) -> list[str]:
    entry = f"{service}:{action}"
    with _lock:
        _history[session_id].append(entry)
        return list(_history[session_id])


def get_turn_count(session_id: str) -> int:
    with _lock:
        return len(_history.get(session_id, []))


def get_profile(session_id: str) -> SessionProfile:
    with _lock:
        return _profiles.get(
            session_id,
            {
                "attack_stage": "recon",
                "attacker_type": "unknown",
                "confidence": 0.0,
                "summary": "No session analysis yet.",
                "intent": "",
                "predicted_next": [],
                "deception_hint": "",
            },
        )


def update_profile(session_id: str, profile: SessionProfile) -> None:
    with _lock:
        _profiles[session_id] = profile


def mark_strategy_inflight(session_id: str) -> bool:
    with _lock:
        if session_id in _inflight_strategy:
            return False
        _inflight_strategy.add(session_id)
        return True


def clear_strategy_inflight(session_id: str) -> None:
    with _lock:
        _inflight_strategy.discard(session_id)


def analyze_session(history: list[str], current_body: dict[str, Any] | None = None) -> SessionProfile:
    actions = [_action_name(item) for item in history]
    services = {_service_name(item) for item in history}

    stage = "recon"
    confidence = 0.55 if history else 0.0
    if any(action in _EXFIL_ACTIONS for action in actions):
        stage, confidence = "exfil", 0.85
    elif any(action in _PRIVESC_ACTIONS for action in actions):
        stage, confidence = "privesc", 0.82
    elif any(action in _CRED_ACTIONS for action in actions):
        stage, confidence = "cred_access", 0.8

    attacker_type = "unknown"
    if len(history) >= 8 and len(services) >= 4:
        attacker_type = "script_kiddie"
    if _looks_like_internal_knowledge(history, current_body or {}):
        attacker_type = "insider"
        confidence = max(confidence, 0.75)
    if len(history) >= 6 and 1 <= len(services) <= 2 and stage != "recon":
        attacker_type = "apt"
        confidence = max(confidence, 0.78)

    summary = _summarize(history, stage, attacker_type)
    return {
        "attack_stage": stage,
        "attacker_type": attacker_type,
        "confidence": confidence,
        "summary": summary,
        "intent": "",
        "predicted_next": [],
        "deception_hint": "",
    }


def _service_name(entry: str) -> str:
    return entry.split(":", 1)[0].lower()


def _action_name(entry: str) -> str:
    if ":" in entry:
        entry = entry.split(":", 1)[1]
    return re.sub(r"[^a-z0-9]", "", entry.lower())


def _looks_like_internal_knowledge(history: list[str], body: dict[str, Any]) -> bool:
    text = " ".join(history + [str(v) for v in body.values()]).lower()
    markers = ("prod-", "production", "payroll", "finance", "backup", "root", "admin", "breakglass")
    return any(marker in text for marker in markers)


def _summarize(history: list[str], stage: str, attacker_type: str) -> str:
    if not history:
        return "No previous commands."
    tail = ", ".join(history[-5:])
    return f"{len(history)} commands observed; recent={tail}; stage={stage}; type={attacker_type}."
