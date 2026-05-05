from __future__ import annotations

from typing import Any, TypedDict


class AgentState(TypedDict):
    session_id: str
    service: str
    action: str
    body: dict[str, Any]
    history: list[str]
    turn_count: int
    attack_stage: str
    attacker_type: str
    response: str
    decoy_placed: bool
    decoy_hit: bool
    content_type: str
    active_decoys: list[dict[str, str]]
    source: str


class SessionProfile(TypedDict):
    attack_stage: str
    attacker_type: str
    confidence: float
    summary: str
    intent: str
    predicted_next: list[str]
    deception_hint: str
