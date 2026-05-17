from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from moto.core.llm_agents.state import AgentState


_lock = threading.RLock()
_cache: dict[str, str] = {}


def get_cached_response(state: AgentState, schema: dict[str, Any] | None) -> str | None:
    with _lock:
        return _cache.get(_cache_key(state, schema))


def set_cached_response(state: AgentState, schema: dict[str, Any] | None, body: str) -> None:
    if not body:
        return
    with _lock:
        _cache[_cache_key(state, schema)] = body


def _cache_key(state: AgentState, schema: dict[str, Any] | None) -> str:
    decoys = [
        {
            "service": item.get("decoy_service", ""),
            "type": item.get("decoy_type", ""),
            "name": item.get("decoy_name", ""),
        }
        for item in state.get("active_decoys", [])
    ]
    payload = {
        "service": state["service"],
        "action": state["action"],
        "protocol": (schema or {}).get("protocol", "json"),
        "stage": state["attack_stage"],
        "attacker_type": state["attacker_type"],
        "decoy_hit": state.get("decoy_hit", False),
        "decoys": decoys,
        "request_scope": _request_scope(state),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _request_scope(state: AgentState) -> dict[str, Any]:
    """Keep cache hits broad for list APIs and precise for resource-specific APIs."""
    action = str(state.get("action", "")).lower()
    if action.startswith("list") and action not in {"listobjects", "listobjectsv2"}:
        return {}
    body = state.get("body", {})
    if not isinstance(body, dict):
        return {}
    interesting = {
        "arn",
        "bucket",
        "encodedmessage",
        "layerdigest",
        "layerdigests",
        "name",
        "policyarn",
        "policysourcearn",
        "repositoryname",
        "resourcearn",
        "resourcepolicy",
        "secretid",
        "uploadid",
        "username",
        "volumeid",
        "volumeids",
    }
    scoped = {}
    for key, value in body.items():
        normalized = "".join(ch for ch in str(key).lower() if ch.isalnum())
        if normalized in interesting:
            scoped[str(key)] = value
    return scoped
