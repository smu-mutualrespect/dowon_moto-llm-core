from __future__ import annotations

import threading
from typing import Any


_lock = threading.RLock()
_decoys: dict[str, list[dict[str, str]]] = {}
_hits: dict[str, list[dict[str, str]]] = {}


def add_decoy(session_id: str, decoy: dict[str, Any]) -> None:
    normalized = {str(k): str(v) for k, v in decoy.items() if v is not None}
    if not normalized:
        return
    with _lock:
        existing = _decoys.setdefault(session_id, [])
        key = (normalized.get("decoy_type"), normalized.get("decoy_name"))
        if key not in {(d.get("decoy_type"), d.get("decoy_name")) for d in existing}:
            existing.append(normalized)


def list_decoys(session_id: str) -> list[dict[str, str]]:
    with _lock:
        return list(_decoys.get(session_id, []))


def detect_decoy_hit(session_id: str, service: str, action: str, body: dict[str, Any]) -> bool:
    body_values = _flatten_values(body)
    hit = False
    with _lock:
        for decoy in _decoys.get(session_id, []):
            targets = [
                decoy.get("decoy_name", "").lower(),
                decoy.get("decoy_value", "").lower(),
            ]
            if any(t and t in body_values for t in targets):
                _hits.setdefault(session_id, []).append(decoy)
                hit = True
        return hit


def _flatten_values(body: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(body, dict):
        for v in body.values():
            result |= _flatten_values(v)
    elif isinstance(body, list):
        for item in body:
            result |= _flatten_values(item)
    elif body is not None:
        result.add(str(body).lower())
    return result


def list_hits(session_id: str) -> list[dict[str, str]]:
    with _lock:
        return list(_hits.get(session_id, []))
