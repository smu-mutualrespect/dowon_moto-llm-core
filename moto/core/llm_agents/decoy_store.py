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
    haystack = f"{service} {action} {body}".lower()
    hit = False
    with _lock:
        for decoy in _decoys.get(session_id, []):
            values = [
                decoy.get("decoy_name", ""),
                decoy.get("decoy_value", ""),
                decoy.get("decoy_service", ""),
            ]
            if any(value and value.lower() in haystack for value in values):
                _hits.setdefault(session_id, []).append(decoy)
                hit = True
        return hit


def list_hits(session_id: str) -> list[dict[str, str]]:
    with _lock:
        return list(_hits.get(session_id, []))
