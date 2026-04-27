from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional


class Bait:
    def __init__(self, bait_type: str, value: str, planted_at: int) -> None:
        self.id = f"bait-{uuid.uuid4().hex[:8]}"
        self.type = bait_type
        self.value = value
        self.planted_at = planted_at
        self.status = "pending"
        self.taken_at: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "planted_at": self.planted_at,
            "status": self.status,
            "taken_at": self.taken_at,
        }


class AttackSession:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.first_seen = _now()
        self.last_seen = self.first_seen
        self.request_count = 0
        self.threat_level = "unknown"
        self.current_stage = "정찰"
        self.current_strategy = "observe"
        self.actions: list[dict] = []
        self.stage_history: list[dict] = []
        self.strategy_history: list[dict] = []
        self.baits: list[Bait] = []

    def record_request(
        self,
        service: str,
        action: str,
        params: dict,
        body: Any,
    ) -> Optional[str]:
        matched_bait_id = self._match_baits(params)
        self.actions.append({
            "timestamp": _now(),
            "service": service,
            "action": action,
            "params": params,
            "body": str(body)[:500],
            "matched_bait": matched_bait_id,
        })
        self.request_count += 1
        self.last_seen = _now()
        return matched_bait_id

    def _match_baits(self, params: dict) -> Optional[str]:
        params_str = str(params).lower()
        for bait in self.baits:
            if bait.status != "pending":
                continue
            if bait.value.lower() in params_str:
                bait.status = "taken"
                bait.taken_at = self.request_count
                return bait.id
        return None

    def register_bait(self, bait_type: str, value: str) -> Bait:
        bait = Bait(
            bait_type=bait_type,
            value=value,
            planted_at=self.request_count,
        )
        self.baits.append(bait)
        return bait

    def update_stage_and_strategy(
        self, stage: str, strategy: str, threat_level: str
    ) -> None:
        if stage != self.current_stage:
            if self.stage_history:
                self.stage_history[-1]["request_range"][1] = self.request_count - 1
            self.stage_history.append({
                "stage": stage,
                "request_range": [self.request_count, self.request_count],
            })
            self.current_stage = stage

        if strategy != self.current_strategy:
            if self.strategy_history:
                self.strategy_history[-1]["request_range"][1] = self.request_count - 1
            self.strategy_history.append({
                "strategy": strategy,
                "request_range": [self.request_count, self.request_count],
                "baits_taken": 0,
            })
            self.current_strategy = strategy

        self.threat_level = threat_level

    def baits_taken_count(self) -> int:
        return sum(1 for b in self.baits if b.status == "taken")

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "request_count": self.request_count,
            "threat_level": self.threat_level,
            "current_stage": self.current_stage,
            "current_strategy": self.current_strategy,
            "actions": self.actions,
            "stage_history": self.stage_history,
            "strategy_history": self.strategy_history,
            "baits": [b.to_dict() for b in self.baits],
        }


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, AttackSession] = {}
        self._lock = threading.Lock()

    def get_or_create(self, session_id: str) -> AttackSession:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = AttackSession(session_id)
            return self._sessions[session_id]

    def get(self, session_id: str) -> Optional[AttackSession]:
        return self._sessions.get(session_id)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_store = SessionStore()


def get_store() -> SessionStore:
    return _store
