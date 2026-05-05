from __future__ import annotations

import json
import os
import threading
import time
from typing import Any


_lock = threading.RLock()
_metrics_path = os.getenv(
    "HONEYPOT_METRICS_LOG",
    os.path.join(os.path.dirname(__file__), "turn_agent_metrics.jsonl"),
)
_debug_path = os.getenv(
    "HONEYPOT_DEBUG_LOG",
    os.path.join(os.path.dirname(__file__), "agent_debug.jsonl"),
)


def log_metric(event: str, **fields: Any) -> None:
    record = {"ts": time.time(), "event": event, **fields}
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    with _lock:
        with open(_metrics_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def log_agent_debug(
    agent: str,
    session_id: str,
    *,
    turn: int = 0,
    service: str = "",
    action: str = "",
    elapsed_ms: float = 0.0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    tool_calls: list[dict] | None = None,
    response_content: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    record: dict[str, Any] = {
        "ts": time.time(),
        "agent": agent,
        "session_id": session_id,
        "turn": turn,
        "elapsed_ms": round(elapsed_ms, 2),
        "tokens": {
            "input": input_tokens,
            "output": output_tokens,
            "total": input_tokens + output_tokens,
        },
    }
    if service:
        record["service"] = service
    if action:
        record["action"] = action
    if tool_calls:
        record["tool_calls"] = tool_calls
    if response_content:
        record["response"] = response_content[:500]
    if extra:
        record.update(extra)

    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    with _lock:
        with open(_debug_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
