from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

_LOG_DIR = os.path.expanduser("~")

_PATHS = {
    "analyst":        os.path.join(_LOG_DIR, "moto_agent_analyst.json"),
    "strategy_agent": os.path.join(_LOG_DIR, "moto_agent_strategy_agent.json"),
    "response":       os.path.join(_LOG_DIR, "moto_agent_response.json"),
    "orchestrator":   os.path.join(_LOG_DIR, "moto_agent_orchestrator.json"),
}


def log_analyst(
    session_id: str,
    service: str,
    action: str,
    request_count: int,
    output: Optional[dict],
    input_tokens: int,
    output_tokens: int,
) -> None:
    _append(_PATHS["analyst"], {
        "timestamp": _now(),
        "session_id": session_id,
        "service": service,
        "action": action,
        "request_count": request_count,
        "tokens": {"input": input_tokens, "output": output_tokens, "total": input_tokens + output_tokens},
        "output": output,
    })


def log_strategy_agent(
    session_id: str,
    service: str,
    action: str,
    request_count: int,
    output: Optional[dict],
    input_tokens: int,
    output_tokens: int,
) -> None:
    _append(_PATHS["strategy_agent"], {
        "timestamp": _now(),
        "session_id": session_id,
        "service": service,
        "action": action,
        "request_count": request_count,
        "tokens": {"input": input_tokens, "output": output_tokens, "total": input_tokens + output_tokens},
        "output": output,
    })


def log_response(
    session_id: str,
    service: str,
    action: str,
    request_count: int,
    response_text: str,
    input_tokens: int,
    output_tokens: int,
) -> None:
    _append(_PATHS["response"], {
        "timestamp": _now(),
        "session_id": session_id,
        "service": service,
        "action": action,
        "request_count": request_count,
        "tokens": {"input": input_tokens, "output": output_tokens, "total": input_tokens + output_tokens},
        "output": _try_parse_json(response_text),
    })


def log_orchestrator(
    session_id: str,
    service: str,
    action: str,
    request_count: int,
    input_tokens: int,
    output_tokens: int,
) -> None:
    _append(_PATHS["orchestrator"], {
        "timestamp": _now(),
        "session_id": session_id,
        "service": service,
        "action": action,
        "request_count": request_count,
        "tokens": {"input": input_tokens, "output": output_tokens, "total": input_tokens + output_tokens},
    })


def _append(path: str, entry: dict) -> None:
    try:
        existing: list[Any] = []
        if os.path.exists(path):
            with open(path, "r") as f:
                existing = json.load(f)
        existing.append(entry)
        with open(path, "w") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _try_parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
