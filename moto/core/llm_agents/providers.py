from __future__ import annotations

import os
import pathlib
from typing import Any, NamedTuple, Optional

import requests as _requests


def _load_dotenv() -> None:
    env_path = pathlib.Path.home() / ".env"
    if not env_path.exists():
        return
    with env_path.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()


class LLMResult(NamedTuple):
    text: str
    input_tokens: int
    output_tokens: int


def call_gpt_api(
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: float = 20.0,
) -> LLMResult:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set")

    payload = {
        "model": model or os.getenv("MOTO_LLM_OPENAI_MODEL", "gpt-4o-mini"),
        "input": [{"role": "user", "content": prompt}],
    }

    response = _post_json(
        url="https://api.openai.com/v1/responses",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        payload=payload,
        timeout=timeout,
    )

    parts: list[str] = []
    for item in response.get("output", []):
        for content in item.get("content", []):
            if content.get("type") == "output_text":
                text = content.get("text")
                if text:
                    parts.append(text)

    usage = response.get("usage", {})
    return LLMResult(
        text="\n".join(parts).strip(),
        input_tokens=usage.get("input_tokens", 0),
        output_tokens=usage.get("output_tokens", 0),
    )


def call_claude_api(
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: float = 20.0,
) -> LLMResult:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY is not set")

    payload = {
        "model": model or os.getenv("MOTO_LLM_ANTHROPIC_MODEL", "claude-3-5-sonnet-latest"),
        "max_tokens": 2000,
        "messages": [{"role": "user", "content": prompt}],
    }

    response = _post_json(
        url="https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        payload=payload,
        timeout=timeout,
    )

    parts: list[str] = []
    for item in response.get("content", []):
        if item.get("type") == "text":
            text = item.get("text")
            if text:
                parts.append(text)

    usage = response.get("usage", {})
    return LLMResult(
        text="\n".join(parts).strip(),
        input_tokens=usage.get("input_tokens", 0),
        output_tokens=usage.get("output_tokens", 0),
    )


def call_gpt_with_tools(
    messages: list[dict],
    tools: list[dict],
    *,
    model: Optional[str] = None,
    timeout: float = 30.0,
) -> tuple[dict, int, int]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set")

    payload = {
        "model": model or os.getenv("MOTO_LLM_OPENAI_MODEL", "gpt-4o-mini"),
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
    }

    resp = _requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()

    message = data["choices"][0]["message"]
    usage = data.get("usage", {})
    return message, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)


def _post_json(
    *,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    resp = _requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    parsed = resp.json()
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object response")
    return parsed
