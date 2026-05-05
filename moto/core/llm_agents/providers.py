from __future__ import annotations
# 미래형 타입 힌트를 문자열 평가 없이 사용할 수 있게 한다.

import json
# HTTP 요청/응답 body를 JSON으로 직렬화/역직렬화할 때 사용한다.

import os
# API 키와 기본 모델명을 환경변수에서 읽기 위해 사용한다.

import time

from typing import Any, Optional
# 함수 시그니처에 사용하는 타입 힌트를 가져온다.

from urllib.request import Request, urlopen
# 표준 라이브러리만으로 HTTP POST 요청을 보내기 위해 사용한다.


def call_gpt_api(
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: float = 20.0,
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
) -> tuple[str, dict[str, Any]]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set")

    model_name = model or os.getenv("MOTO_LLM_OPENAI_MODEL", "gpt-5.4-mini")
    messages: list[dict[str, Any]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload: dict[str, Any] = {
        "model": model_name,
        "messages": messages,
        "temperature": temperature,
    }

    started = time.perf_counter()
    response = _post_json(
        url="https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        payload=payload,
        timeout=timeout,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

    text = response.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
    usage = response.get("usage", {})
    usage_info: dict[str, Any] = {
        "model": model_name,
        "input_tokens": usage.get("prompt_tokens", 0),
        "output_tokens": usage.get("completion_tokens", 0),
        "elapsed_ms": elapsed_ms,
    }
    if usage:
        import logging
        logging.getLogger("turn_agent").info(
            "[USAGE] input=%d output=%d total=%d model=%s elapsed_ms=%.2f",
            usage.get("prompt_tokens", 0),
            usage.get("completion_tokens", 0),
            usage.get("total_tokens", 0),
            model_name,
            elapsed_ms,
        )
        try:
            from moto.core.llm_agents.metrics import log_metric
            log_metric(
                "llm_usage",
                provider="openai",
                model=model_name,
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
                elapsed_ms=elapsed_ms,
            )
        except Exception:
            pass
    return text.strip(), usage_info


def call_gpt_api_with_tools(
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: float = 30.0,
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
    tools: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set")

    model_name = model or os.getenv("MOTO_LLM_OPENAI_MODEL", "gpt-5.4-mini")

    # Anthropic tool format → OpenAI function format 변환
    openai_tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {}),
            },
        }
        for t in tools
    ]

    messages: list[dict[str, Any]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    executed_tools: list[dict[str, Any]] = []
    started = time.perf_counter()

    for _ in range(4):
        payload: dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "temperature": temperature,
            "tools": openai_tools,
            "tool_choice": "auto",
        }
        response = _post_json(
            url="https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            payload=payload,
            timeout=timeout,
        )
        choice = response.get("choices", [{}])[0]
        message = choice.get("message", {})
        finish_reason = choice.get("finish_reason", "stop")

        if finish_reason == "tool_calls":
            tool_calls = message.get("tool_calls", [])
            messages.append({
                "role": "assistant",
                "content": message.get("content"),
                "tool_calls": tool_calls,
            })
            for tc in tool_calls:
                func = tc.get("function", {})
                try:
                    args = json.loads(func.get("arguments", "{}"))
                except Exception:
                    args = {}
                executed_tools.append({"name": func.get("name", ""), "input": args})
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": "registered"})
            continue

        usage = response.get("usage", {})
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        if usage:
            import logging
            logging.getLogger("turn_agent").info(
                "[USAGE] input=%d output=%d total=%d model=%s elapsed_ms=%.2f",
                usage.get("prompt_tokens", 0),
                usage.get("completion_tokens", 0),
                usage.get("total_tokens", 0),
                model_name,
                elapsed_ms,
            )
            try:
                from moto.core.llm_agents.metrics import log_metric
                log_metric(
                    "llm_usage",
                    provider="openai",
                    model=model_name,
                    input_tokens=usage.get("prompt_tokens", 0),
                    output_tokens=usage.get("completion_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                    elapsed_ms=elapsed_ms,
                )
            except Exception:
                pass
        usage_info: dict[str, Any] = {
            "model": model_name,
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "elapsed_ms": elapsed_ms,
        }
        text = (message.get("content") or "").strip()
        return text, executed_tools, usage_info

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return "", executed_tools, {"model": model_name, "input_tokens": 0, "output_tokens": 0, "elapsed_ms": elapsed_ms}


def call_claude_api(
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: float = 20.0,
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
) -> tuple[str, dict[str, Any]]:
    # Anthropic Messages API를 호출해서 텍스트 응답을 받아오는 함수다.

    api_key = os.getenv("ANTHROPIC_API_KEY")
    # Anthropic API 키를 환경변수에서 읽는다.

    if not api_key:
        # API 키가 없으면 바로 예외를 발생시킨다.
        raise ValueError("ANTHROPIC_API_KEY is not set")

    payload: dict[str, Any] = {
        # Anthropic API에 보낼 JSON 요청 body를 만든다.
        "model": model
        or os.getenv("MOTO_LLM_ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
        # 사용할 Claude 모델명을 정한다. 인자가 우선이고, 없으면 환경변수, 그것도 없으면 기본값을 쓴다.
        "max_tokens": 2000,
        "temperature": temperature,
        # Claude가 생성할 최대 토큰 수를 정한다.
        "messages": [
            # Anthropic Messages API의 공식 messages 배열을 구성한다.
            {
                "role": "user",
                # 사용자 메시지라는 뜻이다.
                "content": prompt,
                # 실제 프롬프트 문자열을 넣는다.
            }
        ],
    }

    if system_prompt:
        # 시스템 프롬프트가 있으면 payload에 추가한다.
        # LLM의 역할과 출력 형식을 강제할 때 사용한다.
        payload["system"] = system_prompt

    started = time.perf_counter()
    response = _post_json(
        # 공통 POST 함수로 Anthropic Messages API를 호출한다.
        url="https://api.anthropic.com/v1/messages",
        # Anthropic Messages API 엔드포인트다.
        headers={
            # Anthropic 요청에 필요한 HTTP 헤더를 만든다.
            "x-api-key": api_key,
            # Anthropic 전용 API 키 헤더다.
            "anthropic-version": "2023-06-01",
            # 사용할 API 버전을 명시한다.
            "content-type": "application/json",
            # 요청 body가 JSON이라는 것을 명시한다.
        },
        payload=payload,
        # 위에서 만든 요청 body를 전달한다.
        timeout=timeout,
        # 네트워크 대기 시간을 초 단위로 전달한다.
    )

    parts: list[str] = []
    # 응답 안의 텍스트 조각들을 모을 리스트를 만든다.

    for item in response.get("content", []):
        # Anthropic 응답의 content 배열을 순회한다.
        if item.get("type") == "text":
            # 텍스트 타입 블록만 골라낸다.
            text = item.get("text")
            # 실제 생성된 텍스트를 읽는다.
            if text:
                # 비어 있지 않은 텍스트만 추가한다.
                parts.append(text)

    usage = response.get("usage", {})
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    usage_info: dict[str, Any] = {
        "model": payload.get("model", "unknown"),
        "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0),
        "elapsed_ms": elapsed_ms,
    }
    if usage:
        import logging
        _usage_logger = logging.getLogger("turn_agent")
        _usage_logger.info(
            "[USAGE] input=%d output=%d total=%d model=%s elapsed_ms=%.2f",
            usage.get("input_tokens", 0),
            usage.get("output_tokens", 0),
            usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            payload.get("model", "unknown"),
            elapsed_ms,
        )
        try:
            from moto.core.llm_agents.metrics import log_metric
            log_metric(
                "llm_usage",
                provider="anthropic",
                model=payload.get("model", "unknown"),
                input_tokens=usage.get("input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
                total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                elapsed_ms=elapsed_ms,
            )
        except Exception:
            pass

    return "\n".join(parts).strip(), usage_info
    # 여러 텍스트 조각을 하나의 문자열로 합쳐 최종 응답으로 돌려준다.


def call_claude_api_with_tools(
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: float = 30.0,
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
    tools: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    """Claude tool use 지원 버전. (text_response, executed_tool_calls, usage_info) 반환."""

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY is not set")

    model_name = model or os.getenv("MOTO_LLM_ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
    executed_tools: list[dict[str, Any]] = []

    started = time.perf_counter()
    for _ in range(4):
        payload: dict[str, Any] = {
            "model": model_name,
            "max_tokens": 2000,
            "temperature": temperature,
            "messages": messages,
            "tools": tools,
        }
        if system_prompt:
            payload["system"] = system_prompt

        response = _post_json(url="https://api.anthropic.com/v1/messages", headers=headers, payload=payload, timeout=timeout)
        stop_reason = response.get("stop_reason")
        content = response.get("content", [])

        if stop_reason == "tool_use":
            tool_uses = [c for c in content if c.get("type") == "tool_use"]
            messages.append({"role": "assistant", "content": content})
            tool_results = []
            for tu in tool_uses:
                executed_tools.append({"name": tu["name"], "input": tu.get("input", {})})
                tool_results.append({"type": "tool_result", "tool_use_id": tu["id"], "content": "registered"})
            messages.append({"role": "user", "content": tool_results})
            continue

        # end_turn — 최종 응답
        usage = response.get("usage", {})
        if usage:
            import logging
            _usage_logger = logging.getLogger("turn_agent")
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            _usage_logger.info(
                "[USAGE] input=%d output=%d total=%d model=%s elapsed_ms=%.2f",
                usage.get("input_tokens", 0),
                usage.get("output_tokens", 0),
                usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                model_name,
                elapsed_ms,
            )
            try:
                from moto.core.llm_agents.metrics import log_metric
                log_metric(
                    "llm_usage",
                    provider="anthropic",
                    model=model_name,
                    input_tokens=usage.get("input_tokens", 0),
                    output_tokens=usage.get("output_tokens", 0),
                    total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                    elapsed_ms=elapsed_ms,
                )
            except Exception:
                pass

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        usage_info: dict[str, Any] = {
            "model": model_name,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "elapsed_ms": elapsed_ms,
        }
        parts = [c["text"] for c in content if c.get("type") == "text" and c.get("text")]
        return "\n".join(parts).strip(), executed_tools, usage_info

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return "", executed_tools, {"model": model_name, "input_tokens": 0, "output_tokens": 0, "elapsed_ms": elapsed_ms}


def _post_json(
    *,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    # JSON POST 요청을 보내고 JSON 객체를 돌려주는 공통 헬퍼 함수다.

    request = Request(
        # urllib가 사용할 Request 객체를 만든다.
        url=url,
        # 요청 URL을 넣는다.
        headers=headers,
        # 요청 헤더를 넣는다.
        data=json.dumps(payload).encode("utf-8"),
        # payload를 JSON 문자열로 만든 뒤 바이트로 인코딩해 body에 넣는다.
        method="POST",
        # HTTP 메서드를 POST로 지정한다.
    )

    with urlopen(request, timeout=timeout) as response:
        # 지정한 timeout으로 실제 HTTP 요청을 보낸다.
        raw = response.read().decode("utf-8")
        # 응답 body 전체를 읽고 UTF-8 문자열로 디코딩한다.

    parsed = json.loads(raw)
    # 응답 문자열을 JSON으로 파싱한다.

    if not isinstance(parsed, dict):
        # 최상위 JSON이 객체가 아니면 예상한 형식이 아니라고 본다.
        raise ValueError("Expected JSON object response")

    return parsed
    # 파싱된 JSON 객체를 호출자에게 돌려준다.
