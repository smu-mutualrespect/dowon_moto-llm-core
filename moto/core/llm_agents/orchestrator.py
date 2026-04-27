from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from typing import Any

from moto.core.llm_agents import session_store as _store_module
from moto.core.llm_agents import debug_logger
from moto.core.llm_agents.agents import analyst, strategy_agent, response_agent
from moto.core.llm_agents.providers import call_gpt_with_tools

_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_threat",
            "description": (
                "Analyze the attack session history to reassess threat level, "
                "attack phase, and strategy. Call this when you need a fresh evaluation."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "plan_bait",
            "description": (
                "Design bait to embed in the AWS response. "
                "Call this when strategy is lure, engage, or trap."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_response",
            "description": (
                "Generate the final AWS API response to return to the attacker. "
                "Always call this as the last step."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "bait_instructions": {
                        "type": "string",
                        "description": "Bait instructions from plan_bait. Omit if no bait.",
                    }
                },
                "required": [],
            },
        },
    },
]


@dataclass
class RequestContext:
    service: str
    action: str
    body: Any
    ip: str = "unknown"
    user_agent: str = ""
    params: dict = field(default_factory=dict)
    method: str = "POST"
    url: str = ""


def _prefetch_schema(service: str, action: str) -> None:
    """오케스트레이터 LLM 호출과 병렬로 스키마를 미리 캐싱."""
    cache_key = f"{service}.{action}"
    if cache_key in response_agent._schema_cache:
        return
    model = os.getenv("MOTO_LLM_OPENAI_MODEL", "gpt-4o-mini")
    t = threading.Thread(
        target=response_agent._get_schema,
        args=(service, action, model),
        daemon=True,
    )
    t.start()


def run(ctx: RequestContext) -> tuple[int, dict, str]:
    session_id = f"{ctx.ip}|{ctx.user_agent[:64]}"
    store = _store_module.get_store()
    session = store.get_or_create(session_id)

    # Layer 5: SessionManager — bait 매칭 및 요청 기록
    session.record_request(ctx.service, ctx.action, ctx.params, ctx.body)

    # 스키마 pre-fetch: 오케스트레이터가 결정하는 동안 백그라운드에서 병렬 실행
    _prefetch_schema(ctx.service, ctx.action)

    # Layer 3: Orchestrator LLM — tool use로 흐름 자율 결정
    messages = [
        {"role": "system", "content": _build_system_prompt(ctx, session)},
        {
            "role": "user",
            "content": (
                f"Incoming AWS request: service={ctx.service}, action={ctx.action}. "
                "Coordinate the honeypot response."
            ),
        },
    ]

    response_text = json.dumps({"message": "llm_fallback!!"})
    total_in_tok = 0
    total_out_tok = 0

    for _ in range(5):
        message, in_tok, out_tok = call_gpt_with_tools(messages, _TOOLS)
        total_in_tok += in_tok
        total_out_tok += out_tok
        messages.append(message)

        tool_calls = message.get("tool_calls")
        if not tool_calls:
            break

        names = [tc["function"]["name"] for tc in tool_calls]

        # analyze_threat + generate_response 동시 호출인 경우에만 병렬 실행
        # plan_bait는 결과가 generate_response에 필요하므로 항상 순차 실행
        parallel_ok = (
            "generate_response" in names
            and len(tool_calls) > 1
            and "plan_bait" not in names
        )
        if parallel_ok:
            response_text = _execute_parallel(tool_calls, ctx, session, response_text)
            debug_logger.log_orchestrator(
                session_id=session.session_id,
                service=ctx.service,
                action=ctx.action,
                request_count=session.request_count,
                input_tokens=total_in_tok,
                output_tokens=total_out_tok,
            )
            return 200, {"Content-Type": "application/json"}, response_text

        # 단일 또는 generate_response 없는 경우 → 순차 실행
        for tool_call in tool_calls:
            name = tool_call["function"]["name"]
            args = json.loads(tool_call["function"]["arguments"] or "{}")
            result, response_text = _execute_tool(name, args, ctx, session, response_text)

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call["id"],
                "content": json.dumps(result),
            })

            if name == "generate_response":
                debug_logger.log_orchestrator(
                    session_id=session.session_id,
                    service=ctx.service,
                    action=ctx.action,
                    request_count=session.request_count,
                    input_tokens=total_in_tok,
                    output_tokens=total_out_tok,
                )
                return 200, {"Content-Type": "application/json"}, response_text

    debug_logger.log_orchestrator(
        session_id=session.session_id,
        service=ctx.service,
        action=ctx.action,
        request_count=session.request_count,
        input_tokens=total_in_tok,
        output_tokens=total_out_tok,
    )
    return 200, {"Content-Type": "application/json"}, response_text


def _execute_parallel(
    tool_calls: list,
    ctx: RequestContext,
    session: Any,
    current_response_text: str,
) -> str:
    """generate_response는 즉시 실행하고, 나머지 tool은 백그라운드 스레드로 실행."""
    generate_tc = None
    background_tcs = []

    for tc in tool_calls:
        if tc["function"]["name"] == "generate_response":
            generate_tc = tc
        else:
            background_tcs.append(tc)

    # 백그라운드 tool들 (analyze_threat, plan_bait) → daemon 스레드로 실행
    for tc in background_tcs:
        name = tc["function"]["name"]
        args = json.loads(tc["function"]["arguments"] or "{}")
        t = threading.Thread(
            target=_execute_tool,
            args=(name, args, ctx, session, current_response_text),
            daemon=True,
        )
        t.start()

    # generate_response → 즉시 실행 후 반환
    args = json.loads(generate_tc["function"]["arguments"] or "{}")
    _, response_text = _execute_tool("generate_response", args, ctx, session, current_response_text)
    return response_text


def _execute_tool(
    name: str,
    args: dict,
    ctx: RequestContext,
    session: Any,
    current_response_text: str,
) -> tuple[dict, str]:
    if name == "analyze_threat":
        output, in_tok, out_tok = analyst.analyze(session)
        session.update_stage_and_strategy(
            stage=output["phase"],
            strategy=output["strategy"],
            threat_level=output["threat_level"],
        )
        debug_logger.log_analyst(
            session_id=session.session_id,
            service=ctx.service,
            action=ctx.action,
            request_count=session.request_count,
            output=output,
            input_tokens=in_tok,
            output_tokens=out_tok,
        )
        return output, current_response_text

    if name == "plan_bait":
        output, in_tok, out_tok = strategy_agent.plan(
            strategy=session.current_strategy,
            service=ctx.service,
            action=ctx.action,
            session=session,
        )
        for marker in output.get("bait_markers", []):
            session.register_bait(marker["type"], marker["value"])
        debug_logger.log_strategy_agent(
            session_id=session.session_id,
            service=ctx.service,
            action=ctx.action,
            request_count=session.request_count,
            output=output,
            input_tokens=in_tok,
            output_tokens=out_tok,
        )
        return output, current_response_text

    if name == "generate_response":
        bait_instructions = args.get("bait_instructions")
        pending_markers = [
            {"type": b.type, "value": b.value}
            for b in session.baits
            if b.status == "pending"
        ]
        try:
            result = response_agent.generate(
                service=ctx.service,
                action=ctx.action,
                body=ctx.body,
                bait_instructions=bait_instructions,
                bait_markers=pending_markers if pending_markers else None,
            )
            text = result.text
            in_tok, out_tok = result.input_tokens, result.output_tokens
        except Exception:
            text = json.dumps({"message": "llm_fallback!!"})
            in_tok = out_tok = 0

        debug_logger.log_response(
            session_id=session.session_id,
            service=ctx.service,
            action=ctx.action,
            request_count=session.request_count,
            response_text=text,
            input_tokens=in_tok,
            output_tokens=out_tok,
        )
        return {"status": "generated"}, text

    return {"error": f"unknown tool: {name}"}, current_response_text


def _build_system_prompt(ctx: RequestContext, session: Any) -> str:
    recent_actions = "\n".join(
        f"  [{i+1}] {a['service']}:{a['action']} bait_hit={a.get('matched_bait')}"
        for i, a in enumerate(session.actions[-10:])
    ) or "  none"

    baits_summary = "\n".join(
        f"  {b.type}={b.value} status={b.status}"
        for b in session.baits
    ) or "  none"

    return f"""You are an autonomous honeypot operator managing a fake AWS environment.

Goal: Keep the attacker engaged as long as possible while gathering maximum intelligence.
      Make every response look completely real. Never reveal this is a honeypot.

Current session:
- request_count: {session.request_count}
- phase: {session.current_stage}
- strategy: {session.current_strategy}
- baits_planted: {len(session.baits)}
- baits_taken: {session.baits_taken_count()}

Recent attacker actions (latest up to 10):
{recent_actions}

Active baits:
{baits_summary}

Tools available:
- analyze_threat: Re-analyze the full attack pattern and get updated phase/strategy recommendation
- plan_bait: Design bait to embed in the response based on current strategy
- generate_response: Generate the final AWS API response — must always be called

Execution rules:
- analyze_threat + generate_response: can be called together in one response. analyze_threat runs in the background and its result is applied to the NEXT request.
- plan_bait: MUST be called alone first. After receiving the bait_instructions from the result, call generate_response in the next step with those bait_instructions.
- generate_response: must always be called as the final step in every request."""
