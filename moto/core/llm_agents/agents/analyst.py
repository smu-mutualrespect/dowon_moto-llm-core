from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from moto.core.llm_agents.session_store import AttackSession

from moto.core.llm_agents.providers import call_gpt_api


def analyze(session: "AttackSession") -> tuple[dict, int, int]:
    prompt = _build_prompt(session)
    try:
        result = call_gpt_api(prompt)
        output = json.loads(result.text)
        _validate(output)
        return output, result.input_tokens, result.output_tokens
    except Exception:
        fallback = _rule_based_fallback(session)
        return fallback, 0, 0


def _build_prompt(session: "AttackSession") -> str:
    recent_actions = session.actions[-10:]
    formatted_actions = "\n".join(
        f"  [{i+1}] {a['service']}:{a['action']} | bait_hit={a.get('matched_bait')}"
        for i, a in enumerate(recent_actions)
    )

    baits_planted = [b for b in session.baits]
    baits_taken = [b for b in session.baits if b.status == "taken"]

    return f"""You are a security analyst monitoring a honeypot AWS environment.
Analyze the following attack session and determine the current threat status.

Total requests so far: {session.request_count}

Recent API calls (latest up to 10):
{formatted_actions}

Baits planted: {len(baits_planted)} | Baits taken: {len(baits_taken)}

Attack phase definitions:
- 정찰: reconnaissance — listing resources (ListBuckets, ListUsers, DescribeInstances, GetCallerIdentity...)
- 권한_탈취: credential theft (GetSecretValue, AssumeRole, CreateAccessKey, GetParameter...)
- 데이터_유출: data exfiltration (GetObject, GetParameter, DownloadDBLogFilePortion...)
- 횡적_이동: lateral movement (CreateRole, AttachRolePolicy, RunInstances, CreateFunction...)

Strategy definitions:
- observe: watch passively, return normal realistic responses
- lure: plant enticing fake resource names in responses to draw attacker deeper
- engage: make attacker believe they fully succeeded, return convincing fake credentials/data
- trap: deploy canary tokens that can be tracked if used outside this environment

Current session state: phase={session.current_stage}, strategy={session.current_strategy}

Based on the attack pattern, return ONLY this JSON with no explanation or markdown:
{{"phase": "<정찰|권한_탈취|데이터_유출|횡적_이동>", "threat_level": "<low|medium|high|critical>", "strategy": "<observe|lure|engage|trap>", "reasoning": "<one sentence why>"}}"""


def _validate(output: dict) -> None:
    valid_phases = {"정찰", "권한_탈취", "데이터_유출", "횡적_이동"}
    valid_threats = {"low", "medium", "high", "critical"}
    valid_strategies = {"observe", "lure", "engage", "trap"}
    assert output.get("phase") in valid_phases
    assert output.get("threat_level") in valid_threats
    assert output.get("strategy") in valid_strategies


def _rule_based_fallback(session: "AttackSession") -> dict:
    recent = {a["action"] for a in session.actions[-5:]}
    phase_patterns = {
        "횡적_이동": {"CreateRole", "AttachRolePolicy", "RunInstances", "CreateFunction", "PutRolePolicy"},
        "데이터_유출": {"GetObject", "ExportTableToPointInTime", "CopySnapshot"},
        "권한_탈취": {"GetSecretValue", "AssumeRole", "CreateAccessKey", "GetParameter"},
        "정찰": {"ListBuckets", "DescribeInstances", "ListUsers", "GetCallerIdentity", "ListSecrets"},
    }
    phase = "정찰"
    for p, patterns in phase_patterns.items():
        if recent & patterns:
            phase = p
            break

    strategy = session.current_strategy
    if session.request_count >= 3 and strategy == "observe":
        strategy = "lure"

    return {
        "phase": phase,
        "threat_level": "medium",
        "strategy": strategy,
        "reasoning": "rule-based fallback due to LLM parse error",
    }
