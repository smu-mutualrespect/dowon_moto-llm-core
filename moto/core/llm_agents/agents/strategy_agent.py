from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from moto.core.llm_agents.session_store import AttackSession

from moto.core.llm_agents.providers import call_gpt_api


def plan(
    strategy: str,
    service: str,
    action: str,
    session: "AttackSession",
) -> tuple[dict, int, int]:
    if strategy == "observe":
        return {"bait_instructions": None, "bait_markers": []}, 0, 0

    prompt = _build_prompt(strategy, service, action, session)
    try:
        result = call_gpt_api(prompt)
        output = json.loads(result.text)
        _validate(output)
        return output, result.input_tokens, result.output_tokens
    except Exception:
        fallback = _template_fallback(strategy, service, session)
        return fallback, 0, 0


def _build_prompt(
    strategy: str,
    service: str,
    action: str,
    session: "AttackSession",
) -> str:
    recent_actions = ", ".join(
        f"{a['service']}:{a['action']}" for a in session.actions[-5:]
    )
    existing_baits = [b.value for b in session.baits]

    return f"""You are a honeypot bait designer for a fake AWS environment.
Design specific bait to embed inside an AWS API response to lure the attacker deeper.

Attack context:
- Service: {service}
- Action: {action}
- Current attack phase: {session.current_stage}
- Strategy: {strategy}
- Recent attacker actions: {recent_actions}
- Already planted baits (do NOT reuse): {existing_baits}

Strategy guidance:
- lure: include 1-2 enticing fake resource names that look sensitive (e.g. "prod/db/password", "admin-user")
- engage: make the operation look fully successful with realistic fake credentials/ARNs/data
- trap: embed a trackable canary value (fake access key, secret) that can be detected if used externally

Return ONLY this JSON with no explanation or markdown:
{{
  "bait_instructions": "<specific instruction describing exactly what fake data to include in the response>",
  "bait_markers": [
    {{"type": "<secret_name|iam_user|bucket_name|parameter_name|access_key>", "value": "<exact fake value the attacker would use in a follow-up request>"}}
  ]
}}

Rules:
- bait_instructions must be actionable and specific to {service} {action}
- bait_markers values must follow real AWS naming conventions
- Include at most 2 bait_markers
- Do NOT reuse already planted bait values"""


def _validate(output: dict) -> None:
    assert isinstance(output.get("bait_instructions"), str)
    assert isinstance(output.get("bait_markers"), list)


def _template_fallback(
    strategy: str, service: str, session: "AttackSession"
) -> dict:
    templates: dict[str, list[dict]] = {
        "secretsmanager": [{"type": "secret_name", "values": ["prod/db/password", "internal/api-key"]}],
        "iam":            [{"type": "iam_user",    "values": ["admin", "prod-deploy-bot"]}],
        "s3":             [{"type": "bucket_name", "values": ["prod-backups-2024", "internal-data-lake"]}],
        "ssm":            [{"type": "parameter_name", "values": ["/prod/db/password"]}],
    }

    existing = {b.value for b in session.baits}
    markers = []
    for template in templates.get(service, []):
        for value in template["values"]:
            if value not in existing:
                markers.append({"type": template["type"], "value": value})
                break

    if strategy == "trap":
        fake_key = "AKIA" + uuid.uuid4().hex[:16].upper()
        markers = [{"type": "access_key", "value": fake_key}]

    instructions = {
        "lure":   "Include 1-2 sensitive-looking fake resource names naturally in the response.",
        "engage": "Return a fully successful response with realistic fake credentials and ARNs.",
        "trap":   f"Include a fake AWS access key pair. Present it as active.",
    }.get(strategy, "")

    return {"bait_instructions": instructions, "bait_markers": markers}
