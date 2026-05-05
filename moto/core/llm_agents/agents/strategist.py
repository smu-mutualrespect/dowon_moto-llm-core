from __future__ import annotations

import json
import logging
import os
import re

from moto.core.llm_agents.metrics import log_agent_debug
from moto.core.llm_agents.providers import call_gpt_api
from moto.core.llm_agents.state import SessionProfile

logger = logging.getLogger("turn_agent")

_STRATEGIST_MODEL = os.getenv("HONEYPOT_STRATEGIST_MODEL", "gpt-5.4-mini")
_STRATEGIST_TEMP = float(os.getenv("HONEYPOT_STRATEGIST_TEMP", "0.25"))

_STRATEGIST_SYSTEM = """\
You are a deception strategist for an AWS API honeypot.
Given a compact session profile and command history, choose decoys that can be reused in later API responses.

Output ONLY valid JSON:
{
  "decoys":[
    {
      "decoy_service":"iam|s3|secretsmanager|ec2|ssm",
      "decoy_type":"access_key|role|bucket|secret|parameter",
      "decoy_name":"<resource name>",
      "decoy_value":"<fake but realistic value>"
    }
  ],
  "reasoning":"<one short sentence>"
}

Keep decoys realistic, internally consistent, and connected across AWS services. Never mention honeypot.
"""


def strategy_agent(session_id: str, history: list[str], profile: SessionProfile) -> dict[str, str]:
    prompt = (
        f"session={session_id}\n"
        f"profile={json.dumps(profile, ensure_ascii=False, separators=(',', ':'))}\n"
        f"recent_history={json.dumps(history[-10:], ensure_ascii=False, separators=(',', ':'))}\n"
    )
    try:
        raw, usage = call_gpt_api(
            prompt,
            model=_STRATEGIST_MODEL,
            system_prompt=_STRATEGIST_SYSTEM,
            temperature=_STRATEGIST_TEMP,
        )
        log_agent_debug(
            "strategist",
            session_id,
            turn=len(history),
            elapsed_ms=usage.get("elapsed_ms", 0.0),
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            response_content=raw,
        )
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
        parsed = json.loads(cleaned)
        if isinstance(parsed.get("decoys"), list):
            normalized: dict[str, str] = {"reasoning": str(parsed.get("reasoning", ""))}
            for idx, decoy in enumerate(parsed["decoys"][:3]):
                if isinstance(decoy, dict):
                    for key, value in decoy.items():
                        normalized[f"decoys.{idx}.{key}"] = str(value)
            return normalized
        return {str(k): str(v) for k, v in parsed.items() if v is not None}
    except Exception as e:
        logger.warning("strategy_agent failed: %s", e)
        return {}
