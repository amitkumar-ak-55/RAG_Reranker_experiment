from __future__ import annotations

import json

from openai import OpenAI

from ..config import settings
from .jev import JEVClient, Judgment


def split_claims(answer: str) -> list[str]:
    if answer.strip() == "INSUFFICIENT EVIDENCE":
        return []
    if not settings.answer_model or not settings.gemini_api_key or not settings.gemini_base_url:
        raise RuntimeError("ANSWER_MODEL, GEMINI_API_KEY, and GEMINI_BASE_URL are required for claim splitting")
    response = OpenAI(api_key=settings.gemini_api_key, base_url=settings.gemini_base_url).chat.completions.create(
        model=settings.answer_model,
        messages=[{"role": "user", "content": f"Split this answer into atomic factual claims. Return JSON only: {{\"claims\":[string]}}.\n{answer}"}],
        response_format={"type": "json_object"},
    )
    data = json.loads(response.choices[0].message.content or '{"claims":[]}')
    return [str(claim).strip() for claim in data.get("claims", []) if str(claim).strip()]


def judge_claims(answer: str, evidence: list[str], client: JEVClient | None = None) -> list[dict[str, object]]:
    client = client or JEVClient()
    results = []
    for claim in split_claims(answer):
        judgment: Judgment = client.judge(claim, evidence)
        results.append({"claim": claim, "label": judgment.label, "citation_correct": judgment.citation_correct})
    return results


def unsupported_rate(claims: list[dict[str, object]]) -> float | None:
    return None if not claims else sum(c.get("label") in {"UNSUPPORTED", "CONTRADICTED"} for c in claims) / len(claims)


def citation_correctness(claims: list[dict[str, object]]) -> float | None:
    cited = [c for c in claims if c.get("citation_correct") is not None]
    return None if not cited else sum(bool(c["citation_correct"]) for c in cited) / len(cited)
