from __future__ import annotations

from dataclasses import dataclass

from openai import OpenAI
from ..config import settings


@dataclass
class Answer:
    text: str
    tokens_in: int
    tokens_out: int
    cost: float | None


def _price(tokens: int, price: str) -> float | None:
    return tokens * float(price) / 1_000_000 if price else None


def _is_rate_limit(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    message = str(exc).lower()
    return status == 429 or "429" in message or "rate limit" in message or "quota" in message


def answer_question(question: str, evidence: list[dict[str, object]]) -> Answer:
    if not settings.answer_model:
        raise RuntimeError("Answer model not configured")
    pieces = [f"[E{i}] {item.get('title', item.get('text', ''))}: {item.get('description', item.get('text', ''))}" for i, item in enumerate(evidence, 1)]
    prompt = (
        "Answer the security assessment question using only the evidence. Cite every factual "
        "claim with [E#]. If the evidence does not support an answer, say exactly "
        "\"INSUFFICIENT EVIDENCE\". Evidence:\n" + "\n".join(pieces)
    )
    if not settings.answer_api_key or not settings.answer_base_url:
        raise RuntimeError("ANSWER_MODEL is set but answer API key or base URL is blank")
    response = None
    last_error: Exception | None = None
    for api_key in settings.answer_api_keys:
        try:
            response = OpenAI(api_key=api_key, base_url=settings.answer_base_url).chat.completions.create(
                model=settings.answer_model,
                messages=[{"role": "user", "content": question + "\n\n" + prompt}],
                max_tokens=settings.answer_max_tokens,
            )
            break
        except Exception as exc:
            last_error = exc
            if not _is_rate_limit(exc):
                raise
    if response is None:
        raise RuntimeError("all configured answer API keys reached their rate limit") from last_error
    usage = response.usage
    tokens_in = int(usage.prompt_tokens) if usage else 0
    tokens_out = int(usage.completion_tokens) if usage else 0
    return Answer(response.choices[0].message.content or "INSUFFICIENT EVIDENCE", tokens_in, tokens_out, (_price(tokens_in, settings.price_answer_in_per_m) or 0) + (_price(tokens_out, settings.price_answer_out_per_m) or 0) if settings.price_answer_in_per_m or settings.price_answer_out_per_m else None)
