from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import json
import re
from typing import Any

from rag_verify_lab.config import settings as production_settings
from rag_verify_lab.rag.answer import Answer, answer_question

from .pipeline import Candidate


@dataclass(frozen=True)
class GenerationSettings:
    """The production generation settings used by the shared answer function."""

    model: str
    max_tokens: int
    temperature: None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GenerationResult:
    text: str | None
    provider: str
    model: str | None
    generation_config: dict[str, Any]
    tokens_in: int | None
    tokens_out: int | None
    cost: float | None
    success: bool
    error_category: str | None = None
    error_message: str | None = None


UNAVAILABLE = "unavailable"
_SECRET_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*[:=]\s*)[^\r\n,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (
        re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|secret|password)\b\s*[:=]\s*)[^\s,;]+"),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?i)(https?://)([^/@\s]+):([^/@\s]+)@"), r"\1[REDACTED]@"),
    (
        re.compile(r"(?i)([?&](?:api[_-]?key|access[_-]?token|token|secret|password)=)[^&\s]+"),
        r"\1[REDACTED]",
    ),
)


def sanitize_log_text(value: str) -> str:
    sanitized = value
    for secret in production_settings.answer_api_keys:
        if secret:
            sanitized = sanitized.replace(secret, "[REDACTED]")
    for pattern, replacement in _SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized[:1000]


def sanitize_persisted_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return sanitize_log_text(value)
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            safe_key = sanitize_log_text(str(key))
            if re.search(r"(?i)(api[_-]?key|access[_-]?token|secret|password)", str(key)):
                sanitized[safe_key] = "[REDACTED]"
            else:
                sanitized[safe_key] = sanitize_persisted_value(item)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [sanitize_persisted_value(item) for item in value]
    return sanitize_log_text(f"<{type(value).__name__}: {value!s}>")


def canonical_json(value: Any) -> str:
    return json.dumps(sanitize_persisted_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sanitize_generation_result(result: GenerationResult) -> GenerationResult:
    return GenerationResult(
        text=sanitize_log_text(result.text) if result.text is not None else None,
        provider=sanitize_log_text(result.provider),
        model=sanitize_log_text(result.model) if result.model is not None else None,
        generation_config=sanitize_persisted_value(result.generation_config),
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost=result.cost,
        success=result.success,
        error_category=sanitize_log_text(result.error_category) if result.error_category is not None else None,
        error_message=sanitize_log_text(result.error_message) if result.error_message is not None else None,
    )


class ProductionAnswerProvider:
    """Adapt the unchanged production answer function to experiment candidates."""

    name = "production-answer-provider"

    def __init__(
        self,
        answer_fn: Callable[[str, list[dict[str, object]]], Answer] = answer_question,
    ) -> None:
        self._answer_fn = answer_fn
        self.generation_settings = GenerationSettings(
            model=production_settings.answer_model,
            max_tokens=production_settings.answer_max_tokens,
        )

    def answer(self, query: str, evidence: list[Candidate]) -> GenerationResult:
        payload = [
            {
                "title": str(candidate.metadata.get("title", candidate.doc_id)),
                "description": candidate.text,
                "text": candidate.text,
                "doc_id": candidate.doc_id,
            }
            for candidate in evidence
        ]
        answer = self._answer_fn(query, payload)
        return GenerationResult(
            text=answer.text,
            provider=self.name,
            model=self.generation_settings.model or None,
            generation_config=self.generation_settings.as_dict(),
            tokens_in=answer.tokens_in,
            tokens_out=answer.tokens_out,
            cost=answer.cost,
            success=True,
        )


class AnswerProviderSelectionError(ValueError):
    """The experiment was given an invalid or unavailable answer provider."""


def validate_production_configuration() -> None:
    missing = [
        name
        for name, value in (
            ("ANSWER_MODEL", production_settings.answer_model),
            ("ANSWER_API_KEY", production_settings.answer_api_keys),
            ("ANSWER_BASE_URL", production_settings.answer_base_url),
        )
        if not value
    ]
    if missing:
        raise AnswerProviderSelectionError(
            "Production answer provider is not configured: " + ", ".join(missing)
        )
    if production_settings.answer_max_tokens <= 0:
        raise AnswerProviderSelectionError("ANSWER_MAX_TOKENS must be greater than zero")


def select_answer_provider(provider: str, *, mock_provider: Any = None) -> Any:
    """Resolve an explicitly selected provider without implicit fallback."""
    if provider not in {"mock", "production"}:
        raise AnswerProviderSelectionError(
            "provider must be explicitly selected as 'mock' or 'production'"
        )
    if provider == "mock":
        return mock_provider or _mock_answer_provider()
    if mock_provider is not None:
        raise AnswerProviderSelectionError(
            "A custom provider cannot be injected for the production selection"
        )
    validate_production_configuration()
    return ProductionAnswerProvider()


def _mock_answer_provider() -> Any:
    from .pipeline import MockAnswerProvider

    return MockAnswerProvider()


def failed_generation_result(provider: Any, exc: Exception) -> GenerationResult:
    status = getattr(exc, "status_code", None)
    message = str(exc).lower()
    if status in {401, 403} or "authentication" in message or "unauthorized" in message:
        category = "authentication"
    elif status == 429 or "rate limit" in message or "quota" in message:
        category = "rate_limit"
    elif isinstance(exc, AnswerProviderSelectionError):
        category = "configuration"
    else:
        category = "provider_error"
    settings = getattr(provider, "generation_settings", None)
    config = settings.as_dict() if settings is not None else {"provider": provider.name}
    return GenerationResult(
        text=None,
        provider=provider.name,
        model=getattr(settings, "model", None) if settings is not None else None,
        generation_config=config,
        tokens_in=None,
        tokens_out=None,
        cost=None,
        success=False,
        error_category=category,
        error_message="answer generation failed",
    )
