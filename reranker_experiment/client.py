from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .config import ExperimentSettings, settings


class JinaConfigurationError(RuntimeError):
    """The Jina experiment is missing required configuration."""


class JinaRequestError(RuntimeError):
    """Jina rejected or failed a reranking request."""


@dataclass(frozen=True)
class KeySlot:
    slot: int
    secret: str


class KeyRotator:
    """Thread-safe round-robin selection of configured API keys."""

    def __init__(self, keys: tuple[str, ...]) -> None:
        self._keys = tuple(key for key in keys if key)
        self._next = 0
        self._lock = threading.Lock()

    @property
    def configured_slots(self) -> tuple[int, ...]:
        return tuple(range(1, len(self._keys) + 1))

    def next(self) -> KeySlot:
        if not self._keys:
            raise JinaConfigurationError("JINA_API_KEY_1 or JINA_API_KEY_2 is not configured")
        with self._lock:
            index = self._next % len(self._keys)
            self._next = (self._next + 1) % len(self._keys)
        return KeySlot(index + 1, self._keys[index])


@dataclass(frozen=True)
class RequestRecord:
    key_slot: int
    status_code: int | None
    latency_ms: float
    retry: bool


@dataclass(frozen=True)
class RerankResponse:
    scores: list[float]
    request_records: list[RequestRecord]


class JinaReranker:
    def __init__(
        self,
        experiment_settings: ExperimentSettings = settings,
        *,
        client: httpx.Client | None = None,
        sleeper: Any = time.sleep,
    ) -> None:
        self.settings = experiment_settings
        self.rotator = KeyRotator(experiment_settings.api_keys)
        self._client = client or httpx.Client(timeout=experiment_settings.timeout_seconds)
        self._owns_client = client is None
        self._sleeper = sleeper

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> JinaReranker:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _url(self) -> str:
        base = self.settings.jina_base_url.strip().rstrip("/")
        if not base:
            raise JinaConfigurationError("JINA_BASE_URL is not configured")
        return base if base.endswith("/rerank") else f"{base}/rerank"

    def rerank(self, query: str, documents: list[str], top_n: int | None = None) -> RerankResponse:
        if not query.strip():
            raise ValueError("query must not be blank")
        if not documents:
            return RerankResponse([], [])
        if not self.settings.jina_reranker_model:
            raise JinaConfigurationError("JINA_RERANKER_MODEL is not configured")

        records: list[RequestRecord] = []
        errors: list[str] = []
        slots = self.rotator.configured_slots
        if not slots:
            raise JinaConfigurationError("JINA_API_KEY_1 or JINA_API_KEY_2 is not configured")
        for attempt in range(len(slots)):
            key = self.rotator.next()
            started = time.perf_counter()
            try:
                response = self._client.post(
                    self._url(),
                    headers={"Authorization": f"Bearer {key.secret}", "Content-Type": "application/json"},
                    json={
                        "model": self.settings.jina_reranker_model,
                        "query": query,
                        "documents": documents,
                        "top_n": top_n or min(len(documents), self.settings.result_limit),
                        "return_documents": False,
                    },
                )
                latency_ms = (time.perf_counter() - started) * 1000
                records.append(RequestRecord(key.slot, response.status_code, latency_ms, attempt > 0))
                if response.is_success:
                    return RerankResponse(self._scores(response, len(documents)), records)
                errors.append(f"key slot {key.slot}: HTTP {response.status_code}")
                if response.status_code not in {401, 403, 429, 500, 502, 503, 504}:
                    break
            except httpx.HTTPError as exc:
                latency_ms = (time.perf_counter() - started) * 1000
                records.append(RequestRecord(key.slot, None, latency_ms, attempt > 0))
                errors.append(f"key slot {key.slot}: {type(exc).__name__}")
        raise JinaRequestError("; ".join(errors) or "Jina request failed")

    @staticmethod
    def _scores(response: httpx.Response, document_count: int) -> list[float]:
        try:
            payload = response.json()
            data = payload["data"]
            values = [float(item["relevance_score"]) for item in data]
            indices = [int(item["index"]) for item in data]
        except (KeyError, TypeError, ValueError, IndexError) as exc:
            raise JinaRequestError("Jina response has an invalid reranking shape") from exc
        if len(values) != len(set(indices)) or any(index < 0 or index >= document_count for index in indices):
            raise JinaRequestError("Jina response contains invalid document indices")
        scores = [float("-inf")] * document_count
        for index, value in zip(indices, values):
            scores[index] = value
        return scores

