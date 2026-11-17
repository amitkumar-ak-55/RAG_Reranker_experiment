from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .gold import normalize_cve

JEV_PATH = "/v1/systemone"
PROMPT_VERSION = "jev-relevance-v1"
RELEVANCE_PROMPT = (
    "Evaluate this candidate document independently against the original query. "
    "Assess semantic and factual relevance, including whether it identifies the "
    "requested vulnerability, product, behavior, or fact. Do not reward superficial "
    "keyword overlap. Return a noul score from 0.0 (not relevant) to 1.0 (directly "
    "relevant). Candidate ID: {candidate_id}."
)


@dataclass(frozen=True)
class JEVBatchResult:
    scores: dict[str, float]
    request_log: dict[str, object]


def prompt_hash() -> str:
    return hashlib.sha256(RELEVANCE_PROMPT.encode("utf-8")).hexdigest()


class JEVBatchClient:
    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        timeout_seconds: float = 60,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.http_client = http_client or httpx.Client(timeout=timeout_seconds)
        self._owns_client = http_client is None

    def __enter__(self) -> JEVBatchClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self.http_client.close()

    def score(self, question_id: str, query: str, candidates: list[dict[str, Any]]) -> JEVBatchResult:
        if len(candidates) != 10:
            raise ValueError("JEV batch scoring requires exactly ten candidates")
        questions = {
            f"candidate_{str(candidate['doc_id'])}": {
                "type": "noul",
                "instructions": RELEVANCE_PROMPT.format(candidate_id=candidate["doc_id"]),
            }
            for candidate in candidates
        }
        payload = {
            "model": self.model,
            "state": {
                "claim": query,
                "question": query,
                "evidence": [
                    f"Candidate ID: {candidate['doc_id']}\nDocument: {candidate.get('text', '')}"
                    for candidate in candidates
                ],
            },
            "questions": questions,
        }
        started = time.perf_counter()
        response = self.http_client.post(
            f"{self.base_url}{JEV_PATH}",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload,
        )
        latency_ms = (time.perf_counter() - started) * 1000
        sanitized = {"model": self.model, "question_count": len(questions), "question_id": question_id}
        if response.status_code >= 400:
            raise RuntimeError(f"JEV batch failed: HTTP {response.status_code}")
        try:
            answers = response.json()["answers"]
            scores: dict[str, float] = {}
            invalid = 0
            for key in questions:
                value = answers.get(key, {}).get("noul")
                if value is None:
                    continue
                try:
                    score = float(value)
                except (TypeError, ValueError):
                    invalid += 1
                    continue
                if not 0 <= score <= 1:
                    invalid += 1
                    continue
                scores[key.removeprefix("candidate_")] = score
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("JEV batch response has an invalid shape") from exc
        sanitized.update({
            "http_status": response.status_code,
            "latency_ms": latency_ms,
            "successful_answer_count": len(scores),
            "missing_answer_count": len(questions) - len(scores) - invalid,
            "invalid_answer_count": invalid,
            "parsing_status": "ok",
        })
        return JEVBatchResult(scores, sanitized)

