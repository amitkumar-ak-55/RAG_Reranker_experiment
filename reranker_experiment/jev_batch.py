from __future__ import annotations

import hashlib
import math
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
        if not 1 <= len(candidates) <= 10:
            raise ValueError("JEV batch scoring requires 1 to 10 candidates")
        candidate_ids = [str(candidate.get("doc_id", "")) for candidate in candidates]
        if any(not candidate_id for candidate_id in candidate_ids):
            raise ValueError("JEV batch candidates require non-empty candidate IDs")
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("JEV batch contains duplicate candidate IDs")
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
        response = None
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = self.http_client.post(
                    f"{self.base_url}{JEV_PATH}",
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload,
                )
                if response.status_code not in {429, 500, 502, 503, 504} or attempt == 1:
                    break
                time.sleep(1.0)
            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt == 1:
                    raise RuntimeError("JEV batch request timed out") from exc
                time.sleep(1.0)
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == 1:
                    raise RuntimeError("JEV batch network request failed") from exc
                time.sleep(1.0)
        if response is None:
            raise RuntimeError("JEV batch network request failed") from last_error
        latency_ms = (time.perf_counter() - started) * 1000
        sanitized = {"model": self.model, "question_count": len(questions), "question_id": question_id}
        if response.status_code >= 400:
            raise RuntimeError(f"JEV batch failed: HTTP {response.status_code}")
        try:
            payload_response = response.json()
        except (TypeError, ValueError) as exc:
            raise RuntimeError("JEV batch response has invalid JSON") from exc
        if not isinstance(payload_response, dict):
            raise RuntimeError("JEV batch response has an invalid shape")
        model = payload_response.get("model")
        if not isinstance(model, str) or not model.strip():
            raise RuntimeError("JEV batch response is missing a valid model")
        answers = payload_response.get("answers")
        if not isinstance(answers, dict):
            raise RuntimeError("JEV batch response is missing the answers object")
        usage = payload_response.get("usage")
        if not isinstance(usage, dict):
            raise RuntimeError("JEV batch response is missing usage")
        for usage_field in ("input_tokens", "output_tokens"):
            usage_value = usage.get(usage_field)
            if isinstance(usage_value, bool) or not isinstance(usage_value, int) or usage_value < 0:
                raise RuntimeError("JEV batch response has invalid usage")
        scores: dict[str, float] = {}
        for key in questions:
            answer = answers.get(key)
            if not isinstance(answer, dict):
                raise RuntimeError("JEV batch response is missing a candidate answer")
            if answer.get("type") != "noul":
                raise RuntimeError("JEV batch response has a wrong answer type")
            value = answer.get("noul")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise RuntimeError("JEV batch response has a malformed Noul score")
            score = float(value)
            if not math.isfinite(score):
                raise RuntimeError("JEV batch response has a non-finite Noul score")
            if not 0 <= score <= 1:
                raise RuntimeError("JEV batch response has an out-of-range Noul score")
            candidate_id = key.removeprefix("candidate_")
            if candidate_id in scores:
                raise RuntimeError("JEV batch response contains duplicate candidate scores")
            scores[candidate_id] = score
        if len(scores) != len(questions):
            raise RuntimeError("JEV batch response is missing candidate scores")
        sanitized.update({
            "http_status": response.status_code,
            "latency_ms": latency_ms,
            "successful_answer_count": len(scores),
            "missing_answer_count": 0,
            "invalid_answer_count": 0,
            "parsing_status": "ok",
        })
        return JEVBatchResult(scores, sanitized)

