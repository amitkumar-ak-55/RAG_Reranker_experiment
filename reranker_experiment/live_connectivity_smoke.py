from __future__ import annotations

import argparse
import math
import time
from dataclasses import replace
from typing import Callable, Sequence

import httpx

from .client import JinaConfigurationError, JinaReranker, JinaRequestError
from .config import settings
from .jev_batch import JEVBatchClient


LIVE_TIMEOUT_SECONDS = 10.0
JINA_QUERY = "Which CVE describes remote code execution in Apache HTTP Server?"
JINA_DOCUMENTS = [
    "CVE-2021-41773 allows path traversal and remote code execution in Apache HTTP Server 2.4.49.",
    "A weather forecast for tomorrow includes rain and mild temperatures.",
]
JEV_QUERY = "Does the candidate identify the requested Apache HTTP Server vulnerability?"
JEV_CANDIDATES = [
    {"doc_id": "candidate-relevant", "text": JINA_DOCUMENTS[0]},
    {"doc_id": "candidate-irrelevant", "text": JINA_DOCUMENTS[1]},
]


def sanitized_error(exc: BaseException) -> str:
    sensitive_values = (
        settings.jina_api_key_1,
        settings.jina_api_key_2,
        settings.jev_api_key,
    )
    text = f"{type(exc).__name__}: {exc}"
    for value in sensitive_values:
        if value:
            text = text.replace(value, "[REDACTED]")
    text = " ".join(text.split())
    return text[:500]


def http_status_from_error(exc: BaseException) -> int | None:
    text = str(exc)
    marker = "HTTP "
    if marker not in text:
        return None
    status_text = text.rsplit(marker, 1)[-1].split()[0].strip(");")
    return int(status_text) if status_text.isdigit() else None


def run_jina(*, http_client: httpx.Client | None = None) -> dict[str, object]:
    if not settings.api_keys:
        return {
            "provider": "jina",
            "http_status": None,
            "response_valid": False,
            "returned_scores": None,
            "latency_ms": None,
            "error": "JinaConfigurationError: JINA API key is not configured",
        }
    if not settings.jina_base_url or not settings.jina_reranker_model:
        return {
            "provider": "jina",
            "http_status": None,
            "response_valid": False,
            "returned_scores": None,
            "latency_ms": None,
            "error": "JinaConfigurationError: JINA base URL or reranker model is not configured",
        }

    smoke_settings = replace(
        settings,
        jina_api_key_1=settings.jina_api_key_1 or settings.jina_api_key_2,
        jina_api_key_2="",
        timeout_seconds=LIVE_TIMEOUT_SECONDS,
    )
    client = http_client
    started = time.perf_counter()
    try:
        owns_client = client is None
        if client is None:
            client = httpx.Client(timeout=LIVE_TIMEOUT_SECONDS)
        reranker = JinaReranker(smoke_settings, client=client)
        try:
            result = reranker.rerank(JINA_QUERY, JINA_DOCUMENTS, top_n=2)
        finally:
            reranker.close()
            if owns_client:
                client.close()
        latency_ms = (time.perf_counter() - started) * 1000
        status = result.request_records[-1].status_code if result.request_records else None
        valid_scores = all(math.isfinite(score) for score in result.scores)
        return {
            "provider": "jina",
            "http_status": status,
            "response_valid": valid_scores and len(result.scores) == len(JINA_DOCUMENTS),
            "returned_scores": result.scores,
            "latency_ms": round(latency_ms, 2),
            "error": None,
        }
    except (JinaConfigurationError, JinaRequestError, httpx.HTTPError) as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        status = http_status_from_error(exc)
        return {
            "provider": "jina",
            "http_status": status,
            "response_valid": False,
            "returned_scores": None,
            "latency_ms": round(latency_ms, 2),
            "error": sanitized_error(exc),
        }
    except Exception as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        return {
            "provider": "jina",
            "http_status": None,
            "response_valid": False,
            "returned_scores": None,
            "latency_ms": round(latency_ms, 2),
            "error": sanitized_error(exc),
        }


def run_jev(*, http_client: httpx.Client | None = None) -> dict[str, object]:
    if not settings.jev_api_key or not settings.jev_base_url or not settings.jev_model:
        return {
            "provider": "jev",
            "http_status": None,
            "response_valid": False,
            "returned_scores": None,
            "latency_ms": None,
            "error": "JEVConfigurationError: JEV API key, base URL, or model is not configured",
        }

    started = time.perf_counter()
    try:
        owns_client = http_client is None
        client = http_client or httpx.Client(timeout=LIVE_TIMEOUT_SECONDS)
        with JEVBatchClient(
            api_key=settings.jev_api_key,
            base_url=settings.jev_base_url,
            model=settings.jev_model,
            timeout_seconds=LIVE_TIMEOUT_SECONDS,
            http_client=client,
        ) as jev:
            result = jev.score("SMOKE", JEV_QUERY, JEV_CANDIDATES)
        if owns_client:
            client.close()
        latency_ms = (time.perf_counter() - started) * 1000
        valid_scores = (
            set(result.scores) == {"candidate-relevant", "candidate-irrelevant"}
            and all(isinstance(score, float) and math.isfinite(score) and 0 <= score <= 1
                    for score in result.scores.values())
        )
        return {
            "provider": "jev",
            "http_status": result.request_log.get("http_status"),
            "response_valid": valid_scores,
            "returned_scores": result.scores,
            "latency_ms": round(latency_ms, 2),
            "error": None,
        }
    except Exception as exc:
        latency_ms = (time.perf_counter() - started) * 1000
        if owns_client:
            client.close()
        status = None
        message = str(exc)
        if "HTTP " in message:
            suffix = message.rsplit("HTTP ", 1)[-1]
            status_text = suffix.split()[0].strip(");")
            if status_text.isdigit():
                status = int(status_text)
        return {
            "provider": "jev",
            "http_status": status,
            "response_valid": False,
            "returned_scores": None,
            "latency_ms": round(latency_ms, 2),
            "error": sanitized_error(exc),
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manually invoke a 10-second, no-retry Jina/JEV connectivity smoke test."
    )
    parser.add_argument("--live-approved", action="store_true")
    parser.add_argument("--provider", choices=("jina", "jev", "both"), default="both")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    jina_runner: Callable[..., dict[str, object]] = run_jina,
    jev_runner: Callable[..., dict[str, object]] = run_jev,
) -> int:
    args = build_parser().parse_args(argv)
    if not args.live_approved:
        print("Live connectivity smoke test disabled. Re-run with --live-approved.")
        return 2

    results = []
    if args.provider in ("jina", "both"):
        results.append(jina_runner())
    if args.provider in ("jev", "both"):
        results.append(jev_runner())
    for report in results:
        print(report)
    return 0 if all(bool(report["response_valid"]) for report in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
