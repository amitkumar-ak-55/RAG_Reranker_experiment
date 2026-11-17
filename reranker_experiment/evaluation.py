from __future__ import annotations

import math
import statistics
from collections.abc import Iterable

from .gold import document_cves, extract_cves, normalize_cve


def cve_hit_at_k(ranked: list[dict[str, object]], gold_cve: str | None, k: int) -> float:
    gold = normalize_cve(gold_cve)
    return float(bool(gold and any(gold in document_cves(dict(item))[0] for item in ranked[:k])))


def first_relevant_rank(ranked: list[dict[str, object]], gold_cve: str | None, k: int) -> int | None:
    gold = normalize_cve(gold_cve)
    if not gold:
        return None
    for rank, item in enumerate(ranked[:k], 1):
        if gold in document_cves(dict(item))[0]:
            return rank
    return None


def cve_mrr_at_10(ranked: list[dict[str, object]], gold_cve: str | None) -> float:
    rank = first_relevant_rank(ranked, gold_cve, 10)
    return 1 / rank if rank else 0.0


def cve_ndcg_at_k(ranked: list[dict[str, object]], gold_cve: str | None, k: int) -> float:
    rank = first_relevant_rank(ranked, gold_cve, k)
    return 1 / math.log2(rank + 1) if rank else 0.0


def chunk_relevance(ranked: list[dict[str, object]], gold_cve: str | None, k: int) -> list[int]:
    gold = normalize_cve(gold_cve)
    return [int(bool(gold and gold in document_cves(dict(item))[0])) for item in ranked[:k]]


def chunk_precision_at_k(ranked: list[dict[str, object]], gold_cve: str | None, k: int) -> float:
    return sum(chunk_relevance(ranked, gold_cve, k)) / k


def chunk_recall_at_k(ranked: list[dict[str, object]], gold_cve: str | None, k: int, total_relevant: int) -> float:
    return sum(chunk_relevance(ranked, gold_cve, k)) / total_relevant if total_relevant else 0.0


def chunk_mrr_at_10(ranked: list[dict[str, object]], gold_cve: str | None) -> float:
    relevance = chunk_relevance(ranked, gold_cve, 10)
    return next((1 / rank for rank, value in enumerate(relevance, 1) if value), 0.0)


def chunk_ndcg_at_10(ranked: list[dict[str, object]], gold_cve: str | None, total_relevant: int) -> float:
    relevance = chunk_relevance(ranked, gold_cve, 10)
    dcg = sum(value / math.log2(rank + 1) for rank, value in enumerate(relevance, 1))
    ideal = sum(1 / math.log2(rank + 1) for rank in range(1, min(10, total_relevant) + 1))
    return dcg / ideal if ideal else 0.0


def answer_evaluation(answer: str, gold_cve: str | None) -> dict[str, object]:
    gold = normalize_cve(gold_cve)
    found = extract_cves(answer)
    if not answer.strip():
        category = "unparseable"
    elif not found:
        category = "no_cve"
    elif gold in found and len(found) == 1:
        category = "correct"
    elif gold in found:
        category = "gold_with_other_cves"
    else:
        category = "incorrect_cve"
    return {
        "extracted_cves": found,
        "gold_cve_mention": bool(gold and gold in found),
        "unambiguous_cve_identification": bool(gold and found == [gold]),
        "category": category,
    }


def summarize(values: Iterable[float]) -> dict[str, float | int]:
    data = list(values)
    if not data:
        return {"count": 0}
    ordered = sorted(data)
    percentile = lambda fraction: ordered[min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1)]
    return {
        "count": len(data),
        "mean": statistics.fmean(data),
        "median": statistics.median(data),
        "stddev": statistics.stdev(data) if len(data) > 1 else 0.0,
        "p90": percentile(0.90),
        "p95": percentile(0.95),
        "min": min(data),
        "max": max(data),
    }

