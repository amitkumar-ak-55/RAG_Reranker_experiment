from __future__ import annotations

import math
from collections.abc import Iterable


def recall_at_k(ranked_ids: list[str], gold_ids: set[str], k: int) -> float:
    return len(set(ranked_ids[:k]) & gold_ids) / len(gold_ids) if gold_ids else 0.0


def precision_at_k(ranked_ids: list[str], gold_ids: set[str], k: int) -> float:
    return len(set(ranked_ids[:k]) & gold_ids) / k


def reciprocal_rank(ranked_ids: list[str], gold_ids: set[str]) -> float:
    return next((1.0 / rank for rank, value in enumerate(ranked_ids, 1) if value in gold_ids), 0.0)


def ndcg_at_k(ranked_ids: list[str], gold_ids: set[str], k: int) -> float:
    dcg = sum(1 / math.log2(rank + 1) for rank, value in enumerate(ranked_ids[:k], 1) if value in gold_ids)
    ideal = sum(1 / math.log2(rank + 1) for rank in range(1, min(k, len(gold_ids)) + 1))
    return dcg / ideal if ideal else 0.0


def aggregate(rows: Iterable[dict[str, object]]) -> dict[str, float | int]:
    values = list(rows)
    successful = [row for row in values if not row.get("error")]
    if not successful:
        return {"questions": len(values), "successful": 0, "failed": len(values)}
    return {
        "questions": len(values),
        "successful": len(successful),
        "failed": len(values) - len(successful),
        "mean_recall_at_5": sum(float(row["recall_at_5"]) for row in successful) / len(successful),
        "mean_precision_at_5": sum(float(row["precision_at_5"]) for row in successful) / len(successful),
        "mean_mrr": sum(float(row["mrr"]) for row in successful) / len(successful),
        "mean_ndcg_at_5": sum(float(row["ndcg_at_5"]) for row in successful) / len(successful),
        "mean_latency_ms": sum(float(row["latency_ms"]) for row in successful) / len(successful),
    }

