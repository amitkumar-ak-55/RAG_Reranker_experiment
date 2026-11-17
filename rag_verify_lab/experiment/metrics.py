from __future__ import annotations

import math
from statistics import mean

from ..verify.claims import citation_correctness, unsupported_rate


def precision_at_k(retrieved_ids: list[int], gold_ids: list[int], k: int) -> float:
    selected = retrieved_ids[:k]
    return sum(item in set(gold_ids) for item in selected) / k if k else 0.0


def percentile(values: list[float], percentile_value: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    index = (len(values) - 1) * percentile_value
    lower, upper = math.floor(index), math.ceil(index)
    return values[lower] + (values[upper] - values[lower]) * (index - lower)


def summarize(results: list[dict[str, object]]) -> dict[str, object]:
    claims = [claim for result in results for claim in result.get("claims", [])]
    costs = [r["cost_usd"] for r in results if r.get("cost_usd") is not None]
    latencies = [float(r["latency_ms"]) for r in results]
    return {"unsupported_claim_rate": unsupported_rate(claims), "citation_correctness": citation_correctness(claims), "mean_latency_ms": mean(latencies) if latencies else None, "p95_latency_ms": percentile(latencies, .95), "cost_per_answer": (mean(costs) if costs else None), "total_cost": sum(costs) if costs else None, "error_count": sum(bool(r.get("error")) for r in results)}
