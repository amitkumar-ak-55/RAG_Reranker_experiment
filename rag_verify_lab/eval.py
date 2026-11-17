from __future__ import annotations

import csv
import json
import math
import random
from pathlib import Path
from typing import Iterable

import numpy as np

from .config import ROOT
from .rag.index import FindingIndex
from .rag.retrieve import retrieve


def recall_at_k(ids: list[str], gold: set[str], k: int) -> float:
    return len(set(ids[:k]) & gold) / len(gold) if gold else 0.0


def precision_at_k(ids: list[str], gold: set[str], k: int) -> float:
    return len(set(ids[:k]) & gold) / k


def mrr(ids: list[str], gold: set[str]) -> float:
    return next((1 / rank for rank, value in enumerate(ids, 1) if value in gold), 0.0)


def ndcg10(ids: list[str], gold: set[str]) -> float:
    dcg = sum(1 / math.log2(rank + 1) for rank, value in enumerate(ids[:10], 1) if value in gold)
    ideal = sum(1 / math.log2(rank + 1) for rank in range(1, min(10, len(gold)) + 1))
    return dcg / ideal if ideal else 0.0


def bootstrap(values: list[float], seed: int = 17, samples: int = 1000) -> tuple[float, float]:
    rng = random.Random(seed)
    means = [sum(rng.choices(values, k=len(values))) / len(values) for _ in range(samples)]
    return float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def run_retrieval(path: Path = ROOT / "data" / "eval_questions.jsonl") -> Path:
    questions = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    # The CLI intentionally accepts a fixture index through the application database.
    from .db import Finding, db_session
    with db_session() as db:
        rows = db.query(Finding).all()
    records = [{"id": str(row.id), "text": f"{row.title} {row.description}", "metadata": {"vm_id": row.vm_id, "doc_id": str(row.id)}} for row in rows]
    index = FindingIndex(records)
    output: list[dict[str, object]] = []
    for mode, sparse, rerank_enabled in (("dense", False, False), ("hybrid", True, False), ("hybrid_reranker", True, True)):
        per_metric: dict[str, list[float]] = {key: [] for key in ("recall@5", "recall@10", "precision@5", "mrr", "ndcg@10")}
        for question in questions:
            result = retrieve(index, question["question"], use_sparse=sparse, use_reranker=rerank_enabled,
                              filters={"vm_id": question["vm_id"]} if question.get("vm_id") is not None else None, limit=10)
            ids = [str(item.metadata.get("doc_id", item.id)) for item in result.items]
            gold = {str(value) for value in question.get("gold_doc_ids", [])}
            values = {
                "recall@5": recall_at_k(ids, gold, 5), "recall@10": recall_at_k(ids, gold, 10),
                "precision@5": precision_at_k(ids, gold, 5), "mrr": mrr(ids, gold), "ndcg@10": ndcg10(ids, gold),
            }
            for key, value in values.items():
                per_metric[key].append(value)
        for metric, values in per_metric.items():
            low, high = bootstrap(values)
            output.append({"configuration": mode, "metric": metric, "value": sum(values) / len(values) if values else 0, "ci_low": low, "ci_high": high})
    version = index.index_version
    out_dir = ROOT / "data" / "eval" / version
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "retrieval_eval.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=output[0].keys())
        writer.writeheader(); writer.writerows(output)
    lines = [
        "# Retrieval evaluation", "",
        "Metrics use fixed-seed 1000-resample 95% confidence intervals.", "",
        "| configuration | metric | value | ci_low | ci_high |",
        "|---|---|---:|---:|---:|",
    ]
    lines.extend(
        f"| {row['configuration']} | {row['metric']} | {row['value']:.6f} | "
        f"{row['ci_low']:.6f} | {row['ci_high']:.6f} |" for row in output
    )
    (out_dir / "retrieval_eval.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_dir


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["retrieval"])
    parser.parse_args()
    print(run_retrieval())
