from __future__ import annotations

import csv
import hashlib
import json
import shutil
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from .config import ROOT, settings
from .evaluation import (
    answer_evaluation,
    chunk_mrr_at_10,
    chunk_ndcg_at_10,
    chunk_precision_at_k,
    chunk_recall_at_k,
    cve_hit_at_k,
    cve_mrr_at_10,
    cve_ndcg_at_k,
)
from .gold import document_cves, map_gold, normalize_cve
from .provenance import runtime_manifest, sha256_file, sha256_text, utc_now, write_json

ARMS = ("baseline", "jina", "jev")
EXPERIMENT_VERSION = "abcrerank-v2"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def duplicate_groups(questions: list[dict[str, Any]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for question in questions:
        grouped[str(question["question"])].append(str(question["question_id"]))
    return {text: ids for text, ids in grouped.items() if len(ids) > 1}


def validate_dataset(path: Path = ROOT / "data" / "eval" / "final" / "eval_hard_300.jsonl") -> dict[str, Any]:
    questions = load_jsonl(path)
    ids = [str(question.get("question_id", "")) for question in questions]
    texts = [str(question.get("question", "")) for question in questions]
    return {
        "filename": str(path),
        "sha256": sha256_file(path),
        "record_count": len(questions),
        "unique_question_ids": len(set(ids)),
        "unique_question_texts": len(set(texts)),
        "duplicate_groups": duplicate_groups(questions),
        "difficulty_counts": {
            difficulty: sum(question.get("difficulty") == difficulty for question in questions)
            for difficulty in ("easy", "medium", "hard")
        },
        "valid_300_record_dataset": len(questions) == 300 and len(ids) == len(set(ids)),
    }


def config_snapshot() -> dict[str, Any]:
    answer_prompt = (
        "Answer the security assessment question using only the supplied evidence. "
        "Cite factual claims with [E#]. If unsupported, say INSUFFICIENT EVIDENCE."
    )
    return {
        "experiment_version": EXPERIMENT_VERSION,
        "created_at_utc": utc_now(),
        "settings": settings.masked_snapshot(),
        "candidate_budget": 10,
        "evidence_budget": 5,
        "arms": list(ARMS),
        "retrieval": {"dense_limit": 50, "bm25_limit": 50, "rrf_k": 60, "candidate_limit": 10},
        "answer_generation": {
            "prompt": answer_prompt,
            "prompt_hash": sha256_text(answer_prompt),
            "model": settings.answer_model,
            "max_tokens": settings.answer_max_tokens,
            "temperature": None,
        },
        "jev": {"prompt_version": "jev-relevance-v1", "scoring_method": "noul"},
        "runtime": runtime_manifest(),
        "random_seed": 17,
        "statistics": {"primary_endpoint": "unique_cve_hit_at_5", "bootstrap_iterations": 10000},
    }


def _rank_by_scores(candidates: list[dict[str, Any]], scores: dict[str, float]) -> list[dict[str, Any]]:
    return sorted(
        candidates,
        key=lambda item: scores.get(str(item["doc_id"]), float("-inf")),
        reverse=True,
    )


def _metric_row(
    question: dict[str, Any],
    candidates: list[dict[str, Any]],
    ranked: list[dict[str, Any]],
    arm: str,
    mapping: Any,
) -> dict[str, Any]:
    gold = normalize_cve(question.get("gold_cve"))
    row: dict[str, Any] = {
        "question_id": question["question_id"],
        "arm": arm,
        "gold_cve": gold,
        "candidate_pool_recall_at_10": cve_hit_at_k(candidates, gold, 10),
        "unique_cve_hit_at_5": cve_hit_at_k(ranked, gold, 5),
        "unique_cve_hit_at_10": cve_hit_at_k(ranked, gold, 10),
        "mrr_at_10": cve_mrr_at_10(ranked, gold),
        "ndcg_at_5": cve_ndcg_at_k(ranked, gold, 5),
        "ndcg_at_10": cve_ndcg_at_k(ranked, gold, 10),
        "chunk_precision_at_5": chunk_precision_at_k(ranked, gold, 5),
        "chunk_precision_at_10": chunk_precision_at_k(ranked, gold, 10),
        "chunk_recall_at_5": chunk_recall_at_k(ranked, gold, 5, mapping.kb_chunk_count),
        "chunk_recall_at_10": chunk_recall_at_k(ranked, gold, 10, mapping.kb_chunk_count),
        "chunk_mrr_at_10": chunk_mrr_at_10(ranked, gold),
        "chunk_ndcg_at_10": chunk_ndcg_at_10(ranked, gold, mapping.kb_chunk_count),
        "selected_evidence_ids": [str(item["doc_id"]) for item in ranked[:5]],
        "ranking_ids": [str(item["doc_id"]) for item in ranked],
        "failure": "",
    }
    return row


def run_mock_dry_run(
    output_dir: Path | None = None,
    *,
    question_limit: int = 3,
) -> Path:
    from .pipeline import run_mock_pipeline

    destination = output_dir or (ROOT / "data" / "experiments" / f"mock_pipeline_{uuid.uuid4().hex[:12]}")
    return run_mock_pipeline(destination, provider="mock", question_limit=question_limit)


def run_production_pilot(
    output_dir: Path | None = None,
    *,
    question_limit: int = 1,
    resume: bool = False,
) -> Path:
    from .pipeline import run_production_pipeline

    destination = output_dir or (ROOT / "data" / "experiments" / f"production_pilot_{uuid.uuid4().hex[:12]}")
    return run_production_pipeline(destination, question_limit=question_limit, resume=resume)


def run_production_full(
    output_dir: Path | None = None,
    *,
    resume: bool = False,
) -> Path:
    from .pipeline import run_production_full
    destination = output_dir or (ROOT / "data" / "experiments" / f"production_full_{uuid.uuid4().hex[:12]}")
    return run_production_full(destination, resume=resume)


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=sorted({key for row in rows for key in row}))
        writer.writeheader()
        writer.writerows(rows)

