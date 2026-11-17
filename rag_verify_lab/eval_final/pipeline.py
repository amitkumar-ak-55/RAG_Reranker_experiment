from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import ROOT, settings
from ..db import KBChunk, KBEmbedding, db_session
from .build import CORPUS_SHA256, METHODS, SEED, _read_jsonl, _difficulty, validate_candidate


OUTPUT = ROOT / "data" / "eval" / "final"
CORPUS = ROOT / "data" / "kb" / "documents.jsonl"
INDEX_MANIFEST = ROOT / "data" / "kb" / "index_manifest.json"


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _checkpoint(stage: str, status: str, **details: object) -> None:
    _write_json(ROOT / "checkpoints" / f"{stage}.json", {"stage": stage, "status": status, **details})


def _read_pool() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pool = [json.loads(line) for line in (OUTPUT / "candidate_pool.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    rejected = [json.loads(line) for line in (OUTPUT / "rejected.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    return pool, rejected


def _read_ranks() -> tuple[dict[str, dict[str, Any]], int]:
    by_candidate: dict[str, dict[str, Any]] = {}
    errors = 0
    with (OUTPUT / "ranks.csv").open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            try:
                value: Any = row["rank"] if row["rank"] == "not_found@50" else int(row["rank"])
                if isinstance(value, int) and not 1 <= value <= 50:
                    errors += 1
            except (KeyError, ValueError):
                errors += 1
                continue
            by_candidate.setdefault(row["candidate_id"], {})[row["method"]] = value
    return by_candidate, errors


def _gate_counts(validation: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        gate: {
            "pass": sum(bool(row["checks"].get(gate)) for row in validation),
            "fail": sum(not bool(row["checks"].get(gate)) for row in validation),
        }
        for gate in ("G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8")
    }


def run() -> dict[str, Any]:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    actual_hash = hashlib.sha256(CORPUS.read_bytes()).hexdigest()
    manifest = json.loads(INDEX_MANIFEST.read_text(encoding="utf-8"))
    index_version = str(manifest.get("index_version", ""))
    with db_session() as db:
        index_readable = db.query(KBChunk).count() > 0 and db.query(KBEmbedding).count() >= db.query(KBChunk).count()
    stage0_ok = actual_hash == CORPUS_SHA256 and manifest.get("corpus_sha256") == actual_hash and bool(index_version) and index_readable
    _write_json(OUTPUT / "run_manifest.json", {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "corpus_sha256": actual_hash,
        "index_version": index_version,
        "thread_count": 2,
        "retrieval_methods": [method for method, _, _ in METHODS],
        "retrieval_settings": {
            "dense_limit": 50,
            "hybrid_limit": 10,
            "reranker_input_limit": 10,
            "reranker_not_found_rule": "gold outside hybrid top 10 is not_found@50",
            "document_level_collapsing": "best chunk rank per CVE",
            "filters": {},
        },
        "settings": {
            "embedding_model": settings.embedding_model,
            "embedding_revision": settings.embedding_revision,
            "rerank_model": settings.rerank_model,
            "rerank_revision": settings.rerank_revision,
        },
    })
    _checkpoint("stage0", "pass" if stage0_ok else "fail", corpus_sha256=actual_hash, index_version=index_version, index_readable=index_readable)
    if not stage0_ok:
        raise RuntimeError("Stage 0 frozen-input verification failed")

    pool, rejected = _read_pool()
    eligible = [row for row in pool if not row.get("initial_rejection_reasons")]
    pool_hash = hashlib.sha256((OUTPUT / "candidate_pool.jsonl").read_bytes()).hexdigest()
    stage1_ok = len(pool) >= 600 and len({row["candidate_id"] for row in pool}) == len(pool) and len({row["candidate_id"] for row in rejected}) == len(rejected)
    _checkpoint("stage1", "pass" if stage1_ok else "fail", total=len(pool), eligible=len(eligible), rejected=len(rejected), pool_sha256=pool_hash, rejection_counts=dict(sorted(Counter(reason for row in rejected for reason in row["rejection_reasons"]).items())))
    if not stage1_ok:
        raise RuntimeError("Stage 1 candidate gate failed")

    ranks, rank_errors = _read_ranks()
    methods = {method for method, _, _ in METHODS}
    complete = sum(set(ranks.get(row["candidate_id"], {})) == methods for row in eligible)
    stage2_ok = complete == len(eligible) and rank_errors == 0
    _checkpoint("stage2", "pass" if stage2_ok else "fail", completed_candidates=complete, errors=rank_errors)
    if not stage2_ok:
        raise RuntimeError("Stage 2 ranking is incomplete or contains errors")

    labels = [{"candidate_id": row["candidate_id"], "difficulty": _difficulty(ranks[row["candidate_id"]])} for row in sorted(eligible, key=lambda row: row["candidate_id"])]
    (OUTPUT / "difficulty_labels.jsonl").write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in labels), encoding="utf-8")
    _checkpoint("stage3", "pass", counts=dict(sorted(Counter(row["difficulty"] for row in labels).items())))

    records, _ = _read_jsonl(CORPUS)
    record_map = {str(record["doc_id"]): record for record in records}
    validation = [validate_candidate(row, ranks[row["candidate_id"]], record_map, Counter()) for row in sorted(eligible, key=lambda row: row["candidate_id"])]
    (OUTPUT / "candidate_validation.jsonl").write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in validation), encoding="utf-8")
    gate_counts = _gate_counts(validation)
    _checkpoint("stage4", "pass" if all(item["fail"] == 0 for item in gate_counts.values()) else "fail", gate_counts=gate_counts)
    if any(item["fail"] for item in gate_counts.values()):
        raise RuntimeError("Stage 4 gate failure")

    passed = [row for row, result in zip(sorted(eligible, key=lambda row: row["candidate_id"]), validation) if result["passed"]]
    uses: Counter[str] = Counter()
    used_gold: set[str] = set()
    selected: list[dict[str, Any]] = []
    for row in passed:
        if row["gold_cve"] in used_gold or any(uses[item["cve"]] >= 3 for item in row["confusers"]):
            continue
        item = {key: value for key, value in row.items() if key != "gold_record"}
        item["difficulty"] = _difficulty(ranks[row["candidate_id"]])
        item["ranks"] = ranks[row["candidate_id"]]
        item["index_version"] = index_version
        selected.append(item)
        used_gold.add(row["gold_cve"])
        for confuser in row["confusers"]:
            uses[confuser["cve"]] += 1
        if len(selected) == 300:
            break
    stage5_ok = len(selected) == 300 and len(used_gold) == 300 and max(uses.values(), default=0) <= 3
    _checkpoint("stage5", "pass" if stage5_ok else "fail", selected_count=len(selected), required_count=300, confuser_max=max(uses.values(), default=0), gold_unique=len(used_gold) == len(selected))
    if not stage5_ok:
        raise RuntimeError(f"Stage 5 selection shortfall: {len(selected)}")
    (OUTPUT / "eval_hard_300.jsonl").write_text("".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in selected), encoding="utf-8")

    (OUTPUT / "blind_score.md").write_text("not run — predictor not authorized/configured\n", encoding="utf-8")
    (OUTPUT / "blind_predictions.csv").write_text("status,reason\nnot run,not authorized/configured\n", encoding="utf-8")
    rng = random.Random(SEED)
    sample = sorted(rng.sample(selected, 30), key=lambda item: item["question_id"])
    (OUTPUT / "handcheck.md").write_text(
        "not run — requires human review\nsampled_question_ids: " + ",".join(item["question_id"] for item in sample) + "\n",
        encoding="utf-8",
    )
    counts = {
        "candidates_generated": len(pool),
        "rejected": len(rejected),
        "eligible": len(eligible),
        "ranked": complete,
        "errors": rank_errors,
        "selected": len(selected),
        "difficulty": dict(sorted(Counter(item["difficulty"] for item in selected).items())),
        "product": dict(sorted(Counter(item["product"] for item in selected).items())),
        "cwe": dict(sorted(Counter(cwe for item in selected for cwe in record_map[item["gold_cve"]].get("cwe_ids", [])).items())),
        "confuser_max": max(uses.values(), default=0),
        "confuser_distribution": dict(sorted(Counter(uses.values()).items())),
        "rejection_counts": dict(sorted(Counter(reason for row in rejected for reason in row["rejection_reasons"]).items())),
        "seed": SEED,
        "corpus_sha256": actual_hash,
        "index_version": index_version,
        "blind_audit": "not run — predictor not authorized/configured",
        "hand_check": "not run — requires human review",
        "stage4_gate_counts": gate_counts,
    }
    (OUTPUT / "counts.md").write_text("# Final evaluation counts\n\n```json\n" + json.dumps(counts, indent=2) + "\n```\n", encoding="utf-8")
    return counts


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
