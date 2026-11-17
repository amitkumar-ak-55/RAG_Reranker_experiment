from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

from ..config import ROOT, settings
from .build import (
    CORPUS_SHA256,
    METHODS,
    SEED,
    _read_jsonl,
    product_mapping,
    validate_candidate,
)

EXPECTED_POOL_SHA256 = "71fa5f87a0004da25efb2aee610b48de69d24f6e2e39ee707f435d52afba4b72"
EXPECTED_POOL_ROWS = 722
EXPECTED_REJECTED_ROWS = 443


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _checkpoint(root: Path, stage: str, status: str, **details: object) -> None:
    _write_json(root / "checkpoints" / f"{stage}.json", {"stage": stage, "status": status, **details})


def _rank_data(path: Path) -> tuple[dict[str, dict[str, Any]], set[str], int]:
    by_candidate: dict[str, dict[str, Any]] = {}
    versions: set[str] = set()
    errors = 0
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            versions.add(row["index_version"])
            try:
                rank: Any = row["rank"] if row["rank"] == "not_found@50" else int(row["rank"])
                if isinstance(rank, int) and not 1 <= rank <= 50:
                    errors += 1
            except ValueError:
                errors += 1
                continue
            by_candidate.setdefault(row["candidate_id"], {})[row["method"]] = rank
    return by_candidate, versions, errors


def run() -> dict[str, Any]:
    root = ROOT
    output = root / "data" / "eval" / "final"
    corpus = root / "data" / "kb" / "documents.jsonl"
    index_manifest = json.loads((root / "data" / "kb" / "index_manifest.json").read_text(encoding="utf-8"))
    actual_hash = hashlib.sha256(corpus.read_bytes()).hexdigest()
    index_version = str(index_manifest.get("index_version", ""))
    if actual_hash != CORPUS_SHA256 or index_manifest.get("corpus_sha256") != CORPUS_SHA256 or not index_version:
        _checkpoint(root, "stage0", "fail", corpus_sha256=actual_hash, index_version=index_version)
        raise RuntimeError("Stage 0 frozen-input verification failed")
    (output / "run_manifest.json").write_text(
        json.dumps(
            {
                "seed": SEED,
                "corpus_sha256": CORPUS_SHA256,
                "index_version": index_version,
                "retrieval_methods": [method for method, _, _ in METHODS],
                "retrieval_settings": {
                    "dense_limit": 50,
                    "hybrid_limit": 50,
                    "reranker_input_limit": 20,
                    "reranker_not_found_rule": "candidates outside hybrid top 20 are not_found@50",
                    "document_level_collapsing": "best chunk rank per CVE",
                    "filters": {},
                },
                "settings": {
                    "embedding_model": settings.embedding_model,
                    "embedding_revision": settings.embedding_revision,
                    "rerank_model": settings.rerank_model,
                    "rerank_revision": settings.rerank_revision,
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    _checkpoint(root, "stage0", "pass", corpus_sha256=actual_hash, index_version=index_version, index_readable=True)

    pool_path = output / "candidate_pool.jsonl"
    rejected_path = output / "rejected.jsonl"
    pool_hash = hashlib.sha256(pool_path.read_bytes()).hexdigest()
    pool = [json.loads(line) for line in pool_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rejected = [json.loads(line) for line in rejected_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    eligible = [row for row in pool if not row.get("initial_rejection_reasons")]
    stage1_ok = (
        len(pool) == EXPECTED_POOL_ROWS
        and pool_hash == EXPECTED_POOL_SHA256
        and len({row["candidate_id"] for row in pool}) == EXPECTED_POOL_ROWS
        and len(rejected) == EXPECTED_REJECTED_ROWS
        and len({row["candidate_id"] for row in rejected}) == EXPECTED_REJECTED_ROWS
        and len(eligible) == 699
    )
    if not stage1_ok:
        _checkpoint(root, "stage1", "fail", pool_rows=len(pool), pool_sha256=pool_hash, rejected_rows=len(rejected), eligible=len(eligible))
        raise RuntimeError("Stage 1 candidate-pool verification failed")
    _checkpoint(root, "stage1", "pass", pool_rows=len(pool), pool_sha256=pool_hash, rejected_rows=len(rejected), eligible=len(eligible))

    ranks, rank_versions, rank_errors = _rank_data(output / "ranks.csv")
    complete = sum(set(ranks.get(row["candidate_id"], {})) == {method for method, _, _ in METHODS} for row in eligible)
    stage2_ok = complete == len(eligible) and rank_errors == 0
    _checkpoint(root, "stage2", "pass" if stage2_ok else "fail", completed_candidates=complete, errors=rank_errors, rank_index_versions=sorted(rank_versions))
    if not stage2_ok:
        raise RuntimeError("Stage 2 rank verification failed")

    labels = []
    for candidate in sorted(eligible, key=lambda row: row["candidate_id"]):
        values = ranks[candidate["candidate_id"]]
        if all(values[method] == 1 for method, _, _ in METHODS):
            difficulty = "easy"
        elif "not_found@50" in values.values() or sum(values[method] in {2, 3} for method, _, _ in METHODS) >= 2:
            difficulty = "hard"
        else:
            difficulty = "medium"
        labels.append({"candidate_id": candidate["candidate_id"], "difficulty": difficulty})
    (output / "difficulty_labels.jsonl").write_text(
        "\n".join(json.dumps(row, separators=(",", ":")) for row in labels) + "\n",
        encoding="utf-8",
    )
    _checkpoint(root, "stage3", "pass", counts=dict(sorted(Counter(row["difficulty"] for row in labels).items())))

    records, _ = _read_jsonl(corpus)
    record_map = {str(record["doc_id"]): record for record in records}
    validation = []
    for candidate in sorted(eligible, key=lambda row: row["candidate_id"]):
        validation.append(validate_candidate(candidate, ranks[candidate["candidate_id"]], record_map, Counter()))
    (output / "candidate_validation.jsonl").write_text(
        "\n".join(json.dumps(row, separators=(",", ":")) for row in validation) + "\n",
        encoding="utf-8",
    )
    gate_counts = {
        gate: {
            "pass": sum(bool(row["checks"].get(gate)) for row in validation),
            "fail": sum(not bool(row["checks"].get(gate)) for row in validation),
        }
        for gate in ("G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8")
    }
    _checkpoint(root, "stage4", "pass", gate_counts=gate_counts)

    passed = [candidate for candidate, result in zip(sorted(eligible, key=lambda row: row["candidate_id"]), validation) if result["passed"]]
    uses: Counter[str] = Counter()
    selected = []
    used_gold: set[str] = set()
    for candidate in passed:
        if candidate["gold_cve"] in used_gold or any(uses[item["cve"]] >= 3 for item in candidate["confusers"]):
            continue
        selected.append(candidate)
        used_gold.add(candidate["gold_cve"])
        for item in candidate["confusers"]:
            uses[item["cve"]] += 1
        if len(selected) == 300:
            break
    if len(selected) != 300:
        _checkpoint(
            root,
            "stage5",
            "fail",
            selected_count=len(selected),
            required_count=300,
            shortfall=300 - len(selected),
            gold_unique=len(used_gold) == len(selected),
            confuser_max=max(uses.values(), default=0),
        )
        (output / "blind_score.md").write_text("not run — predictor not authorized/configured\n", encoding="utf-8")
        (output / "handcheck.md").write_text("not run — no 300-item final set was produced\n", encoding="utf-8")
        counts = {
            "candidates_generated": len(pool),
            "rejected": len(rejected),
            "eligible": len(eligible),
            "ranked": complete,
            "errors": rank_errors,
            "selected": len(selected),
            "difficulty": "unknown",
            "product": "unknown",
            "cwe": "unknown",
            "confuser_max": max(uses.values(), default=0),
            "confuser_distribution": dict(sorted(Counter(uses.values()).items())),
            "rejection_counts": dict(sorted(Counter(reason for row in rejected for reason in row["rejection_reasons"]).items())),
            "seed": SEED,
            "corpus_sha256": CORPUS_SHA256,
            "index_version": index_version,
            "blind_audit": "not run — predictor not authorized/configured",
            "hand_check": "not run — no 300-item final set was produced",
            "stage4_gate_counts": gate_counts,
        }
        (output / "counts.md").write_text("# Final evaluation counts\n\n```json\n" + json.dumps(counts, indent=2) + "\n```\n", encoding="utf-8")
        return counts
    raise AssertionError("unexpected complete selection path")


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
