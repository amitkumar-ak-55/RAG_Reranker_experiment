from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path
from typing import Any

from rank_bm25 import BM25Okapi

from .client import JinaReranker
from .config import ROOT, settings
from .metrics import aggregate, ndcg_at_k, precision_at_k, recall_at_k, reciprocal_rank


def _tokens(text: str) -> list[str]:
    return [token.lower() for token in text.split() if token.strip()]


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _candidate_documents(documents: list[dict[str, Any]], question: str, limit: int) -> list[dict[str, Any]]:
    ranker = BM25Okapi([_tokens(str(document.get("text", ""))) for document in documents])
    ranked = sorted(
        zip(ranker.get_scores(_tokens(question)), documents),
        key=lambda pair: pair[0],
        reverse=True,
    )
    return [document for _, document in ranked[:limit]]


def run(
    *,
    questions_path: Path = ROOT / "data" / "eval_questions.jsonl",
    documents_path: Path = ROOT / "data" / "kb" / "documents.jsonl",
    output_dir: Path = Path(__file__).resolve().parent / "results",
    max_questions: int | None = None,
) -> Path:
    questions = _load_jsonl(questions_path)[:max_questions]
    documents = _load_jsonl(documents_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    with JinaReranker() as reranker:
        for question in questions:
            query = str(question["question"])
            candidates = _candidate_documents(documents, query, settings.candidate_limit)
            baseline_ids = [str(item["doc_id"]) for item in candidates]
            started = time.perf_counter()
            row: dict[str, object] = {
                "question_id": question["question_id"],
                "candidate_ids": baseline_ids,
                "baseline_ids": baseline_ids[: settings.result_limit],
                "jina_ids": [],
                "key_slots": [],
                "request_count": 0,
                "latency_ms": 0.0,
                "error": "",
            }
            try:
                response = reranker.rerank(query, [str(item.get("text", "")) for item in candidates], settings.result_limit)
                order = sorted(range(len(candidates)), key=lambda index: response.scores[index], reverse=True)
                row["jina_ids"] = [str(candidates[index]["doc_id"]) for index in order[: settings.result_limit]]
                row["key_slots"] = [record.key_slot for record in response.request_records]
                row["request_count"] = len(response.request_records)
            except Exception as exc:
                row["error"] = str(exc)
            row["latency_ms"] = (time.perf_counter() - started) * 1000
            gold = {str(value) for value in question.get("gold_evidence_ids", [])}
            ranked = list(row["jina_ids"]) if not row["error"] else []
            row.update({
                "recall_at_5": recall_at_k(ranked, gold, 5),
                "precision_at_5": precision_at_k(ranked, gold, 5),
                "mrr": reciprocal_rank(ranked, gold),
                "ndcg_at_5": ndcg_at_k(ranked, gold, 5),
            })
            rows.append(row)

    manifest = {
        "settings": settings.masked_snapshot(),
        "questions_path": str(questions_path),
        "documents_path": str(documents_path),
        "question_count": len(questions),
    }
    (output_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (output_dir / "per_question.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    (output_dir / "summary.json").write_text(json.dumps(aggregate(rows), indent=2), encoding="utf-8")
    if rows:
        with (output_dir / "per_question.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=sorted(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    return output_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the isolated Jina reranker experiment.")
    parser.add_argument("--max-questions", type=int)
    args = parser.parse_args()
    print(run(max_questions=args.max_questions))


if __name__ == "__main__":
    main()

