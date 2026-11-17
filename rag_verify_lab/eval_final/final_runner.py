from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from openai import OpenAI
from PIL import Image, ImageDraw

from ..config import ROOT, settings
from ..db import KBChunk, KBEmbedding, db_session
from ..models import encode
from ..rag.index import IndexedFinding, reciprocal_rank_fusion, tokenize
from ..verify.jev import JEVClient


ARMS = ("llm_only", "vector_rag", "hybrid_rag", "hybrid_jev", "jev_retrieval")
ARM_LABELS = {
    "llm_only": "LLM only", "vector_rag": "Vector RAG", "hybrid_rag": "Hybrid RAG",
    "hybrid_jev": "Hybrid RAG + JEV", "jev_retrieval": "JEV retrieval",
}
PREDICTION_FIELDS = ("question_id", "arm", "answer", "valid", "error", "latency_ms", "input_tokens", "output_tokens", "jev_calls")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
Z_95 = 1.959963984540054
ANSWER_RPM = max(1, int(os.getenv("GROQ_REQUESTS_PER_MINUTE", "24")))
ANSWER_MIN_INTERVAL_SECONDS = 60 / ANSWER_RPM
_answer_lock = threading.Lock()
_last_answer_start = 0.0
_preferred_key_index = 0
_answer_key_cooldown_until: dict[int, float] = {}


def parse_answer(value: str) -> str | None:
    """Return the first study-valid CVE identifier, or None when absent."""
    normalized = (value or "").translate(str.maketrans({"‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-"}))
    match = CVE_RE.search(normalized)
    return match.group(0).upper() if match else None


def wilson_interval(correct: int, total: int) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    proportion = correct / total
    denominator = 1 + Z_95 * Z_95 / total
    centre = (proportion + Z_95 * Z_95 / (2 * total)) / denominator
    spread = Z_95 * math.sqrt(proportion * (1 - proportion) / total + Z_95 * Z_95 / (4 * total * total)) / denominator
    lower = centre - spread
    upper = centre + spread
    return (0.0 if abs(lower) < 1e-15 else max(0.0, lower)), min(1.0, upper)


def mcnemar_p_value(b: int, c: int) -> float:
    """Two-sided exact binomial McNemar p-value."""
    discordant = b + c
    if not discordant:
        return 1.0
    tail = sum(math.comb(discordant, value) for value in range(min(b, c) + 1)) / (2 ** discordant)
    return min(1.0, 2 * tail)


def score_predictions(rows: list[dict[str, str]], gold: dict[str, str]) -> dict[str, dict[str, int]]:
    result = {arm: {"correct": 0, "wrong": 0, "error": 0} for arm in ARMS}
    by_key = {(row["question_id"], row["arm"]): row for row in rows}
    for question_id, expected in gold.items():
        for arm in ARMS:
            row = by_key.get((question_id, arm))
            if row is None:
                result[arm]["wrong"] += 1
            elif row["error"]:
                result[arm]["error"] += 1
            elif row["valid"].lower() != "true":
                result[arm]["wrong"] += 1
            elif row["answer"] == expected:
                result[arm]["correct"] += 1
            else:
                result[arm]["wrong"] += 1
    return result


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def validate_inputs(items: list[dict[str, Any]]) -> dict[str, Any]:
    final = ROOT / "data" / "eval" / "final"
    manifest = json.loads((final / "run_manifest.json").read_text(encoding="utf-8"))
    handcheck = (final / "handcheck.md").read_text(encoding="utf-8")
    actual_hash = hashlib.sha256((ROOT / "data" / "kb" / "documents.jsonl").read_bytes()).hexdigest()
    gates = {
        "row_count": len(items) == 300,
        "unique_question_ids": len({row["question_id"] for row in items}) == 300,
        "unique_gold_cve": len({row["gold_cve"] for row in items}) == 300,
        "questions_do_not_contain_gold": all(str(row["gold_cve"]).casefold() not in str(row["question"]).casefold() for row in items),
        "handcheck_30_pass": len(re.findall(r"Result:\s*PASS\b", handcheck)) == 30,
        "handcheck_no_fail": not re.search(r"Result:\s*FAIL\b", handcheck),
        "corpus_hash_matches_manifest": actual_hash == manifest.get("corpus_sha256"),
        "item_corpus_hash_matches": all(row.get("corpus_sha256") == manifest.get("corpus_sha256") for row in items),
        "item_index_matches": all(row.get("index_version") == manifest.get("index_version") for row in items),
    }
    if not all(gates.values()):
        failed = ", ".join(key for key, passed in gates.items() if not passed)
        raise RuntimeError(f"Input gate failure: {failed}")
    return {"gates": gates, "corpus_sha256": actual_hash, "index_version": manifest["index_version"]}


def _load_index(index_version: str) -> list[IndexedFinding]:
    with db_session() as db:
        chunks = db.query(KBChunk).filter(KBChunk.index_version == index_version).all()
        vectors = {
            row.content_hash: np.frombuffer(row.vector, dtype=np.float32).copy()
            for row in db.query(KBEmbedding).filter(
                KBEmbedding.model_name == settings.embedding_model,
                KBEmbedding.model_revision == settings.embedding_revision,
            ).all()
        }
    result = []
    for number, chunk in enumerate(chunks):
        vector = vectors.get(chunk.content_hash)
        if vector is None:
            raise RuntimeError(f"Missing indexed vector for {chunk.chunk_id}")
        metadata = json.loads(chunk.metadata_json)
        metadata["doc_id"] = chunk.doc_id
        result.append(IndexedFinding(number, chunk.text, metadata, vector))
    if not result:
        raise RuntimeError("The frozen index has no readable chunks")
    return result


def _dense(query: str, index: list[IndexedFinding], limit: int) -> list[IndexedFinding]:
    query_vector = encode([query], query=True)[0]
    ranked = sorted(((float(np.dot(item.vector, query_vector)), item) for item in index), key=lambda pair: pair[0], reverse=True)
    for score, item in ranked[:limit]:
        item.dense_score = score
    return [item for _, item in ranked[:limit]]


def _bm25(query: str, index: list[IndexedFinding], limit: int) -> list[IndexedFinding]:
    from rank_bm25 import BM25Okapi
    scores = BM25Okapi([tokenize(item.text) for item in index]).get_scores(tokenize(query))
    ranked = sorted(((float(score), item) for score, item in zip(scores, index)), key=lambda pair: pair[0], reverse=True)
    for score, item in ranked[:limit]:
        item.sparse_score = score
    return [item for _, item in ranked[:limit]]


def _unique_docs(items: list[IndexedFinding], limit: int = 5) -> list[IndexedFinding]:
    selected: list[IndexedFinding] = []
    seen: set[str] = set()
    for item in items:
        doc_id = str(item.metadata.get("doc_id", item.id))
        if doc_id not in seen:
            selected.append(item)
            seen.add(doc_id)
        if len(selected) == limit:
            break
    return selected


def _evidence(items: list[IndexedFinding]) -> list[dict[str, str]]:
    """Format retrieved records without using an evaluation label."""
    return [
        {
            "cve_id": str(item.metadata.get("doc_id", "")),
            "title": str(item.metadata.get("title", item.metadata.get("doc_id", ""))),
            "description": item.text,
        }
        for item in items
    ]


def _cve_evidence(items: list[IndexedFinding]) -> list[dict[str, str]]:
    return [row for row in _evidence(items) if CVE_RE.fullmatch(row["cve_id"])]


def _answer(question: str, evidence: list[dict[str, str]]) -> tuple[str, int | str, int | str]:
    content = "\n".join(
        f"[E{number}] CVE: {row['cve_id']}\nTitle: {row['title']}\nDescription: {row['description']}"
        for number, row in enumerate(evidence, 1)
    )
    prompt = "Return one CVE ID that appears in the evidence and answers the question. No other text.\n"
    if evidence:
        prompt += "Use only this evidence:\n" + content
    else:
        prompt += "Question only; do not assume supporting evidence."
    api_keys = settings.answer_api_keys
    if not api_keys:
        raise RuntimeError("No answer API key is configured")
    global _preferred_key_index
    first = _preferred_key_index % len(api_keys)
    key_order = [(first + offset) % len(api_keys) for offset in range(len(api_keys))]
    response = None
    rate_errors: list[tuple[int, Exception]] = []
    auth_errors: list[Exception] = []
    attempted_key_indexes: set[int] = set()
    for key_index in key_order:
        now = time.monotonic()
        cooldown = _answer_key_cooldown_until.get(key_index, 0.0) - now
        if cooldown > 0:
            continue
        api_key = api_keys[key_index]
        attempted_key_indexes.add(key_index)
        _wait_for_answer_slot()
        try:
            client = OpenAI(api_key=api_key, base_url=settings.answer_base_url, timeout=60.0, max_retries=0)
            completion_limit = settings.answer_max_tokens
            if "gpt-oss" in settings.answer_model.lower():
                completion_limit = max(completion_limit, 256)
            params: dict[str, object] = {
                "model": settings.answer_model,
                "messages": [{"role": "user", "content": question + "\n\n" + prompt}],
                "max_completion_tokens": completion_limit,
            }
            if "gpt-oss" in settings.answer_model.lower():
                params["extra_body"] = {"reasoning_effort": "low", "include_reasoning": False}
            response = client.chat.completions.create(**params)
            _preferred_key_index = key_index
            break
        except Exception as exc:
            status = getattr(exc, "status_code", None)
            message = str(exc).lower()
            if status == 429 or "429" in message or "rate limit" in message:
                delay = _retry_after_seconds(exc, 60.0)
                _answer_key_cooldown_until[key_index] = time.monotonic() + delay
                rate_errors.append((key_index, exc))
                continue
            if status in {401, 403} or any(marker in message for marker in ("401", "403", "unauthorized", "invalid api key")):
                auth_errors.append(exc)
                continue
            else:
                raise
    if response is None:
        if rate_errors:
            daily_errors = [error for _, error in rate_errors if "per day" in str(error).lower() or "daily" in str(error).lower()]
            untried_keys = set(range(len(api_keys))) - attempted_key_indexes
            if untried_keys:
                available_at = min(_answer_key_cooldown_until.get(index, 0.0) for index in untried_keys)
                wait = max(0.0, available_at - time.monotonic())
                if wait:
                    time.sleep(wait)
                return _answer(question, evidence)
            if len(daily_errors) == len(rate_errors) and len(attempted_key_indexes) == len(api_keys):
                raise daily_errors[0]
            retryable = [(index, error) for index, error in rate_errors if error not in daily_errors]
            if retryable:
                raise min(retryable, key=lambda pair: _answer_key_cooldown_until.get(pair[0], float("inf")))[1]
            raise rate_errors[0][1]
        if auth_errors:
            raise RuntimeError("all configured answer API keys were rejected") from auth_errors[-1]
        available_at = min(_answer_key_cooldown_until.values(), default=0.0)
        wait = available_at - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        return _answer(question, evidence)
    usage = response.usage
    return response.choices[0].message.content or "", (int(usage.prompt_tokens) if usage else "unknown"), (int(usage.completion_tokens) if usage else "unknown")


def _wait_for_answer_slot() -> None:
    """Pace Groq requests below its shared per-organization model RPM limit."""
    global _last_answer_start
    with _answer_lock:
        now = time.monotonic()
        wait = ANSWER_MIN_INTERVAL_SECONDS - (now - _last_answer_start)
        if wait > 0:
            time.sleep(wait)
        _last_answer_start = time.monotonic()


def _retry_after_seconds(exc: Exception, fallback: float) -> float:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", {}) or {}
    retry_after = headers.get("retry-after") or headers.get("Retry-After")
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except (TypeError, ValueError):
            pass
    match = re.search(r"(?:retry in|try again in)\s*(?:(\d+)h)?\s*(?:(\d+)m)?\s*([0-9]+(?:\.[0-9]+)?)s", str(exc), re.IGNORECASE)
    if match:
        hours, minutes, seconds = match.groups()
        return int(hours or 0) * 3600 + int(minutes or 0) * 60 + float(seconds)
    return fallback


def _retry(call: Any) -> Any:
    for attempt in range(4):
        try:
            return call()
        except Exception as exc:
            status = getattr(exc, "status_code", None)
            message = str(exc).lower()
            if status == 429 or "429" in message or "rate limit" in message:
                if "daily" in message or "per day" in message or attempt == 3:
                    raise RuntimeError(f"quota_or_rate_limit: {exc}") from exc
                time.sleep(_retry_after_seconds(exc, max(2.0, 2 ** (attempt + 1))))
                continue
            raise
    raise RuntimeError("unreachable retry state")


def _jev_retry(call: Any) -> Any:
    """JEV has one retry at most, including when the provider returns HTTP 429."""
    for attempt in range(2):
        try:
            return call()
        except Exception as exc:
            message = str(exc).lower()
            if attempt == 0 and (getattr(exc, "status_code", None) == 429 or "429" in message or "rate limit" in message):
                if "daily" in message or "per day" in message:
                    raise RuntimeError(f"quota_or_rate_limit: {exc}") from exc
                time.sleep(_retry_after_seconds(exc, 1.0))
                continue
            raise
    raise RuntimeError("unreachable JEV retry state")


def _prediction(question_id: str, arm: str, raw: str, error: str, started: float, tokens_in: int | str, tokens_out: int | str, jev_calls: int) -> dict[str, str]:
    answer = parse_answer(raw) if not error else None
    return {
        "question_id": question_id, "arm": arm, "answer": answer or "", "valid": str(answer is not None and not error),
        "error": error, "latency_ms": f"{(time.perf_counter() - started) * 1000:.3f}", "input_tokens": str(tokens_in),
        "output_tokens": str(tokens_out), "jev_calls": str(jev_calls),
    }


def _append_prediction(path: Path, row: dict[str, str]) -> None:
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PREDICTION_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def deduplicate_predictions(path: Path) -> int:
    """Keep the first completed checkpoint for each question/arm after an interrupted run."""
    if not path.exists():
        return 0
    rows = list(csv.DictReader(path.open(encoding="utf-8", newline="")))
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for row in rows:
        key = (row["question_id"], row["arm"])
        if key not in seen:
            unique.append(row)
            seen.add(key)
    removed = len(rows) - len(unique)
    if removed:
        _write_csv(path, unique, PREDICTION_FIELDS)
    return removed


def remove_groq_setup_failures(path: Path) -> int:
    """Remove attempts rejected locally by the SDK before a provider call."""
    if not path.exists():
        return 0
    rows = list(csv.DictReader(path.open(encoding="utf-8", newline="")))
    setup_failed_questions = {
        row["question_id"] for row in rows
        if row["arm"] == "hybrid_rag" and "unexpected keyword argument 'include_reasoning'" in row["error"]
    }
    filtered = [
        row for row in rows
        if "unexpected keyword argument 'include_reasoning'" not in row["error"]
        and not (row["arm"] == "hybrid_jev" and row["question_id"] in setup_failed_questions)
    ]
    removed = len(rows) - len(filtered)
    if removed:
        _write_csv(path, filtered, PREDICTION_FIELDS)
    return removed


def remove_failed_answer_rows(path: Path) -> int:
    """Requeue failed generation arms without repeating completed JEV checks."""
    if not path.exists():
        return 0
    rows = list(csv.DictReader(path.open(encoding="utf-8", newline="")))
    generation_arms = {"llm_only", "vector_rag", "hybrid_rag"}
    failed_hybrid_questions = {
        row["question_id"] for row in rows
        if row["arm"] == "hybrid_rag" and row["error"]
    }
    filtered = [
        row for row in rows
        if not (row["arm"] in generation_arms and row["error"])
        and not (
            row["arm"] == "hybrid_jev"
            and row["question_id"] in failed_hybrid_questions
            and (row.get("jev_calls") or "0").isdigit()
            and int(row.get("jev_calls") or "0") == 0
        )
    ]
    removed = len(rows) - len(filtered)
    if removed:
        _write_csv(path, filtered, PREDICTION_FIELDS)
    return removed


def _write_reports(run_dir: Path, items: list[dict[str, Any]], config: dict[str, Any]) -> None:
    predictions_path = run_dir / "predictions.csv"
    rows = list(csv.DictReader(predictions_path.open(encoding="utf-8", newline=""))) if predictions_path.exists() else []
    gold = {row["question_id"]: row["gold_cve"] for row in items}
    scores = score_predictions(rows, gold)
    difficulties = {row["question_id"]: row["difficulty"] for row in items}
    by_key = {(row["question_id"], row["arm"]): row for row in rows}
    stats: dict[str, Any] = {"arms": {}}
    table_rows = []
    for arm in ARMS:
        count = scores[arm]
        low, high = wilson_interval(count["correct"], 300)
        accuracy = count["correct"] / 300
        stats["arms"][arm] = {"accuracy": accuracy, "wilson_95_ci": [low, high], "counts": count, "completed": sum(1 for row in rows if row["arm"] == arm)}
        table_rows.append({"arm": arm, "accuracy": accuracy, "ci_low": low, "ci_high": high, "wrong": count["wrong"], "error": count["error"]})
    b = c = 0
    for question_id, expected in gold.items():
        c_row, d_row = by_key.get((question_id, "hybrid_rag")), by_key.get((question_id, "hybrid_jev"))
        c_right = bool(c_row and not c_row["error"] and c_row["valid"] == "True" and c_row["answer"] == expected)
        d_right = bool(d_row and not d_row["error"] and d_row["valid"] == "True" and d_row["answer"] == expected)
        b += int(d_right and not c_right)
        c += int(c_right and not d_right)
    stats["paired_C_vs_D"] = {"b": b, "c": c, "mcnemar_p_value": mcnemar_p_value(b, c)}
    (run_dir / "stats.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    lines = ["# Scores", "", "| Arm | Accuracy | Correct | Wrong | Error |", "|---|---:|---:|---:|---:|"]
    for arm in ARMS:
        count, arm_stats = scores[arm], stats["arms"][arm]
        lines.append(f"| {ARM_LABELS[arm]} | {arm_stats['accuracy']:.4f} | {count['correct']} | {count['wrong']} | {count['error']} |")
    lines += ["", f"C vs D: b={b}, c={c}, exact two-sided McNemar p={mcnemar_p_value(b, c):.8g}."]
    (run_dir / "scores.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    tables = run_dir / "tables"; tables.mkdir(exist_ok=True)
    corpus_cwes = {record["doc_id"]: record.get("cwe_ids", []) for record in _read_jsonl(ROOT / "data" / "kb" / "documents.jsonl")}
    difficulty_counts = Counter(item["difficulty"] for item in items)
    product_counts = Counter(item["product"] for item in items)
    dataset_rows = [{"question_id": item["question_id"], "difficulty": item["difficulty"], "difficulty_count": difficulty_counts[item["difficulty"]], "product": item["product"], "product_count": product_counts[item["product"]], "cwe_count": len(corpus_cwes.get(item["gold_cve"], [])), "confuser_rules": ";".join(value["match_reason"] for value in item["confusers"])} for item in items]
    _write_csv(tables / "Table1_dataset.csv", dataset_rows, ("question_id", "difficulty", "difficulty_count", "product", "product_count", "cwe_count", "confuser_rules"))
    _write_csv(tables / "Table2_main_results.csv", table_rows, ("arm", "accuracy", "ci_low", "ci_high", "wrong", "error"))
    difficulty_rows = []
    for arm in ARMS:
        for difficulty in ("easy", "medium", "hard"):
            ids = [qid for qid, value in difficulties.items() if value == difficulty]
            correct = sum(1 for qid in ids if (row := by_key.get((qid, arm))) and not row["error"] and row["valid"] == "True" and row["answer"] == gold[qid])
            difficulty_rows.append({"arm": arm, "difficulty": difficulty, "accuracy": correct / len(ids) if ids else 0.0, "n": len(ids)})
    _write_csv(tables / "Table3_difficulty.csv", difficulty_rows, ("arm", "difficulty", "accuracy", "n"))
    _write_csv(tables / "Table4_paired_C_vs_D.csv", [{"b": b, "c": c, "mcnemar_p": mcnemar_p_value(b, c)}], ("b", "c", "mcnemar_p"))
    cost_rows = []
    for arm in ARMS:
        arm_rows = [row for row in rows if row["arm"] == arm]
        latencies = sorted(float(row["latency_ms"]) for row in arm_rows)
        generated_rows = [row for row in arm_rows if arm != "hybrid_jev"]
        known_tokens = [int(row["input_tokens"]) + int(row["output_tokens"]) for row in generated_rows if row["input_tokens"].isdigit() and row["output_tokens"].isdigit()]
        tokens_total: int | str = sum(known_tokens) if len(known_tokens) == len(generated_rows) else "unknown"
        answer_cost: float | None = None
        if generated_rows and len(known_tokens) == len(generated_rows) and settings.price_answer_in_per_m and settings.price_answer_out_per_m:
            answer_cost = sum(
                int(row["input_tokens"]) * float(settings.price_answer_in_per_m) / 1_000_000
                + int(row["output_tokens"]) * float(settings.price_answer_out_per_m) / 1_000_000
                for row in generated_rows
            )
        jev_cost: float | None = None
        if settings.price_jev_per_call and all(row["jev_calls"].isdigit() for row in arm_rows):
            jev_cost = sum(int(row["jev_calls"]) for row in arm_rows) * float(settings.price_jev_per_call)
        total_cost = (answer_cost or 0.0) + (jev_cost or 0.0) if (not generated_rows or answer_cost is not None) and (not any(int(row["jev_calls"] or 0) for row in arm_rows) or jev_cost is not None) else "unknown"
        cost_per_question = total_cost / len(arm_rows) if isinstance(total_cost, (int, float)) and arm_rows else "unknown"
        cost_rows.append({"arm": arm, "calls": len(arm_rows), "answer_calls": len(generated_rows), "jev_calls": sum(int(row["jev_calls"]) for row in arm_rows if row["jev_calls"].isdigit()), "tokens": tokens_total, "median_latency_ms": _percentile(latencies, 50), "p95_latency_ms": _percentile(latencies, 95), "cost": total_cost, "cost_per_question": cost_per_question})
    _write_csv(tables / "Table5_cost_time.csv", cost_rows, ("arm", "calls", "answer_calls", "jev_calls", "tokens", "median_latency_ms", "p95_latency_ms", "cost", "cost_per_question"))
    _figures(run_dir, table_rows, difficulty_rows, cost_rows)
    config["questions_completed_per_arm"] = {arm: sum(1 for row in rows if row["arm"] == arm) for arm in ARMS}
    config["usage"] = {row["arm"]: {"calls": row["calls"], "answer_calls": row["answer_calls"], "jev_calls": row["jev_calls"], "tokens": row["tokens"], "cost": row["cost"], "cost_per_question": row["cost_per_question"]} for row in cost_rows}
    (run_dir / "run_config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    methods = """# Methods

Run ID: {run_id}
Timestamp (UTC): {timestamp}

Accuracy = correct / 300; any response without an exact matching CVE, including an unparseable or withheld response, is scored as wrong. Provider errors are reported separately and are incorrect. Wilson 95% intervals use z=1.959963984540054. McNemar uses discordant counts b (D correct/C wrong) and c (C correct/D wrong), with exact two-sided binomial p=min(1, 2*P[X<=min(b,c)]) for X~Binomial(b+c,0.5). Cost per question is total recorded cost / completed questions; unavailable provider prices remain unknown. Median and p95 latency use the nearest-rank percentile.

Software: Python {python}; numpy {numpy}; Pillow {pillow}.
""".format(run_id=run_dir.name, timestamp=config["timestamp_utc"], python=sys.version.split()[0], numpy=np.__version__, pillow=Image.__version__)
    (run_dir / "methods.md").write_text(methods, encoding="utf-8")


def _resume_config(run_dir: Path, run_id: str, validation: dict[str, Any]) -> dict[str, Any]:
    config_path = run_dir / "run_config.json"
    if config_path.exists():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        previous_model = config.get("models", {}).get("answer")
        if previous_model and previous_model != settings.answer_model:
            raise RuntimeError(f"Cannot resume with a different answer model: run used {previous_model}")
        if config.get("stopped_cleanly"):
            history = config.setdefault("quota_stops", [])
            history.append({
                "stopped_at_utc": config.get("stop_timestamp_utc", "unknown"),
                "reason": config["stopped_cleanly"],
                "questions_completed_per_arm": config.get("questions_completed_per_arm", {}),
            })
            config.pop("stopped_cleanly", None)
            config.pop("stop_timestamp_utc", None)
        config["resume_count"] = int(config.get("resume_count", 0)) + 1
        config["last_resumed_at_utc"] = datetime.now(timezone.utc).isoformat()
        config.setdefault("thresholds", {})["answer_key_fallback_policy"] = "rotate across configured accounts after 401/403/429; keep a per-key Retry-After cooldown"
        return config
    return {
        "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "models": {
            "answer": settings.answer_model or "unknown",
            "answer_provider_base_url": settings.answer_base_url or "unknown",
            "embedding": settings.embedding_model or "unknown",
            "reranker": settings.rerank_model or "unknown",
            "jev": settings.jev_model or "unknown",
        },
        "arms": list(ARMS),
        "thresholds": {
            "top_k": 5,
            "jev_bm25_candidate_limit": settings.jev_candidate_limit,
            "answer_max_tokens_from_env": settings.answer_max_tokens,
            "answer_effective_completion_tokens": max(settings.answer_max_tokens, 256) if "gpt-oss" in settings.answer_model.lower() else settings.answer_max_tokens,
            "gpt_oss_reasoning_effort": "low" if "gpt-oss" in settings.answer_model.lower() else "unknown",
            "answer_retries_on_429": 3,
            "jev_retries_per_check": 1,
            "answer_requests_per_minute_cap": ANSWER_RPM,
            "shared_limit_pacing_seconds": ANSWER_MIN_INTERVAL_SECONDS,
            "answer_api_key_count": len(settings.answer_api_keys),
            "answer_key_fallback_policy": "rotate across configured accounts after 401/403/429; keep a per-key Retry-After cooldown",
        },
        "timings": {
            "latency_ms": "per question-arm from start through provider response",
            "retry_after": "provider Retry-After header, then provider response retry-delay text, then exponential fallback",
        },
        "usage": "per-call token usage recorded when provider supplies it",
        "cost": {
            "answer": "unknown" if not (settings.price_answer_in_per_m and settings.price_answer_out_per_m) else "computed from configured .env token prices",
            "jev": "unknown" if not settings.price_jev_per_call else "computed from configured .env per-call price",
        },
        "input_validation": validation,
    }


def _percentile(values: list[float], percentile: int) -> float | str:
    if not values:
        return "unknown"
    return values[math.ceil(percentile / 100 * len(values)) - 1]


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(rows)


def _figures(run_dir: Path, main: list[dict[str, Any]], difficulty: list[dict[str, Any]], costs: list[dict[str, Any]]) -> None:
    figures = run_dir / "figures"; figures.mkdir(exist_ok=True)
    _write_csv(figures / "figure_data_fig2_accuracy_bar.csv", main, tuple(main[0]) if main else ("arm",))
    _write_csv(figures / "figure_data_fig3_accuracy_by_difficulty.csv", difficulty, tuple(difficulty[0]) if difficulty else ("arm",))
    _write_csv(figures / "figure_data_fig4_cost_vs_accuracy.csv", [{"arm": row["arm"], "cost": row["cost"], "accuracy": next(value["accuracy"] for value in main if value["arm"] == row["arm"]), "included": row["cost"] != "unknown"} for row in costs], ("arm", "cost", "accuracy", "included"))
    _simple_png(figures / "fig2_accuracy_bar.png", "Accuracy by arm (Wilson 95% CI)", [(ARM_LABELS[row["arm"]], float(row["accuracy"])) for row in main], [(float(row["ci_low"]), float(row["ci_high"])) for row in main])
    _simple_png(figures / "fig3_accuracy_by_difficulty.png", "Accuracy by difficulty", [(f"{row['arm']} {row['difficulty']}", float(row["accuracy"])) for row in difficulty], groups=["easy", "medium", "hard"])
    _simple_png(figures / "fig4_cost_vs_accuracy.png", "Cost vs accuracy", [])
    (figures / "fig4_cost_vs_accuracy.caption.txt").write_text("All arms are excluded: recorded cost is unknown for every arm.\n", encoding="utf-8")


def _simple_png(path: Path, title: str, values: list[tuple[str, float]], intervals: list[tuple[float, float]] | None = None, groups: list[str] | None = None) -> None:
    image = Image.new("RGB", (1000, 600), "white"); draw = ImageDraw.Draw(image)
    draw.text((30, 20), title, fill="black")
    if values and groups:
        baseline = 540; chart_left = 70; chart_width = 890; group_width = chart_width / len(groups)
        arms = list(dict.fromkeys(label.rsplit(" ", 1)[0] for label, _ in values))
        bar_width = max(4, int(group_width / (len(arms) + 1)))
        palette = [(67, 120, 178), (93, 159, 127), (211, 153, 74), (158, 112, 175), (194, 99, 99)]
        for group_index, group in enumerate(groups):
            group_values = [(label.rsplit(" ", 1)[0], value) for label, value in values if label.endswith(" " + group)]
            for arm_index, (_, value) in enumerate(group_values):
                left = int(chart_left + group_index * group_width + arm_index * bar_width)
                height = int(max(0, min(1, value)) * 440)
                draw.rectangle((left, baseline - height, left + bar_width - 4, baseline), fill=palette[arm_index % len(palette)])
            draw.text((int(chart_left + group_index * group_width), baseline + 10), group, fill="black")
        for arm_index, arm in enumerate(arms):
            draw.rectangle((70 + arm_index * 175, 65, 82 + arm_index * 175, 77), fill=palette[arm_index % len(palette)])
            draw.text((88 + arm_index * 175, 62), arm[:18], fill="black")
    elif values:
        width = max(20, 900 // len(values)); baseline = 540
        for index, (label, value) in enumerate(values):
            left = 60 + index * width; height = int(max(0, min(1, value)) * 440)
            draw.rectangle((left, baseline - height, left + width - 10, baseline), fill=(80, 140, 200))
            if intervals:
                lower, upper = intervals[index]
                middle = left + (width - 10) // 2
                draw.line((middle, baseline - int(lower * 440), middle, baseline - int(upper * 440)), fill="black", width=2)
                draw.line((middle - 5, baseline - int(lower * 440), middle + 5, baseline - int(lower * 440)), fill="black", width=2)
                draw.line((middle - 5, baseline - int(upper * 440), middle + 5, baseline - int(upper * 440)), fill="black", width=2)
            draw.text((left, baseline + 8), label[:18], fill="black")
            draw.text((left, baseline - height - 18), f"{value:.3f}", fill="black")
    image.save(path)


def run(run_id: str | None = None) -> Path:
    items = _read_jsonl(ROOT / "data" / "eval" / "final" / "eval_hard_300.jsonl")
    validation = validate_inputs(items)
    run_id = run_id or datetime.now(timezone.utc).strftime("final_%Y%m%dT%H%M%SZ")
    run_dir = ROOT / "data" / "eval" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    config = _resume_config(run_dir, run_id, validation)
    index = _load_index(validation["index_version"])
    existing = set()
    predictions_path = run_dir / "predictions.csv"
    deduplicate_predictions(predictions_path)
    requeued = remove_failed_answer_rows(predictions_path)
    if requeued:
        config["failed_answer_rows_requeued"] = int(config.get("failed_answer_rows_requeued", 0)) + requeued
        (run_dir / "run_config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    if predictions_path.exists():
        existing = {(row["question_id"], row["arm"]) for row in csv.DictReader(predictions_path.open(encoding="utf-8", newline=""))}
    stopped = ""
    for item in items:
        question = str(item["question"])
        cache: dict[str, list[IndexedFinding]] = {}
        for arm in ARMS:
            if (item["question_id"], arm) in existing:
                continue
            started = time.perf_counter(); raw = ""; tokens_in: int | str = "unknown"; tokens_out: int | str = "unknown"; jev_calls = 0; error = ""
            try:
                if arm == "llm_only":
                    evidence = []
                elif arm == "vector_rag":
                    evidence = _evidence(_unique_docs(_dense(question, index, 50)))
                elif arm in {"hybrid_rag", "hybrid_jev"}:
                    if "hybrid" not in cache:
                        cache["hybrid"] = _unique_docs(reciprocal_rank_fusion([_dense(question, index, 50), _bm25(question, index, 50)]))
                    evidence = _evidence(cache["hybrid"])
                else:
                    candidates = _cve_evidence(_unique_docs(_bm25(question, index, settings.jev_candidate_limit), settings.jev_candidate_limit))
                    selected = _jev_retry(lambda: JEVClient().select_candidate(question, candidates))
                    raw = selected.cve_id
                    jev_calls = 1
                    evidence = []
                if arm == "hybrid_jev":
                    base = next((row for row in csv.DictReader(predictions_path.open(encoding="utf-8", newline="")) if row["question_id"] == item["question_id"] and row["arm"] == "hybrid_rag"), None)
                    raw = base["answer"] if base else ""
                    claim = parse_answer(raw)
                    if claim:
                        candidates = [row for row in evidence if CVE_RE.fullmatch(row["cve_id"])]
                        selected = _jev_retry(lambda: JEVClient().select_candidate(question, candidates))
                        jev_calls += 1
                        if claim != selected.cve_id:
                            raw = ""
                elif arm != "jev_retrieval":
                    raw, tokens_in, tokens_out = _retry(lambda: _answer(question, evidence))
            except Exception as exc:
                error = str(exc)
                if "quota_or_rate_limit" in error and ("daily" in error.lower() or "per day" in error.lower()):
                    stopped = error
            row = _prediction(item["question_id"], arm, raw, error, started, tokens_in, tokens_out, jev_calls)
            _append_prediction(predictions_path, row)
            if stopped:
                config["stopped_cleanly"] = stopped
                config["stop_timestamp_utc"] = datetime.now(timezone.utc).isoformat()
                _write_reports(run_dir, items, config)
                return run_dir
    _write_reports(run_dir, items, config)
    return run_dir


if __name__ == "__main__":
    supplied = sys.argv[1] if len(sys.argv) > 1 else None
    if supplied == "--repair":
        repair_dir = Path(sys.argv[2]).resolve()
        repair_items = _read_jsonl(ROOT / "data" / "eval" / "final" / "eval_hard_300.jsonl")
        repair_config = json.loads((repair_dir / "run_config.json").read_text(encoding="utf-8"))
        repair_config["duplicate_checkpoints_removed"] = deduplicate_predictions(repair_dir / "predictions.csv")
        _write_reports(repair_dir, repair_items, repair_config)
        print(repair_dir)
        raise SystemExit(0)
    print(run(supplied))
