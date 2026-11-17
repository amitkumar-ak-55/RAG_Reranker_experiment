from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from ..config import ROOT, settings
from ..db import KBChunk, KBEmbedding, db_session
from ..models import encode, reranker_model, validate_model_configuration
from ..rag.index import FindingIndex, reciprocal_rank_fusion, tokenize
from ..rag.retrieve import retrieve

CORPUS_SHA256 = "8c4daa39da534a7f4871f4e4f4d72af03bf8fd3ce5b34e5dac586e11e585f6fc"
SEED = 42
METHODS = (("dense", False, False), ("hybrid", True, False), ("hybrid_reranker", True, True))
WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9'_-]*")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")
BEHAVIOUR_RE = re.compile(
    r"\b(?:allow(?:s|ed)?|let(?:s)?|can|could|execute|bypass|read|write|upload|"
    r"inject|cause|permit|lead|result|disclose|expose|trigger|access|modify|"
    r"delete|overwrite|download|evaluate|deserialize|arbitrary|vulnerab\w*)\b",
    re.IGNORECASE,
)
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "by", "can", "for", "from", "in",
    "is", "it", "of", "on", "or", "that", "the", "this", "to", "via", "was",
    "were", "with", "which",
}


def _read_jsonl(path: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    records: list[dict[str, Any]] = []
    raw_by_id: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip():
            record = json.loads(raw)
            records.append(record)
            raw_by_id[str(record["doc_id"])] = raw
    return records, raw_by_id


def _cpe_pair(cpe: str) -> tuple[str, str] | None:
    fields = cpe.split(":")
    if len(fields) < 5 or fields[2] != "a":
        return None
    return tuple(re.sub(r"\\([!&,:])", r"\1", value).replace("_", " ") for value in fields[3:5])


def product_mapping(record: dict[str, Any]) -> tuple[str, str] | None:
    pairs = sorted({_cpe_pair(cpe) for cpe in record.get("products", []) if _cpe_pair(cpe)})
    text = f"{record.get('title', '')} {record.get('text', '')}".lower()
    mentioned = [
        pair for pair in pairs
        if pair[1].replace("_", " ").lower() in text
    ]
    if len(mentioned) != 1:
        return None
    vendor, product = mentioned[0]
    return f"{vendor} {product}", f"{vendor}:{product}"


def _first_product_mapping(record: dict[str, Any]) -> tuple[str, str] | None:
    pairs = sorted({_cpe_pair(cpe) for cpe in record.get("products", []) if _cpe_pair(cpe)})
    if not pairs:
        return None
    vendor, product = pairs[0]
    return f"{vendor} {product}", f"{vendor}:{product}"


def _sentence(record: dict[str, Any]) -> str | None:
    candidates = [
        sentence.strip()
        for sentence in SENTENCE_RE.split(str(record.get("text", "")))
        if len(WORD_RE.findall(sentence)) >= 12 and BEHAVIOUR_RE.search(sentence)
    ]
    return sorted(candidates, key=lambda value: (-len(WORD_RE.findall(value)), value))[0] if candidates else None


def _six_word_overlap(left: str, right: str) -> bool:
    left_words = [word.lower() for word in WORD_RE.findall(left)]
    right_words = [word.lower() for word in WORD_RE.findall(right)]
    runs = {tuple(right_words[index:index + 6]) for index in range(len(right_words) - 5)}
    return any(tuple(left_words[index:index + 6]) in runs for index in range(len(left_words) - 5))


def _normalized_prefix(text: str) -> str:
    return " ".join(word.lower() for word in WORD_RE.findall(text)[:4])


def _question(product: str, sentence: str, index: int) -> str:
    words = [word for word in WORD_RE.findall(sentence) if word.lower() not in STOPWORDS]
    signal = "; ".join(
        " ".join(words[start:start + 5])
        for start in range(0, min(len(words), 19), 7)
    )
    templates = (
        "Which CVE affects {product} when the report describes {signal}?",
        "For {product}, what CVE matches the security behavior involving {signal}?",
        "Identify the {product} CVE associated with this behavior: {signal}.",
        "What vulnerability identifier belongs to {product} when {signal}?",
        "Which {product} issue is characterized by {signal}?",
        "In {product}, which CVE is associated with a flaw where {signal}?",
        "What CVE should be assigned to {product} for the described case of {signal}?",
        "Which security defect in {product} is summarized by {signal}?",
        "Name the CVE for {product} matching the reported behavior {signal}.",
        "Given {product}, select the CVE whose report indicates {signal}.",
        "From the {product} report, which vulnerability involves {signal}?",
        "Could you identify the {product} vulnerability described by {signal}?",
        "The {product} report describes {signal}; which CVE is it?",
        "A finding for {product} mentions {signal}; what CVE fits?",
        "When reviewing {product}, which CVE corresponds to {signal}?",
        "For a {product} assessment involving {signal}, give the CVE.",
        "Match {product} to the CVE for the behavior {signal}.",
        "Please find the CVE affecting {product} in the case of {signal}.",
        "Which vulnerability record for {product} reports {signal}?",
        "What CVE is indicated by the {product} behavior described as {signal}?",
        "A security issue in {product} lets an attacker {signal}; identify the CVE.",
        "Using the {product} description, which CVE covers {signal}?",
        "Determine the CVE for {product} where the behavior is {signal}.",
        "The affected product is {product}; which CVE matches {signal}?",
        "Which CVE should a reviewer associate with {product} and {signal}?",
        "Report the CVE linked to {product} when the behavior is {signal}.",
        "Find the {product} CVE whose vulnerability permits {signal}.",
        "In a {product} finding, what CVE is tied to {signal}?",
        "What identifier matches {product} and the described behavior {signal}?",
        "Reviewing {product}, which vulnerability is represented by {signal}?",
        "For the affected {product}, identify the CVE involving {signal}.",
        "Which CVE entry describes {product} with behavior {signal}?",
    )
    return templates[index % len(templates)].format(product=product, signal=signal)


def _seed_distractors(path: Path) -> set[str]:
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}


def _confusers(record: dict[str, Any], records: list[dict[str, Any]], excluded: set[str]) -> list[dict[str, str]]:
    gold_cwes = set(record.get("cwe_ids", []))
    gold_pairs = {_cpe_pair(cpe) for cpe in record.get("products", []) if _cpe_pair(cpe)}
    options: list[tuple[tuple[str, str], dict[str, str]]] = []
    behavior = (_sentence(record) or str(record.get("text", ""))).lower()
    for other in records:
        other_id = str(other.get("doc_id", ""))
        if other_id in excluded or other_id == record.get("doc_id") or other.get("doc_type") != "cve":
            continue
        if other.get("group") not in {"positive", "kev"}:
            continue
        if behavior and behavior in str(other.get("text", "")).lower():
            continue
        other_pairs = {_cpe_pair(cpe) for cpe in other.get("products", []) if _cpe_pair(cpe)}
        shared_cwe = sorted(gold_cwes & set(other.get("cwe_ids", [])))
        shared_pair = sorted(gold_pairs & other_pairs)
        if not shared_cwe and not shared_pair:
            continue
        reason = "both" if shared_cwe and shared_pair else ("cwe" if shared_cwe else "vendor+product")
        vendor = shared_pair[0][0] if shared_pair else (sorted(other_pairs)[0][0] if other_pairs else "")
        options.append(((vendor, other_id), {"cve": other_id, "match_reason": reason}))
    options.sort(key=lambda item: item[0])
    return [option for _, option in options[:2]]


def _balanced_confusers(
    candidates: list[dict[str, Any]],
    records: list[dict[str, Any]],
    excluded: set[str],
) -> None:
    """Assign the least-used valid confusers in candidate order."""
    uses: Counter[str] = Counter()
    for candidate in candidates:
        if not candidate["product"] or not candidate["behavior_sentence"]:
            continue
        record = next(row for row in records if str(row.get("doc_id")) == candidate["gold_cve"])
        options = _confuser_options(record, records, excluded, candidate["behavior_sentence"])
        if len(options) < 2:
            candidate["confusers"] = []
            continue
        options.sort(key=lambda item: (uses[item["cve"]], item["cve"]))
        chosen = [options[0]]
        for option in options[1:]:
            if option["cve"] != chosen[0]["cve"]:
                chosen.append(option)
                break
        candidate["confusers"] = chosen
        for option in chosen:
            uses[option["cve"]] += 1


def _confuser_options(
    record: dict[str, Any],
    records: list[dict[str, Any]],
    excluded: set[str],
    behavior_sentence: str,
) -> list[dict[str, str]]:
    gold_cwes = set(record.get("cwe_ids", []))
    gold_pairs = {_cpe_pair(cpe) for cpe in record.get("products", []) if _cpe_pair(cpe)}
    behavior = behavior_sentence.lower()
    options: list[tuple[tuple[str, str], dict[str, str]]] = []
    for other in records:
        other_id = str(other.get("doc_id", ""))
        if other_id in excluded or other_id == record.get("doc_id") or other.get("doc_type") != "cve":
            continue
        if other.get("group") not in {"positive", "kev"}:
            continue
        if behavior and behavior in str(other.get("text", "")).lower():
            continue
        other_pairs = {_cpe_pair(cpe) for cpe in other.get("products", []) if _cpe_pair(cpe)}
        shared_cwe = sorted(gold_cwes & set(other.get("cwe_ids", [])))
        shared_pair = sorted(gold_pairs & other_pairs)
        if not shared_cwe and not shared_pair:
            continue
        reason = "both" if shared_cwe and shared_pair else ("cwe" if shared_cwe else "vendor+product")
        vendor = shared_pair[0][0] if shared_pair else (sorted(other_pairs)[0][0] if other_pairs else "")
        options.append(((vendor, other_id), {"cve": other_id, "match_reason": reason}))
    options.sort(key=lambda item: item[0])
    return [option for _, option in options]


def generate_candidates(corpus: Path, distractors: Path, limit: int = 2000) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records, raw_by_id = _read_jsonl(corpus)
    excluded = _seed_distractors(distractors)
    candidates: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for number, record in enumerate(sorted(records, key=lambda value: str(value.get("doc_id", ""))), 1):
        if len(candidates) >= limit:
            break
        if record.get("doc_type") != "cve" or record.get("group") not in {"positive", "kev"}:
            continue
        candidate_id = f"C-{number:04d}"
        mapping = product_mapping(record)
        selected_mapping = mapping
        sentence = _sentence(record)
        reasons: list[str] = []
        if str(record["doc_id"]) in excluded:
            reasons.append("SEED_DISTRACTOR")
        if selected_mapping is None:
            reasons.append("AMBIGUOUS_PRODUCT")
        if sentence is None:
            reasons.append("NO_BEHAVIOUR_SENTENCE")
        product = selected_mapping[0] if selected_mapping else ""
        selected_pair = selected_mapping[1] if selected_mapping else ""
        question = _question(product, sentence, len(candidates)) if sentence and selected_mapping else ""
        confusers = _confusers(record, records, excluded) if sentence and selected_mapping else []
        if sentence and selected_mapping and len(confusers) < 2:
            reasons.append("NO_CONFUSERS")
        question_lower = question.lower()
        if question and (
            str(record["doc_id"]).lower() in question_lower
            or any(cwe.lower() in question_lower for cwe in record.get("cwe_ids", []))
            or any(str(cpe).lower() in question_lower for cpe in record.get("products", []))
        ):
            reasons.append("IDENTIFIER_LEAK")
        if question and sentence and _six_word_overlap(question, sentence):
            reasons.append("SIX_WORD_OVERLAP")
        if reasons:
            rejected.append({"candidate_id": candidate_id, "gold_cve": record["doc_id"], "rejection_reasons": reasons})
        candidates.append({
            "candidate_id": candidate_id,
            "question_id": candidate_id.replace("C-", "Q-"),
            "question": question,
            "gold_cve": record["doc_id"],
            "gold_record": json.loads(raw_by_id[str(record["doc_id"])]),
            "product": product,
            "selected_cpe_vendor_product": selected_pair,
            "behavior_sentence": sentence,
            "confusers": confusers,
            "corpus_sha256": CORPUS_SHA256,
            "initial_rejection_reasons": reasons,
        })
    _balanced_confusers(candidates, records, excluded)
    prefixes = Counter(
        _normalized_prefix(candidate["question"])
        for candidate in candidates
        if candidate["question"]
    )
    threshold = len(candidates) * 0.05
    for candidate in candidates:
        if candidate["product"] and len(candidate["confusers"]) < 2 and "NO_CONFUSERS" not in candidate["initial_rejection_reasons"]:
            candidate["initial_rejection_reasons"].append("NO_CONFUSERS")
        if candidate["question"] and prefixes[_normalized_prefix(candidate["question"])] > threshold:
            candidate["initial_rejection_reasons"].append("PREFIX_OVERUSE")
        if candidate["initial_rejection_reasons"]:
            rejected.append({
                "candidate_id": candidate["candidate_id"],
                "gold_cve": candidate["gold_cve"],
                "rejection_reasons": sorted(set(candidate["initial_rejection_reasons"])),
            })
    rejected_by_id = {
        candidate["candidate_id"]: {
            "candidate_id": candidate["candidate_id"],
            "gold_cve": candidate["gold_cve"],
            "rejection_reasons": sorted(set(candidate["initial_rejection_reasons"])),
        }
        for candidate in candidates
        if candidate["initial_rejection_reasons"]
    }
    return candidates, list(rejected_by_id.values())


def _load_index() -> FindingIndex:
    with db_session() as db:
        chunks = db.query(KBChunk).order_by(KBChunk.chunk_id).all()
        embeddings = {
            row.content_hash: np.frombuffer(row.vector, dtype=np.float32)
            for row in db.query(KBEmbedding).all()
        }
    if not chunks or len(embeddings) < len(chunks):
        raise RuntimeError("required local index embeddings are missing")
    return FindingIndex([
        {
            "id": index,
            "text": row.text,
            "vector": embeddings[row.content_hash],
            "metadata": {"doc_id": row.doc_id, "doc_type": row.doc_type, "group": row.group},
        }
        for index, row in enumerate(chunks)
    ])


def _load_candidate_pool(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise RuntimeError(f"required candidate pool is missing: {path}")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) < 600:
        raise RuntimeError(f"candidate pool must contain at least 600 candidates, found {len(rows)}")
    return rows


def rank_candidates(
    candidates: list[dict[str, Any]],
    index: FindingIndex,
    output: Path,
    *,
    recorded_index_version: str,
) -> None:
    fieldnames = ("candidate_id", "question_id", "gold_cve", "method", "rank", "index_version", "filters")
    complete_methods = {method for method, _, _ in METHODS}
    completed: set[str] = set()
    if output.is_file() and output.stat().st_size:
        with output.open(newline="", encoding="utf-8") as handle:
            existing: dict[str, set[str]] = {}
            for row in csv.DictReader(handle):
                existing.setdefault(row["candidate_id"], set()).add(row["method"])
            completed = {candidate_id for candidate_id, methods in existing.items() if methods == complete_methods}
    pending = [candidate for candidate in candidates if candidate["candidate_id"] not in completed]
    mode = "a" if output.is_file() and output.stat().st_size else "w"
    validate_model_configuration()
    model = reranker_model(settings.rerank_model, settings.rerank_revision, settings.rerank_device)
    with output.open(mode, newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if mode == "w":
            writer.writeheader()
        for batch_start in range(0, len(pending), 5):
            batch = pending[batch_start:batch_start + 5]
            queries = [candidate["question"] for candidate in batch]
            vectors = encode(queries, query=True) if settings.embedding_model else np.vstack(
                [index.vector_search(query, 1)[0].vector for query in queries]
            )
            retrieval: list[tuple[dict[str, Any], list[Any], list[Any]]] = []
            rerank_inputs: list[tuple[str, str]] = []
            for candidate, vector in zip(batch, vectors):
                dense = [
                    item for _, item in sorted(
                        ((float(np.dot(item.vector, vector)), item) for item in index.items),
                        key=lambda pair: (-pair[0], pair[1].id),
                    )[:50]
                ]
                sparse_scores = index.bm25.get_scores(tokenize(candidate["question"])) if index.bm25 else np.zeros(len(index.items))
                sparse = [
                    item for _, item in sorted(
                        ((float(score), item) for score, item in zip(sparse_scores, index.items)),
                        key=lambda pair: (-pair[0], pair[1].id),
                    )[:50]
                ]
                hybrid = reciprocal_rank_fusion([dense, sparse])[:10]
                retrieval.append((candidate, dense, hybrid))
                rerank_inputs.extend((candidate["question"], item.text) for item in hybrid)
            scores: list[float] = []
            for input_start in range(0, len(rerank_inputs), 8):
                scores.extend(
                    float(score)
                    for score in model.predict(
                        rerank_inputs[input_start:input_start + 8],
                        batch_size=8,
                        show_progress_bar=False,
                    )
                )
            offset = 0
            for batch_offset, (candidate, dense, hybrid) in enumerate(retrieval):
                candidate_scores = scores[offset:offset + len(hybrid)]
                offset += len(hybrid)
                reranked = [
                    item for item, _ in sorted(
                        zip(hybrid, candidate_scores), key=lambda pair: float(pair[1]), reverse=True
                    )
                ]
                for method, items in (("dense", dense), ("hybrid", hybrid), ("hybrid_reranker", reranked)):
                    docs: list[str] = []
                    for item in items:
                        doc_id = str(item.metadata.get("doc_id", item.id))
                        if doc_id not in docs:
                            docs.append(doc_id)
                    rank = docs.index(candidate["gold_cve"]) + 1 if candidate["gold_cve"] in docs else "not_found@50"
                    writer.writerow({
                        "candidate_id": candidate["candidate_id"], "question_id": candidate["question_id"],
                        "gold_cve": candidate["gold_cve"], "method": method, "rank": rank,
                        "index_version": recorded_index_version, "filters": "{}",
                    })
                    handle.flush()
                done = len(completed) + batch_start + batch_offset + 1
                if done % 50 == 0 or done == len(candidates):
                    print(f"rank progress: {done}/{len(candidates)} candidates", flush=True)


def validate_candidate(candidate: dict[str, Any], ranks: dict[str, dict[str, Any]], records: dict[str, dict[str, Any]], confuser_uses: Counter[str]) -> dict[str, Any]:
    gold = records.get(candidate["gold_cve"])
    checks: dict[str, bool] = {}
    checks["G1"] = bool(gold and gold.get("group") in {"positive", "kev"})
    checks["G2"] = bool(gold and product_mapping(gold) is not None and candidate["product"] == product_mapping(gold)[0])
    checks["G3"] = bool(gold and candidate["behavior_sentence"] in str(gold.get("text", "")))
    confusers = candidate.get("confusers", [])
    checks["G4"] = len(confusers) == 2 and all(candidate["behavior_sentence"].lower() not in str(records.get(item["cve"], {}).get("text", "")).lower() for item in confusers)
    checks["G5"] = bool(gold and candidate["gold_cve"] not in candidate["question"] and not any(cwe.lower() in candidate["question"].lower() for cwe in gold.get("cwe_ids", [])) and all(cpe not in candidate["question"] for cpe in gold.get("products", [])))
    checks["G6"] = not _six_word_overlap(candidate["question"], candidate["behavior_sentence"])
    checks["G7"] = all(confuser_uses[item["cve"]] < 3 for item in confusers)
    checks["G8"] = set(ranks) == {method for method, _, _ in METHODS} and all(value is not None for value in ranks.values())
    return {"candidate_id": candidate["candidate_id"], "gold_cve": candidate["gold_cve"], "checks": checks, "passed": all(checks.values())}


def _difficulty(ranks: dict[str, Any]) -> str:
    values = list(ranks.values())
    if all(value == 1 for value in values):
        return "easy"
    if "not_found@50" in values or sum(value in {2, 3} for value in values) >= 2:
        return "hard"
    return "medium"


def build(output_dir: Path = ROOT / "data" / "eval" / "final") -> dict[str, Any]:
    corpus = ROOT / "data" / "kb" / "documents.jsonl"
    manifest_path = ROOT / "data" / "kb" / "index_manifest.json"
    actual_hash = hashlib.sha256(corpus.read_bytes()).hexdigest()
    if actual_hash != CORPUS_SHA256:
        raise RuntimeError(f"corpus hash mismatch: expected {CORPUS_SHA256}, got {actual_hash}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("corpus_sha256") != CORPUS_SHA256 or not manifest.get("index_version"):
        raise RuntimeError("index manifest does not identify the frozen corpus and index")
    output_dir.mkdir(parents=True, exist_ok=True)
    candidates = _load_candidate_pool(output_dir / "candidate_pool.jsonl")
    candidates = [candidate for candidate in candidates if not candidate.get("initial_rejection_reasons")]
    if len(candidates) < 600:
        raise RuntimeError(f"eligible candidate gate failed: only {len(candidates)} candidates available")
    rejected = []
    index = _load_index()
    rank_candidates(candidates, index, output_dir / "ranks.csv", recorded_index_version=manifest["index_version"])
    rank_rows = list(csv.DictReader((output_dir / "ranks.csv").open(encoding="utf-8")))
    by_candidate: dict[str, dict[str, Any]] = {}
    for row in rank_rows:
        value: Any = row["rank"] if row["rank"] == "not_found@50" else int(row["rank"])
        by_candidate.setdefault(row["candidate_id"], {})[row["method"]] = value
    records, _ = _read_jsonl(corpus)
    record_map = {str(record["doc_id"]): record for record in records}
    validation: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    uses: Counter[str] = Counter()
    for candidate in candidates:
        result = validate_candidate(candidate, by_candidate.get(candidate["candidate_id"], {}), record_map, uses)
        validation.append(result)
        if result["passed"] and candidate["gold_cve"] not in {item["gold_cve"] for item in selected} and all(uses[item["cve"]] < 3 for item in candidate["confusers"]):
            candidate = {key: value for key, value in candidate.items() if key != "gold_record"}
            candidate["difficulty"] = _difficulty(by_candidate[candidate["candidate_id"]])
            candidate["ranks"] = by_candidate[candidate["candidate_id"]]
            candidate["index_version"] = manifest["index_version"]
            selected.append(candidate)
            for item in candidate["confusers"]:
                uses[item["cve"]] += 1
        if len(selected) == 300:
            break
    if len(selected) != 300:
        raise RuntimeError(f"selection shortfall: selected {len(selected)} of 300")
    (output_dir / "rejected.jsonl").write_text("\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in rejected) + "\n", encoding="utf-8")
    (output_dir / "candidate_validation.jsonl").write_text("\n".join(json.dumps(item, separators=(",", ":")) for item in validation) + "\n", encoding="utf-8")
    (output_dir / "eval_hard_300.jsonl").write_text("\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in selected) + "\n", encoding="utf-8")
    (output_dir / "blind_predictions.csv").write_text("status,reason\nnot run,predictor not authorized/configured\n", encoding="utf-8")
    (output_dir / "blind_score.md").write_text("# Blind prediction audit\n\nNot run — predictor not authorized/configured.\n", encoding="utf-8")
    rng = random.Random(SEED)
    sample = sorted(rng.sample(selected, 30), key=lambda item: item["question_id"])
    (output_dir / "handcheck.md").write_text("# Human hand check\n\nNot performed. Deterministic sample IDs: " + ", ".join(item["question_id"] for item in sample) + ".\n", encoding="utf-8")
    counts = {
        "candidate_total": len(candidates), "selected_total": len(selected),
        "difficulty": dict(sorted(Counter(item["difficulty"] for item in selected).items())),
        "product": dict(sorted(Counter(item["product"] for item in selected).items())),
        "cwe": dict(sorted(Counter(cwe for item in selected for cwe in record_map[item["gold_cve"]].get("cwe_ids", [])).items())),
        "confuser_max": max(uses.values()), "confuser_distribution": dict(sorted(Counter(uses.values()).items())),
        "rejections": dict(sorted(Counter(reason for item in rejected for reason in item["rejection_reasons"]).items())),
        "seed": SEED, "corpus_sha256": CORPUS_SHA256, "index_version": manifest["index_version"],
        "blind_audit": "not run — predictor not authorized/configured", "hand_check": "not performed",
    }
    (output_dir / "counts.md").write_text("# Final evaluation counts\n\n```json\n" + json.dumps(counts, indent=2) + "\n```\n", encoding="utf-8")
    manifest_output = {
        "created_at": datetime.now(timezone.utc).isoformat(), "seed": SEED, "corpus_sha256": CORPUS_SHA256,
        "index_version": manifest["index_version"], "retrieval_methods": [method for method, _, _ in METHODS],
        "retrieval_settings": {"dense_limit": 50, "hybrid_limit": 50, "reranker_limit": 50, "filters": {}},
        "settings": {"embedding_model": settings.embedding_model, "embedding_revision": settings.embedding_revision, "rerank_model": settings.rerank_model, "rerank_revision": settings.rerank_revision},
    }
    (output_dir / "run_manifest.json").write_text(json.dumps(manifest_output, indent=2) + "\n", encoding="utf-8")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "eval" / "final")
    args = parser.parse_args()
    print(json.dumps(build(args.output), indent=2))


if __name__ == "__main__":
    main()
