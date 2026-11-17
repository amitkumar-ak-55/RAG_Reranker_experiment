from __future__ import annotations

import hashlib
import json
import re
import time

from .. import cache
from ..config import settings
from ..db import ArmResult, ExperimentRun, Finding, Question, db_session, json_value, now
from ..rag.answer import answer_question
from ..rag.index import FindingIndex
from ..rag.retrieve import hybrid_search, retrieve
from ..verify.claims import judge_claims
from ..verify.jev import JEVClient
from ..verify.jev_health import jev_health
from .arms import ARMS
from .metrics import precision_at_k


def _question_filters(question: Question) -> dict[str, object]:
    filters: dict[str, object] = {}
    if question.vm_id is not None:
        filters["vm_id"] = question.vm_id
    port = re.search(r"\bport\s+(\d+)\b|\b(\d{2,5})/(?:tcp|udp)\b", question.text, re.IGNORECASE)
    if port:
        filters["port"] = int(port.group(1) or port.group(2))
    severity = re.search(r"\b(critical|high|medium|low|info(?:rmational)?)\s+severity\b", question.text, re.IGNORECASE)
    if severity:
        filters["severity"] = severity.group(1).lower()
    cve = re.search(r"\bCVE-\d{4}-\d{4,7}\b", question.text, re.IGNORECASE)
    if cve:
        filters["cve_id"] = cve.group(0).upper()
    doc_type = re.search(r"\b(doc(?:ument)? type|type)\s*[:=]?\s*([a-z0-9_-]+)\b", question.text, re.IGNORECASE)
    if doc_type:
        filters["doc_type"] = doc_type.group(2).lower()
    return filters


def _records(findings: list[Finding]) -> list[dict[str, object]]:
    return [
        {
            "id": finding.id,
            "text": f"{finding.title} {finding.description}",
            "metadata": {
                "vm_id": finding.vm_id,
                "port": finding.port,
                "severity": finding.severity.lower(),
                "cve_id": finding.cve_id.upper() if finding.cve_id else None,
            },
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "service": finding.service,
            "port": finding.port,
            "cve_id": finding.cve_id,
        }
        for finding in findings
    ]


def _candidate_set(question: Question, findings: list[Finding]) -> tuple[list[dict[str, object]], bool]:
    records = _records(findings)
    index = FindingIndex(records)
    ranked = index.bm25_search(question.text, len(records), _question_filters(question))
    capped = len(ranked) > settings.jev_candidate_limit
    return ([next(record for record in records if int(record["id"]) == item.id) for item in ranked[:settings.jev_candidate_limit]], capped)


def _score_cache_key(question: Question, finding: dict[str, object]) -> tuple[str, str, dict[str, object]]:
    content = json_value({
        "title": finding.get("title", ""),
        "description": finding.get("description", ""),
        "severity": finding.get("severity", ""),
        "service": finding.get("service", ""),
        "port": finding.get("port"),
        "cve_id": finding.get("cve_id") or "none",
    })
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return settings.jev_model, "arm-e-relevance-v1", {
        "question": question.text,
        "finding_id": finding["id"],
        "finding_content_hash": digest,
    }


def _price_jev(calls: int) -> float | None:
    return calls * float(settings.price_jev_per_call) if settings.price_jev_per_call else None


def rank_jev_candidates(candidates: list[dict[str, object]], scores: dict[int, float]) -> list[dict[str, object]]:
    return [
        item
        for _, _, item in sorted(
            ((float(scores[int(item["id"])]), -rank, item) for rank, item in enumerate(candidates)),
            key=lambda value: (value[0], value[1]),
            reverse=True,
        )[:5]
    ]


def _gold_ids(question: Question) -> list[int]:
    import json

    return [int(value) for value in json.loads(question.gold_finding_ids or "[]")]


def run_experiment(arm_names: list[str], question_ids: list[int], force_fresh: bool = False) -> str:
    if "jev_retrieval" in arm_names:
        health = jev_health()
        if not all(health[key] for key in ("configured", "reachable", "authenticated", "model_accepted")):
            raise RuntimeError(f"JEV health check failed: {health.get('error_message') or health}")
    run_errors: list[str] = []
    with db_session() as db:
        snapshot = settings.snapshot()
        snapshot["embedding_mode"] = "real" if settings.embedding_model else "lexical fallback"
        snapshot["rerank_note"] = "reranker: off" if not settings.rerank_model else "enabled"
        from ..models import reranker_manifest
        snapshot["reranker"] = reranker_manifest()
        snapshot["embedding_tokenizer"] = settings.embedding_model or "test lexical tokenizer"
        snapshot["chunking"] = {"whole_under_tokens": 512, "max_tokens": 450, "overlap_tokens": 50}
        snapshot["index_version"] = ""
        snapshot["arm_e"] = {
            "jev_model": settings.jev_model,
            "batching_mode": "single item per request (System One contract)",
            "candidate_limit": settings.jev_candidate_limit,
        }
        run = ExperimentRun(config_snapshot_json=json_value(snapshot))
        db.add(run)
        db.commit()
        run_id = run.id
    for arm in arm_names:
        if arm == "jev_retrieval" and not JEVClient().configured:
            for question_id in question_ids:
                with db_session() as db:
                    db.add(ArmResult(run_id=run_id, arm=arm, question_id=question_id, answer="not configured", error="JEV is not configured"))
                    db.commit()
            continue
        if arm != "jev_retrieval" and not settings.answer_model:
            for question_id in question_ids:
                with db_session() as db:
                    db.add(ArmResult(run_id=run_id, arm=arm, question_id=question_id, answer="not configured", error="ANSWER_MODEL is not configured"))
                    db.commit()
            continue
        if arm == "hybrid_jev" and not JEVClient().configured:
            for question_id in question_ids:
                with db_session() as db:
                    db.add(ArmResult(run_id=run_id, arm=arm, question_id=question_id, answer="not configured", error="JEV is not configured"))
                    db.commit()
            continue
        for question_id in question_ids:
            started = time.perf_counter()
            retrieval_started = started
            answer_latency = 0.0
            candidate_ids: list[int] = []
            evidence: list[dict[str, object]] = []
            retrieval_calls = 0
            candidate_cap = False
            precision: tuple[float | None, float | None, float | None] = (None, None, None)
            skipped_gold = False
            jev_cost: float | None = None
            with db_session() as db:
                question = db.get(Question, question_id)
                finding_rows = db.query(Finding).all() if question else []
            if not question:
                continue
            try:
                if arm in {"vector_rag", "hybrid_rag", "hybrid_jev", "jev_retrieval"}:
                    if arm in {"hybrid_rag", "jev_retrieval"}:
                        candidates, candidate_cap = _candidate_set(question, finding_rows)
                    else:
                        candidates = _records(finding_rows)
                    candidate_ids = [int(item["id"]) for item in candidates]
                    index = FindingIndex(candidates)
                    if arm == "vector_rag":
                        selected = index.vector_search(question.text, 5, _question_filters(question))
                    elif arm == "hybrid_rag":
                        retrieval = retrieve(index, question.text, filters=_question_filters(question), use_reranker=bool(settings.rerank_model), limit=5)
                        selected = retrieval.items
                    elif arm == "hybrid_jev":
                        retrieval = retrieve(index, question.text, filters=_question_filters(question), use_reranker=bool(settings.rerank_model), limit=5)
                        selected = retrieval.items
                    else:
                        client = JEVClient()
                        scores: dict[int, float] = {}
                        for candidate in candidates:
                            model, prompt, input_data = _score_cache_key(question, candidate)
                            result = cache.get(model, prompt, input_data)
                            if result is None:
                                relevance = client.score_finding(question.text, candidate)
                                result = {"relevant": relevance.relevant, "score": relevance.score}
                                cache.put(model, prompt, input_data, result)
                                retrieval_calls += 1
                            scores[int(candidate["id"])] = float(result["score"])
                        selected = rank_jev_candidates(candidates, scores)
                    evidence = [{"id": item.id, "title": item.metadata.get("title", item.text), "description": item.text} if hasattr(item, "id") else item for item in selected]
                    if arm == "jev_retrieval":
                        evidence = [{"id": item["id"], "title": item["title"], "description": item["description"]} for item in selected]
                retrieval_latency = (time.perf_counter() - retrieval_started) * 1000
                answer_started = time.perf_counter()
                answer = answer_question(question.text, evidence)
                answer_latency = (time.perf_counter() - answer_started) * 1000
                claims = judge_claims(answer.text, [str(item.get("description", "")) for item in evidence]) if arm == "hybrid_jev" or (arm == "hybrid_rag" and JEVClient().configured) else []
                gold = _gold_ids(question)
                if gold and arm in {"hybrid_rag", "jev_retrieval"}:
                    retrieved = [int(item["id"]) for item in evidence]
                    precision = tuple(precision_at_k(retrieved, gold, k) for k in (1, 3, 5))
                elif not gold and arm in {"hybrid_rag", "jev_retrieval"}:
                    skipped_gold = True
                jev_cost = _price_jev(retrieval_calls) if arm == "jev_retrieval" else None
                error = ""
            except Exception as exc:
                answer, claims, error = None, [], str(exc)
                if arm in {"hybrid_jev", "jev_retrieval"}:
                    run_errors.append(error)
                retrieval_latency = (time.perf_counter() - retrieval_started) * 1000
            with db_session() as db:
                retrieved = [int(item["id"]) for item in evidence]
                db.add(ArmResult(
                    run_id=run_id, arm=arm, question_id=question_id,
                    answer=answer.text if answer else "", retrieved_ids=json_value(retrieved),
                    retrieved_ids_json=json_value(retrieved), candidate_ids_json=json_value(candidate_ids),
                    claims_json=json_value(claims), latency_ms=(time.perf_counter() - started) * 1000,
                    retrieval_latency_ms=retrieval_latency, answer_latency_ms=answer_latency,
                    retrieval_calls=retrieval_calls, jev_calls=retrieval_calls, jev_cost_usd=jev_cost,
                    precision_at_1=precision[0], precision_at_3=precision[1], precision_at_5=precision[2],
                    candidate_cap_applied=candidate_cap, gold_evidence_skipped=skipped_gold,
                    tokens_in=answer.tokens_in if answer else 0, tokens_out=answer.tokens_out if answer else 0,
                    cost_usd=answer.cost if answer else None, error=error,
                    index_version=index.index_version if 'index' in locals() else "",
                    stage_scores_json=json_value(retrieval.stages if 'retrieval' in locals() else {}),
                ))
                db.commit()
    with db_session() as db:
        run = db.get(ExperimentRun, run_id)
        from ..models import reranker_manifest
        snapshot = json.loads(run.config_snapshot_json or "{}")
        snapshot["reranker"] = reranker_manifest()
        run.config_snapshot_json = json_value(snapshot)
        run.status, run.finished_at = "done", now()
        db.commit()
    suffix = f"; JEV failures: {' | '.join(run_errors)}" if run_errors else ""
    return f"Experiment {run_id} completed{suffix}"
