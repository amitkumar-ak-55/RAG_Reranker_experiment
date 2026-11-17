from __future__ import annotations

import time
from dataclasses import dataclass

from ..models import rerank
from ..config import settings
from .index import FindingIndex, IndexedFinding, reciprocal_rank_fusion


@dataclass
class RetrievalResult:
    items: list[IndexedFinding]
    stages: dict[str, list[dict[str, float | int]]]
    timings_ms: dict[str, float]
    duplicate_documents: bool = False


def _stage(items: list[IndexedFinding], score: str) -> list[dict[str, float | int]]:
    return [{"id": item.id, "score": float(getattr(item, score))} for item in items]


def _unique_documents(items: list[IndexedFinding]) -> list[IndexedFinding]:
    selected: list[IndexedFinding] = []
    seen: set[object] = set()
    for item in items:
        document_id = item.metadata.get("doc_id", item.id)
        if document_id in seen:
            continue
        seen.add(document_id)
        selected.append(item)
    return selected


def retrieve(index: FindingIndex, query: str, *, filters: dict[str, object] | None = None,
             use_sparse: bool = True, use_reranker: bool = False, limit: int = 5) -> RetrievalResult:
    timings: dict[str, float] = {}
    stages: dict[str, list[dict[str, float | int]]] = {}
    started = time.perf_counter()
    dense = index.vector_search(query, 50, filters)
    timings["dense"] = (time.perf_counter() - started) * 1000
    stages["dense"] = _stage(dense, "dense_score")
    if not use_sparse:
        return RetrievalResult(dense[:limit], stages, timings)
    started = time.perf_counter()
    sparse = index.bm25_search(query, 50, filters)
    timings["sparse"] = (time.perf_counter() - started) * 1000
    stages["sparse"] = _stage(sparse, "sparse_score")
    started = time.perf_counter()
    fused = _unique_documents(reciprocal_rank_fusion([dense, sparse]))[:20]
    timings["fusion"] = (time.perf_counter() - started) * 1000
    stages["fusion"] = _stage(fused, "fusion_score")
    if use_reranker and fused:
        started = time.perf_counter()
        scores = rerank(query, [item.text for item in fused])
        for item, score in zip(fused, scores):
            item.reranker_score = float(score)
        fused.sort(key=lambda item: item.reranker_score or 0, reverse=True)
        timings["rerank"] = (time.perf_counter() - started) * 1000
        stages["rerank"] = _stage(fused, "reranker_score")
    selected: list[IndexedFinding] = []
    seen: set[object] = set()
    for item in fused:
        doc_id = item.metadata.get("doc_id", item.id)
        if doc_id not in seen:
            selected.append(item)
            seen.add(doc_id)
        if len(selected) == limit:
            break
    if len(selected) < limit:
        for item in fused:
            if item not in selected:
                selected.append(item)
            if len(selected) == limit:
                break
    return RetrievalResult(selected, stages, timings, len({item.metadata.get("doc_id", item.id) for item in selected}) < len(selected))


def hybrid_search(index: FindingIndex, query: str, limit: int = 5, filters: dict[str, object] | None = None) -> list[IndexedFinding]:
    return retrieve(index, query, filters=filters, use_reranker=False, limit=limit).items
