from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable

import numpy as np
from rank_bm25 import BM25Okapi

from ..config import settings
from ..db import KBEmbedding, KBChunk, db_session
from .embed import embed_query, embed_text

TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.IGNORECASE)
SCHEMA_VERSION = "kb-v1"


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


def reciprocal_rank_fusion(
    rankings: list[list[IndexedFinding]], k: int = 60,
) -> list[IndexedFinding]:
    scores: dict[int, float] = {}
    items: dict[int, IndexedFinding] = {}
    for ranking in rankings:
        for rank, item in enumerate(ranking, 1):
            scores[item.id] = scores.get(item.id, 0.0) + 1 / (k + rank)
            items[item.id] = item
            item.fusion_score = scores[item.id]
    return sorted(items.values(), key=lambda item: (-item.fusion_score, item.id))


def index_version(chunks: Iterable[dict[str, object]], *, chunk_size: int = 450, overlap: int = 50) -> str:
    values = [
        settings.embedding_model, settings.embedding_revision, str(chunk_size), str(overlap),
        SCHEMA_VERSION,
        *sorted(str(chunk["content_hash"]) for chunk in chunks),
    ]
    return hashlib.sha256("\n".join(values).encode()).hexdigest()


@dataclass
class IndexedFinding:
    id: int
    text: str
    metadata: dict[str, object]
    vector: np.ndarray
    dense_score: float = 0.0
    sparse_score: float = 0.0
    fusion_score: float = 0.0
    reranker_score: float | None = None


class FindingIndex:
    def __init__(self, findings: list[dict[str, object]], *, rerank: bool = False) -> None:
        self.items: list[IndexedFinding] = []
        for finding in findings:
            text = str(finding.get("text", ""))
            vector = finding.get("vector")
            if vector is None:
                vector = embed_text(text)
            self.items.append(IndexedFinding(int(finding["id"]), text, dict(finding.get("metadata", {})), np.asarray(vector, dtype=np.float32)))
        self.matrix = np.vstack([item.vector for item in self.items]) if self.items else np.empty((0, 0), dtype=np.float32)
        self.bm25 = BM25Okapi([tokenize(item.text) for item in self.items]) if self.items else None
        self.rerank_enabled = rerank

    def _filtered(self, filters: dict[str, object] | None) -> list[int]:
        return [i for i, item in enumerate(self.items) if all(item.metadata.get(k) == v for k, v in (filters or {}).items())]

    def vector_search(self, query: str, limit: int = 5, filters: dict[str, object] | None = None) -> list[IndexedFinding]:
        if not self.items:
            return []
        q = embed_query(query) if settings.embedding_model else embed_text(query)
        allowed = self._filtered(filters)
        scored = [(float(np.dot(self.items[i].vector, q)), i) for i in allowed]
        result = []
        for score, i in sorted(scored, reverse=True)[:limit]:
            item = self.items[i]
            item.dense_score = score
            result.append(item)
        return result

    def bm25_search(self, query: str, limit: int = 5, filters: dict[str, object] | None = None) -> list[IndexedFinding]:
        if not self.bm25:
            return []
        allowed = self._filtered(filters)
        if not allowed:
            return []
        filtered_bm25 = BM25Okapi([tokenize(self.items[i].text) for i in allowed])
        scores = filtered_bm25.get_scores(tokenize(query))
        scored = [(float(scores[position]), i) for position, i in enumerate(allowed)]
        result = []
        for score, i in sorted(scored, reverse=True)[:limit]:
            item = self.items[i]
            item.sparse_score = score
            result.append(item)
        return result

    @property
    def index_version(self) -> str:
        chunks = [{"content_hash": hashlib.sha256(item.text.encode()).hexdigest()} for item in self.items]
        return index_version(chunks)
