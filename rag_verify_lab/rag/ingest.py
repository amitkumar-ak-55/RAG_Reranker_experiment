from __future__ import annotations

import hashlib
import json
import random
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import numpy as np
from rank_bm25 import BM25Okapi

from ..config import ROOT, settings
from ..db import KBChunk, KBEmbedding, db_session, init_db, json_value
from ..models import encode, embedding_model, embedding_tokenizer, validate_model_configuration
from ..models import reranker_manifest
from .chunk import chunk_document
from .index import index_version, tokenize

CORPUS_PATH = ROOT / "data" / "kb" / "documents.jsonl"
CORPUS_MANIFEST_PATH = ROOT / "data" / "kb" / "manifest.json"
INDEX_MANIFEST_PATH = ROOT / "data" / "kb" / "index_manifest.json"
INDEX_DIR = ROOT / "data" / "index"


@dataclass(frozen=True)
class BuildSummary:
    documents: int
    chunks: int
    vectors: int
    new_vectors: int
    index_version: str
    self_retrieval_rate: float
    self_retrieval_by_doc_type: dict[str, float]
    embedding_dimension: int
    elapsed_seconds: float


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_documents(path: Path = CORPUS_PATH) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _check_frozen(path: Path) -> str:
    if not CORPUS_MANIFEST_PATH.is_file():
        raise RuntimeError("data/kb/manifest.json is missing; rebuild the knowledge base first")
    manifest = json.loads(CORPUS_MANIFEST_PATH.read_text(encoding="utf-8"))
    expected = manifest.get("corpus_sha256")
    actual = _sha256(path)
    if not expected:
        raise RuntimeError("manifest.corpus_sha256 is missing; rebuild the knowledge base first")
    if expected != actual:
        raise RuntimeError("manifest.corpus_sha256 does not match documents.jsonl; rebuild the knowledge base first")
    return actual


def _tokenizer() -> Callable[[str], list[Any]]:
    model_tokenizer = embedding_tokenizer()
    return lambda text: model_tokenizer.encode(text, add_special_tokens=False)


def _embedding_text(chunk: dict[str, Any]) -> str:
    metadata = chunk.get("metadata", {})
    title = metadata.get("title", "") if isinstance(metadata, dict) else ""
    return f"{title}\n{chunk['text']}"


def _normalise(vectors: Any) -> np.ndarray:
    values = np.asarray(vectors, dtype=np.float32)
    norms = np.linalg.norm(values, axis=1, keepdims=True)
    return (values / np.maximum(norms, 1e-12)).astype(np.float32)


def embed_chunks(
    chunks: list[dict[str, Any]],
    cache: dict[tuple[str, str, str], np.ndarray],
    encoder: Callable[[list[str]], Any],
) -> tuple[dict[tuple[str, str, str], np.ndarray], int]:
    missing = [
        chunk for chunk in chunks
        if (str(chunk["content_hash"]), settings.embedding_model, settings.embedding_revision) not in cache
    ]
    if missing:
        vectors = _normalise(encoder([_embedding_text(chunk) for chunk in missing]))
        for chunk, vector in zip(missing, vectors):
            cache[(str(chunk["content_hash"]), settings.embedding_model, settings.embedding_revision)] = vector
    return cache, len(missing)


def _self_retrieval(chunks: list[dict[str, Any]], vectors: dict[str, np.ndarray], documents: list[dict[str, Any]]) -> tuple[float, dict[str, float]]:
    if not documents:
        return 1.0, {}
    sample = random.Random(17).sample(documents, min(200, len(documents)))
    matrix = np.vstack([vectors[str(chunk["content_hash"])] for chunk in chunks])
    by_doc: dict[str, list[int]] = {}
    for position, chunk in enumerate(chunks):
        by_doc.setdefault(str(chunk["doc_id"]), []).append(position)
    passed = 0
    failures: list[str] = []
    by_type: dict[str, list[bool]] = {}
    for document in sample:
        query = _normalise(encode([str(document.get("title", ""))], query=False))[0]
        ranking = np.argsort(matrix @ query)[::-1][:5]
        passed_document = any(position in by_doc[str(document["doc_id"])] for position in ranking)
        by_type.setdefault(str(document.get("doc_type", "")), []).append(passed_document)
        if passed_document:
            passed += 1
        else:
            failures.append(str(document["doc_id"]))
    rate = passed / len(sample)
    if rate < 0.95:
        print(f"warning: self-retrieval rate {rate:.3f} below 0.950; failing doc_ids: {', '.join(failures)}")
    return rate, {key: sum(values) / len(values) for key, values in sorted(by_type.items())}


def build_index_report(path: Path = CORPUS_PATH) -> BuildSummary:
    started = time.perf_counter()
    corpus_sha = _check_frozen(path)
    validate_model_configuration()
    existing_manifest = json.loads(INDEX_MANIFEST_PATH.read_text(encoding="utf-8")) if INDEX_MANIFEST_PATH.exists() else {}
    if (
        existing_manifest.get("embedding_model") == settings.embedding_model
        and existing_manifest.get("embedding_revision")
        and existing_manifest["embedding_revision"] != settings.embedding_revision
    ):
        raise RuntimeError("embedding revision differs from index manifest; rebuild the index")
    documents = load_documents(path)
    tokenizer = _tokenizer()
    chunks = [chunk for document in documents for chunk in chunk_document(document, tokenizer=tokenizer)]
    version = index_version(chunks)
    init_db()
    cache: dict[tuple[str, str, str], np.ndarray] = {}
    new_vectors = 0
    vectors: dict[str, np.ndarray] = {}
    with db_session() as db:
        current_hashes = {str(chunk["content_hash"]) for chunk in chunks}
        if existing_manifest.get("embedding_model") != settings.embedding_model or existing_manifest.get("embedding_revision") != settings.embedding_revision:
            db.query(KBChunk).delete(synchronize_session=False)
            db.query(KBEmbedding).filter(
                (KBEmbedding.model_name != settings.embedding_model)
                | (KBEmbedding.model_revision != settings.embedding_revision)
            ).delete(synchronize_session=False)
        db.query(KBEmbedding).filter(
            KBEmbedding.model_name == settings.embedding_model,
            KBEmbedding.model_revision == settings.embedding_revision,
            ~KBEmbedding.content_hash.in_(current_hashes),
        ).delete(synchronize_session=False)
        for chunk in chunks:
            key = {
                "content_hash": str(chunk["content_hash"]),
                "model_name": settings.embedding_model,
                "model_revision": settings.embedding_revision,
            }
            row = db.get(KBEmbedding, key)
            if row is not None:
                vectors[str(chunk["content_hash"])] = np.frombuffer(row.vector, dtype=np.float32)
        missing = [chunk for chunk in chunks if str(chunk["content_hash"]) not in vectors]
        for start in range(0, len(missing), settings.embedding_batch_size):
            batch = missing[start:start + settings.embedding_batch_size]
            encoded = _normalise(encode([_embedding_text(chunk) for chunk in batch], query=False))
            for chunk, vector in zip(batch, encoded):
                content_hash = str(chunk["content_hash"])
                vectors[content_hash] = vector
                db.merge(KBEmbedding(
                    content_hash=content_hash,
                    model_name=settings.embedding_model,
                    model_revision=settings.embedding_revision,
                    vector=vector.tobytes(),
                ))
            new_vectors += len(batch)
            if (start + len(batch)) % 1000 == 0 or start + len(batch) == len(missing):
                print(f"embedded {start + len(batch)}/{len(missing)} chunks")
        for chunk in chunks:
            metadata = dict(chunk["metadata"])
            db.merge(KBChunk(
                chunk_id=str(chunk["chunk_id"]), doc_id=str(chunk["doc_id"]),
                doc_type=str(metadata.get("doc_type", "")), group=str(metadata.get("group", "")),
                chunk_index=int(chunk["chunk_index"]), text=str(chunk["text"]),
                metadata_json=json_value(metadata), content_hash=str(chunk["content_hash"]),
                index_version=version,
            ))
        db.commit()
    BM25Okapi([tokenize(str(chunk["text"])) for chunk in chunks])
    counts_type = Counter(str(document.get("doc_type", "")) for document in documents)
    counts_group = Counter(str(document.get("group", "")) for document in documents)
    INDEX_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    index_manifest = {
        "corpus_sha256": corpus_sha,
        "document_count": len(documents),
        "document_count_by_doc_type": dict(sorted(counts_type.items())),
        "document_count_by_group": dict(sorted(counts_group.items())),
        "embedding_model": settings.embedding_model,
        "embedding_revision": settings.embedding_revision,
        "chunking": {"short_document_tokens": 512, "max_tokens": 450, "overlap_tokens": 50, "sentence_boundaries": True},
        "embedding_input": "document title, newline, then chunk text",
        "index_version": version,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "bm25_tokenizer": "rag_verify_lab.rag.index.tokenize (CVE/CWE IDs remain single tokens)",
    }
    INDEX_MANIFEST_PATH.write_text(json.dumps(index_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rate, by_type = _self_retrieval(chunks, vectors, documents)
    dimension = len(next(iter(vectors.values()))) if vectors else 0
    index_manifest["reranker_model"] = settings.rerank_model
    index_manifest["reranker_revision"] = settings.rerank_revision
    index_manifest.update(reranker_manifest())
    index_manifest["embedding_dimension"] = dimension
    index_manifest["tokenizer_name"] = f"{settings.embedding_model}@{settings.embedding_revision}"
    index_manifest["self_retrieval_rate"] = rate
    index_manifest["self_retrieval_by_doc_type"] = by_type
    INDEX_MANIFEST_PATH.write_text(json.dumps(index_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return BuildSummary(len(documents), len(chunks), len(vectors), new_vectors, version, rate, by_type, dimension, time.perf_counter() - started)


def build_index(path: Path = CORPUS_PATH) -> str:
    return build_index_report(path).index_version
