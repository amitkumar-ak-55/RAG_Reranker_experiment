from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest
from huggingface_hub.constants import HF_HUB_CACHE

from rag_verify_lab import models
from rag_verify_lab.config import settings
from rag_verify_lab.eval import bootstrap, mrr, ndcg10, precision_at_k, recall_at_k
from rag_verify_lab.rag.chunk import chunk_document
from rag_verify_lab.rag.index import FindingIndex, index_version, reciprocal_rank_fusion, tokenize
from rag_verify_lab.rag.ingest import embed_chunks
from rag_verify_lab.rag.retrieve import retrieve


def test_chunker_keeps_short_documents_whole_and_metadata():
    document = {"doc_id": "doc-1", "text": "Short document.", "severity": "high", "cve_ids": ["CVE-1"]}
    chunks = chunk_document(document)
    assert len(chunks) == 1
    assert chunks[0]["text"] == document["text"]
    assert chunks[0]["doc_id"] == "doc-1"
    assert chunks[0]["chunk_index"] == 0
    assert chunks[0]["metadata"]["severity"] == "high"


def test_chunker_splits_on_sentences_with_fifty_token_overlap():
    sentences = [" ".join(f"w{j}_{i}" for j in range(100)) + "." for i in range(6)]
    chunks = chunk_document({"doc_id": "long", "text": " ".join(sentences)}, max_tokens=150, overlap=50)
    assert len(chunks) > 1
    first = chunks[0]["text"].split()
    second = chunks[1]["text"].split()
    assert second[:50] == first[-50:]
    assert chunks[0]["text"].endswith(".")


def test_index_version_changes_only_for_index_inputs(monkeypatch):
    chunks = [{"content_hash": "a"}]
    local = replace(settings, embedding_model="model", embedding_revision="r1")
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", local)
    original = index_version(chunks)
    assert original == index_version(chunks)
    assert original != index_version(chunks, chunk_size=451)
    assert original != index_version([{"content_hash": "b"}])
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", replace(local, embedding_revision="r2"))
    assert original != index_version(chunks)


def test_embedding_cache_makes_zero_calls_for_unchanged_chunks(monkeypatch):
    local = replace(settings, embedding_model="model", embedding_revision="r1")
    monkeypatch.setattr("rag_verify_lab.rag.ingest.settings", local)
    chunks = [{"content_hash": "a", "text": "one"}, {"content_hash": "b", "text": "two"}]
    calls = []

    def encoder(texts):
        calls.append(texts)
        return np.ones((len(texts), 2), dtype=np.float32)

    cache, missing = embed_chunks(chunks, {}, encoder)
    cache, second_missing = embed_chunks(chunks, cache, encoder)
    assert missing == 2 and second_missing == 0
    assert len(calls) == 1


def test_tokenizer_keeps_cve_and_cwe_ids_whole():
    assert "cve-2021-44228" in tokenize("CVE-2021-44228 and CWE-89")
    assert "cwe-89" in tokenize("CVE-2021-44228 and CWE-89")


def test_rrf_matches_hand_computed_k60():
    first = FindingIndex([{"id": 1, "text": "a", "vector": [1.0], "metadata": {}}]).items[0]
    second = FindingIndex([{"id": 2, "text": "b", "vector": [1.0], "metadata": {}}]).items[0]
    result = reciprocal_rank_fusion([[first, second], [second, first]], k=60)
    assert result[0].fusion_score == result[1].fusion_score == (1 / 61 + 1 / 62)


def test_metadata_filter_is_applied_before_every_stage(monkeypatch):
    local = replace(settings, embedding_model="")
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", local)
    monkeypatch.setattr("rag_verify_lab.rag.embed.settings", local)
    monkeypatch.setattr("rag_verify_lab.rag.index.embed_text", lambda text: np.array([1.0, 0.0], dtype=np.float32))
    index = FindingIndex([
        {"id": 1, "text": "allowed", "vector": [1.0, 0.0], "metadata": {"vm_id": 1}},
        {"id": 2, "text": "blocked", "vector": [1.0, 0.0], "metadata": {"vm_id": 2}},
    ])
    result = retrieve(index, "allowed", filters={"vm_id": 1})
    for stage in result.stages.values():
        assert all(item["id"] != 2 for item in stage)


def test_reranker_fallback_is_recorded(monkeypatch):
    local = replace(
        settings,
        rerank_model="primary",
        rerank_revision="primary-revision",
        rerank_fallback_model="fallback",
        rerank_fallback_revision="fallback-revision",
    )
    monkeypatch.setattr(models, "settings", local)
    models.reranker_model.cache_clear()
    loaded = []

    def loader(name, revision, device):
        loaded.append(name)
        if name == "primary":
            raise models.ModelLoadError("broken")
        return type("FakeReranker", (), {"predict": lambda self, pairs: [0.5 for _ in pairs]})()

    monkeypatch.setattr(models, "reranker_model", loader)
    models.RERANK_FALLBACK_USED = False
    models.RERANKER_USED_MODEL = ""
    scores = models.rerank("q", ["text", "other"])
    assert loaded == ["primary", "fallback"]
    assert np.array_equal(scores, np.array([0.5, 0.5], dtype=np.float32))
    assert models.RERANK_FALLBACK_USED
    assert models.RERANKER_USED_MODEL == "fallback"
    manifest = models.reranker_manifest()
    assert manifest["reranker_model_requested"] == "primary"
    assert manifest["reranker_model_used"] == "fallback"
    assert manifest["reranker_revision_used"] == "fallback-revision"
    assert manifest["fallback_used"] is True
    assert manifest["fallback_reason"] == "broken"


def test_reranker_fails_without_scores_when_primary_and_fallback_fail(monkeypatch):
    local = replace(
        settings,
        rerank_model="primary",
        rerank_revision="primary-revision",
        rerank_fallback_model="fallback",
        rerank_fallback_revision="fallback-revision",
    )
    monkeypatch.setattr(models, "settings", local)
    loaded = []

    def loader(name, revision, device):
        loaded.append((name, revision))
        raise models.ModelLoadError("broken")

    monkeypatch.setattr(models, "reranker_model", loader)
    with pytest.raises(models.ModelLoadError, match="fallback reranker failed"):
        models.rerank("q", ["text"])
    assert loaded == [
        ("primary", "primary-revision"),
        ("fallback", "fallback-revision"),
    ]


def test_real_configured_primary_reranker() -> None:
    snapshot = Path(HF_HUB_CACHE) / "models--BAAI--bge-reranker-v2-m3" / "snapshots" / settings.rerank_revision
    if not snapshot.is_dir():
        pytest.skip(f"configured primary model files are not local: {snapshot}")
    scores = models.rerank("security issue", ["security issue", "unrelated text"])
    assert len(scores) == 2
    assert np.isfinite(scores).all()
    manifest = models.reranker_manifest()
    assert manifest["reranker_model_used"] == settings.rerank_model
    assert manifest["reranker_revision_used"] == settings.rerank_revision
    assert manifest["fallback_used"] is False


def test_arm_2_path_never_calls_sparse_or_reranker(monkeypatch):
    local = replace(settings, embedding_model="")
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", local)
    monkeypatch.setattr("rag_verify_lab.rag.embed.settings", local)
    monkeypatch.setattr("rag_verify_lab.rag.index.embed_text", lambda text: np.array([1.0, 0.0], dtype=np.float32))
    index = FindingIndex([
        {"id": 1, "text": "allowed", "vector": [1.0, 0.0], "metadata": {}},
    ])
    monkeypatch.setattr(index, "bm25_search", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setattr("rag_verify_lab.rag.retrieve.rerank", lambda *args: (_ for _ in ()).throw(AssertionError()))
    result = retrieve(index, "allowed", use_sparse=False, use_reranker=False)
    assert [item.id for item in result.items] == [1]


def test_eval_metrics_hand_computed_fixture():
    ids, gold = ["x", "a", "b", "c", "d"], {"a", "c"}
    assert mrr(ids, gold) == 0.5
    assert recall_at_k(ids, gold, 3) == 0.5
    assert precision_at_k(ids, gold, 5) == 0.4
    assert round(ndcg10(ids, gold), 6) == round((1 / np.log2(3) + 1 / np.log2(5)) / (1 + 1 / np.log2(3)), 6)


def test_bootstrap_ci_is_reproducible():
    assert bootstrap([0.0, 0.5, 1.0], seed=17) == bootstrap([0.0, 0.5, 1.0], seed=17)
