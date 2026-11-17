from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

from rag_verify_lab.rag.answer import Answer

from reranker_experiment import generation
from reranker_experiment.generation import GenerationResult, ProductionAnswerProvider
from reranker_experiment.pipeline import Candidate, MockAnswerProvider


def _candidate(index: int) -> Candidate:
    return Candidate(
        candidate_id=f"chunk-{index}",
        doc_id=f"doc-{index}",
        text=f"evidence {index}",
        metadata={"title": f"title {index}"},
        original_rank=index,
        dense_score=0.0,
        sparse_score=0.0,
        fusion_score=0.0,
    )


def test_production_provider_preserves_metadata_and_evidence(monkeypatch):
    monkeypatch.setattr(
        generation,
        "production_settings",
        SimpleNamespace(answer_model="test-model", answer_max_tokens=64),
    )
    calls: list[tuple[str, list[dict[str, object]]]] = []

    def answer_fn(query: str, evidence: list[dict[str, object]]) -> Answer:
        calls.append((query, evidence))
        return Answer("generated", 1, 2, None)

    provider = ProductionAnswerProvider(answer_fn)
    evidence = [_candidate(4), _candidate(1)]

    result = provider.answer("question", evidence)

    assert result == GenerationResult(
        text="generated",
        provider="production-answer-provider",
        model="test-model",
        generation_config={"model": "test-model", "max_tokens": 64, "temperature": None},
        tokens_in=1,
        tokens_out=2,
        cost=None,
        success=True,
    )
    assert calls == [
        (
            "question",
            [
                {"title": "title 4", "description": "evidence 4", "text": "evidence 4", "doc_id": "doc-4"},
                {"title": "title 1", "description": "evidence 1", "text": "evidence 1", "doc_id": "doc-1"},
            ],
        )
    ]


def test_all_arms_can_share_identical_generation_settings():
    provider = ProductionAnswerProvider(lambda query, evidence: Answer("ok", 0, 0, None))
    settings = provider.generation_settings.as_dict()

    assert [settings.copy() for _ in ("baseline", "jina", "jev")] == [settings, settings, settings]


def test_mock_answer_provider_remains_available():
    answer = MockAnswerProvider().answer("question", [_candidate(0)])

    assert isinstance(answer, GenerationResult)
    assert answer.success is True
    assert "Mock answer" in answer.text
    assert "[E1] doc-0" in answer.text
    assert answer.tokens_in is None
    assert answer.tokens_out is None
    assert answer.cost is None


def test_production_answer_source_is_not_modified():
    source = Path(__file__).parents[2] / "rag_verify_lab" / "rag" / "answer.py"
    before = hashlib.sha256(source.read_bytes()).digest()
    ProductionAnswerProvider(lambda query, evidence: Answer("ok", 0, 0, None))
    assert hashlib.sha256(source.read_bytes()).digest() == before
