from __future__ import annotations

import csv
import json
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest

from rag_verify_lab.rag.retrieve import RetrievalResult

from reranker_experiment.generation import GenerationResult, GenerationSettings
from reranker_experiment import pipeline


class FixedProvider:
    def __init__(self, name: str, reverse: bool = False) -> None:
        self.name = name
        self.reverse = reverse
        self.calls: list[list[str]] = []

    def rank(self, query, candidates):
        ids = [candidate.candidate_id for candidate in candidates]
        self.calls.append(ids)
        scores = {
            candidate_id: (len(ids) - index if self.reverse else index)
            for index, candidate_id in enumerate(ids)
        }
        return pipeline.ProviderResult(scores, 0.1)


class FakeIndex:
    index_version = "frozen-test-index"


class RecordingAnswerProvider:
    name = "recording-answer-provider"
    generation_settings = GenerationSettings("test-model", 32)

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    def answer(self, query, evidence):
        self.calls.append((query, [candidate.candidate_id for candidate in evidence]))
        return GenerationResult(
            text=f"offline answer for {query}",
            provider=self.name,
            model="test-model",
            generation_config=self.generation_settings.as_dict(),
            tokens_in=10,
            tokens_out=5,
            cost=0.25,
            success=True,
        )


class FailingAnswerProvider:
    name = "failing-answer-provider"
    generation_settings = GenerationSettings("test-model", 32)

    def __init__(self) -> None:
        self.calls = 0

    def answer(self, query, evidence):
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("Bearer super-secret api_key=super-secret")
        return GenerationResult(
            text="successful answer",
            provider=self.name,
            model="test-model",
            generation_config=self.generation_settings.as_dict(),
            tokens_in=None,
            tokens_out=None,
            cost=None,
            success=True,
        )


class AlwaysFailingAnswerProvider(FailingAnswerProvider):
    def answer(self, query, evidence):
        self.calls += 1
        raise RuntimeError(f"failure for {query}")


class MaliciousAnswerProvider:
    name = "provider api_key=provider-secret"
    generation_settings = GenerationSettings("https://user:pass@example.test", 32)

    def answer(self, query, evidence):
        return GenerationResult(
            text="ordinary answer Authorization: Bearer answer-secret",
            provider=self.name,
            model="https://user:pass@example.test?token=url-secret",
            generation_config={"api_key": "config-secret", "nested": object()},
            tokens_in=None,
            tokens_out=None,
            cost=None,
            success=False,
            error_category="provider_error",
            error_message="Authorization: Basic error-secret https://user:pass@example.test",
        )


class MalformedAnswerProvider:
    name = "malformed-answer-provider"

    def answer(self, query, evidence):
        return "not a GenerationResult"


def _expected_keys() -> set[str]:
    return {
        "Q-0091:A_hybrid_baseline",
        "Q-0091:B_hybrid_jina_mock",
        "Q-0091:C_hybrid_jev_mock",
    }


def _fingerprints(
    *,
    provider_mode: str = "mock",
    jina=None,
    jev=None,
    answer=None,
):
    return pipeline._fingerprints(
        provider_mode=provider_mode,
        question_limit=1,
        jina_provider=jina or pipeline.HashReranker("jina-mock"),
        jev_provider=jev or pipeline.HashReranker("jev-mock"),
        answer_provider=answer or pipeline.MockAnswerProvider(),
    )


def _fake_retrieval(calls: list[str]):
    def retrieve_once(index, query, **kwargs):
        calls.append(query)
        items = [
            pipeline.IndexedFinding(
                id=index,
                text=f"candidate text {index}",
                metadata={"chunk_id": f"chunk-{index}", "doc_id": f"doc-{index}"},
                vector=[],
                dense_score=float(index),
                sparse_score=float(index) / 10,
                fusion_score=float(100 - index),
            )
            for index in range(10)
        ]
        return RetrievalResult(items, {}, {"dense": 1.0, "sparse": 1.0, "fusion": 1.0})

    return retrieve_once


def test_pipeline_retrieves_once_shares_candidates_and_persists_top_five(monkeypatch, tmp_path: Path):
    calls: list[str] = []
    jina = FixedProvider("jina-fixed", reverse=True)
    jev = FixedProvider("jev-fixed", reverse=False)
    answer_provider = RecordingAnswerProvider()
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval(calls))
    output = pipeline.run_mock_pipeline(
        tmp_path,
        provider="mock",
        question_limit=1,
        jina_provider=jina,
        jev_provider=jev,
        answer_provider=answer_provider,
    )

    assert len(calls) == 1
    assert jina.calls == jev.calls == [["chunk-0", "chunk-1", "chunk-2", "chunk-3", "chunk-4", "chunk-5", "chunk-6", "chunk-7", "chunk-8", "chunk-9"]]
    assert len(answer_provider.calls) == 3
    assert [evidence for _, evidence in answer_provider.calls] == [
        ["chunk-0", "chunk-1", "chunk-2", "chunk-3", "chunk-4"],
        ["chunk-0", "chunk-1", "chunk-2", "chunk-3", "chunk-4"],
        ["chunk-9", "chunk-8", "chunk-7", "chunk-6", "chunk-5"],
    ]
    with (output / "per_question_results.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 3
    assert all(len(json.loads(row["selected_evidence_ids"])) == 5 for row in rows)
    assert json.loads(next(row for row in rows if row["arm"] == "B_hybrid_jina_mock")["ranking_ids"])[0] == "chunk-0"
    metadata = json.loads((output / "experiment_metadata.json").read_text(encoding="utf-8"))
    assert metadata["answer_generation"] == {"model": "test-model", "max_tokens": 32, "temperature": None}
    with (output / "generated_answers.jsonl").open(encoding="utf-8") as handle:
        answers = [json.loads(line) for line in handle if line.strip()]
    assert all(answer["answer_status"] == "success" for answer in answers)
    assert all(answer["answer_tokens_in"] == 10 for answer in answers)
    assert all(answer["answer_cost"] == 0.25 for answer in answers)
    assert [answer["evidence_ids"] for answer in answers] == [
        json.dumps(["chunk-0", "chunk-1", "chunk-2", "chunk-3", "chunk-4"]),
        json.dumps(["chunk-0", "chunk-1", "chunk-2", "chunk-3", "chunk-4"]),
        json.dumps(["chunk-9", "chunk-8", "chunk-7", "chunk-6", "chunk-5"]),
    ]
    assert (output / "generated_answers.jsonl").exists()
    assert (output / "checkpoint.json").exists()


def test_answer_failures_persist_sanitized_telemetry(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    output = pipeline.run_mock_pipeline(
        tmp_path,
        provider="mock",
        question_limit=1,
        answer_provider=FailingAnswerProvider(),
    )

    with (output / "generated_answers.jsonl").open(encoding="utf-8") as handle:
        answers = [json.loads(line) for line in handle if line.strip()]
    failed = next(answer for answer in answers if answer["answer_status"] == "failure")
    assert failed["answer"] == "unavailable"
    assert failed["answer_error_category"] == "provider_error"
    assert failed["answer_error_message"] == "answer generation failed"
    assert "super-secret" not in json.dumps(failed)
    assert failed["answer_tokens_in"] == "unavailable"
    assert failed["answer_tokens_out"] == "unavailable"
    assert failed["answer_cost"] == "unavailable"
    events = json.loads((output / "structured_events.json").read_text(encoding="utf-8"))
    completed = events[-1]
    assert completed["status"] == "completed_with_failures"
    assert completed["generation_success_count"] == 2
    assert completed["generation_failure_count"] == 1
    assert completed["generation_failures"] == [{"question_id": "Q-0091", "arm": "B_hybrid_jina_mock"}]


def test_all_arm_failures_persist_failed_aggregate(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    output = pipeline.run_mock_pipeline(
        tmp_path,
        provider="mock",
        question_limit=1,
        answer_provider=AlwaysFailingAnswerProvider(),
    )

    events = json.loads((output / "structured_events.json").read_text(encoding="utf-8"))
    completed = events[-1]
    assert completed["status"] == "failed"
    assert completed["generation_success_count"] == 0
    assert completed["generation_failure_count"] == 3
    assert {(item["question_id"], item["arm"]) for item in completed["generation_failures"]} == {
        ("Q-0091", "A_hybrid_baseline"),
        ("Q-0091", "B_hybrid_jina_mock"),
        ("Q-0091", "C_hybrid_jev_mock"),
    }


def test_malformed_provider_result_becomes_failure(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    output = pipeline.run_mock_pipeline(
        tmp_path,
        provider="mock",
        question_limit=1,
        answer_provider=MalformedAnswerProvider(),
    )

    with (output / "generated_answers.jsonl").open(encoding="utf-8") as handle:
        answers = [json.loads(line) for line in handle if line.strip()]
    assert all(answer["answer_status"] == "failure" for answer in answers)
    assert all(answer["answer"] == "unavailable" for answer in answers)


def test_malicious_provider_metadata_is_sanitized(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    output = pipeline.run_mock_pipeline(
        tmp_path,
        provider="mock",
        question_limit=1,
        answer_provider=MaliciousAnswerProvider(),
    )

    csv_text = (output / "per_question_results.csv").read_text(encoding="utf-8")
    jsonl_text = (output / "generated_answers.jsonl").read_text(encoding="utf-8")
    metadata_text = (output / "experiment_metadata.json").read_text(encoding="utf-8")
    for secret in ("provider-secret", "answer-secret", "config-secret", "url-secret", "error-secret", "user:pass"):
        assert secret not in csv_text
        assert secret not in jsonl_text
        assert secret not in metadata_text
    assert "ordinary answer" in jsonl_text


def test_csv_and_jsonl_use_explicit_unavailable_and_canonical_config(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    output = pipeline.run_mock_pipeline(
        tmp_path,
        provider="mock",
        question_limit=1,
        answer_provider=FailingAnswerProvider(),
    )

    with (output / "per_question_results.csv").open(newline="", encoding="utf-8") as handle:
        csv_rows = list(csv.DictReader(handle))
    with (output / "generated_answers.jsonl").open(encoding="utf-8") as handle:
        json_rows = [json.loads(line) for line in handle if line.strip()]
    csv_failed = next(row for row in csv_rows if row["answer_status"] == "failure")
    json_failed = next(row for row in json_rows if row["answer_status"] == "failure")
    assert csv_failed["answer_tokens_in"] == json_failed["answer_tokens_in"] == "unavailable"
    assert csv_failed["answer_cost"] == json_failed["answer_cost"] == "unavailable"
    assert csv_failed["generation_config"] == json_failed["generation_config"]


def test_gold_labels_do_not_change_provider_ranking(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    monkeypatch.setattr(
        pipeline,
        "validate_dataset",
        lambda path: {"record_count": 1, "question_ids": ["q1"]},
    )
    gold = {"value": "CVE-2024-0001"}

    def questions(_path):
        return [{"question_id": "q1", "question": "same query", "gold_cve": gold["value"]}]

    monkeypatch.setattr(pipeline, "load_jsonl", questions)
    first = pipeline.run_mock_pipeline(tmp_path / "first", provider="mock", question_limit=1)
    gold["value"] = "CVE-2099-9999"
    second = pipeline.run_mock_pipeline(tmp_path / "second", provider="mock", question_limit=1)

    def ranking(path: Path, arm: str) -> str:
        with (path / "per_question_results.csv").open(newline="", encoding="utf-8") as handle:
            return next(row["ranking_ids"] for row in csv.DictReader(handle) if row["arm"] == arm)

    assert ranking(first, "B_hybrid_jina_mock") == ranking(second, "B_hybrid_jina_mock")
    assert ranking(first, "C_hybrid_jev_mock") == ranking(second, "C_hybrid_jev_mock")


def test_metadata_uses_frozen_manifest_provenance(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    output = pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    metadata = json.loads((output / "experiment_metadata.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        (Path(__file__).parents[2] / "data" / "kb" / "index_manifest.json").read_text(encoding="utf-8")
    )
    assert metadata["index_version"] == manifest["index_version"]
    assert metadata["snapshot_fingerprints"]["index_manifest_sha256"]
    assert metadata["snapshot"]["embedding_dimension"] == manifest["embedding_dimension"]


def test_frozen_snapshot_rejects_vector_dimension_mismatch():
    chunk = type("Chunk", (), {"chunk_id": "chunk-1", "content_hash": "hash-1", "index_version": "v1"})()
    with pytest.raises(RuntimeError, match="dimension mismatch"):
        pipeline._validate_frozen_snapshot(
            [chunk],
            {"hash-1": np.zeros(3, dtype=np.float32)},
            {"index_version": "v1", "embedding_dimension": 4},
        )


def test_resume_rejects_changed_input_hash(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    original_hash = pipeline.sha256_file

    def changed_hash(path):
        value = original_hash(path)
        return "changed-dataset" if path.name == "eval_hard_300.jsonl" else value

    monkeypatch.setattr(pipeline, "sha256_file", changed_hash)
    with pytest.raises(RuntimeError, match="dataset_sha256"):
        pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1, resume=True)


def test_resume_accepts_unchanged_complete_artifact_without_loading(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: pytest.fail("index loaded during resume"))
    monkeypatch.setattr(pipeline, "retrieve", lambda *args, **kwargs: pytest.fail("retrieval started during resume"))
    assert pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1, resume=True) == tmp_path


def test_resume_rejects_changed_provider_mode(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    with pytest.raises(RuntimeError, match="provenance|experiment_config"):
        pipeline._validate_checkpoint(tmp_path, _fingerprints(provider_mode="production"), _expected_keys())


@pytest.mark.parametrize("change", ["model", "prompt", "generation"])
def test_resume_rejects_changed_answer_provenance(monkeypatch, tmp_path: Path, change: str):
    original = RecordingAnswerProvider()
    changed = RecordingAnswerProvider()
    if change == "model":
        changed.generation_settings = GenerationSettings("changed-model", 32)
    elif change == "prompt":
        changed.prompt_hash = "changed-prompt-hash"
    else:
        changed.generation_settings = GenerationSettings("test-model", 64)
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1, answer_provider=original)
    base = _fingerprints(answer=original)
    altered = _fingerprints(answer=changed)
    assert base["provenance_sha256"] != altered["provenance_sha256"]
    with pytest.raises(RuntimeError, match="provenance|experiment_config"):
        pipeline._validate_checkpoint(tmp_path, altered, _expected_keys())


def test_resume_rejects_changed_reranker_configuration(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    base = _fingerprints(jina=pipeline.HashReranker("jina-mock"))
    altered = _fingerprints(jina=pipeline.HashReranker("jina-changed"))
    assert base["provenance_sha256"] != altered["provenance_sha256"]
    with pytest.raises(RuntimeError, match="provenance|experiment_config"):
        pipeline._validate_checkpoint(tmp_path, altered, _expected_keys())


def test_resume_rejects_changed_embedding_and_retrieval_settings(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    base = _fingerprints()
    monkeypatch.setattr(
        pipeline,
        "experiment_settings",
        replace(pipeline.experiment_settings, embedding_revision="changed-revision", candidate_limit=99),
    )
    altered = _fingerprints()
    assert base["provenance_sha256"] != altered["provenance_sha256"]
    with pytest.raises(RuntimeError, match="provenance|experiment_config"):
        pipeline._validate_checkpoint(tmp_path, altered, _expected_keys())


def test_resume_rejects_changed_source_identity(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    base = _fingerprints()
    original = pipeline.sha256_file

    def changed_source(path):
        value = original(path)
        return "changed-source" if path.name == "pipeline.py" else value

    monkeypatch.setattr(pipeline, "sha256_file", changed_source)
    altered = _fingerprints()
    assert base["provenance_sha256"] != altered["provenance_sha256"]
    with pytest.raises(RuntimeError, match="provenance|experiment_config"):
        pipeline._validate_checkpoint(tmp_path, altered, _expected_keys())


def test_checkpoint_rejects_duplicate_rows_and_parseable_corruption(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    result_path = tmp_path / "per_question_results.csv"
    original = result_path.read_text(encoding="utf-8")
    result_path.write_text(original + original.splitlines()[1] + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="row count"):
        pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1, resume=True)

    result_path.write_text(original, encoding="utf-8")
    rows = list(csv.DictReader(original.splitlines()))
    rows[0]["selected_evidence_ids"] = json.dumps(["corrupt"])
    with result_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(RuntimeError, match="evidence|inconsistent"):
        pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1, resume=True)


def test_checkpoint_rejects_cross_artifact_evidence_mismatch(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: FakeIndex())
    monkeypatch.setattr(pipeline, "retrieve", _fake_retrieval([]))
    pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1)
    answers_path = tmp_path / "generated_answers.jsonl"
    answers = [json.loads(line) for line in answers_path.read_text(encoding="utf-8").splitlines()]
    answers[0]["evidence_ids"] = json.dumps(["wrong-evidence"])
    answers_path.write_text("".join(json.dumps(row) + "\n" for row in answers), encoding="utf-8")
    with pytest.raises(RuntimeError, match="evidence|inconsistent"):
        pipeline.run_mock_pipeline(tmp_path, provider="mock", question_limit=1, resume=True)


def test_provenance_payload_excludes_secrets():
    provider = MaliciousAnswerProvider()
    fingerprints = _fingerprints(answer=provider)
    payload = fingerprints["provenance_json"]
    for secret in ("provider-secret", "answer-secret", "config-secret", "url-secret", "user:pass"):
        assert secret not in payload
    assert "provenance_sha256" in fingerprints
