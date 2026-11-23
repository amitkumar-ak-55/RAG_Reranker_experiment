from __future__ import annotations

from types import SimpleNamespace

import pytest

from reranker_experiment import generation, pipeline


def test_pipeline_requires_explicit_provider(tmp_path):
    with pytest.raises(TypeError):
        pipeline.run_pipeline(tmp_path, question_limit=1)


def test_invalid_provider_fails_before_retrieval(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: pytest.fail("retrieval started"))

    with pytest.raises(generation.AnswerProviderSelectionError, match="explicitly selected"):
        pipeline.run_pipeline(tmp_path, provider="unknown", question_limit=1)


def test_unavailable_production_provider_fails_before_retrieval(monkeypatch, tmp_path):
    monkeypatch.setattr(
        generation,
        "production_settings",
        SimpleNamespace(
            answer_model="",
            answer_api_keys=(),
            answer_base_url="",
            answer_max_tokens=32,
        ),
    )
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: pytest.fail("retrieval started"))

    with pytest.raises(generation.AnswerProviderSelectionError, match="not configured"):
        pipeline.run_pipeline(tmp_path, provider="production", question_limit=1)


def test_explicit_mock_provider_still_runs(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: type("Index", (), {})())
    monkeypatch.setattr(pipeline, "retrieve", lambda *args, **kwargs: pytest.fail("not needed"))
    selected = generation.select_answer_provider("mock")

    assert selected.name == "mock-answer-provider"


def test_mock_pipeline_rejects_production_before_index_loading(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: pytest.fail("index loading started"))

    with pytest.raises(ValueError, match="requires provider='mock'"):
        pipeline.run_mock_pipeline(tmp_path, provider="production", question_limit=1)


def test_production_selection_rejects_injected_mock_before_index_loading(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: pytest.fail("index loading started"))

    with pytest.raises(generation.AnswerProviderSelectionError, match="custom provider"):
        pipeline.run_pipeline(
            tmp_path,
            provider="production",
            question_limit=1,
            answer_provider=pipeline.MockAnswerProvider(),
        )


@pytest.mark.parametrize("question_limit", [0, -1, 301])
def test_invalid_production_limits_fail_before_index_loading(monkeypatch, tmp_path, question_limit):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: pytest.fail("index loading started"))

    with pytest.raises(ValueError, match="between one and 300"):
        pipeline.run_pipeline(tmp_path, provider="production", question_limit=question_limit)


@pytest.mark.parametrize("question_limit", [1, 3])
def test_valid_production_limits_pass_range_check(monkeypatch, tmp_path, question_limit):
    monkeypatch.setattr(
        generation,
        "select_answer_provider",
        lambda provider, mock_provider=None: pipeline.MockAnswerProvider(),
    )
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: pytest.fail("index loading started"))

    with pytest.raises(pytest.fail.Exception, match="index loading started"):
        pipeline.run_pipeline(tmp_path, provider="production", question_limit=question_limit)


def test_production_rejects_injected_rerankers_before_index_loading(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "_load_frozen_index", lambda: pytest.fail("index loading started"))
    with pytest.raises(ValueError, match="cannot be injected"):
        pipeline.run_pipeline(
            tmp_path,
            provider="production",
            question_limit=1,
            jina_provider=pipeline.HashReranker("jina-mock"),
            jev_provider=pipeline.HashReranker("jev-mock"),
        )
