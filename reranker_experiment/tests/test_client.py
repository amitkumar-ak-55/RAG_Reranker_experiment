from dataclasses import replace

import httpx
import pytest

from reranker_experiment.client import (
    JinaConfigurationError,
    JinaReranker,
    KeyRotator,
)
from reranker_experiment.config import ExperimentSettings
from reranker_experiment.jev_batch import JEVBatchClient


def test_key_rotator_round_robins_configured_keys():
    rotator = KeyRotator(("one", "two"))
    assert [rotator.next().slot for _ in range(4)] == [1, 2, 1, 2]


def test_reranker_fails_without_keys():
    with pytest.raises(JinaConfigurationError):
        KeyRotator(()).next()


def test_reranker_fails_over_to_second_key():
    settings = ExperimentSettings(
        jina_api_key_1="one",
        jina_api_key_2="two",
        jina_base_url="https://example.test/v1",
        jina_reranker_model="configured-model",
    )
    responses = [
        httpx.Response(429, request=httpx.Request("POST", "https://example.test/v1/rerank")),
        httpx.Response(200, json={"model": "jina-reranker-v2-base-multilingual", "usage": {"total_tokens": 12}, "results": [{"index": 1, "relevance_score": 0.9}, {"index": 0, "relevance_score": 0.1}]},
                       request=httpx.Request("POST", "https://example.test/v1/rerank")),
    ]
    seen = []

    def handler(request):
        seen.append(request.headers["Authorization"])
        return responses.pop(0)

    with JinaReranker(settings, client=httpx.Client(transport=httpx.MockTransport(handler))) as client:
        result = client.rerank("query", ["a", "b"], 2)
    assert result.scores == [0.1, 0.9]
    assert [record.key_slot for record in result.request_records] == [1, 2]
    assert seen == ["Bearer one", "Bearer two"]


def test_reranker_rejects_invalid_response():
    settings = replace(
        ExperimentSettings(jina_api_key_1="one", jina_base_url="https://example.test"),
        jina_reranker_model="configured-model",
    )

    def handler(request):
        return httpx.Response(
            200,
            json={
                "model": "jina-reranker-v2-base-multilingual",
                "usage": {"total_tokens": 2},
                "results": [{"index": 3, "relevance_score": 0.1}],
            },
            request=request,
        )

    with JinaReranker(settings, client=httpx.Client(transport=httpx.MockTransport(handler))) as client:
        with pytest.raises(Exception, match="out-of-range document index"):
            client.rerank("query", ["a"])


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"model": "jina-reranker-v2-base-multilingual", "usage": {"total_tokens": 2}, "results": []}, "expected 2"),
        ({"model": "jina-reranker-v2-base-multilingual", "usage": {"total_tokens": 2}, "data": [{"index": 0, "relevance_score": 0.5}]}, "missing the results array"),
        ({"model": "jina-reranker-v2-base-multilingual", "usage": {"total_tokens": 2}, "results": [{"index": 0, "relevance_score": 0.5}, {"index": 0, "relevance_score": 0.7}]}, "duplicate document indices"),
        ({"model": "jina-reranker-v2-base-multilingual", "usage": {"total_tokens": 2}, "results": [{"index": "0", "relevance_score": 0.5}, {"index": 1, "relevance_score": 0.7}]}, "invalid document index"),
        ({"model": "jina-reranker-v2-base-multilingual", "usage": {"total_tokens": 2}, "results": [{"index": 0, "relevance_score": "high"}, {"index": 1, "relevance_score": 0.7}]}, "non-numeric relevance score"),
    ],
)
def test_jina_rejects_malformed_results(payload, message):
    settings = replace(
        ExperimentSettings(jina_api_key_1="one", jina_base_url="https://example.test"),
        jina_reranker_model="configured-model",
    )

    def handler(request):
        return httpx.Response(200, json=payload, request=request)

    with JinaReranker(settings, client=httpx.Client(transport=httpx.MockTransport(handler))) as client:
        with pytest.raises(Exception, match=message):
            client.rerank("query", ["a", "b"], 2)


@pytest.mark.parametrize("nonfinite", ["NaN", "Infinity"])
def test_jina_rejects_nan_and_infinite_scores(nonfinite):
    settings = replace(
        ExperimentSettings(jina_api_key_1="one", jina_base_url="https://example.test"),
        jina_reranker_model="configured-model",
    )
    content = (
        '{"model":"jina-reranker-v2-base-multilingual","usage":{"total_tokens":2},"results":[{"index":0,"relevance_score":'
        + nonfinite
        + '},{"index":1,"relevance_score":0.7}]}'
    ).encode()

    def handler(request):
        return httpx.Response(
            200,
            content=content,
            headers={"Content-Type": "application/json"},
            request=request,
        )

    with JinaReranker(settings, client=httpx.Client(transport=httpx.MockTransport(handler))) as client:
        with pytest.raises(Exception, match="non-finite relevance score"):
            client.rerank("query", ["a", "b"], 2)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"usage": {"total_tokens": 2}, "results": [{"index": 0, "relevance_score": 0.5}, {"index": 1, "relevance_score": 0.7}]}, "missing a valid model"),
        ({"model": "jina-reranker-v2-base-multilingual", "results": [{"index": 0, "relevance_score": 0.5}, {"index": 1, "relevance_score": 0.7}]}, "missing usage"),
        ({"model": "jina-reranker-v2-base-multilingual", "usage": {"total_tokens": "many"}, "results": [{"index": 0, "relevance_score": 0.5}, {"index": 1, "relevance_score": 0.7}]}, "invalid usage"),
    ],
)
def test_jina_rejects_missing_or_invalid_envelope(payload, message):
    settings = replace(
        ExperimentSettings(jina_api_key_1="one", jina_base_url="https://example.test"),
        jina_reranker_model="configured-model",
    )

    def handler(request):
        return httpx.Response(200, json=payload, request=request)

    with JinaReranker(settings, client=httpx.Client(transport=httpx.MockTransport(handler))) as client:
        with pytest.raises(Exception, match=message):
            client.rerank("query", ["a", "b"], 2)


def _jev_candidates(prefix: str = "candidate"):
    return [
        {"doc_id": f"{prefix}-{index}", "text": f"document {index}"}
        for index in range(10)
    ]


def test_valid_ten_question_jev_response_preserves_candidate_mapping():
    candidates = _jev_candidates()
    answers = {
        f"candidate_{candidate['doc_id']}": {"type": "noul", "noul": (index + 1) / 10}
        for index, candidate in enumerate(candidates)
    }

    def handler(request):
        payload = request.read()
        assert b'"questions"' in payload
        assert len(__import__("json").loads(payload)["questions"]) == 10
        return httpx.Response(
            200,
            json={
                "model": "jev-latest",
                "answers": answers,
                "usage": {"input_tokens": 120, "output_tokens": 12},
            },
            request=request,
        )

    with JEVBatchClient(
        api_key="jev-key",
        base_url="https://example.test",
        model="jev-model",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    ) as client:
        result = client.score("Q-1", "query", candidates)

    assert result.scores == {
        candidate["doc_id"]: (index + 1) / 10
        for index, candidate in enumerate(candidates)
    }


def test_jev_rejects_duplicate_candidate_ids():
    candidates = _jev_candidates()
    candidates[1]["doc_id"] = candidates[0]["doc_id"]
    with JEVBatchClient(
        api_key="jev-key",
        base_url="https://example.test",
        model="jev-model",
    ) as client:
        with pytest.raises(ValueError, match="duplicate candidate IDs"):
            client.score("Q-1", "query", candidates)


@pytest.mark.parametrize(
    ("answer_mutation", "message"),
    [
        (lambda answers: answers.pop("candidate_candidate-3"), "missing a candidate answer"),
        (lambda answers: answers.__setitem__("candidate_candidate-3", {"type": "choice", "noul": 0.5}), "wrong answer type"),
        (lambda answers: answers.__setitem__("candidate_candidate-3", {"type": "noul", "noul": "high"}), "malformed Noul"),
        (lambda answers: answers.__setitem__("candidate_candidate-3", {"type": "noul", "noul": -0.1}), "out-of-range Noul"),
        (lambda answers: answers.__setitem__("candidate_candidate-3", {"type": "noul", "noul": 1.1}), "out-of-range Noul"),
    ],
)
def test_jev_rejects_missing_malformed_and_nonfinite_answers(answer_mutation, message):
    candidates = _jev_candidates()
    answers = {
        f"candidate_{candidate['doc_id']}": {"type": "noul", "noul": 0.5}
        for candidate in candidates
    }
    answer_mutation(answers)

    def handler(request):
        return httpx.Response(
            200,
            json={
                "model": "jev-latest",
                "answers": answers,
                "usage": {"input_tokens": 120, "output_tokens": 12},
            },
            request=request,
        )

    with JEVBatchClient(
        api_key="jev-key",
        base_url="https://example.test",
        model="jev-model",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    ) as client:
        with pytest.raises(RuntimeError, match=message):
            client.score("Q-1", "query", candidates)


@pytest.mark.parametrize("nonfinite", ["NaN", "Infinity"])
def test_jev_rejects_nan_and_infinite_noul_scores(nonfinite):
    candidates = _jev_candidates()
    answers = ", ".join(
        f'"candidate_{candidate["doc_id"]}":{{"type":"noul","noul":{0.5 if index != 3 else nonfinite}}}'
        for index, candidate in enumerate(candidates)
    )
    content = (
        '{"model":"jev-latest","answers":{' + answers
        + '},"usage":{"input_tokens":120,"output_tokens":12}}'
    ).encode()

    def handler(request):
        return httpx.Response(
            200,
            content=content,
            headers={"Content-Type": "application/json"},
            request=request,
        )

    with JEVBatchClient(
        api_key="jev-key",
        base_url="https://example.test",
        model="jev-model",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    ) as client:
        with pytest.raises(RuntimeError, match="non-finite Noul"):
            client.score("Q-1", "query", candidates)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {"answers": {}, "usage": {"input_tokens": 120, "output_tokens": 12}},
            "missing a valid model",
        ),
        (
            {"model": "jev-latest", "answers": {}},
            "missing usage",
        ),
        (
            {"model": "jev-latest", "answers": {}, "usage": {"input_tokens": "many", "output_tokens": 12}},
            "invalid usage",
        ),
    ],
)
def test_jev_rejects_missing_or_invalid_envelope(payload, message):
    candidates = _jev_candidates()

    def handler(request):
        return httpx.Response(200, json=payload, request=request)

    with JEVBatchClient(
        api_key="jev-key",
        base_url="https://example.test",
        model="jev-model",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    ) as client:
        with pytest.raises(RuntimeError, match=message):
            client.score("Q-1", "query", candidates)

