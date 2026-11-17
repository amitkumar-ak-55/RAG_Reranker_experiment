from dataclasses import replace

import httpx
import pytest

from reranker_experiment.client import (
    JinaConfigurationError,
    JinaReranker,
    KeyRotator,
)
from reranker_experiment.config import ExperimentSettings


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
        httpx.Response(200, json={"data": [{"index": 1, "relevance_score": 0.9}, {"index": 0, "relevance_score": 0.1}]},
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
        return httpx.Response(200, json={"data": [{"index": 3, "relevance_score": 0.1}]}, request=request)

    with JinaReranker(settings, client=httpx.Client(transport=httpx.MockTransport(handler))) as client:
        with pytest.raises(Exception, match="invalid document indices"):
            client.rerank("query", ["a"])

