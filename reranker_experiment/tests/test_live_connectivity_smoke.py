import httpx
from dataclasses import replace

from reranker_experiment import live_connectivity_smoke as smoke


def test_default_invocation_makes_no_network_requests(monkeypatch):
    assert smoke.main([]) == 2


def test_live_approval_flag_is_required(monkeypatch):
    monkeypatch.setattr(
        smoke,
        "run_jina",
        lambda: (_ for _ in ()).throw(AssertionError("Jina network called")),
    )
    monkeypatch.setattr(
        smoke,
        "run_jev",
        lambda: (_ for _ in ()).throw(AssertionError("JEV network called")),
    )
    assert smoke.main(["--provider", "both"]) == 2


def test_provider_calls_are_independent(monkeypatch):
    calls = []
    assert smoke.main(
        ["--live-approved", "--provider", "jina"],
        jina_runner=lambda: calls.append("jina") or {"provider": "jina", "response_valid": True},
        jev_runner=lambda: calls.append("jev") or {"provider": "jev", "response_valid": True},
    ) == 0
    assert calls == ["jina"]


def test_smallest_jina_request_uses_two_documents_and_one_post(monkeypatch):
    monkeypatch.setattr(
        smoke,
        "settings",
        replace(
            smoke.settings,
            jina_api_key_1="test-key",
            jina_api_key_2="other-key",
            jina_base_url="https://example.test",
            jina_reranker_model="test-model",
        ),
    )
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "model": "test-model",
                "usage": {"total_tokens": 10},
                "results": [
                    {"index": 0, "relevance_score": 0.8},
                    {"index": 1, "relevance_score": 0.2},
                ],
            },
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler), timeout=10) as client:
        report = smoke.run_jina(http_client=client)
    assert len(seen) == 1
    import json
    payload = json.loads(seen[0].content)
    assert len(payload["documents"]) == 2
    assert payload["top_n"] == 2
    assert report["response_valid"] is True


def test_smallest_jev_request_uses_two_named_noul_questions(monkeypatch):
    monkeypatch.setattr(
        smoke,
        "settings",
        replace(
            smoke.settings,
            jev_api_key="test-key",
            jev_base_url="https://example.test",
            jev_model="test-model",
        ),
    )
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        import json
        payload = json.loads(request.content)
        answers = {
            key: {"type": "noul", "noul": 0.5}
            for key in payload["questions"]
        }
        return httpx.Response(
            200,
            json={
                "model": "test-model",
                "answers": answers,
                "usage": {"input_tokens": 20, "output_tokens": 2},
            },
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler), timeout=10) as client:
        report = smoke.run_jev(http_client=client)
    assert len(seen) == 1
    import json
    payload = json.loads(seen[0].content)
    assert len(payload["questions"]) == 2
    assert all(question["type"] == "noul" for question in payload["questions"].values())
    assert report["response_valid"] is True
