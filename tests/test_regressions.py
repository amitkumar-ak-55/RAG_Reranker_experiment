import numpy as np
from dataclasses import replace

from rag_verify_lab.config import settings
from rag_verify_lab.rag import embed
from rag_verify_lab.rag import answer
from rag_verify_lab.rag.index import FindingIndex
from rag_verify_lab.verify.jev import JEVClient
from rag_verify_lab.verify import jev_health


def test_local_models_produce_embeddings_without_openrouter(monkeypatch):
    calls = []

    class FakeEmbeddingModel:
        def encode(self, texts, **kwargs):
            calls.extend(texts)
            return np.tile(np.array([[1.0, 0.0]], dtype=np.float32), (len(texts), 1))

    local_settings = replace(settings, embedding_model="local-embedding", embedding_revision="rev")
    monkeypatch.setattr(embed, "settings", local_settings)
    monkeypatch.setattr(embed, "encode", lambda texts, query=False: FakeEmbeddingModel().encode(texts))
    monkeypatch.setattr("rag_verify_lab.models.rerank", lambda query, texts: np.ones(len(texts), dtype=np.float32))
    monkeypatch.setattr("rag_verify_lab.models.embedding_model", lambda *args: FakeEmbeddingModel())
    assert np.array_equal(embed.embed_text("semantic query"), np.array([1.0, 0.0], dtype=np.float32))
    assert calls == ["semantic query"]


def test_semantic_embedding_retrieves_paraphrase(monkeypatch):
    local_settings = replace(settings, embedding_model="", rerank_model="")
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", local_settings)
    vectors = {"credential exposure": np.array([1.0, 0.0]), "unrelated": np.array([0.0, 1.0]), "password leak": np.array([1.0, 0.0])}
    monkeypatch.setattr("rag_verify_lab.rag.index.embed_text", lambda text: vectors["credential exposure"] if "credential" in text or "password" in text else vectors["unrelated"])
    index = FindingIndex([{"id": 1, "text": "credential exposure", "metadata": {}}, {"id": 2, "text": "unrelated", "metadata": {}}])
    assert index.vector_search("password leak", 1)[0].id == 1


def test_jev_clean_skip():
    monkeypatch = __import__("pytest").MonkeyPatch()
    monkeypatch.setattr("rag_verify_lab.verify.jev.settings", replace(settings, jev_api_key="", jev_base_url="", jev_model=""))
    assert not JEVClient().configured


def test_jev_uses_system_one_api(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"answers": {"support": {"choice": "SUPPORTED"}, "citation": {"noul": 0.9}}}

    calls = {}

    def post(url, **kwargs):
        calls.update(url=url, kwargs=kwargs)
        return Response()

    local_settings = replace(settings, jev_api_key="jev-key", jev_base_url="https://api.typesafe.ai", jev_model="jev-latest")
    monkeypatch.setattr("rag_verify_lab.verify.jev.settings", local_settings)
    monkeypatch.setattr("rag_verify_lab.verify.jev.httpx.post", post)

    judgment = JEVClient().judge("The claim", ["The evidence"])

    assert judgment.label == "SUPPORTED"
    assert judgment.citation_correct
    assert calls["url"] == "https://api.typesafe.ai/v1/systemone"
    assert calls["kwargs"]["headers"]["Authorization"] == "Bearer jev-key"
    assert calls["kwargs"]["json"]["questions"]["support"]["type"] == "choice"


def test_jev_selects_only_from_supplied_cve_candidates(monkeypatch):
    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {"answers": {"select": {"choice": "CVE-2021-44228"}}}

    local_settings = replace(settings, jev_api_key="jev-key", jev_base_url="https://api.typesafe.ai", jev_model="jev-latest")
    monkeypatch.setattr("rag_verify_lab.verify.jev.settings", local_settings)
    monkeypatch.setattr("rag_verify_lab.verify.jev.httpx.post", lambda *args, **kwargs: Response())

    result = JEVClient().select_candidate("Which CVE?", [{"cve_id": "CVE-2021-44228", "title": "Log4j", "description": "Details"}])

    assert result.cve_id == "CVE-2021-44228"


def test_jev_health_success(monkeypatch):
    class Response:
        status_code = 200
        text = '{"answers":{"health":{"type":"noul","noul":1}}}'

        def json(self):
            return {"answers": {"health": {"type": "noul", "noul": 1}}}

    local_settings = replace(settings, jev_api_key="secret-key", jev_base_url="https://api.typesafe.ai", jev_model="jev-latest")
    monkeypatch.setattr(jev_health, "settings", local_settings)
    monkeypatch.setattr(jev_health.httpx, "post", lambda *args, **kwargs: Response())
    result = jev_health.jev_health()
    assert all(result[key] for key in ("configured", "reachable", "authenticated", "model_accepted"))
    assert result["http_status"] == 200
    assert "secret-key" not in str(result)


def test_jev_health_auth_failure(monkeypatch):
    class Response:
        status_code = 401
        text = '{"detail":"bad key"}'

    monkeypatch.setattr(jev_health, "settings", replace(settings, jev_api_key="key", jev_base_url="https://api.typesafe.ai", jev_model="jev-latest"))
    monkeypatch.setattr(jev_health.httpx, "post", lambda *args, **kwargs: Response())
    result = jev_health.jev_health()
    assert result["reachable"] and not result["authenticated"] and not result["model_accepted"]


def test_jev_health_model_or_endpoint_failure(monkeypatch):
    class Response:
        status_code = 404
        text = '{"detail":"not found"}'

    monkeypatch.setattr(jev_health, "settings", replace(settings, jev_api_key="key", jev_base_url="https://api.typesafe.ai", jev_model="bad-model"))
    monkeypatch.setattr(jev_health.httpx, "post", lambda *args, **kwargs: Response())
    result = jev_health.jev_health()
    assert result["reachable"] and not result["model_accepted"]


def test_jev_health_timeout_and_connection_refused(monkeypatch):
    import httpx

    monkeypatch.setattr(jev_health, "settings", replace(settings, jev_api_key="key", jev_base_url="https://api.typesafe.ai", jev_model="jev-latest"))
    monkeypatch.setattr(jev_health.httpx, "post", lambda *args, **kwargs: (_ for _ in ()).throw(httpx.TimeoutException("slow")))
    assert not jev_health.jev_health()["reachable"]
    monkeypatch.setattr(jev_health.httpx, "post", lambda *args, **kwargs: (_ for _ in ()).throw(httpx.ConnectError("refused")))
    assert not jev_health.jev_health()["reachable"]


def test_jev_health_blank_config(monkeypatch):
    monkeypatch.setattr(jev_health, "settings", replace(settings, jev_api_key="", jev_base_url="", jev_model=""))
    result = jev_health.jev_health()
    assert not result["configured"]
    assert result["http_status"] is None


def test_jev_url_checker_reports_endpoint_path():
    assert "full endpoint path" in " ".join(jev_health.check_jev_url("https://api.typesafe.ai/chat/completions"))


def test_cache_changes_with_model(monkeypatch):
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", replace(settings, embedding_model="model-a"))
    monkeypatch.setattr("rag_verify_lab.rag.index.embed_text", lambda text: np.array([1.0], dtype=np.float32))
    first = FindingIndex([{"id": 900001, "text": "x", "metadata": {}}]).items[0].vector
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", replace(settings, embedding_model="model-b"))
    monkeypatch.setattr("rag_verify_lab.rag.index.embed_text", lambda text: np.array([2.0], dtype=np.float32))
    second = FindingIndex([{"id": 900001, "text": "x", "metadata": {}}]).items[0].vector
    assert not np.array_equal(first, second)


def test_cost_unknown_when_prices_blank(monkeypatch):
    class Completions:
        def create(self, **kwargs):
            return type("Response", (), {"choices": [type("Choice", (), {"message": type("Message", (), {"content": "INSUFFICIENT EVIDENCE"})()})()], "usage": type("Usage", (), {"prompt_tokens": 3, "completion_tokens": 2})()})()

    local_settings = replace(settings, answer_model="answer", gemini_api_key="key", gemini_base_url="https://gemini.example/v1beta/openai/", price_answer_in_per_m="", price_answer_out_per_m="")
    monkeypatch.setattr(answer, "settings", local_settings)
    monkeypatch.setattr(answer, "OpenAI", lambda **kwargs: type("Client", (), {"chat": type("Chat", (), {"completions": Completions()})()})())
    assert answer.answer_question("question", []).cost is None
