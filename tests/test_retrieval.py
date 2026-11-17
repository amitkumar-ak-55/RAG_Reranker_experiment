from dataclasses import replace

from rag_verify_lab.rag.index import FindingIndex
from rag_verify_lab.rag.retrieve import hybrid_search
from rag_verify_lab.config import settings


def test_retrieval_arms(monkeypatch) -> None:
    local_settings = replace(settings, embedding_model="", rerank_model="")
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", local_settings)
    monkeypatch.setattr("rag_verify_lab.rag.embed.settings", local_settings)
    monkeypatch.setattr("rag_verify_lab.rag.retrieve.settings", local_settings)
    index = FindingIndex([
        {"id": 1, "text": "open http web server", "metadata": {"vm_id": 1}},
        {"id": 2, "text": "ssh service", "metadata": {"vm_id": 1}},
    ])
    assert index.vector_search("http", 1)[0].id == 1
    assert index.bm25_search("ssh", 1)[0].id == 2
    assert hybrid_search(index, "http", 1)[0].id == 1
