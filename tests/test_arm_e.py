from dataclasses import replace

from rag_verify_lab.config import settings
from rag_verify_lab.experiment.metrics import precision_at_k
from rag_verify_lab.experiment.runner import _candidate_set, rank_jev_candidates
from rag_verify_lab.verify.jev import JEVClient
from rag_verify_lab.db import Finding, Question


def test_arm_e_ranks_scores_and_breaks_ties_by_bm25_rank() -> None:
    candidates = [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}, {"id": 6}]
    ranked = rank_jev_candidates(candidates, {1: 0.5, 2: 0.9, 3: 0.9, 4: 0.1, 5: 0.8, 6: 0.7})
    assert [item["id"] for item in ranked] == [2, 3, 5, 6, 1]


def test_candidate_cap_sets_flag(monkeypatch) -> None:
    local_settings = replace(settings, jev_candidate_limit=2, embedding_model="", rerank_model="")
    monkeypatch.setattr("rag_verify_lab.experiment.runner.settings", local_settings)
    monkeypatch.setattr("rag_verify_lab.rag.index.settings", local_settings)
    monkeypatch.setattr("rag_verify_lab.rag.embed.settings", local_settings)
    question = Question(text="Which web finding matters?", vm_id=1)
    findings = [
        Finding(id=index, vm_id=1, title=f"web finding {index}", description="web service", severity="high")
        for index in range(1, 4)
    ]
    candidates, capped = _candidate_set(question, findings)
    assert capped
    assert len(candidates) == 2


def test_precision_at_k_handles_fewer_gold_items() -> None:
    assert precision_at_k([10, 20, 30, 40, 50], [10], 1) == 1.0
    assert precision_at_k([10, 20, 30, 40, 50], [10], 3) == 1 / 3
    assert precision_at_k([10, 20], [10, 20], 5) == 2 / 5


def test_arm_e_is_not_configured_without_jev(monkeypatch) -> None:
    monkeypatch.setattr(
        "rag_verify_lab.verify.jev.settings",
        replace(settings, jev_api_key="", jev_base_url="", jev_model=""),
    )
    assert not JEVClient().configured


def test_jev_scoring_uses_choice_and_noul_schema(monkeypatch) -> None:
    class Response:
        status_code = 200
        text = "{}"

        def json(self):
            return {"answers": {"relevant": {"choice": "RELEVANT"}, "score": {"noul": 0.75}}}

    calls = []
    monkeypatch.setattr(
        "rag_verify_lab.verify.jev.settings",
        replace(settings, jev_api_key="key", jev_base_url="https://jev.example", jev_model="model"),
    )
    monkeypatch.setattr("rag_verify_lab.verify.jev.httpx.post", lambda url, **kwargs: calls.append(kwargs["json"]) or Response())
    result = JEVClient().score_finding("Which issue matters?", {"title": "Issue", "description": "Details", "cve_id": None})
    assert result.relevant and result.score == 0.75
    assert calls[0]["questions"]["relevant"]["type"] == "choice"
    assert calls[0]["questions"]["score"]["type"] == "noul"
