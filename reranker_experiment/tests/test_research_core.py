from pathlib import Path

import httpx

from reranker_experiment.evaluation import answer_evaluation, cve_hit_at_k
from reranker_experiment.experiment import duplicate_groups, run_mock_dry_run, validate_dataset
from reranker_experiment.gold import document_cves, normalize_cve
from reranker_experiment.jev_batch import JEVBatchClient
from reranker_experiment.statistics import holm_adjust, paired_bootstrap, wilcoxon_signed_rank


def test_cve_normalization_and_answer_evaluation():
    assert normalize_cve(" cve-2024-1234 ") == "CVE-2024-1234"
    assert document_cves({"doc_id": "CVE-2024-1234", "text": "x"}) == (["CVE-2024-1234"], "structured")
    result = answer_evaluation("The issue is CVE-2024-1234.", "CVE-2024-1234")
    assert result["gold_cve_mention"] is True
    assert result["unambiguous_cve_identification"] is True


def test_dataset_manifest_preserves_all_300_records():
    manifest = validate_dataset()
    assert manifest["record_count"] == 300
    assert manifest["unique_question_ids"] == 300


def test_mock_dry_run_writes_candidate_equality_artifact(tmp_path: Path):
    output = run_mock_dry_run(tmp_path / "mock", question_limit=2)
    assert (output / "experiment_metadata.json").is_file()
    rows = (output / "per_candidate_results.csv").read_text(encoding="utf-8")
    assert "baseline" in rows and "jina" in rows and "jev" in rows


def test_paired_statistics_are_reproducible():
    assert holm_adjust([0.01, 0.02, 0.5]) == [0.03, 0.04, 0.5]
    assert paired_bootstrap([1, 1, 0], [0, 1, 0], seed=17, iterations=100)[0] <= 0.34
    statistic, p_value = wilcoxon_signed_rank([1, 1, 1], [0, 0, 0])
    assert statistic == 0
    assert 0 <= p_value <= 1


def test_jev_batch_uses_one_post_with_ten_keyed_questions():
    candidates = [{"doc_id": f"CVE-2024-{index:04d}", "text": f"document {index}"} for index in range(10)]
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read()
        import json
        parsed = json.loads(payload)
        seen.append(parsed)
        answers = {
            key: {"type": "noul", "noul": index / 10}
            for index, key in enumerate(parsed["questions"])
        }
        return httpx.Response(
            200,
            json={
                "model": "jev-latest",
                "answers": answers,
                "usage": {"input_tokens": 120, "output_tokens": 12},
            },
            request=request,
        )

    transport = httpx.MockTransport(handler)
    with JEVBatchClient(
        api_key="test-key",
        base_url="https://example.test",
        model="test-model",
        http_client=httpx.Client(transport=transport),
    ) as client:
        result = client.score("Q-1", "Which CVE?", candidates)
    assert len(seen) == 1
    assert len(seen[0]["questions"]) == 10
    assert set(result.scores) == {candidate["doc_id"] for candidate in candidates}
