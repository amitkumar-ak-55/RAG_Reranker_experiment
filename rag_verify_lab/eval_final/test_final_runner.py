import csv
from dataclasses import replace
from types import SimpleNamespace

import rag_verify_lab.eval_final.final_runner as final_runner
from rag_verify_lab.config import settings
from rag_verify_lab.eval_final.final_runner import _answer, _evidence, _resume_config, _retry_after_seconds, deduplicate_predictions, mcnemar_p_value, parse_answer, remove_failed_answer_rows, remove_groq_setup_failures, score_predictions, wilson_interval


def test_parse_answer_uses_first_cve_only() -> None:
    assert parse_answer("answer CVE-2021-44228 then CVE-2020-0001") == "CVE-2021-44228"


def test_parse_answer_rejects_non_cve() -> None:
    assert parse_answer("INSUFFICIENT EVIDENCE") is None


def test_parse_answer_accepts_four_digit_cve_serial() -> None:
    assert parse_answer("ANSWER: CVE-2016-3088") == "CVE-2016-3088"


def test_parse_answer_normalizes_unicode_hyphens() -> None:
    assert parse_answer("CVE‑2015‑0016") == "CVE-2015-0016"


def test_scoring_counts_invalid_and_error_as_incorrect() -> None:
    gold = {"Q1": "CVE-2021-44228"}
    rows = [
        {"question_id": "Q1", "arm": "llm_only", "answer": "", "valid": "False", "error": ""},
        {"question_id": "Q1", "arm": "vector_rag", "answer": "", "valid": "False", "error": "network"},
        {"question_id": "Q1", "arm": "hybrid_rag", "answer": "CVE-2021-44228", "valid": "True", "error": ""},
    ]
    scores = score_predictions(rows, gold)
    assert scores["llm_only"]["wrong"] == 1
    assert scores["vector_rag"]["error"] == 1
    assert scores["hybrid_rag"]["correct"] == 1


def test_wilson_interval_for_all_correct_is_bounded() -> None:
    low, high = wilson_interval(300, 300)
    assert 0.98 < low < high <= 1
    assert wilson_interval(0, 300)[0] == 0.0


def test_mcnemar_counts_are_exact() -> None:
    assert mcnemar_p_value(0, 0) == 1.0
    assert mcnemar_p_value(3, 0) == 0.25


def test_deduplicate_predictions_keeps_first_checkpoint(tmp_path) -> None:
    path = tmp_path / "predictions.csv"
    path.write_text("question_id,arm,answer,valid,error,latency_ms,input_tokens,output_tokens,jev_calls\nQ1,llm_only,CVE-2021-1,True,,1,1,1,0\nQ1,llm_only,CVE-2021-2,True,,1,1,1,0\n", encoding="utf-8")
    assert deduplicate_predictions(path) == 1
    assert list(csv.DictReader(path.open(encoding="utf-8")))[0]["answer"] == "CVE-2021-1"


def test_retry_after_seconds_prefers_provider_header() -> None:
    class Response:
        headers = {"retry-after": "7.5"}

    class Error(Exception):
        response = Response()

    assert _retry_after_seconds(Error("429 retry in 2s"), 1.0) == 7.5


def test_retry_after_seconds_reads_provider_delay_text() -> None:
    assert _retry_after_seconds(RuntimeError("rate limited; retry in 4.25s"), 1.0) == 4.25
    assert _retry_after_seconds(RuntimeError("Please try again in 5m23.568s"), 1.0) == 323.568


def test_answer_falls_back_to_next_account_on_429(monkeypatch) -> None:
    calls = []

    class RateLimitError(Exception):
        status_code = 429
        response = SimpleNamespace(headers={"retry-after": "0"})

    class FakeClient:
        def __init__(self, api_key, **kwargs):
            self.api_key = api_key
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **kwargs):
            calls.append(self.api_key)
            if self.api_key == "key-a":
                raise RateLimitError("429 rate limit")
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="CVE-2021-44228"))],
                usage=SimpleNamespace(prompt_tokens=2, completion_tokens=1),
            )

    monkeypatch.setattr(final_runner, "settings", replace(settings, groq_api_key_1="key-a", groq_api_key_2="key-b", groq_api_key_3="key-c", gemini_api_key="", answer_model="openai/gpt-oss-120b"))
    monkeypatch.setattr(final_runner, "OpenAI", FakeClient)
    monkeypatch.setattr(final_runner, "_wait_for_answer_slot", lambda: None)
    final_runner._preferred_key_index = 0
    final_runner._answer_key_cooldown_until.clear()
    result = _answer("question", [])
    assert calls == ["key-a", "key-b"]
    assert result == ("CVE-2021-44228", 2, 1)


def test_daily_limit_waits_for_cooldown_keys_before_stopping(monkeypatch) -> None:
    calls = []

    class DailyLimitError(Exception):
        status_code = 429
        response = SimpleNamespace(headers={"retry-after": "0"})

    class FakeClient:
        def __init__(self, api_key, **kwargs):
            self.api_key = api_key
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **kwargs):
            calls.append(self.api_key)
            if self.api_key == "key-a":
                raise DailyLimitError("tokens per day limit reached")
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="CVE-2021-44228"))],
                usage=SimpleNamespace(prompt_tokens=2, completion_tokens=1),
            )

    monkeypatch.setattr(final_runner, "settings", replace(settings, groq_api_key_1="key-a", groq_api_key_2="key-b", groq_api_key_3="key-c", gemini_api_key="", answer_model="openai/gpt-oss-120b"))
    monkeypatch.setattr(final_runner, "OpenAI", FakeClient)
    monkeypatch.setattr(final_runner, "_wait_for_answer_slot", lambda: None)
    final_runner._preferred_key_index = 0
    final_runner._answer_key_cooldown_until.clear()
    final_runner._answer_key_cooldown_until.update({1: final_runner.time.monotonic() + 10, 2: final_runner.time.monotonic() + 10})
    monkeypatch.setattr(final_runner.time, "sleep", lambda _: final_runner._answer_key_cooldown_until.clear())
    result = _answer("question", [])
    assert calls == ["key-a", "key-a", "key-b"]
    assert result[0] == "CVE-2021-44228"


def test_remove_groq_setup_failures_preserves_completed_jev_checks(tmp_path) -> None:
    path = tmp_path / "predictions.csv"
    path.write_text(
        "question_id,arm,answer,valid,error,latency_ms,input_tokens,output_tokens,jev_calls\n"
        "Q1,hybrid_rag,,False,unexpected keyword argument 'include_reasoning',2,unknown,unknown,0\n"
        "Q1,hybrid_jev,,False,,1,unknown,unknown,0\n"
        "Q1,jev_retrieval,,False,provider 503,20,unknown,unknown,20\n",
        encoding="utf-8",
    )
    assert remove_groq_setup_failures(path) == 2
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert len(rows) == 1 and rows[0]["arm"] == "jev_retrieval" and rows[0]["jev_calls"] == "20"


def test_remove_failed_answers_requeues_generation_but_keeps_completed_jev_calls(tmp_path) -> None:
    path = tmp_path / "predictions.csv"
    path.write_text(
        "question_id,arm,answer,valid,error,latency_ms,input_tokens,output_tokens,jev_calls\n"
        "Q1,llm_only,,False,Connection error.,2,unknown,unknown,0\n"
        "Q1,hybrid_rag,,False,quota_or_rate_limit: daily TPD,2,unknown,unknown,0\n"
        "Q1,hybrid_jev,,False,,1,unknown,unknown,0\n"
        "Q1,jev_retrieval,,False,quota_or_rate_limit: daily TPD,20,unknown,unknown,20\n",
        encoding="utf-8",
    )
    assert remove_failed_answer_rows(path) == 3
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert len(rows) == 1 and rows[0]["arm"] == "jev_retrieval" and rows[0]["jev_calls"] == "20"


def test_evidence_preserves_retrieved_cve_without_a_gold_label() -> None:
    evidence = _evidence(
        [SimpleNamespace(metadata={"title": "CVE-2021-44228: Log4j", "doc_id": "CVE-2021-44228"}, text="Bug details for CVE-2021-44228")],
    )
    assert evidence == [{"cve_id": "CVE-2021-44228", "title": "CVE-2021-44228: Log4j", "description": "Bug details for CVE-2021-44228"}]


def test_resume_config_preserves_quota_stop_and_same_model(tmp_path) -> None:
    (tmp_path / "run_config.json").write_text(
        '{"models":{"answer":"' + settings.answer_model + '"},"stopped_cleanly":"daily quota","questions_completed_per_arm":{"llm_only":4}}',
        encoding="utf-8",
    )
    config = _resume_config(tmp_path, "run-1", {})
    assert config["resume_count"] == 1
    assert config["quota_stops"][0]["reason"] == "daily quota"
    assert "stopped_cleanly" not in config
