import json
from pathlib import Path

import pytest

from rag_verify_lab.eval_questions import generate_questions, validate_questions


def fixture_corpus(tmp_path: Path) -> Path:
    rows = [
        {"doc_id": "CVE-1", "doc_type": "cve", "cwe_ids": ["CWE-79"], "products": ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"], "cvss_score": 7.5, "cvss_version": "3.1", "known_exploited": True, "group": "kev"},
        {"doc_id": "CWE-79", "doc_type": "cwe", "cwe_ids": ["CWE-79"], "group": "positive"},
        {"doc_id": "CVE-2", "doc_type": "distractor", "cwe_ids": [], "products": ["cpe:2.3:a:other:gadget:*:*:*:*:*:*:*:*"], "cvss_score": None, "cvss_version": None, "known_exploited": False, "group": "distractor"},
    ]
    path = tmp_path / "documents.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def test_each_question_type_fixture_answers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = fixture_corpus(tmp_path)
    import rag_verify_lab.eval_questions as module
    monkeypatch.setattr(module, "CORPUS_SHA256", __import__("hashlib").sha256(corpus.read_bytes()).hexdigest())
    monkeypatch.setattr(module, "UNANSWERABLE_CHECKS", [])
    targets = tmp_path / "targets.txt"
    distractors = tmp_path / "distractors.txt"
    targets.write_text("CVE-1\n", encoding="utf-8")
    distractors.write_text("CVE-2\n", encoding="utf-8")
    questions, _ = generate_questions(corpus, targets, distractors)
    answers = {(q["question_type"], q["target_cve"]): q["gold_answer"] for q in questions}
    assert answers[("existence", "CVE-1")] == "yes"
    assert answers[("cwe", "CVE-1")] == ["CWE-79"]
    assert answers[("cvss", "CVE-1")] == "7.5 (CVSS 3.1)"
    assert answers[("kev", "CVE-1")] == "yes"
    assert answers[("distractor_existence", "CVE-2")] == "yes"


def test_target_never_in_both_splits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = fixture_corpus(tmp_path)
    import rag_verify_lab.eval_questions as module
    monkeypatch.setattr(module, "CORPUS_SHA256", __import__("hashlib").sha256(corpus.read_bytes()).hexdigest())
    monkeypatch.setattr(module, "UNANSWERABLE_CHECKS", [])
    targets = tmp_path / "targets.txt"; targets.write_text("CVE-1\n", encoding="utf-8")
    distractors = tmp_path / "distractors.txt"; distractors.write_text("CVE-2\n", encoding="utf-8")
    questions, _ = generate_questions(corpus, targets, distractors)
    assert not validate_questions(questions, corpus)


def test_leakage_check_catches_gold_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = fixture_corpus(tmp_path)
    import rag_verify_lab.eval_questions as module
    monkeypatch.setattr(module, "CORPUS_SHA256", __import__("hashlib").sha256(corpus.read_bytes()).hexdigest())
    monkeypatch.setattr(module, "UNANSWERABLE_CHECKS", [])
    targets = tmp_path / "targets.txt"; targets.write_text("CVE-1\n", encoding="utf-8")
    distractors = tmp_path / "distractors.txt"; distractors.write_text("CVE-2\n", encoding="utf-8")
    questions, _ = generate_questions(corpus, targets, distractors)
    questions[0]["question"] += " yes"
    assert any("gold answer leaked" in failure for failure in validate_questions(questions, corpus))


def test_unanswerable_id_present_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = fixture_corpus(tmp_path)
    import rag_verify_lab.eval_questions as module
    monkeypatch.setattr(module, "CORPUS_SHA256", __import__("hashlib").sha256(corpus.read_bytes()).hexdigest())
    monkeypatch.setattr(module, "UNANSWERABLE_CHECKS", [("CVE-1", "acme", "widget")])
    targets = tmp_path / "targets.txt"; targets.write_text("CVE-1\n", encoding="utf-8")
    distractors = tmp_path / "distractors.txt"; distractors.write_text("CVE-2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unanswerable ID"):
        generate_questions(corpus, targets, distractors)


def test_regeneration_is_identical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    corpus = fixture_corpus(tmp_path)
    import rag_verify_lab.eval_questions as module
    monkeypatch.setattr(module, "CORPUS_SHA256", __import__("hashlib").sha256(corpus.read_bytes()).hexdigest())
    monkeypatch.setattr(module, "UNANSWERABLE_CHECKS", [])
    targets = tmp_path / "targets.txt"; targets.write_text("CVE-1\n", encoding="utf-8")
    distractors = tmp_path / "distractors.txt"; distractors.write_text("CVE-2\n", encoding="utf-8")
    first, first_split = generate_questions(corpus, targets, distractors)
    second, second_split = generate_questions(corpus, targets, distractors)
    assert first == second
    assert first_split == second_split
