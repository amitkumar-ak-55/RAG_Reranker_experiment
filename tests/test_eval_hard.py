import hashlib
import json
from pathlib import Path

import pytest

from rag_verify_lab.eval_hard import build_questions, proof_rows, validate_hard_questions


def fixture_corpus(tmp_path: Path) -> Path:
    rows = [{
        "doc_id": "CVE-1", "doc_type": "cve", "cwe_ids": ["CWE-79"],
        "products": ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"],
        "text": "HTML autoescaping was disabled in a portion of the template.", "group": "positive",
    }]
    path = tmp_path / "documents.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def question_fixture(corpus: Path) -> dict:
    return {
        "question_id": "H-001", "question_type": "behaviour",
        "question": "What flaw is described?", "gold_answer": "CVE-1",
        "gold_evidence_ids": ["CVE-1"], "answerable": True,
        "target_cwe_class": "CWE-79", "product": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
        "group": "positive", "confusers": [], "verification_note": '"HTML autoescaping was disabled"',
        "corpus_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
    }


def test_question_containing_cve_id_fails(tmp_path: Path) -> None:
    corpus = fixture_corpus(tmp_path)
    question = question_fixture(corpus)
    question["question"] = "CVE-1: what flaw is described?"
    assert any("CVE ID leaked" in error for error in validate_hard_questions([question], corpus))


def test_missing_verification_note_fails(tmp_path: Path) -> None:
    corpus = fixture_corpus(tmp_path)
    question = question_fixture(corpus)
    question["verification_note"] = '"not in the record"'
    assert any("verification quote absent" in error for error in validate_hard_questions([question], corpus))


def test_six_word_record_run_fails(tmp_path: Path) -> None:
    corpus = fixture_corpus(tmp_path)
    question = question_fixture(corpus)
    question["question"] = "HTML autoescaping was disabled in a portion of the template. What is it?"
    assert any("six-word record run leaked" in error for error in validate_hard_questions([question], corpus))


def test_fewer_than_ten_cwe_classes_fails(tmp_path: Path) -> None:
    corpus = fixture_corpus(tmp_path)
    questions = [question_fixture(corpus) for _ in range(25)]
    assert any("fewer than 10 CWE classes" in error for error in validate_hard_questions(questions, corpus))


def test_generated_hard_set_is_valid() -> None:
    root = Path(__file__).resolve().parents[1]
    questions = build_questions(root / "data/kb/documents.jsonl")
    assert validate_hard_questions(questions, root / "data/kb/documents.jsonl") == []


def test_machine_proof_has_zero_overlap_and_leakage() -> None:
    root = Path(__file__).resolve().parents[1]
    rows = proof_rows(build_questions(root / "data/kb/documents.jsonl"), root / "data/kb/documents.jsonl")
    assert len(rows) == 25
    assert all(row["six_word_overlap_count"] == 0 for row in rows)
    assert all(not row["gold_cve_in_question"] for row in rows)
    assert all(not row["cpe_in_question"] for row in rows)
    assert all(not row["cwe_in_question"] for row in rows)
    assert all(row["verification_note_is_substring"] for row in rows)
    assert all(row["confusers"] for row in rows)
