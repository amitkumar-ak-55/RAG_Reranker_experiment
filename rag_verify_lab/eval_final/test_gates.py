from __future__ import annotations

from collections import Counter

from .build import METHODS, validate_candidate


def _records() -> dict[str, dict[str, object]]:
    return {
        "CVE-1": {
            "doc_type": "cve",
            "group": "positive",
            "products": ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"],
            "cwe_ids": ["CWE-79"],
            "text": "The widget allows an attacker to read arbitrary files through a crafted request.",
        },
        "CVE-2": {
            "doc_type": "cve",
            "group": "kev",
            "products": ["cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"],
            "cwe_ids": ["CWE-79"],
            "text": "The thing allows an attacker to execute code through a crafted request.",
        },
        "CVE-3": {
            "doc_type": "cve",
            "group": "positive",
            "products": ["cpe:2.3:a:third:thing:*:*:*:*:*:*:*:*"],
            "cwe_ids": ["CWE-79"],
            "text": "The thing allows an attacker to write files through a crafted request.",
        },
    }


def _candidate() -> dict[str, object]:
    return {
        "candidate_id": "C-0001",
        "gold_cve": "CVE-1",
        "question": "Which CVE affects acme widget when the report describes widget allows attacker read files?",
        "product": "acme widget",
        "behavior_sentence": "The widget allows an attacker to read arbitrary files through a crafted request.",
        "confusers": [{"cve": "CVE-2", "match_reason": "cwe"}, {"cve": "CVE-3", "match_reason": "cwe"}],
    }


def _ranks() -> dict[str, object]:
    return {method: 1 for method, _, _ in METHODS}


def test_all_gates_pass() -> None:
    result = validate_candidate(_candidate(), _ranks(), _records(), Counter())
    assert result["passed"] is True
    assert all(result["checks"].values())


def test_g1_rejects_missing_gold() -> None:
    records = _records()
    records.pop("CVE-1")
    assert validate_candidate(_candidate(), _ranks(), records, Counter())["checks"]["G1"] is False


def test_g2_rejects_ambiguous_product() -> None:
    records = _records()
    records["CVE-1"]["products"] = [
        "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*",
    ]
    records["CVE-1"]["title"] = "Acme widget and gadget"
    assert validate_candidate(_candidate(), _ranks(), records, Counter())["checks"]["G2"] is False


def test_g3_rejects_unsupported_sentence() -> None:
    candidate = _candidate()
    candidate["behavior_sentence"] = "not in record"
    assert validate_candidate(candidate, _ranks(), _records(), Counter())["checks"]["G3"] is False


def test_g4_rejects_confuser_sentence_overlap() -> None:
    records = _records()
    records["CVE-2"]["text"] = _records()["CVE-1"]["text"]
    assert validate_candidate(_candidate(), _ranks(), records, Counter())["checks"]["G4"] is False


def test_g5_rejects_identifier_leak() -> None:
    candidate = _candidate()
    candidate["question"] = "CVE-1 affects acme widget."
    assert validate_candidate(candidate, _ranks(), _records(), Counter())["checks"]["G5"] is False


def test_g6_rejects_six_word_overlap() -> None:
    candidate = _candidate()
    candidate["question"] = "The widget allows an attacker to read arbitrary files."
    assert validate_candidate(candidate, _ranks(), _records(), Counter())["checks"]["G6"] is False


def test_g7_rejects_overused_confuser() -> None:
    uses = Counter({"CVE-2": 3})
    assert validate_candidate(_candidate(), _ranks(), _records(), uses)["checks"]["G7"] is False


def test_g8_rejects_incomplete_ranks() -> None:
    ranks = _ranks()
    ranks.pop("hybrid")
    assert validate_candidate(_candidate(), ranks, _records(), Counter())["checks"]["G8"] is False
