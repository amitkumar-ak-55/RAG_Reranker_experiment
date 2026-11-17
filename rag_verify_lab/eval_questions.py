"""Build and validate the frozen evaluation question set."""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any

CORPUS_SHA256 = "8c4daa39da534a7f4871f4e4f4d72af03bf8fd3ce5b34e5dac586e11e585f6fc"
SPLIT_SEED = 42
REMOVED_IDS = {"CVE-2016-1000212", "CVE-2021-28073"}
IGNORED_CWES = {"NVD-CWE-Other", "NVD-CWE-noinfo"}

# These were checked against NVD on 2026-11-06 and are deliberately outside the
# frozen corpus. Their CPEs provide the product wording without becoming gold evidence.
UNANSWERABLE_CHECKS = [
    ("CVE-2000-0114", "microsoft", "internet information server"),
    ("CVE-2002-1131", "squirrelmail", "squirrelmail"),
    ("CVE-2004-0519", "sgi", "propack"),
    ("CVE-2004-1965", "openbb", "openbb"),
    ("CVE-2005-2428", "ibm", "lotus domino"),
    ("CVE-2005-3128", "squirrelmail", "address add plugin"),
    ("CVE-2005-3344", "horde", "horde"),
    ("CVE-2005-3634", "sap", "sap web application server"),
    ("CVE-2005-4385", "cofax", "cofax"),
    ("CVE-2006-1681", "cherokee", "cherokee httpd"),
    ("CVE-2006-2842", "squirrelmail", "squirrelmail"),
    ("CVE-2007-0885", "rainbow portal", "rainbow.zen"),
    ("CVE-2007-4504", "joomla", "rsfiles"),
    ("CVE-2007-4556", "opensymphony", "xwork"),
    ("CVE-2010-0219", "apache", "axis2"),
    ("CVE-2023-35078", "ivanti", "endpoint manager mobile"),
]


def _read_jsonl(path: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    records: list[dict[str, Any]] = []
    lines: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        record = json.loads(raw)
        records.append(record)
        lines[record["doc_id"]] = raw
    return records, lines


def _product_name(record: dict[str, Any]) -> str:
    cpes = record.get("products", [])
    application = next((cpe for cpe in cpes if cpe.startswith("cpe:2.3:a:")), None)
    cpe = application or (cpes[0] if cpes else "")
    fields = cpe.split(":")
    if len(fields) < 5:
        raise ValueError(f"{record['doc_id']} has no usable CPE product")
    return " ".join(
        re.sub(r"\\([!&,:])", r"\1", value).replace("_", " ")
        for value in (fields[3], fields[4])
    )


def _source_hash(ids: list[str], lines: dict[str, str]) -> str:
    joined = "".join(hashlib.sha256(lines[doc_id].encode("utf-8")).hexdigest() for doc_id in ids)
    return hashlib.sha256(joined.encode("ascii")).hexdigest()


def _question(
    qtype: str,
    text: str,
    target: str | None,
    answer: str | list[str],
    evidence: list[str],
    group: str,
    split: str,
    lines: dict[str, str],
) -> dict[str, Any]:
    return {
        "question_id": "",
        "question_type": qtype,
        "question": text,
        "target_cve": target,
        "gold_answer": answer,
        "gold_evidence_ids": evidence,
        "answerable": qtype != "unanswerable",
        "group": group,
        "split": split,
        "source_hash": _source_hash(evidence, lines) if evidence else "",
        "corpus_sha256": CORPUS_SHA256,
    }


def generate_questions(corpus_path: Path, target_seed_path: Path, distractor_seed_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    actual_hash = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    if actual_hash != CORPUS_SHA256:
        raise RuntimeError(f"corpus hash mismatch: expected {CORPUS_SHA256}, got {actual_hash}")
    records, lines = _read_jsonl(corpus_path)
    by_id = {record["doc_id"]: record for record in records}
    targets = [line.strip() for line in target_seed_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    distractors = [line.strip() for line in distractor_seed_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    if set(targets) & REMOVED_IDS or set(distractors) & REMOVED_IDS:
        raise ValueError("removed CVE ID is present in a seed file")
    if any(cve not in by_id or by_id[cve]["doc_type"] != "cve" for cve in targets):
        raise ValueError("target seed does not match the corpus")
    if any(cve not in by_id or by_id[cve]["doc_type"] != "distractor" for cve in distractors):
        raise ValueError("distractor seed does not match the corpus")

    rng = random.Random(SPLIT_SEED)
    dev_targets = set(rng.sample(targets, round(len(targets) * 0.30)))
    assignments = {cve: ("dev" if cve in dev_targets else "test") for cve in targets}
    assignments.update({cve: "test" for cve in distractors})
    assignments.update({cve: "test" for cve, _, _ in UNANSWERABLE_CHECKS})
    cwe_docs = {record["doc_id"]: record for record in records if record["doc_type"] == "cwe"}
    questions: list[dict[str, Any]] = []

    for cve in targets:
        record = by_id[cve]
        split = assignments[cve]
        if record.get("products"):
            product = _product_name(record)
            questions.append(_question("existence", f"Is {product} affected by {cve}?", cve, "yes", [cve], record["group"], split, lines))
        cwes = sorted({cwe for cwe in record.get("cwe_ids", []) if cwe not in IGNORED_CWES})
        if cwes:
            evidence = [cve] + [cwe for cwe in cwes if cwe in cwe_docs]
            cwes = [cwe for cwe in cwes if cwe in cwe_docs]
            if not cwes:
                continue
            questions.append(_question("cwe", f"Which weakness class (CWE) is {cve} classified as?", cve, cwes, evidence, record["group"], split, lines))
        if record.get("cvss_score") is not None:
            answer = f"{record['cvss_score']} (CVSS {record['cvss_version']})"
            questions.append(_question("cvss", f"What is the CVSS base score of {cve}?", cve, answer, [cve], record["group"], split, lines))
        questions.append(_question("kev", f"Is {cve} listed in the CISA Known Exploited Vulnerabilities catalog?", cve, "yes" if record["known_exploited"] else "no", [cve], record["group"], split, lines))

    for cve in distractors:
        record = by_id[cve]
        if record.get("products"):
            product = _product_name(record)
            questions.append(_question("distractor_existence", f"Is {product} affected by {cve}?", cve, "yes", [cve], record["group"], "test", lines))
        questions.append(_question("kev", f"Is {cve} listed in the CISA Known Exploited Vulnerabilities catalog?", cve, "no", [cve], record["group"], "test", lines))

    for cve, vendor, product in UNANSWERABLE_CHECKS:
        if cve in by_id:
            raise ValueError(f"unanswerable ID is present in corpus: {cve}")
        questions.append(_question("unanswerable", f"Is {vendor} {product} affected by {cve}?", cve, "insufficient evidence", [], "unanswerable", "test", lines))

    for index, question in enumerate(questions, 1):
        question["question_id"] = f"Q-{index:04d}"
    split_info = {
        "seed": SPLIT_SEED,
        "assignments": assignments,
        "counts_by_split": dict(sorted(Counter(q["split"] for q in questions).items())),
        "counts_by_question_type": dict(sorted(Counter(q["question_type"] for q in questions).items())),
        "nvd_checks": [{"cve": cve, "nvd_present": True, "corpus_present": False} for cve, _, _ in UNANSWERABLE_CHECKS],
    }
    return questions, split_info


def validate_questions(questions: list[dict[str, Any]], corpus_path: Path) -> list[str]:
    records, lines = _read_jsonl(corpus_path)
    by_id = {record["doc_id"]: record for record in records}
    failures: list[str] = []
    for question in questions:
        answer = question["gold_answer"]
        answer_text = " ".join(answer) if isinstance(answer, list) else str(answer)
        if re.search(rf"(?<!\w){re.escape(answer_text.lower())}(?!\w)", question["question"].lower()):
            failures.append(f"{question['question_id']}: gold answer leaked")
        if question["question_type"] == "cwe" and any(cwe in question["question"] for cwe in answer):
            failures.append(f"{question['question_id']}: CWE leaked")
        for evidence in question["gold_evidence_ids"]:
            if evidence not in by_id:
                failures.append(f"{question['question_id']}: missing evidence {evidence}")
        if question["question_type"] == "unanswerable" and question["target_cve"] in by_id:
            failures.append(f"{question['question_id']}: unanswerable ID is present")
        expected = _source_hash(question["gold_evidence_ids"], lines) if question["gold_evidence_ids"] else ""
        if expected != question["source_hash"]:
            failures.append(f"{question['question_id']}: source hash mismatch")
    by_target: dict[str, set[str]] = {}
    for question in questions:
        if question["target_cve"]:
            by_target.setdefault(question["target_cve"], set()).add(question["split"])
    failures.extend(f"{target}: split leakage" for target, splits in by_target.items() if len(splits) > 1)
    return failures


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    questions, split_info = generate_questions(root / "data/kb/documents.jsonl", root / "data/kb_seed_cves.txt", root / "data/kb_seed_distractors.txt")
    failures = validate_questions(questions, root / "data/kb/documents.jsonl")
    if failures:
        raise RuntimeError("leakage checks failed:\n" + "\n".join(failures))
    eval_dir = root / "data/eval"
    eval_dir.mkdir(exist_ok=True)
    (root / "data/eval_questions.jsonl").write_text("\n".join(json.dumps(q, separators=(",", ":"), ensure_ascii=False) for q in questions) + "\n", encoding="utf-8")
    (root / "data/eval_split.json").write_text(json.dumps(split_info, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"counts_by_split": split_info["counts_by_split"], "counts_by_question_type": split_info["counts_by_question_type"], "seed": SPLIT_SEED, "leakage_failures": 0}, indent=2))


if __name__ == "__main__":
    main()
