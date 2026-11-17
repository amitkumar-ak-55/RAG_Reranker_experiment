"""Build and validate the hand-verified hard evaluation set."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

CORPUS_SHA256 = "8c4daa39da534a7f4871f4e4f4d72af03bf8fd3ce5b34e5dac586e11e585f6fc"
BROAD_CONFUSER_CWES = {"CWE-20", "CWE-89", "CWE-78", "CWE-502"}

PRODUCT_OVERRIDES = {
    "CVE-2015-5254": "cpe:2.3:a:apache:activemq:5.0.0:*:*:*:*:*:*:*",
    "CVE-2016-3081": "cpe:2.3:a:apache:struts:2.3.19:*:*:*:*:*:*",
    "CVE-2016-4437": "cpe:2.3:a:apache:shiro:*:*:*:*:*:*:*:*",
}

PRODUCT_LABELS = {
    "CVE-2021-44228": "Apache Log4j",
    "CVE-2024-39907": "1Panel",
    "CVE-2015-5254": "Apache ActiveMQ",
    "CVE-2026-34197": "Apache ActiveMQ",
    "CVE-2016-1897": "FFmpeg",
    "CVE-2016-3081": "Apache Struts",
    "CVE-2016-3088": "Apache ActiveMQ",
    "CVE-2016-3714": "ImageMagick",
    "CVE-2016-4437": "Apache Shiro",
    "CVE-2016-4977": "Spring Security OAuth",
    "CVE-2016-10033": "PHPMailer",
    "CVE-2016-10134": "Zabbix",
    "CVE-2017-2824": "Zabbix",
    "CVE-2017-3066": "Adobe ColdFusion",
    "CVE-2017-6920": "Drupal",
    "CVE-2017-7494": "Samba",
    "CVE-2017-7504": "JBossMQ",
    "CVE-2017-7525": "jackson-databind",
    "CVE-2017-8917": "Joomla",
    "CVE-2017-9791": "Apache Struts",
    "CVE-2017-12629": "Apache Solr",
    "CVE-2017-12635": "Apache CouchDB",
    "CVE-2017-12794": "Django",
    "CVE-2017-16082": "node-postgres",
    "CVE-2017-17405": "Ruby Net::FTP",
}

HAND_SET = [
    ("CVE-2021-44228", "In Apache Log4j, attacker-controlled log content can trigger a directory lookup and load code from a remote server. Which CVE describes this?", "CWE-502", "JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints."),
    ("CVE-2024-39907", "In 1Panel, insufficiently filtered SQL injection can write arbitrary files and ultimately lead to code execution. Which CVE describes this?", "CWE-89", "There are many sql injections in the project, and some of them are not well filtered, leading to arbitrary file writes, and ultimately leading to RCEs."),
    ("CVE-2015-5254", "In Apache ActiveMQ, serialized message objects are accepted without restricting their classes, allowing code execution. Which CVE describes this?", "CWE-20", "does not restrict the classes that can be serialized in the broker, which allows remote attackers to execute arbitrary code"),
    ("CVE-2026-34197", "In Apache ActiveMQ, an authenticated console request can make the management bridge load a Spring XML context and invoke code during bean setup. Which CVE describes this?", "CWE-94", "arbitrary code execution occurs on the broker's JVM through bean factory methods such as Runtime.exec()."),
    ("CVE-2016-1897", "In FFmpeg, an HLS playlist can make a remote request carry data from a local file. Which CVE describes this?", "CWE-200", "allows remote attackers to conduct cross-origin attacks and read arbitrary files"),
    ("CVE-2016-3081", "In Apache Struts, Dynamic Method Invocation lets a method-prefixed request reach chained expressions and code execution. Which CVE describes this?", "CWE-77", "allow remote attackers to execute arbitrary code via method: prefix, related to chained expressions."),
    ("CVE-2016-3088", "In Apache ActiveMQ, an HTTP upload followed by a move request can leave a remote file executable. Which CVE describes this?", "CWE-434", "allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request."),
    ("CVE-2016-3714", "In ImageMagick, specially prepared picture content can cause command execution through shell syntax. Which CVE describes this?", "CWE-20", "allow remote attackers to execute arbitrary code via shell metacharacters in a crafted image"),
    ("CVE-2016-4437", "In Apache Shiro, leaving the cipher key unset for remember-me can permit code execution or an access-control bypass. Which CVE describes this?", "CWE-321", "allows remote attackers to execute arbitrary code or bypass intended access restrictions via an unspecified request parameter."),
    ("CVE-2016-4977", "In Spring Security OAuth, a crafted response_type value is evaluated as Spring SpEL and can trigger remote code execution. Which CVE describes this?", "CWE-19", "the response_type parameter value was executed as Spring SpEL which enabled a malicious user to trigger remote code execution"),
    ("CVE-2016-10033", "In PHPMailer, a crafted Sender value can add options to the mail command and execute code. Which CVE describes this?", "CWE-88", "might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code"),
    ("CVE-2016-10134", "In Zabbix, the toggle_ids array parameter can be used to inject SQL commands. Which CVE describes this?", "CWE-89", "SQL injection vulnerability in Zabbix"),
    ("CVE-2017-2824", "In Zabbix, packets sent through an active proxy can reach trapper command handling and cause command injection. Which CVE describes this?", "CWE-78", "A specially crafted set of packets can cause a command injection resulting in remote code execution."),
    ("CVE-2017-3066", "In Adobe ColdFusion, unsafe Java deserialization in its BlazeDS library can lead to code execution. Which CVE describes this?", "CWE-502", "have a Java deserialization vulnerability in the Apache BlazeDS library. Successful exploitation could lead to arbitrary code execution."),
    ("CVE-2017-6920", "In Drupal, unsafe PHP-object handling by the PECL YAML parser can let a remote attacker execute code. Which CVE describes this?", "CWE-19", "allows remote attackers to execute arbitrary code due to the PECL YAML parser not handling PHP objects safely"),
    ("CVE-2017-7494", "In Samba, a client can place a library in a writable share and then induce the server to load that library as code. Which CVE describes this?", "CWE-94", "allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it."),
    ("CVE-2017-7504", "In JBossMQ, a messaging endpoint rebuilds attacker-chosen classes from incoming data without an allowlist, leading to execution on the server. Which CVE describes this?", "CWE-502", "does not restrict the classes for which it performs deserialization, which allows remote attackers to execute arbitrary code"),
    ("CVE-2017-7525", "In jackson-databind, malicious input sent to ObjectMapper can let an unauthenticated user execute code. Which CVE describes this?", "CWE-502", "A deserialization flaw was discovered in the jackson-databind"),
    ("CVE-2017-8917", "In Joomla, request handling lets an attacker inject database syntax and issue arbitrary SQL statements. Which CVE describes this?", "CWE-89", "SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands"),
    ("CVE-2017-9791", "In Apache Struts, the Struts 1 plugin can pass a malicious field in ActionMessage to remote code execution. Which CVE describes this?", "CWE-20", "The Struts 1 plugin in Apache Struts 2.1.x and 2.3.x might allow remote code execution via a malicious field value"),
    ("CVE-2017-12629", "In Apache Solr, XML query parsing can expand external entities and read local files through an FTP wrapper. Which CVE describes this?", "CWE-611", "the XML external entity expansion vulnerability occurs in the XML Query Parser"),
    ("CVE-2017-12635", "In Apache CouchDB, duplicate role fields can let a non-admin user grant itself administrator privileges. Which CVE describes this?", "CWE-269", "The vulnerability allows non-admin users to give themselves admin privileges."),
    ("CVE-2017-12794", "In Django, the technical 500 debug page disables HTML autoescaping, allowing cross-site scripting. Which CVE describes this?", "CWE-79", "HTML autoescaping was disabled in a portion of the template for the technical 500 debug page."),
    ("CVE-2017-16082", "In node-postgres, a malicious column name supplied by a query or database can cause code execution. Which CVE describes this?", "CWE-94", "A remote code execution vulnerability was found within the pg module when the remote database or query specifies a specially crafted column name."),
    ("CVE-2017-17405", "In Ruby Net::FTP, a pipe-prefixed localfile makes the following command execute. Which CVE describes this?", "CWE-78", "If the localfile argument starts with the \"|\" pipe character, the command following the pipe character is executed."),
]


def _read_corpus(path: Path) -> dict[str, dict[str, Any]]:
    return {
        record["doc_id"]: record
        for record in (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    }


def _product(record: dict[str, Any]) -> str:
    return next((cpe for cpe in record.get("products", []) if cpe.startswith("cpe:2.3:a:")), record.get("products", [""])[0])


def _product_component(cpe: str) -> str:
    fields = cpe.split(":")
    return fields[4].replace("\\!", "!").replace("_", " ") if len(fields) > 4 else ""


def _seed_distractors() -> set[str]:
    path = Path(__file__).resolve().parents[1] / "data/kb_seed_distractors.txt"
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}


def _vendor_product_pairs(record: dict[str, Any]) -> set[tuple[str, str]]:
    pairs = set()
    for cpe in record.get("products", []):
        fields = cpe.split(":")
        if len(fields) > 4 and fields[0:3] == ["cpe", "2.3", "a"]:
            pairs.add((fields[3], fields[4]))
    return pairs


def _confuser_attributes(target: dict[str, Any], other: dict[str, Any]) -> list[str]:
    attrs = []
    shared_cwes = sorted(set(target.get("cwe_ids", [])).intersection(other.get("cwe_ids", [])))
    if shared_cwes:
        attrs.append("CWE " + ", ".join(shared_cwes))
    if _vendor_product_pairs(target).intersection(_vendor_product_pairs(other)):
        attrs.append("same CPE vendor+product")
    return attrs


def _confusers(target: dict[str, Any], records: dict[str, dict[str, Any]]) -> list[str]:
    target_cwes = set(target.get("cwe_ids", []))
    target_products = _vendor_product_pairs(target)
    excluded = _seed_distractors()
    matches = [
        (
            0 if target_products.intersection(_vendor_product_pairs(r)) else 1,
            r["doc_id"],
        )
        for r in records.values()
        if r["doc_type"] == "cve"
        and r.get("group") in ("positive", "kev")
        and r["doc_id"] != target["doc_id"]
        and r["doc_id"] not in excluded
        and (target_cwes.intersection(r.get("cwe_ids", [])) or target_products.intersection(_vendor_product_pairs(r)))
    ]
    return [doc_id for _, doc_id in sorted(matches)[:2]]


def _confuser_is_weak(target: dict[str, Any], other: dict[str, Any]) -> bool:
    shared_cwes = set(target.get("cwe_ids", [])).intersection(other.get("cwe_ids", []))
    return bool(shared_cwes) and shared_cwes.issubset(BROAD_CONFUSER_CWES) and not _vendor_product_pairs(target).intersection(_vendor_product_pairs(other))


def _normal_words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _six_word_overlap_count(question: str, source: str) -> int:
    qwords = _normal_words(question)
    swords = _normal_words(source)
    source_runs = {tuple(swords[index:index + 6]) for index in range(len(swords) - 5)}
    return sum(tuple(qwords[index:index + 6]) in source_runs for index in range(len(qwords) - 5))


def _has_six_word_run(question: str, source: str) -> bool:
    return _six_word_overlap_count(question, source) > 0


def proof_rows(questions: list[dict[str, Any]], corpus_path: Path) -> list[dict[str, Any]]:
    records = _read_corpus(corpus_path)
    rows = []
    for question in questions:
        answer = question["gold_answer"]
        record = records[answer]
        cpe = question["product"]
        note = question["verification_note"]
        quoted_note = note[1:-1] if note.startswith('"') and note.endswith('"') else note
        rows.append({
            "question_id": question["question_id"],
            "gold_cve": answer,
            "six_word_overlap_count": _six_word_overlap_count(question["question"], record["text"]),
            "gold_cve_in_question": answer in question["question"],
            "cpe_in_question": cpe in question["question"],
            "cwe_in_question": question["target_cwe_class"] in question["question"],
            "verification_note_is_substring": quoted_note in record["text"],
            "confusers": [
                {
                    "cve": confuser,
                    "shared_cwe_ids": sorted(set(record.get("cwe_ids", [])).intersection(records[confuser].get("cwe_ids", []))),
                    "shared_cpe_vendor_product": [
                        list(pair)
                        for pair in sorted(_vendor_product_pairs(record).intersection(_vendor_product_pairs(records[confuser])))
                    ],
                }
                for confuser in question["confusers"]
            ],
        })
    return rows


def validate_hard_questions(questions: list[dict[str, Any]], corpus_path: Path) -> list[str]:
    records = _read_corpus(corpus_path)
    failures: list[str] = []
    if len(questions) != 25:
        failures.append(f"expected 25 questions, got {len(questions)}")
    if len({q.get("target_cwe_class") for q in questions}) < 10:
        failures.append("fewer than 10 CWE classes")
    if len({q.get("product") for q in questions}) < 15:
        failures.append("fewer than 15 products")
    for q in questions:
        target_id = q.get("gold_answer")
        record = records.get(target_id)
        if not record or record.get("doc_type") != "cve":
            failures.append(f"{q.get('question_id')}: gold evidence is not a corpus CVE")
            continue
        if record.get("group") not in ("positive", "kev"):
            failures.append(f"{q.get('question_id')}: target is not positive or KEV")
        if q.get("target_cwe_class") not in record.get("cwe_ids", []):
            failures.append(f"{q.get('question_id')}: target CWE is not in record")
        if target_id in q.get("question", ""):
            failures.append(f"{q.get('question_id')}: CVE ID leaked")
        if q.get("target_cwe_class") in q.get("question", ""):
            failures.append(f"{q.get('question_id')}: CWE leaked")
        if any(product and product in q.get("question", "") for product in record.get("products", [])):
            failures.append(f"{q.get('question_id')}: product leaked")
        if PRODUCT_LABELS.get(target_id, "").lower() not in q.get("question", "").lower():
            failures.append(f"{q.get('question_id')}: product is not identified in question")
        if _has_six_word_run(q.get("question", ""), record.get("text", "")):
            failures.append(f"{q.get('question_id')}: six-word record run leaked")
        if _has_six_word_run(q.get("question", ""), q.get("verification_note", "")):
            failures.append(f"{q.get('question_id')}: six-word note run leaked")
        note = q.get("verification_note", "")
        quoted = note[1:-1] if note.startswith('"') and note.endswith('"') else note
        if quoted not in record.get("text", ""):
            failures.append(f"{q.get('question_id')}: verification quote absent")
        if q.get("gold_evidence_ids") != [target_id]:
            failures.append(f"{q.get('question_id')}: evidence must contain only gold CVE")
        if q.get("answerable") is not True or q.get("question_type") != "behaviour":
            failures.append(f"{q.get('question_id')}: invalid answerability/type")
        if q.get("corpus_sha256") != CORPUS_SHA256:
            failures.append(f"{q.get('question_id')}: corpus hash mismatch")
        for confuser in q.get("confusers", []):
            other = records.get(confuser)
            if not other or other.get("doc_type") != "cve" or other.get("group") not in ("positive", "kev"):
                failures.append(f"{q.get('question_id')}: invalid confuser {confuser}")
            elif confuser == target_id or confuser in _seed_distractors():
                failures.append(f"{q.get('question_id')}: prohibited confuser {confuser}")
            elif not _confuser_attributes(record, other):
                failures.append(f"{q.get('question_id')}: unrelated confuser {confuser}")
    return failures


def build_questions(corpus_path: Path) -> list[dict[str, Any]]:
    actual = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    if actual != CORPUS_SHA256:
        raise RuntimeError(f"corpus hash mismatch: expected {CORPUS_SHA256}, got {actual}")
    records = _read_corpus(corpus_path)
    questions = []
    for index, (cve, question, cwe, quote) in enumerate(HAND_SET, 1):
        record = records[cve]
        confusers = _confusers(record, records)
        questions.append({
            "question_id": f"H-{index:03d}",
            "question_type": "behaviour",
            "question": question,
            "gold_answer": cve,
            "gold_evidence_ids": [cve],
            "answerable": True,
            "target_cwe_class": cwe,
            "product": PRODUCT_OVERRIDES.get(cve, _product(record)),
            "group": record["group"],
            "confusers": confusers,
            "confuser_weak": (
                any(_confuser_is_weak(record, records[confuser]) for confuser in confusers)
                and not any(
                    _vendor_product_pairs(record).intersection(_vendor_product_pairs(records[confuser]))
                    for confuser in confusers
                )
            ),
            "verification_note": f'"{quote}"',
            "corpus_sha256": CORPUS_SHA256,
        })
    failures = validate_hard_questions(questions, corpus_path)
    if failures:
        raise RuntimeError("hard-set checks failed:\n" + "\n".join(failures))
    return questions


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    questions = build_questions(root / "data/kb/documents.jsonl")
    if "--proof" in __import__("sys").argv:
        for row in proof_rows(questions, root / "data/kb/documents.jsonl"):
            print(json.dumps(row, separators=(",", ":"), ensure_ascii=False))
        return
    output = root / "data/eval_hard.jsonl"
    output.write_text("\n".join(json.dumps(q, separators=(",", ":"), ensure_ascii=False) for q in questions) + "\n", encoding="utf-8")
    print(json.dumps({"questions": len(questions), "cwe_classes": len({q["target_cwe_class"] for q in questions}), "products": len({q["product"] for q in questions}), "checks_failed": 0}, indent=2))


if __name__ == "__main__":
    main()
