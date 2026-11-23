from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CVE_RE = re.compile(r"\bCVE[-\s_\u2010-\u2015]?(\d{4})[-\s_\u2010-\u2015]?(\d{4,})\b", re.IGNORECASE)


def normalize_cve(value: object) -> str | None:
    match = CVE_RE.fullmatch(str(value or "").strip())
    return f"CVE-{match.group(1)}-{match.group(2)}" if match else None


def extract_cves(text: str) -> list[str]:
    result: list[str] = []
    for match in CVE_RE.finditer(text or ""):
        value = f"CVE-{match.group(1)}-{match.group(2)}"
        if value not in result:
            result.append(value)
    return result


def document_cves(document: dict[str, Any]) -> tuple[list[str], str]:
    for field in ("cve_ids", "cves"):
        values = document.get(field)
        if isinstance(values, list):
            normalized = [value for value in (normalize_cve(item) for item in values) if value]
            if normalized:
                return list(dict.fromkeys(normalized)), "structured"
    for field in ("cve_id", "doc_id"):
        value = normalize_cve(document.get(field))
        if value:
            return [value], "structured"
    text = " ".join(str(document.get(field, "")) for field in ("title", "text", "description"))
    return extract_cves(text), "text_fallback"


@dataclass(frozen=True)
class GoldMapping:
    question_id: str
    gold_cve: str | None
    kb_chunk_count: int
    candidate_match_count: int
    unique_match_count: int
    status: str
    matching_method: str


def map_gold(question: dict[str, Any], documents: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> GoldMapping:
    question_id = str(question.get("question_id", ""))
    gold = normalize_cve(question.get("gold_cve"))
    if not gold:
        return GoldMapping(question_id, None, 0, 0, 0, "invalid_gold_cve", "none")
    all_matches = [document for document in documents if gold in document_cves(document)[0]]
    candidate_matches = [document for document in candidates if gold in document_cves(document)[0]]
    methods = {document_cves(document)[1] for document in candidate_matches}
    status = "in_candidate_pool" if candidate_matches else ("present_in_kb_not_retrieved" if all_matches else "absent_from_kb")
    return GoldMapping(
        question_id,
        gold,
        len(all_matches),
        len(candidate_matches),
        len({str(document.get("doc_id", "")) for document in candidate_matches}),
        status,
        ",".join(sorted(methods)) if methods else "none",
    )

