from __future__ import annotations

from dataclasses import dataclass
import logging

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

JEV_CONTRACT = {
    "path": "/v1/systemone",
    "request": {"required": ["model", "state", "questions"], "question_types": ["choice", "noul"]},
    "response": {"required": ["model", "answers", "usage"], "answer_fields": ["choice", "noul"]},
}


@dataclass
class Judgment:
    label: str
    citation_correct: bool


@dataclass
class Relevance:
    relevant: bool
    score: float


@dataclass
class CandidateSelection:
    cve_id: str


def jev_url() -> str:
    return f"{settings.jev_base_url.rstrip('/')}{JEV_CONTRACT['path']}"


def _failure_detail(response: httpx.Response) -> str:
    body = response.text[:300].replace(settings.jev_api_key, "[REDACTED]")
    return f"JEV request failed: {jev_url()} status={response.status_code} body={body}"


class JEVClient:
    def __init__(self) -> None:
        self.configured = bool(settings.jev_api_key and settings.jev_base_url and settings.jev_model)

    def judge(self, claim: str, evidence: list[str], question: str | None = None) -> Judgment:
        if not self.configured:
            raise RuntimeError("JEV is not configured")
        support_instructions = (
            "Judge whether the candidate answer correctly answers the question using the evidence. "
            "Return SUPPORTED only when the evidence supports the candidate answer and identifies "
            "the vulnerability asked about, including the relevant product and behavior. "
            "Return UNSUPPORTED when the evidence is missing or insufficient. Return CONTRADICTED "
            "when the evidence identifies a different vulnerability, product, or behavior. "
            "Do not treat a merely related vulnerability as the answer."
            if question is not None
            else "Judge whether the evidence supports the claim. Return SUPPORTED only when the evidence "
            "supports it, UNSUPPORTED when the evidence is insufficient, or CONTRADICTED when the "
            "evidence contradicts it."
        )
        citation_instructions = (
            "Score 1 only if the cited evidence directly supports the candidate answer as the answer "
            "to the question; otherwise score 0."
            if question is not None
            else "The evidence correctly supports the claim's citation."
        )
        state: dict[str, object] = {"claim": claim, "evidence": evidence}
        if question is not None:
            state["question"] = question
        payload = {
            "model": settings.jev_model,
            "state": state,
            "questions": {
                "support": {
                    "type": "choice",
                    "instructions": support_instructions,
                    "criteria": {
                        "SUPPORTED": "The evidence supports this candidate and shows it answers the question.",
                        "UNSUPPORTED": "The evidence is insufficient to show that this candidate answers the question.",
                        "CONTRADICTED": "The evidence points to a different vulnerability or conflicts with the candidate.",
                    },
                },
                "citation": {
                    "type": "noul",
                    "instructions": citation_instructions,
                },
            },
        }
        try:
            response = httpx.post(
                jev_url(),
                headers={"Authorization": "Bearer " + settings.jev_api_key, "Content-Type": "application/json"},
                json=payload,
                timeout=60,
            )
        except httpx.HTTPError as exc:
            detail = f"JEV request failed: {jev_url()} error={exc}"
            logger.error(detail)
            raise RuntimeError(detail) from exc
        if getattr(response, "status_code", 200) >= 400:
            detail = _failure_detail(response)
            logger.error(detail)
            raise RuntimeError(detail)
        try:
            answers = response.json()["answers"]
            return Judgment(str(answers["support"]["choice"]), float(answers["citation"]["noul"]) >= 0.5)
        except (KeyError, TypeError, ValueError) as exc:
            detail = _failure_detail(response)
            logger.error(detail)
            raise RuntimeError(detail) from exc

    def select_candidate(self, question: str, candidates: list[dict[str, str]]) -> CandidateSelection:
        """Select the one evidence-backed CVE that answers a question."""
        if not self.configured:
            raise RuntimeError("JEV is not configured")
        criteria = {
            candidate["cve_id"]: (
                f"CVE: {candidate['cve_id']}\n"
                f"Title: {candidate.get('title', '')}\n"
                f"Description: {candidate.get('description', '')}"
            )
            for candidate in candidates
            if candidate.get("cve_id")
        }
        if not criteria:
            raise RuntimeError("JEV candidate selection requires at least one CVE evidence record")
        payload = {
            "model": settings.jev_model,
            "state": {
                "claim": question,
                "evidence": list(criteria.values()),
            },
            "questions": {
                "select": {
                    "type": "choice",
                    "instructions": (
                        "Select the one candidate CVE whose evidence directly answers the question. "
                        "Use product, version, and behavior to distinguish candidates."
                    ),
                    "criteria": criteria,
                },
            },
        }
        try:
            response = httpx.post(
                jev_url(),
                headers={"Authorization": "Bearer " + settings.jev_api_key, "Content-Type": "application/json"},
                json=payload,
                timeout=60,
            )
        except httpx.HTTPError as exc:
            detail = f"JEV request failed: {jev_url()} error={exc}"
            logger.error(detail)
            raise RuntimeError(detail) from exc
        if getattr(response, "status_code", 200) >= 400:
            detail = _failure_detail(response)
            logger.error(detail)
            raise RuntimeError(detail)
        try:
            selected = str(response.json()["answers"]["select"]["choice"])
            if selected not in criteria:
                raise ValueError(f"JEV selected a CVE outside the candidate set: {selected}")
            return CandidateSelection(selected)
        except (KeyError, TypeError, ValueError) as exc:
            detail = _failure_detail(response)
            logger.error(detail)
            raise RuntimeError(detail) from exc

    def score_finding(self, question: str, finding: dict[str, object]) -> Relevance:
        if not self.configured:
            raise RuntimeError("JEV is not configured")
        evidence = (
            f"Title: {finding.get('title', '')}\n"
            f"Description: {finding.get('description', '')}\n"
            f"Severity: {finding.get('severity', '')}\n"
            f"Service: {finding.get('service', '')}\n"
            f"Port: {finding.get('port', '')}\n"
            f"CVE: {finding.get('cve_id') or 'none'}"
        )
        payload = {
            "model": settings.jev_model,
            "state": {"claim": question, "evidence": [evidence]},
            "questions": {
                "relevant": {
                    "type": "choice",
                    "instructions": "Is this finding relevant to answering the question?",
                    "criteria": {
                        "RELEVANT": "The finding is relevant to the question.",
                        "IRRELEVANT": "The finding is not relevant to the question.",
                    },
                },
                "score": {
                    "type": "noul",
                    "instructions": "Give a relevance score from 0.0 to 1.0.",
                },
            },
        }
        try:
            response = httpx.post(
                jev_url(),
                headers={"Authorization": "Bearer " + settings.jev_api_key, "Content-Type": "application/json"},
                json=payload,
                timeout=60,
            )
        except httpx.HTTPError as exc:
            detail = f"JEV request failed: {jev_url()} error={exc}"
            logger.error(detail)
            raise RuntimeError(detail) from exc
        if getattr(response, "status_code", 200) >= 400:
            detail = _failure_detail(response)
            logger.error(detail)
            raise RuntimeError(detail)
        try:
            answers = response.json()["answers"]
            relevant = str(answers["relevant"]["choice"]).upper() == "RELEVANT"
            score = max(0.0, min(1.0, float(answers["score"]["noul"])))
            return Relevance(relevant, score)
        except (KeyError, TypeError, ValueError) as exc:
            detail = _failure_detail(response)
            logger.error(detail)
            raise RuntimeError(detail) from exc
