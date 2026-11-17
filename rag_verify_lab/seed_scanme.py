from __future__ import annotations

import json

from .db import Finding, Question, VM, db_session, init_db

QUESTION_TEXT = "Which network services are exposed on this host?"


def seed() -> int | None:
    init_db()
    with db_session() as db:
        vm = db.query(VM).filter(VM.name == "scanme.nmap.org").first()
        if not vm:
            print("scanme.nmap.org VM does not exist; run the scan first.")
            return None
        findings = (
            db.query(Finding)
            .filter(Finding.vm_id == vm.id, Finding.scanner == "nmap", Finding.port.isnot(None))
            .order_by(Finding.id)
            .all()
        )
        if not findings:
            print("scanme.nmap.org VM has no Nmap findings; run the scan first.")
            return None
        existing = db.query(Question).filter(Question.text == QUESTION_TEXT).first()
        if existing:
            evidence_ids = json.loads(existing.gold_finding_ids or "[]")
            print(f"Question ID: {existing.id}")
            print(f"Gold evidence IDs: {evidence_ids}")
            return existing.id
        evidence_ids = [finding.id for finding in findings]
        question = Question(
            text=QUESTION_TEXT,
            vm_id=vm.id,
            answerable=True,
            gold_finding_ids=json.dumps(evidence_ids),
        )
        db.add(question)
        db.commit()
        db.refresh(question)
        print(f"Question ID: {question.id}")
        print(f"Gold evidence IDs: {evidence_ids}")
        return question.id


if __name__ == "__main__":
    seed()
