from __future__ import annotations

import json
from typing import Any

from .db import Question, db_session


def export_jsonl() -> str:
    with db_session() as db:
        return "\n".join(json.dumps({"id": q.id, "text": q.text, "gold_answer": q.gold_answer, "answerable": q.answerable, "vm_id": q.vm_id, "gold_finding_ids": json.loads(q.gold_finding_ids)}) for q in db.query(Question).all())


def import_jsonl(text: str) -> int:
    count = 0
    with db_session() as db:
        for line in text.splitlines():
            if not line.strip():
                continue
            data: dict[str, Any] = json.loads(line)
            db.add(Question(text=data["text"], gold_answer=data.get("gold_answer", ""), answerable=bool(data.get("answerable", True)), vm_id=data.get("vm_id"), gold_finding_ids=json.dumps(data.get("gold_finding_ids", []))))
            count += 1
        db.commit()
    return count
