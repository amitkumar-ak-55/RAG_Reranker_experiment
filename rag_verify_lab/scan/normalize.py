from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class FindingData:
    scanner: str
    ip: str
    port: int | None
    protocol: str
    service: str
    cve_id: str | None
    title: str
    severity: str
    description: str
    raw_json: dict[str, Any]
    vm_id: int | None = None
    run_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
