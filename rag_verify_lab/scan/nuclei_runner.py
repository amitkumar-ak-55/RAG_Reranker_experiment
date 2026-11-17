from __future__ import annotations

import json
import subprocess
import tempfile
from .nmap_runner import PUBLIC_TARGET, validate_target
from .normalize import FindingData


def parse_nuclei_jsonl(text: str) -> list[FindingData]:
    findings = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        info = item.get("info", {})
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or classification.get("cve_ids") or []
        cve = cves[0] if isinstance(cves, list) and cves else (cves or None)
        findings.append(FindingData("nuclei", item.get("host") or item.get("matched-at", ""), None, "", item.get("matched-at", ""), cve, info.get("name", item.get("template-id", "")), info.get("severity", ""), info.get("description", ""), item))
    return findings


def run_nuclei(target: str) -> list[FindingData]:
    validate_target(target)
    if target.strip().lower().rstrip(".") == PUBLIC_TARGET:
        return []
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as handle:
        output = Path(handle.name)
    try:
        subprocess.run(["nuclei", "-target", target, "-jsonl", "-o", str(output)], check=True, capture_output=True, text=True, timeout=600)
        return parse_nuclei_jsonl(output.read_text(encoding="utf-8"))
    finally:
        output.unlink(missing_ok=True)
