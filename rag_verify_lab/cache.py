from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .config import ROOT

CACHE_DIR = ROOT / "data" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def cache_key(model: str, prompt: str, input_data: Any) -> str:
    raw = json.dumps([model, prompt, input_data], sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def get(model: str, prompt: str, input_data: Any) -> Any | None:
    path = CACHE_DIR / f"{cache_key(model, prompt, input_data)}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def put(model: str, prompt: str, input_data: Any, value: Any) -> None:
    path = CACHE_DIR / f"{cache_key(model, prompt, input_data)}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
