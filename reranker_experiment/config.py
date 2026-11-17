from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class ExperimentSettings:
    jina_api_key_1: str = os.getenv("JINA_API_KEY_1", "")
    jina_api_key_2: str = os.getenv("JINA_API_KEY_2", "")
    jina_base_url: str = os.getenv("JINA_BASE_URL", "")
    jina_reranker_model: str = os.getenv("JINA_RERANKER_MODEL", "")
    jev_api_key: str = os.getenv("JEV_API_KEY", "")
    jev_base_url: str = os.getenv("JEV_BASE_URL", "")
    jev_model: str = os.getenv("JEV_MODEL", "")
    answer_model: str = os.getenv("ANSWER_MODEL", "")
    answer_max_tokens: int = int(os.getenv("ANSWER_MAX_TOKENS", "32"))
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "")
    embedding_revision: str = os.getenv("EMBEDDING_REVISION", "")
    timeout_seconds: float = float(os.getenv("JINA_RERANK_TIMEOUT_SECONDS", "30"))
    candidate_limit: int = int(os.getenv("JINA_RERANK_CANDIDATE_LIMIT", "20"))
    result_limit: int = int(os.getenv("JINA_RERANK_RESULT_LIMIT", "5"))

    @property
    def api_keys(self) -> tuple[str, ...]:
        return tuple(key for key in (self.jina_api_key_1, self.jina_api_key_2) if key)

    def masked_snapshot(self) -> dict[str, object]:
        data = asdict(self)
        for field in ("jina_api_key_1", "jina_api_key_2", "jev_api_key"):
            value = str(data[field])
            data[field] = ("*" * max(0, len(value) - 4) + value[-4:]) if value else ""
        data["configured_key_slots"] = [index + 1 for index, key in enumerate((self.jina_api_key_1, self.jina_api_key_2)) if key]
        return data


settings = ExperimentSettings()

