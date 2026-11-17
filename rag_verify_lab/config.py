from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_base_url: str = os.getenv("GEMINI_BASE_URL", "")
    groq_api_key_1: str = os.getenv("GROQ_API_KEY_1", "")
    groq_api_key_2: str = os.getenv("GROQ_API_KEY_2", "")
    groq_api_key_3: str = os.getenv("GROQ_API_KEY_3", "")
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_base_url: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    answer_model: str = os.getenv("ANSWER_MODEL", "")
    answer_max_tokens: int = int(os.getenv("ANSWER_MAX_TOKENS", "32"))
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "")
    embedding_revision: str = os.getenv("EMBEDDING_REVISION", "")
    embedding_device: str = os.getenv("EMBEDDING_DEVICE", "auto")
    embedding_batch_size: int = int(os.getenv("EMBEDDING_BATCH_SIZE", "32"))
    rerank_model: str = os.getenv("RERANK_MODEL", "")
    rerank_revision: str = os.getenv("RERANK_REVISION", "")
    rerank_device: str = os.getenv("RERANK_DEVICE", "auto")
    rerank_fallback_model: str = os.getenv("RERANK_FALLBACK_MODEL", "BAAI/bge-reranker-base")
    rerank_fallback_revision: str = os.getenv("RERANK_FALLBACK_REVISION", "")
    jev_api_key: str = os.getenv("JEV_API_KEY", "")
    jev_base_url: str = os.getenv("JEV_BASE_URL", "")
    jev_model: str = os.getenv("JEV_MODEL", "")
    price_answer_in_per_m: str = os.getenv("PRICE_ANSWER_IN_PER_M", "")
    price_answer_out_per_m: str = os.getenv("PRICE_ANSWER_OUT_PER_M", "")
    price_embed_per_m: str = os.getenv("PRICE_EMBED_PER_M", "")
    price_jev_per_call: str = os.getenv("PRICE_JEV_PER_CALL", "")
    jev_candidate_limit: int = int(os.getenv("JEV_CANDIDATE_LIMIT", "20"))
    job_timeout_seconds: int = int(os.getenv("JOB_TIMEOUT_SECONDS", "600"))
    container_wait_seconds: int = int(os.getenv("CONTAINER_WAIT_SECONDS", "120"))
    sweep_cooldown_seconds: int = int(os.getenv("SWEEP_COOLDOWN_SECONDS", "10"))

    def snapshot(self) -> dict[str, object]:
        data = asdict(self)
        secret_fields = {
            "gemini_api_key", "groq_api_key_1", "groq_api_key_2",
            "groq_api_key_3", "groq_api_key", "jev_api_key",
        }
        for key in secret_fields:
            value = str(data[key])
            data[key] = ("*" * max(0, len(value) - 4) + value[-4:]) if value else ""
        return data

    @property
    def answer_api_key(self) -> str:
        return self.answer_api_keys[0] if self.answer_api_keys else ""

    @property
    def answer_api_keys(self) -> tuple[str, ...]:
        configured = (
            self.groq_api_key_1,
            self.groq_api_key_2,
            self.groq_api_key_3,
        )
        keys = tuple(key for key in configured if key)
        if keys:
            return keys
        return (self.groq_api_key,) if self.groq_api_key else ((self.gemini_api_key,) if self.gemini_api_key else ())

    @property
    def answer_base_url(self) -> str:
        return self.groq_base_url if self.answer_api_keys and self.answer_api_keys[0] != self.gemini_api_key else self.gemini_base_url

settings = Settings()
