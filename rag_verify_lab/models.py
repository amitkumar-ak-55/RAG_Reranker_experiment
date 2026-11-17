from __future__ import annotations

import hashlib
from functools import lru_cache
import argparse
from pathlib import Path
from typing import Any

import numpy as np
from huggingface_hub.constants import HF_HUB_CACHE

from .config import ROOT, settings

QUERY_PREFIX = "Represent this sentence for searching relevant passages: "
RERANK_FALLBACK_USED = False
RERANKER_USED_MODEL = ""
RERANKER_USED_REVISION = ""
RERANK_FALLBACK_REASON: str | None = None


class ModelLoadError(RuntimeError):
    """A configured local model could not be loaded."""


def validate_model_configuration() -> None:
    for label, name in (
        ("EMBEDDING_MODEL", settings.embedding_model),
        ("RERANK_MODEL", settings.rerank_model),
        ("RERANK_FALLBACK_MODEL", settings.rerank_fallback_model),
    ):
        if not name:
            raise ModelLoadError(f"{label} is not configured")
        provider = name.split("/", 1)[0].lower()
        if ":" in name or provider in {"openai", "openrouter", "anthropic", "deepseek"}:
            raise ModelLoadError(f"{label} looks like an OpenRouter-style model ID: {name}")
    if settings.rerank_model == settings.rerank_fallback_model:
        raise ModelLoadError("RERANK_MODEL and RERANK_FALLBACK_MODEL must be different")


def _device(value: str) -> str:
    if value != "auto":
        return value
    try:
        import torch
        return "cuda" if torch.cuda.is_available() else "cpu"
    except ImportError:
        return "cpu"


@lru_cache(maxsize=8)
def embedding_model(name: str, revision: str, device: str) -> Any:
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer(name, revision=revision or None, device=_device(device))
    except Exception as exc:
        raise ModelLoadError(f"embedding model {name}@{revision or 'default'} failed to load: {exc}") from exc


@lru_cache(maxsize=8)
def reranker_model(name: str, revision: str, device: str) -> Any:
    try:
        from sentence_transformers import CrossEncoder
        return CrossEncoder(name, revision=revision or None, device=_device(device))
    except Exception as exc:
        raise ModelLoadError(f"reranker model {name}@{revision or 'default'} failed to load: {exc}") from exc


def encode(texts: list[str], *, query: bool = False) -> np.ndarray:
    validate_model_configuration()
    values = [QUERY_PREFIX + text if query else text for text in texts]
    model = embedding_model(settings.embedding_model, settings.embedding_revision, settings.embedding_device)
    try:
        vectors = model.encode(
            values, batch_size=settings.embedding_batch_size, normalize_embeddings=True,
            convert_to_numpy=True, show_progress_bar=False,
        )
    except Exception as exc:
        raise ModelLoadError(f"embedding failed: {exc}") from exc
    return np.asarray(vectors, dtype=np.float32)


def rerank(query: str, texts: list[str]) -> np.ndarray:
    global RERANK_FALLBACK_USED, RERANKER_USED_MODEL, RERANKER_USED_REVISION, RERANK_FALLBACK_REASON
    validate_model_configuration()
    RERANK_FALLBACK_USED = False
    RERANKER_USED_MODEL = ""
    RERANKER_USED_REVISION = ""
    RERANK_FALLBACK_REASON = None
    try:
        model = reranker_model(settings.rerank_model, settings.rerank_revision, settings.rerank_device)
        used_model, used_revision = settings.rerank_model, settings.rerank_revision
    except ModelLoadError as primary_error:
        RERANK_FALLBACK_REASON = str(primary_error)
        if not settings.rerank_fallback_model:
            raise ModelLoadError("primary reranker failed and RERANK_FALLBACK_MODEL is blank") from primary_error
        try:
            model = reranker_model(
                settings.rerank_fallback_model,
                settings.rerank_fallback_revision,
                settings.rerank_device,
            )
        except ModelLoadError as fallback_error:
            raise ModelLoadError(
                f"primary reranker failed and fallback reranker failed: {fallback_error}"
            ) from fallback_error
        RERANK_FALLBACK_USED = True
        used_model, used_revision = settings.rerank_fallback_model, settings.rerank_fallback_revision
    RERANKER_USED_MODEL, RERANKER_USED_REVISION = used_model, used_revision
    try:
        return np.asarray(model.predict([(query, text) for text in texts]), dtype=np.float32)
    except Exception as exc:
        raise ModelLoadError(f"reranking failed: {exc}") from exc


def download_models() -> list[tuple[str, str]]:
    paths: list[tuple[str, str]] = []
    validate_model_configuration()
    embedding = embedding_model(settings.embedding_model, settings.embedding_revision, settings.embedding_device)
    reranker = reranker_model(settings.rerank_model, settings.rerank_revision, settings.rerank_device)
    fallback = reranker_model(
        settings.rerank_fallback_model,
        settings.rerank_fallback_revision,
        settings.rerank_device,
    )
    for model, name, revision in (
        (embedding, settings.embedding_model, settings.embedding_revision),
        (reranker, settings.rerank_model, settings.rerank_revision),
        (fallback, settings.rerank_fallback_model, settings.rerank_fallback_revision),
    ):
        path = str(Path(HF_HUB_CACHE) / f"models--{name.replace('/', '--')}" / "snapshots" / revision)
        paths.append((f"{name} path={path}", revision))
    return paths


def embedding_tokenizer() -> Any:
    validate_model_configuration()
    model = embedding_model(settings.embedding_model, settings.embedding_revision, settings.embedding_device)
    tokenizer = getattr(model, "tokenizer", None)
    if tokenizer is None:
        raise ModelLoadError("embedding model does not expose a tokenizer")
    return tokenizer


def reranker_manifest() -> dict[str, object]:
    return {
        "configured_model": settings.rerank_model,
        "configured_revision": settings.rerank_revision,
        "reranker_model_requested": settings.rerank_model,
        "reranker_model_used": RERANKER_USED_MODEL or settings.rerank_model,
        "reranker_revision_used": RERANKER_USED_REVISION or settings.rerank_revision,
        "loaded_model": RERANKER_USED_MODEL or settings.rerank_model,
        "fallback_used": RERANK_FALLBACK_USED,
        "fallback_reason": RERANK_FALLBACK_REASON,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["download"])
    args = parser.parse_args()
    for model_path, digest in download_models():
        print(f"model: {model_path}\nrevision: {digest}")
