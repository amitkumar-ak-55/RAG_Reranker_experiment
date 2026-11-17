from __future__ import annotations

import re
import hashlib

import numpy as np

from ..config import settings
from ..models import encode


def _lexical_embedding(text: str) -> np.ndarray:
    vector = np.zeros(128, dtype=np.float32)
    for token in re.findall(r"\w+", text.lower()):
        bucket = int.from_bytes(hashlib.sha256(token.encode()).digest()[:8], "big") % len(vector)
        vector[bucket] += 1
    norm = np.linalg.norm(vector)
    return vector / norm if norm else vector


def embed_text(text: str) -> np.ndarray:
    """Encode locally; the blank-model mode is a deterministic test/dev fallback."""
    if not settings.embedding_model:
        return _lexical_embedding(text)
    return encode([text], query=False)[0]


def embed_query(text: str) -> np.ndarray:
    if not settings.embedding_model:
        return _lexical_embedding(text)
    return encode([text], query=True)[0]
