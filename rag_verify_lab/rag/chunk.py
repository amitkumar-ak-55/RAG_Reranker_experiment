from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


def _whitespace_tokenizer(text: str) -> list[str]:
    return text.split()


def chunk_document(
    document: dict[str, Any],
    max_tokens: int = 450,
    overlap: int = 50,
    tokenizer: Callable[[str], list[str]] | None = None,
) -> list[dict[str, Any]]:
    tokenizer = tokenizer or _whitespace_tokenizer
    text = str(document.get("text", "")).strip()
    if len(tokenizer(text)) <= 512:
        pieces = [text]
    else:
        sentences = [part.strip() for part in SENTENCE_RE.split(text) if part.strip()]
        pieces: list[str] = []
        current: list[str] = []
        for sentence in sentences:
            if len(tokenizer(" ".join(current + [sentence]))) > max_tokens and current:
                pieces.append(" ".join(current))
                overlap_words = " ".join(current).split()[-overlap:]
                current = [" ".join(overlap_words)] if overlap_words else []
            current.append(sentence)
        if current:
            pieces.append(" ".join(current))
    result = []
    for index, piece in enumerate(pieces):
        metadata = {key: value for key, value in document.items() if key not in {"text", "doc_id"}}
        result.append({
            "chunk_id": f"{document['doc_id']}:{index}", "doc_id": document["doc_id"],
            "chunk_index": index, "text": piece, "metadata": metadata,
            "content_hash": hashlib.sha256(
                f"{document['doc_id']}:{index}\n{piece}".encode()
            ).hexdigest(),
        })
    return result
