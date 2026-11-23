from __future__ import annotations

import csv
import hashlib
import json
import math
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import numpy as np

from rag_verify_lab.config import settings as app_settings
from rag_verify_lab.db import KBChunk, KBEmbedding, db_session
from rag_verify_lab import models as app_models
from rag_verify_lab.rag.index import FindingIndex, IndexedFinding
from rag_verify_lab.rag.retrieve import retrieve

from .experiment import EXPERIMENT_VERSION, load_jsonl, validate_dataset
from .config import settings as experiment_settings
from .gold import normalize_cve
from .provenance import canonical_hash, runtime_manifest, sha256_file, utc_now, write_json

ARM_IDS = ("A_hybrid_baseline", "B_hybrid_jina", "C_hybrid_jev")
LEGACY_ARM_IDS = (
    "A_hybrid_baseline",
    "B_hybrid_jina_mock",
    "C_hybrid_jev_mock",
)

if TYPE_CHECKING:
    from .generation import GenerationResult


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    doc_id: str
    text: str
    metadata: dict[str, object]
    original_rank: int
    dense_score: float
    sparse_score: float
    fusion_score: float


@dataclass(frozen=True)
class ProviderResult:
    scores: dict[str, float]
    latency_ms: float


class RerankerProvider(Protocol):
    name: str

    def rank(self, query: str, candidates: list[Candidate]) -> ProviderResult:
        ...


class AnswerProvider(Protocol):
    name: str

    def answer(self, query: str, evidence: list[Candidate]) -> GenerationResult:
        ...


class HashReranker:
    """Deterministic mock provider whose scores use only query and candidate content."""

    def __init__(self, name: str) -> None:
        self.name = name

    def rank(self, query: str, candidates: list[Candidate]) -> ProviderResult:
        started = time.perf_counter()
        scores = {
            candidate.candidate_id: int.from_bytes(
                hashlib.sha256(f"{self.name}\0{query}\0{candidate.candidate_id}\0{candidate.text}".encode()).digest()[:8],
                "big",
            ) / 2**64
            for candidate in candidates
        }
        return ProviderResult(scores, (time.perf_counter() - started) * 1000)


class JinaRerankerProvider:
    """Adapter for the tested Jina reranker HTTP implementation."""

    name = "jina-reranker"

    def __init__(self, experiment_settings: object | None = None, *, http_client: object | None = None) -> None:
        from .config import settings

        self.settings = experiment_settings or settings
        self._http_client = http_client
        self.name = f"jina-reranker:{getattr(self.settings, 'jina_reranker_model', 'unavailable')}"

    def rank(self, query: str, candidates: list[Candidate]) -> ProviderResult:
        if len(candidates) != 10:
            raise RuntimeError(f"Jina reranking requires exactly 10 candidates, got {len(candidates)}")
        if len({candidate.candidate_id for candidate in candidates}) != len(candidates):
            raise RuntimeError("Jina reranking received duplicate candidate IDs")

        from .client import JinaReranker

        started = time.perf_counter()
        with JinaReranker(self.settings, client=self._http_client) as reranker:
            response = reranker.rerank(
                query,
                [candidate.text for candidate in candidates],
                top_n=len(candidates),
            )
        latency_ms = (time.perf_counter() - started) * 1000
        if not isinstance(response.scores, list) or len(response.scores) != len(candidates):
            raise RuntimeError(
                f"Jina returned {len(response.scores) if isinstance(response.scores, list) else 'invalid'} "
                f"scores; expected {len(candidates)}"
            )
        scores: dict[str, float] = {}
        for index, candidate in enumerate(candidates):
            score = response.scores[index]
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise RuntimeError("Jina returned a non-numeric relevance score")
            numeric = float(score)
            if not math.isfinite(numeric):
                raise RuntimeError("Jina returned a missing or non-finite relevance score")
            scores[candidate.candidate_id] = numeric
        return ProviderResult(scores, latency_ms)


class JEVRerankerProvider:
    """Adapter for the tested TypeSafe JEV System One batch implementation."""

    name = "jev-system-one"

    def __init__(self, experiment_settings: object | None = None, *, http_client: object | None = None) -> None:
        from .config import settings

        self.settings = experiment_settings or settings
        self._http_client = http_client
        self.name = f"jev-system-one:{getattr(self.settings, 'jev_model', 'unavailable')}"

    def rank(self, query: str, candidates: list[Candidate]) -> ProviderResult:
        if len(candidates) != 10:
            raise RuntimeError(f"JEV reranking requires exactly 10 candidates, got {len(candidates)}")
        candidate_ids = [candidate.candidate_id for candidate in candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise RuntimeError("JEV reranking received duplicate candidate IDs")
        if not getattr(self.settings, "jev_api_key", ""):
            raise RuntimeError("JEV API key is not configured")
        if not getattr(self.settings, "jev_base_url", ""):
            raise RuntimeError("JEV base URL is not configured")
        if not getattr(self.settings, "jev_model", ""):
            raise RuntimeError("JEV model is not configured")

        from .jev_batch import JEVBatchClient

        started = time.perf_counter()
        with JEVBatchClient(
            api_key=self.settings.jev_api_key,
            base_url=self.settings.jev_base_url,
            model=self.settings.jev_model,
            timeout_seconds=getattr(self.settings, "timeout_seconds", 30),
            http_client=self._http_client,
        ) as jev:
            result = jev.score(
                "experiment",
                query,
                [
                    {"doc_id": candidate.candidate_id, "text": candidate.text}
                    for candidate in candidates
                ],
            )
        latency_ms = (time.perf_counter() - started) * 1000
        if set(result.scores) != set(candidate_ids):
            missing = sorted(set(candidate_ids) - set(result.scores))
            extra = sorted(set(result.scores) - set(candidate_ids))
            raise RuntimeError(f"JEV returned incomplete candidate scores; missing={missing}, extra={extra}")
        scores: dict[str, float] = {}
        for candidate_id in candidate_ids:
            score = result.scores[candidate_id]
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise RuntimeError("JEV returned a non-numeric Noul score")
            numeric = float(score)
            if not math.isfinite(numeric) or not 0 <= numeric <= 1:
                raise RuntimeError("JEV returned an invalid Noul score")
            scores[candidate_id] = numeric
        return ProviderResult(scores, latency_ms)


class MockAnswerProvider:
    name = "mock-answer-provider"

    def answer(self, query: str, evidence: list[Candidate]) -> GenerationResult:
        from .generation import GenerationResult

        references = " ".join(f"[E{index}] {candidate.doc_id}" for index, candidate in enumerate(evidence, 1))
        return GenerationResult(
            text=f"Mock answer for {query}. Evidence references: {references}",
            provider=self.name,
            model=None,
            generation_config={"mode": "mock"},
            tokens_in=None,
            tokens_out=None,
            cost=None,
            success=True,
        )


def _load_frozen_index() -> FindingIndex:
    manifest = _load_index_manifest()
    expected_version = str(manifest["index_version"])
    expected_model = str(manifest["embedding_model"])
    expected_revision = str(manifest["embedding_revision"])
    if app_settings.embedding_model != expected_model or app_settings.embedding_revision != expected_revision:
        raise RuntimeError(
            "Frozen index embedding configuration mismatch: "
            f"manifest={expected_model}@{expected_revision}, "
            f"configured={app_settings.embedding_model}@{app_settings.embedding_revision}"
        )
    with db_session() as db:
        chunks = (
            db.query(KBChunk)
            .filter(KBChunk.index_version == expected_version)
            .order_by(KBChunk.chunk_id)
            .all()
        )
        vectors = {
            row.content_hash: np.frombuffer(row.vector, dtype=np.float32).copy()
            for row in db.query(KBEmbedding).filter(
                KBEmbedding.model_name == app_settings.embedding_model,
                KBEmbedding.model_revision == app_settings.embedding_revision,
            ).all()
        }
    if not chunks:
        raise RuntimeError("Frozen SQLite KB has no chunks for the recorded index version")
    _validate_frozen_snapshot(chunks, vectors, manifest)
    records: list[dict[str, object]] = []
    for chunk in chunks:
        vector = vectors.get(chunk.content_hash)
        if vector is None:
            raise RuntimeError(f"Missing frozen embedding for KB chunk {chunk.chunk_id}")
        metadata = json.loads(chunk.metadata_json or "{}")
        metadata.update({"doc_id": chunk.doc_id, "chunk_id": chunk.chunk_id, "content_hash": chunk.content_hash})
        records.append({"id": len(records), "text": chunk.text, "metadata": metadata, "vector": vector})
    return FindingIndex(records)


def _validate_frozen_snapshot(
    chunks: list[KBChunk],
    vectors: dict[str, np.ndarray],
    manifest: dict[str, object],
) -> None:
    expected_version = str(manifest["index_version"])
    expected_dimension = int(manifest["embedding_dimension"])
    if len(vectors) != len(chunks):
        raise RuntimeError(
            f"Frozen embedding count mismatch: {len(vectors)} vectors for {len(chunks)} chunks"
        )
    for chunk in chunks:
        if chunk.index_version != expected_version:
            raise RuntimeError(
                f"Frozen chunk index version mismatch for {chunk.chunk_id}: "
                f"expected {expected_version}, got {chunk.index_version}"
            )
        vector = vectors.get(chunk.content_hash)
        if vector is None:
            raise RuntimeError(f"Missing frozen embedding for KB chunk {chunk.chunk_id}")
        if vector.ndim != 1 or vector.size != expected_dimension:
            raise RuntimeError(
                f"Frozen embedding dimension mismatch for {chunk.chunk_id}: "
                f"expected {expected_dimension}, got {vector.size}"
            )


def _load_index_manifest() -> dict[str, object]:
    path = Path(__file__).resolve().parent.parent / "data" / "kb" / "index_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    required = ("index_version", "embedding_model", "embedding_revision", "embedding_dimension")
    missing = [key for key in required if key not in manifest]
    if missing:
        raise RuntimeError(f"Frozen index manifest is missing required fields: {missing}")
    return manifest


def _snapshot_paths() -> dict[str, Path]:
    root = Path(__file__).resolve().parent.parent
    return {
        "dataset": root / "data" / "eval" / "final" / "eval_hard_300.jsonl",
        "kb_database": root / "data" / "app.db",
        "kb_manifest": root / "data" / "kb" / "manifest.json",
        "index_manifest": root / "data" / "kb" / "index_manifest.json",
    }


def _fingerprints(
    *,
    provider_mode: str,
    question_limit: int,
    jina_provider: RerankerProvider,
    jev_provider: RerankerProvider,
    answer_provider: AnswerProvider,
) -> dict[str, str]:
    paths = _snapshot_paths()
    from .generation import canonical_json, sanitize_persisted_value

    def provider_identity(provider: object, configured_model: str | None = None) -> dict[str, object]:
        settings = getattr(provider, "generation_settings", None)
        settings_value = settings.as_dict() if settings is not None else None
        return {
            "implementation": f"{type(provider).__module__}.{type(provider).__qualname__}",
            "name": getattr(provider, "name", "unavailable"),
            "model": configured_model or getattr(settings, "model", "unavailable"),
            "prompt_hash": getattr(provider, "prompt_hash", "unavailable"),
            "settings": settings_value if settings_value is not None else "unavailable",
        }

    source_paths = {
        "experiment_pipeline": Path(__file__),
        "experiment_generation": Path(__file__).with_name("generation.py"),
        "experiment_config": Path(__file__).with_name("config.py"),
        "experiment_definition": Path(__file__).with_name("experiment.py"),
        "experiment_provenance": Path(__file__).with_name("provenance.py"),
        "experiment_client": Path(__file__).with_name("client.py"),
        "production_answer": paths["dataset"].parents[3] / "rag_verify_lab" / "rag" / "answer.py",
        "production_retrieve": paths["dataset"].parents[3] / "rag_verify_lab" / "rag" / "retrieve.py",
        "production_index": paths["dataset"].parents[3] / "rag_verify_lab" / "rag" / "index.py",
    }
    source_hashes = {
        name: sha256_file(path) if path.is_file() else "unavailable"
        for name, path in source_paths.items()
    }
    non_secret_settings = {
        "jina_base_url": experiment_settings.jina_base_url,
        "jina_reranker_model": experiment_settings.jina_reranker_model,
        "jina_key_slots": len(experiment_settings.api_keys),
        "jev_base_url": experiment_settings.jev_base_url,
        "jev_model": experiment_settings.jev_model,
        "answer_model": app_settings.answer_model,
        "answer_max_tokens": app_settings.answer_max_tokens,
        "embedding_model": experiment_settings.embedding_model,
        "embedding_revision": experiment_settings.embedding_revision,
        "timeout_seconds": experiment_settings.timeout_seconds,
        "configured_candidate_limit": experiment_settings.candidate_limit,
        "configured_result_limit": experiment_settings.result_limit,
    }
    retrieval_config = {
        "implementation": "rag_verify_lab.rag.retrieve.retrieve",
        "use_sparse": True,
        "use_reranker": False,
        "candidate_limit": 10,
        "evidence_limit": 5,
        "embedding_model": experiment_settings.embedding_model,
        "embedding_revision": experiment_settings.embedding_revision,
        "embedding_device": "cpu",
        "embedding_warmup_required": True,
    }
    provenance = {
        "experiment_version": EXPERIMENT_VERSION,
        "provider_mode": provider_mode,
        "question_limit": question_limit,
        "arms": list(ARM_IDS),
        "candidate_pool_size": 10,
        "evidence_size": 5,
        "retrieval": retrieval_config,
        "ranking": {
            "baseline": "original_rank_descending",
            "jina": provider_identity(jina_provider, experiment_settings.jina_reranker_model),
            "jev": provider_identity(jev_provider, experiment_settings.jev_model),
        },
        "answer_generation": {
            "provider": provider_identity(answer_provider),
            "prompt_hash": getattr(answer_provider, "prompt_hash", "unavailable"),
            "settings": getattr(
                getattr(answer_provider, "generation_settings", None),
                "as_dict",
                lambda: {"provider": getattr(answer_provider, "name", "unavailable")},
            )(),
        },
        "settings": non_secret_settings,
        "source_hashes": source_hashes,
        "runtime": runtime_manifest(),
    }
    provenance_json = canonical_json(sanitize_persisted_value(provenance))
    return {
        "dataset_sha256": sha256_file(paths["dataset"]),
        "kb_database_sha256": sha256_file(paths["kb_database"]),
        "kb_manifest_sha256": sha256_file(paths["kb_manifest"]),
        "index_manifest_sha256": sha256_file(paths["index_manifest"]),
        "retrieval_config_sha256": canonical_hash(retrieval_config),
        "experiment_config_sha256": canonical_hash(provenance),
        "provenance_json": provenance_json,
        "provenance_sha256": canonical_hash(provenance),
    }


def _validate_checkpoint(output_dir: Path, expected: dict[str, str], expected_keys: set[str]) -> None:
    def invalid(message: str) -> None:
        raise RuntimeError(f"Cannot resume: {message}")

    legacy_arm_aliases = {
        "B_hybrid_jina_mock": "B_hybrid_jina",
        "C_hybrid_jev_mock": "C_hybrid_jev",
    }

    def normalize_arm_key(key: str) -> str:
        question_id, separator, arm = key.partition(":")
        if not separator:
            return key
        return f"{question_id}:{legacy_arm_aliases.get(arm, arm)}"

    try:
        checkpoint_path = output_dir / "checkpoint.json"
        if not checkpoint_path.is_file():
            invalid(f"checkpoint is missing at {checkpoint_path}")
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        invalid("checkpoint is malformed")
    if not isinstance(checkpoint, dict):
        invalid("checkpoint is malformed")
    actual = checkpoint.get("fingerprints")
    if actual != expected:
        changed = sorted(set(expected) | set(actual or {}))
        changed = [key for key in changed if (actual or {}).get(key) != expected.get(key)]
        invalid(f"input/configuration hashes changed: {', '.join(changed)}")
    completed_values = checkpoint.get("completed_question_arm_keys")
    if not isinstance(completed_values, list) or len(completed_values) != len(set(completed_values)):
        invalid("completed question-arm keys contain duplicates or have an invalid shape")
    completed = set(completed_values)
    completed = {normalize_arm_key(key) for key in completed}
    if completed != expected_keys:
        invalid("completed question-arm results are incomplete or inconsistent")
    expected_question_ids = {key.split(":", 1)[0] for key in expected_keys}
    completed_ids = checkpoint.get("completed_question_ids")
    if (
        not isinstance(completed_ids, list)
        or len(completed_ids) != len(set(completed_ids))
        or set(completed_ids) != expected_question_ids
    ):
        invalid("completed question IDs are inconsistent")
    result_path = output_dir / "per_question_results.csv"
    candidate_path = output_dir / "per_candidate_results.csv"
    answers_path = output_dir / "generated_answers.jsonl"
    events_path = output_dir / "structured_events.json"
    retrieval_path = output_dir / "retrieval_candidates.jsonl"
    if any(not path.is_file() for path in (result_path, candidate_path, answers_path, events_path, retrieval_path)):
        invalid("one or more persisted result files are missing")

    def read_csv_rows(path: Path) -> list[dict[str, str]]:
        try:
            with path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        except (OSError, csv.Error, UnicodeError):
            invalid(f"{path.name} is malformed")
        if not rows or any(None in row for row in rows):
            invalid(f"{path.name} is malformed")
        return rows

    def read_jsonl(path: Path) -> list[dict[str, object]]:
        try:
            values = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            invalid(f"{path.name} is malformed")
        if not values or any(not isinstance(value, dict) for value in values):
            invalid(f"{path.name} is malformed")
        return values

    def valid_number(value: object, *, integer: bool = False) -> bool:
        if value == "unavailable":
            return True
        try:
            parsed = float(str(value))
        except (TypeError, ValueError):
            return False
        return math.isfinite(parsed) and (not integer or parsed.is_integer())

    from .generation import canonical_json

    results = read_csv_rows(result_path)
    candidates = read_csv_rows(candidate_path)
    answers = read_jsonl(answers_path)
    retrieval_rows = read_jsonl(retrieval_path)
    required_result = {
        "question_id", "arm",
        "candidate_ids", "ranking_ids", "selected_evidence_ids",
        "answer", "answer_provider", "answer_model", "generation_config",
        "answer_generation_latency_ms", "answer_tokens_in", "answer_tokens_out",
        "answer_cost", "answer_status", "answer_error_category", "answer_error_message",
    }
    if len(results) != len(expected_keys) or any(
        not required_result.issubset(row) for row in results
    ):
        invalid("per-question results have an invalid schema or row count")
    result_by_key: dict[str, dict[str, str]] = {}
    candidate_by_key: dict[str, list[dict[str, str]]] = {}
    answer_by_key: dict[str, dict[str, object]] = {}
    for row in results:
        key = normalize_arm_key(f"{row.get('question_id')}:{row.get('arm')}")
        if key in result_by_key or key not in expected_keys:
            invalid("per-question results contain duplicate or unexpected question-arm rows")
        result_by_key[key] = row
        try:
            candidate_ids = json.loads(row["candidate_ids"])
            ranking_ids = json.loads(row["ranking_ids"])
            evidence_ids = json.loads(row["selected_evidence_ids"])
            generation_config = json.loads(row["generation_config"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            invalid("per-question results contain corrupted JSON fields")
        if (
            not isinstance(candidate_ids, list) or len(candidate_ids) != 10 or len(set(candidate_ids)) != 10
            or not isinstance(ranking_ids, list) or len(ranking_ids) != 10
            or len(set(ranking_ids)) != 10 or set(ranking_ids) != set(candidate_ids)
            or not isinstance(evidence_ids, list) or len(evidence_ids) != 5
            or evidence_ids != ranking_ids[:5] or not isinstance(generation_config, dict)
            or row["answer_status"] not in {"success", "failure"}
            or any(row[field] == "" for field in (
                "answer_generation_latency_ms", "answer_tokens_in", "answer_tokens_out",
                "answer_cost", "answer_provider", "answer_model",
                "answer_error_category", "answer_error_message",
            ))
            or canonical_json(generation_config) != row["generation_config"]
            or not valid_number(row["answer_generation_latency_ms"])
            or not valid_number(row["answer_tokens_in"], integer=True)
            or not valid_number(row["answer_tokens_out"], integer=True)
            or not valid_number(row["answer_cost"])
            or (
                row["answer_status"] == "success"
                and (row["answer"] == "unavailable" or row["answer_error_category"] != "unavailable")
            )
            or (
                row["answer_status"] == "failure"
                and row["answer"] != "unavailable"
            )
        ):
            invalid("per-question results contain inconsistent evidence or telemetry")
    if len(candidates) != len(expected_keys) * 10:
        invalid("per-candidate results have an invalid row count")
    for row in candidates:
        key = normalize_arm_key(f"{row.get('question_id')}:{row.get('arm')}")
        if key not in expected_keys:
            invalid("per-candidate results contain unexpected question-arm rows")
        candidate_by_key.setdefault(key, []).append(row)
    for key, rows in candidate_by_key.items():
        ids = [row.get("candidate_id") for row in rows]
        ranks = [row.get("final_rank") for row in rows]
        try:
            numeric_ranks = sorted(int(rank) for rank in ranks)
        except (TypeError, ValueError):
            numeric_ranks = []
        if (
            len(rows) != 10
            or len(set(ids)) != 10
            or numeric_ranks != list(range(1, 11))
            or any(row.get("selected_for_generation") not in {"True", "False"} for row in rows)
            or [row["selected_for_generation"] for row in rows[:5]] != ["True"] * 5
            or any(row["selected_for_generation"] != "False" for row in rows[5:])
        ):
            invalid("per-candidate results contain duplicates or invalid ranks")
        result = result_by_key[key]
        if ids != json.loads(result["ranking_ids"]):
            invalid("candidate and per-question evidence are inconsistent")
    if len(retrieval_rows) != len(expected_question_ids):
        invalid("retrieval candidate rows have an invalid count")
    retrieval_by_question: dict[str, dict[str, object]] = {}
    for row in retrieval_rows:
        question_id = row.get("question_id")
        if not isinstance(question_id, str) or question_id in retrieval_by_question:
            invalid("retrieval candidate rows contain duplicates or invalid IDs")
        candidate_ids = row.get("candidate_ids")
        if not isinstance(candidate_ids, list) or len(candidate_ids) != 10 or len(set(candidate_ids)) != 10:
            invalid("retrieval candidate rows contain invalid candidate IDs")
        retrieval_by_question[question_id] = row
    if set(retrieval_by_question) != expected_question_ids:
        invalid("retrieval candidate rows have unexpected question IDs")
    for key, result in result_by_key.items():
        question_id = key.split(":", 1)[0]
        if retrieval_by_question[question_id]["candidate_ids"] != json.loads(result["candidate_ids"]):
            invalid("retrieval candidates and per-question results are inconsistent")
    required_answer = {
        "question_id", "arm", "answer", "evidence_ids", "answer_provider",
        "answer_model", "generation_config", "answer_generation_latency_ms",
        "answer_tokens_in", "answer_tokens_out", "answer_cost", "answer_status",
        "answer_error_category", "answer_error_message",
    }
    if len(answers) != len(expected_keys) or any(
        not required_answer.issubset(answer) for answer in answers
    ):
        invalid("generated answers have an invalid schema or row count")
    for answer in answers:
        try:
            key = normalize_arm_key(f"{answer['question_id']}:{answer['arm']}")
        except (KeyError, TypeError):
            invalid("generated answers have an invalid schema")
        if key in answer_by_key or key not in expected_keys:
            invalid("generated answers contain duplicate or unexpected records")
        try:
            evidence_ids = json.loads(str(answer["evidence_ids"]))
            generation_config = json.loads(str(answer["generation_config"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            invalid("generated answers contain corrupted JSON fields")
        if (
            not isinstance(evidence_ids, list)
            or len(evidence_ids) != 5
            or not isinstance(generation_config, dict)
            or answer["answer_status"] not in {"success", "failure"}
            or any(answer[field] == "" for field in (
                "answer_provider", "answer_model", "answer_generation_latency_ms",
                "answer_tokens_in", "answer_tokens_out", "answer_cost",
                "answer_error_category", "answer_error_message",
            ))
            or canonical_json(generation_config) != str(answer["generation_config"])
            or not valid_number(answer["answer_generation_latency_ms"])
            or not valid_number(answer["answer_tokens_in"], integer=True)
            or not valid_number(answer["answer_tokens_out"], integer=True)
            or not valid_number(answer["answer_cost"])
            or (
                answer["answer_status"] == "success"
                and (answer["answer"] == "unavailable" or answer["answer_error_category"] != "unavailable")
            )
            or (
                answer["answer_status"] == "failure"
                and answer["answer"] != "unavailable"
            )
        ):
            invalid("generated answers contain invalid evidence or telemetry")
        answer_by_key[key] = answer
        result = result_by_key[key]
        if (
            evidence_ids != json.loads(result["selected_evidence_ids"])
            or answer["answer_status"] != result["answer_status"]
            or answer["generation_config"] != result["generation_config"]
            or answer["answer_provider"] != result["answer_provider"]
            or answer["answer_model"] != result["answer_model"]
        ):
            invalid("generated answers are inconsistent with per-question results")
    if set(result_by_key) != expected_keys or set(candidate_by_key) != expected_keys or set(answer_by_key) != expected_keys:
        invalid("persisted result artifacts have inconsistent question-arm keys")
    try:
        event_rows = json.loads(events_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        invalid("structured_events.json is malformed")
    if not isinstance(event_rows, list) or not event_rows or not isinstance(event_rows[-1], dict):
        invalid("structured events have an invalid shape")
    completed_event = event_rows[-1]
    statuses = [row["answer_status"] for row in result_by_key.values()]
    expected_status = "failed" if all(status == "failure" for status in statuses) else "completed_with_failures" if any(status == "failure" for status in statuses) else "completed"
    failure_keys = sorted(
        {"question_id": row["question_id"], "arm": row["arm"]}
        for row in results if row["answer_status"] == "failure"
    )
    if (
        completed_event.get("event") != "experiment_completed"
        or completed_event.get("status") != expected_status
        or completed_event.get("generation_success_count") != statuses.count("success")
        or completed_event.get("generation_failure_count") != statuses.count("failure")
        or completed_event.get("generation_failures") != failure_keys
    ):
        invalid("aggregate generation status is missing or inconsistent")


def _validate_partial_checkpoint(output_dir: Path, expected: dict[str, str]) -> set[str]:
    checkpoint_path = output_dir / "checkpoint.json"
    if not checkpoint_path.is_file():
        raise RuntimeError("Cannot resume: checkpoint is missing")
    try:
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        raise RuntimeError("Cannot resume: checkpoint is malformed")
    if not isinstance(checkpoint, dict):
        raise RuntimeError("Cannot resume: checkpoint is malformed")
    if checkpoint.get("fingerprints") != expected:
        raise RuntimeError("Cannot resume: input/configuration hashes changed")
    completed = checkpoint.get("completed_question_ids")
    if not isinstance(completed, list) or len(completed) != len(set(completed)):
        raise RuntimeError("Cannot resume: completed question IDs are malformed")
    return {str(question_id) for question_id in completed}


def _candidate(item: IndexedFinding, rank: int) -> Candidate:
    return Candidate(
        candidate_id=str(item.metadata.get("chunk_id", item.id)),
        doc_id=str(item.metadata.get("doc_id", item.id)),
        text=item.text,
        metadata=dict(item.metadata),
        original_rank=rank,
        dense_score=float(item.dense_score),
        sparse_score=float(item.sparse_score),
        fusion_score=float(item.fusion_score),
    )


def _rank(candidates: list[Candidate], scores: dict[str, float]) -> list[Candidate]:
    if not isinstance(scores, dict):
        raise RuntimeError("Provider returned an invalid score mapping")
    candidate_ids = [candidate.candidate_id for candidate in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise RuntimeError("Candidate pool contains duplicate candidate IDs")
    missing = [candidate.candidate_id for candidate in candidates if candidate.candidate_id not in scores]
    if missing:
        raise RuntimeError(f"Provider returned no score for candidates: {missing}")
    extra = sorted(set(scores) - set(candidate_ids))
    if extra:
        raise RuntimeError(f"Provider returned scores for unknown candidates: {extra}")
    for candidate_id, score in scores.items():
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RuntimeError(f"Provider returned a non-numeric score for {candidate_id}")
        if not math.isfinite(float(score)):
            raise RuntimeError(f"Provider returned a non-finite score for {candidate_id}")
    return sorted(candidates, key=lambda candidate: (-scores[candidate.candidate_id], candidate.original_rank))


@contextmanager
def _retrieval_model_configuration():
    """Allow embedding-only retrieval when the unused production reranker is unset."""
    original = app_models.validate_model_configuration
    if not app_settings.rerank_model:
        app_models.validate_model_configuration = lambda: None
    try:
        yield
    finally:
        app_models.validate_model_configuration = original


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=sorted({key for row in rows for key in row}))
        writer.writeheader()
        writer.writerows(rows)


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, default=str) + "\n" for row in rows),
        encoding="utf-8",
    )


def run_pipeline(
    output_dir: Path,
    *,
    provider: str,
    question_limit: int = 3,
    jina_provider: RerankerProvider | None = None,
    jev_provider: RerankerProvider | None = None,
    answer_provider: AnswerProvider | None = None,
    resume: bool = False,
) -> Path:
    if provider == "production" and not 1 <= question_limit <= 300:
        raise ValueError("Production question limit must be between one and 300")
    if provider not in {"mock", "production"}:
        from .generation import select_answer_provider

        select_answer_provider(provider, mock_provider=answer_provider)
    if provider == "production" and (jina_provider is not None or jev_provider is not None):
        raise ValueError("Production reranker providers cannot be injected; use the real configured adapters")
    dataset_path = Path(__file__).resolve().parent.parent / "data" / "eval" / "final" / "eval_hard_300.jsonl"
    questions = load_jsonl(dataset_path)[:question_limit]
    if provider == "mock" and question_limit > 3:
        raise ValueError("Development mock pipeline is capped at three questions")
    if provider == "mock":
        jina_provider = jina_provider or HashReranker("jina-mock")
        jev_provider = jev_provider or HashReranker("jev-mock")
    else:
        if not experiment_settings.api_keys:
            raise RuntimeError("Production Jina reranker is not configured: JINA API key is missing")
        if not experiment_settings.jina_base_url or not experiment_settings.jina_reranker_model:
            raise RuntimeError("Production Jina reranker is not configured: base URL or model is missing")
        if not experiment_settings.jev_api_key:
            raise RuntimeError("Production JEV reranker is not configured: JEV API key is missing")
        if not experiment_settings.jev_base_url or not experiment_settings.jev_model:
            raise RuntimeError("Production JEV reranker is not configured: base URL or model is missing")
        jina_provider = JinaRerankerProvider(experiment_settings)
        jev_provider = JEVRerankerProvider(experiment_settings)
    from .generation import select_answer_provider
    from .generation import sanitize_persisted_value

    answer_provider = select_answer_provider(provider, mock_provider=answer_provider)
    output_dir.mkdir(parents=True, exist_ok=True)
    fingerprints = _fingerprints(
        provider_mode=provider,
        question_limit=question_limit,
        jina_provider=jina_provider,
        jev_provider=jev_provider,
        answer_provider=answer_provider,
    )
    expected_keys = {
        f"{question['question_id']}:{arm}"
        for question in questions
        for arm in ARM_IDS
    }
    completed_ids: set[str] = set()
    if resume:
        try:
            _validate_checkpoint(output_dir, fingerprints, expected_keys)
            return output_dir
        except RuntimeError as complete_error:
            checkpoint_path = output_dir / "checkpoint.json"
            try:
                partial_checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                partial_keys = set(partial_checkpoint.get("completed_question_arm_keys", []))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                raise complete_error
            if partial_keys and partial_keys != expected_keys:
                completed_ids = _validate_partial_checkpoint(output_dir, fingerprints)
                questions = [
                    question
                    for question in questions
                    if str(question["question_id"]) not in completed_ids
                ]
            else:
                raise complete_error

    index = _load_frozen_index()
    index_manifest = _load_index_manifest()
    embedding_warmup_latency_ms = 0.0
    if provider == "production":
        from rag_verify_lab.models import warm_up_embedding_model

        embedding_warmup_latency_ms = warm_up_embedding_model()

    metadata = {
        "mode": (
            "mock_provider_development"
            if provider == "mock"
            else "production_full"
            if question_limit == 300
            else "production_pilot"
        ),
        "created_at_utc": utc_now(),
        "dataset": validate_dataset(dataset_path),
        "index_version": str(index_manifest["index_version"]),
        "embedding_model": app_settings.embedding_model,
        "embedding_revision": app_settings.embedding_revision,
        "embedding_device": "cpu",
        "embedding_warmup_latency_ms": embedding_warmup_latency_ms,
        "snapshot_fingerprints": fingerprints,
        "snapshot": {
            "index_version": str(index_manifest["index_version"]),
            "embedding_dimension": int(index_manifest["embedding_dimension"]),
            "corpus_sha256": index_manifest.get("corpus_sha256", ""),
        },
        "retrieval": {"implementation": "rag_verify_lab.rag.retrieve.retrieve", "sparse": True, "reranker": False, "candidate_limit": 10},
        "evidence_limit": 5,
        "arms": list(ARM_IDS),
        "provider_mode": provider,
        "rerankers": sanitize_persisted_value({
            "baseline": {"name": "hybrid-original-order", "model": None},
            "jina": {"name": jina_provider.name, "model": experiment_settings.jina_reranker_model},
            "jev": {"name": jev_provider.name, "model": experiment_settings.jev_model},
        }),
        "providers": sanitize_persisted_value({
            "jina": jina_provider.name,
            "jev": jev_provider.name,
            "answer": answer_provider.name,
        }),
        "answer_generation": sanitize_persisted_value(getattr(
            getattr(answer_provider, "generation_settings", None),
            "as_dict",
            lambda: {"provider": answer_provider.name},
        )()),
        "external_calls": provider == "production",
    }
    write_json(output_dir / "experiment_metadata.json", metadata)

    question_rows: list[dict[str, object]] = []
    candidate_rows: list[dict[str, object]] = []
    answer_rows: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    candidate_log: list[dict[str, object]] = []
    if resume and completed_ids:
        with (output_dir / "per_question_results.csv").open(newline="", encoding="utf-8") as handle:
            question_rows = [dict(row) for row in csv.DictReader(handle)]
        with (output_dir / "per_candidate_results.csv").open(newline="", encoding="utf-8") as handle:
            candidate_rows = [dict(row) for row in csv.DictReader(handle)]
        with (output_dir / "generated_answers.jsonl").open(encoding="utf-8") as handle:
            answer_rows = [json.loads(line) for line in handle if line.strip()]
        with (output_dir / "retrieval_candidates.jsonl").open(encoding="utf-8") as handle:
            candidate_log = [json.loads(line) for line in handle if line.strip()]
        try:
            events = json.loads((output_dir / "structured_events.json").read_text(encoding="utf-8"))[1:]
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            events = []
    retrieval_calls = len(completed_ids)
    generation_successes = 0
    generation_failures = 0
    generation_failure_keys: list[dict[str, str]] = []
    for question in questions:
        query = str(question["question"])
        retrieval_calls += 1
        with _retrieval_model_configuration():
            result = retrieve(index, query, use_sparse=True, use_reranker=False, limit=10)
        candidates = [_candidate(item, rank) for rank, item in enumerate(result.items, 1)]
        if len(candidates) != 10:
            raise RuntimeError(f"Expected ten hybrid candidates, got {len(candidates)} for {question['question_id']}")
        candidate_ids = [candidate.candidate_id for candidate in candidates]
        candidate_log.append({"question_id": question["question_id"], "candidate_ids": candidate_ids})
        provider_results = {
            "A_hybrid_baseline": ProviderResult(
                {candidate.candidate_id: -float(candidate.original_rank) for candidate in candidates}, 0.0
            ),
            "B_hybrid_jina": jina_provider.rank(query, candidates),
            "C_hybrid_jev": jev_provider.rank(query, candidates),
        }
        rankings = {arm: _rank(candidates, result.scores) for arm, result in provider_results.items()}
        for arm, ranking in rankings.items():
            if {candidate.candidate_id for candidate in ranking} != set(candidate_ids):
                raise AssertionError(f"Candidate membership changed for {question['question_id']} in {arm}")
            evidence = ranking[:5]
            started = time.perf_counter()
            from .generation import (
                GenerationResult,
                UNAVAILABLE,
                canonical_json,
                failed_generation_result,
                sanitize_generation_result,
            )

            try:
                answer_result = answer_provider.answer(query, evidence)
                if not isinstance(answer_result, GenerationResult):
                    raise TypeError("answer provider returned an invalid structured result")
            except Exception as exc:
                answer_result = failed_generation_result(answer_provider, exc)
            answer_result = sanitize_generation_result(answer_result)
            answer_latency = (time.perf_counter() - started) * 1000
            provider_result = provider_results[arm]
            if answer_result.success:
                generation_successes += 1
            else:
                generation_failures += 1
                generation_failure_keys.append({"question_id": question["question_id"], "arm": arm})
            if arm == "A_hybrid_baseline":
                reranker_name = "hybrid-original-order"
                reranker_model = None
            elif arm == "B_hybrid_jina":
                reranker_name = jina_provider.name
                reranker_model = experiment_settings.jina_reranker_model
            else:
                reranker_name = jev_provider.name
                reranker_model = experiment_settings.jev_model
            question_rows.append({
                "question_id": question["question_id"],
                "arm": arm,
                "provider_mode": provider,
                "reranker_provider": reranker_name,
                "reranker_model": reranker_model or "unavailable",
                "gold_cve": normalize_cve(question.get("gold_cve")),
                "candidate_ids": json.dumps(candidate_ids),
                "ranking_ids": json.dumps([candidate.candidate_id for candidate in ranking]),
                "selected_evidence_ids": json.dumps([candidate.candidate_id for candidate in evidence]),
                "answer": answer_result.text if answer_result.text is not None else UNAVAILABLE,
                "answer_provider": answer_result.provider,
                "answer_model": answer_result.model or UNAVAILABLE,
                "generation_config": canonical_json(answer_result.generation_config),
                "retrieval_latency_ms": sum(result.timings_ms.values()),
                "reranking_latency_ms": provider_result.latency_ms,
                "answer_latency_ms": answer_latency,
                "answer_generation_latency_ms": answer_latency,
                "answer_tokens_in": answer_result.tokens_in if answer_result.tokens_in is not None else UNAVAILABLE,
                "answer_tokens_out": answer_result.tokens_out if answer_result.tokens_out is not None else UNAVAILABLE,
                "answer_cost": answer_result.cost if answer_result.cost is not None else UNAVAILABLE,
                "answer_status": "success" if answer_result.success else "failure",
                "answer_error_category": answer_result.error_category or UNAVAILABLE,
                "answer_error_message": answer_result.error_message or UNAVAILABLE,
                "total_latency_ms": sum(result.timings_ms.values()) + provider_result.latency_ms + answer_latency,
                "failure": answer_result.error_category or "",
            })
            answer_rows.append({
                "question_id": question["question_id"],
                "arm": arm,
                "provider_mode": provider,
                "reranker_provider": reranker_name,
                "reranker_model": reranker_model or "unavailable",
                "answer": answer_result.text if answer_result.text is not None else UNAVAILABLE,
                "evidence_ids": json.dumps([candidate.candidate_id for candidate in evidence]),
                "answer_provider": answer_result.provider,
                "answer_model": answer_result.model or UNAVAILABLE,
                "generation_config": canonical_json(answer_result.generation_config),
                "answer_generation_latency_ms": answer_latency,
                "answer_tokens_in": answer_result.tokens_in if answer_result.tokens_in is not None else UNAVAILABLE,
                "answer_tokens_out": answer_result.tokens_out if answer_result.tokens_out is not None else UNAVAILABLE,
                "answer_cost": answer_result.cost if answer_result.cost is not None else UNAVAILABLE,
                "answer_status": "success" if answer_result.success else "failure",
                "answer_error_category": answer_result.error_category or UNAVAILABLE,
                "answer_error_message": answer_result.error_message or UNAVAILABLE,
            })
            for final_rank, candidate in enumerate(ranking, 1):
                candidate_rows.append({
                    "question_id": question["question_id"],
                    "arm": arm,
                    "provider_mode": provider,
                    "reranker_provider": reranker_name,
                    "reranker_model": reranker_model or "unavailable",
                    "candidate_id": candidate.candidate_id,
                    "doc_id": candidate.doc_id,
                    "document_hash": hashlib.sha256(candidate.text.encode()).hexdigest(),
                    "original_rank": candidate.original_rank,
                    "dense_score": candidate.dense_score,
                    "sparse_score": candidate.sparse_score,
                    "fusion_score": candidate.fusion_score,
                    "reranker_score": provider_result.scores[candidate.candidate_id],
                    "final_rank": final_rank,
                    "selected_for_generation": final_rank <= 5,
                })
        completed_ids.add(str(question["question_id"]))
        events.append({"event": "question_completed", "question_id": question["question_id"], "retrieval_calls": retrieval_calls})
        write_json(output_dir / "checkpoint.json", {
            "completed_question_ids": sorted(completed_ids),
            "completed_question_arm_keys": sorted(
                f"{question_id}:{arm}"
                for question_id in completed_ids
                for arm in ARM_IDS
            ),
            "retrieval_calls": retrieval_calls,
            "fingerprints": fingerprints,
        })

    generation_status = (
        "failed"
        if generation_failures and not generation_successes
        else "completed_with_failures"
        if generation_failures
        else "completed"
    )
    events.append({
        "event": "experiment_completed",
        "status": generation_status,
        "generation_success_count": generation_successes,
        "generation_failure_count": generation_failures,
        "generation_failures": generation_failure_keys,
    })
    _write_jsonl(output_dir / "retrieval_candidates.jsonl", candidate_log)
    write_json(output_dir / "structured_events.json", [{"event": "experiment_started"}] + events)
    _write_jsonl(output_dir / "generated_answers.jsonl", answer_rows)
    _write_csv(output_dir / "per_question_results.csv", question_rows)
    _write_csv(output_dir / "per_candidate_results.csv", candidate_rows)
    write_json(output_dir / "checkpoint.json", {
        "completed_question_ids": sorted(completed_ids),
        "completed_question_arm_keys": sorted(
            f"{question_id}:{arm}"
            for question_id in completed_ids
            for arm in ARM_IDS
        ),
        "retrieval_calls": retrieval_calls,
        "fingerprints": fingerprints,
    })
    try:
        from .paper_report import generate_paper_artifacts

        generate_paper_artifacts(output_dir)
    except Exception:
        pass
    return output_dir


def run_mock_pipeline(
    output_dir: Path,
    *,
    provider: str,
    question_limit: int = 3,
    jina_provider: RerankerProvider | None = None,
    jev_provider: RerankerProvider | None = None,
    answer_provider: AnswerProvider | None = None,
    resume: bool = False,
) -> Path:
    if provider != "mock":
        raise ValueError("run_mock_pipeline requires provider='mock'")
    return run_pipeline(
        output_dir,
        provider=provider,
        question_limit=question_limit,
        jina_provider=jina_provider,
        jev_provider=jev_provider,
        answer_provider=answer_provider,
        resume=resume,
    )


def run_production_pipeline(output_dir: Path, *, question_limit: int = 1, resume: bool = False) -> Path:
    if not 1 <= question_limit <= 300:
        raise ValueError("Production question limit must be between one and 300")
    return run_pipeline(
        output_dir,
        provider="production",
        question_limit=question_limit,
        resume=resume,
    )


def run_production_full(output_dir: Path, *, resume: bool = False) -> Path:
    return run_pipeline(
        output_dir,
        provider="production",
        question_limit=300,
        resume=resume,
    )

