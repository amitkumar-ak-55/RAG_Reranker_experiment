from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, Integer, LargeBinary, String, Text, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import ROOT

DB_PATH = ROOT / "data" / "app.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class VM(Base):
    __tablename__ = "vms"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    ip: Mapped[str] = mapped_column(String(100))
    image_ref: Mapped[str] = mapped_column(String(300))
    container_port: Mapped[int] = mapped_column(Integer, default=0)
    host_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port_range: Mapped[str] = mapped_column(String(100), default="1-1024")
    status: Mapped[str] = mapped_column(String(30), default="stopped")
    notes: Mapped[str] = mapped_column(Text, default="")
    container_name: Mapped[str | None] = mapped_column(String(100), nullable=True)


class Image(Base):
    __tablename__ = "images"
    ref: Mapped[str] = mapped_column(String(300), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    pulled: Mapped[bool] = mapped_column(Boolean, default=False)


class Question(Base):
    __tablename__ = "questions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text)
    gold_answer: Mapped[str] = mapped_column(Text, default="")
    answerable: Mapped[bool] = mapped_column(Boolean, default=True)
    vm_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gold_finding_ids: Mapped[str] = mapped_column(Text, default="[]")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(100))
    scanner: Mapped[str] = mapped_column(String(30))
    vm_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip: Mapped[str] = mapped_column(String(100))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(30), default="")
    service: Mapped[str] = mapped_column(String(200), default="")
    cve_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    title: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(30), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    raw_json: Mapped[str] = mapped_column(Text, default="{}")


class EmbeddingCache(Base):
    __tablename__ = "embedding_cache"
    finding_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_name: Mapped[str] = mapped_column(String(300), primary_key=True)
    vector: Mapped[bytes] = mapped_column(LargeBinary)


class KBChunk(Base):
    __tablename__ = "kb_chunks"
    chunk_id: Mapped[str] = mapped_column(String(300), primary_key=True)
    doc_id: Mapped[str] = mapped_column(String(200), index=True)
    doc_type: Mapped[str] = mapped_column(String(50), default="")
    group: Mapped[str] = mapped_column(String(100), default="")
    chunk_index: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str] = mapped_column("metadata_json", Text, default="{}")
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    index_version: Mapped[str] = mapped_column(String(64), index=True)


class KBEmbedding(Base):
    __tablename__ = "kb_embeddings"
    content_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    model_name: Mapped[str] = mapped_column(String(300), primary_key=True)
    model_revision: Mapped[str] = mapped_column(String(300), primary_key=True)
    vector: Mapped[bytes] = mapped_column(LargeBinary)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(30))
    target: Mapped[str] = mapped_column(String(300), default="")
    status: Mapped[str] = mapped_column(String(20), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    target_hostname: Mapped[str] = mapped_column(String(300), default="")
    resolved_ip: Mapped[str] = mapped_column(String(100), default="")
    public_target: Mapped[bool] = mapped_column(Boolean, default=False)
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    tools: Mapped[str] = mapped_column(Text, default="[]")


class ExperimentRun(Base):
    __tablename__ = "experiment_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    config_snapshot_json: Mapped[str] = mapped_column(Text, default="{}")


class ArmResult(Base):
    __tablename__ = "arm_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(Integer)
    arm: Mapped[str] = mapped_column(String(40))
    question_id: Mapped[int] = mapped_column(Integer)
    answer: Mapped[str] = mapped_column(Text, default="")
    retrieved_ids: Mapped[str] = mapped_column(Text, default="[]")
    candidate_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    retrieved_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    claims_json: Mapped[str] = mapped_column(Text, default="[]")
    latency_ms: Mapped[float] = mapped_column(Float, default=0)
    retrieval_latency_ms: Mapped[float] = mapped_column(Float, default=0)
    answer_latency_ms: Mapped[float] = mapped_column(Float, default=0)
    retrieval_calls: Mapped[int] = mapped_column(Integer, default=0)
    jev_calls: Mapped[int] = mapped_column(Integer, default=0)
    jev_cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    precision_at_1: Mapped[float | None] = mapped_column(Float, nullable=True)
    precision_at_3: Mapped[float | None] = mapped_column(Float, nullable=True)
    precision_at_5: Mapped[float | None] = mapped_column(Float, nullable=True)
    candidate_cap_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    gold_evidence_skipped: Mapped[bool] = mapped_column(Boolean, default=False)
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
    index_version: Mapped[str] = mapped_column(String(64), default="")
    stage_scores_json: Mapped[str] = mapped_column(Text, default="{}")


def init_db() -> None:
    Base.metadata.create_all(engine)
    kb_columns = {column["name"] for column in inspect(engine).get_columns("kb_chunks")}
    with engine.begin() as connection:
        for column, definition in {
            "doc_type": "VARCHAR(50) DEFAULT ''",
            "group": "VARCHAR(100) DEFAULT ''",
        }.items():
            if column not in kb_columns:
                connection.execute(text(f'ALTER TABLE kb_chunks ADD COLUMN "{column}" {definition}'))
    columns = {column["name"] for column in inspect(engine).get_columns("vms")}
    if "container_name" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE vms ADD COLUMN container_name VARCHAR(100)"))
    result_columns = {column["name"] for column in inspect(engine).get_columns("arm_results")}
    additions = {
        "candidate_ids_json": "TEXT DEFAULT '[]'",
        "retrieved_ids_json": "TEXT DEFAULT '[]'",
        "retrieval_latency_ms": "FLOAT DEFAULT 0",
        "answer_latency_ms": "FLOAT DEFAULT 0",
        "retrieval_calls": "INTEGER DEFAULT 0",
        "jev_calls": "INTEGER DEFAULT 0",
        "jev_cost_usd": "FLOAT",
        "precision_at_1": "FLOAT",
        "precision_at_3": "FLOAT",
        "precision_at_5": "FLOAT",
        "candidate_cap_applied": "BOOLEAN DEFAULT 0",
        "gold_evidence_skipped": "BOOLEAN DEFAULT 0",
        "index_version": "VARCHAR(64) DEFAULT ''",
        "stage_scores_json": "TEXT DEFAULT '{}'",
    }
    with engine.begin() as connection:
        job_columns = {column["name"] for column in inspect(engine).get_columns("jobs")}
        for column, definition in {
            "target_hostname": "VARCHAR(300) DEFAULT ''",
            "resolved_ip": "VARCHAR(100) DEFAULT ''",
            "public_target": "BOOLEAN DEFAULT 0",
            "authorized": "BOOLEAN DEFAULT 0",
            "created_at": "DATETIME",
            "timestamp": "DATETIME",
            "tools": "TEXT DEFAULT '[]'",
        }.items():
            if column not in job_columns:
                connection.execute(text(f"ALTER TABLE jobs ADD COLUMN {column} {definition}"))
        for column, definition in additions.items():
            if column not in result_columns:
                connection.execute(text(f"ALTER TABLE arm_results ADD COLUMN {column} {definition}"))
    with db_session() as db:
        db.query(Job).filter(Job.status.in_(["queued", "running"])).update(
            {Job.status: "failed", Job.finished_at: now(), Job.message: "Interrupted by server restart"},
            synchronize_session=False,
        )
        db.commit()


def json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)


def db_session() -> Session:
    return SessionLocal()
