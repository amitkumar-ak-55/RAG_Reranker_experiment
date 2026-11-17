from __future__ import annotations

import argparse
import re
import sys
import time
from typing import Sequence

from .app import _enqueue_scan
from .db import ArmResult, Job, VM, db_session, init_db
from .experiment.arms import ARMS
from .experiment.runner import run_experiment
from .jobs import job_queue
from .seed_scanme import seed
from .scan.nmap_runner import PUBLIC_TARGET, target_ip, validate_target
from .verify.jev_health import jev_health

AUTHORIZATION_MESSAGE = (
    "Refusing to scan: pass --authorized to confirm you are allowed to scan this target."
)
TOOLS = {"nmap", "nuclei"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m rag_verify_lab.cli")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan")
    scan.add_argument("target")
    scan.add_argument("--authorized", action="store_true")
    scan.add_argument("--ports", default="1-1000")
    scan.add_argument("--tools", default="nmap")

    commands.add_parser("check-jev")
    commands.add_parser("download-models")
    commands.add_parser("build-index")
    commands.add_parser("retrieval-eval")
    commands.add_parser("seed").add_argument("seed_name", choices=["scanme"])
    arms = commands.add_parser("arms")
    arms.add_argument("--question", required=True, type=int)
    arms.add_argument("--arms", required=True)
    return parser


def _valid_ports(value: str) -> str:
    if not re.fullmatch(r"\d+(?:-\d+)?", value):
        raise ValueError("Ports must be a single port or range such as 1-1000")
    parts = [int(part) for part in value.split("-")]
    if any(port < 1 or port > 65535 for port in parts) or (len(parts) == 2 and parts[0] > parts[1]):
        raise ValueError("Ports must be between 1 and 65535")
    return value


def _ensure_vm(target: str, resolved_ip: str, ports: str) -> int:
    with db_session() as db:
        vm = db.query(VM).filter(VM.name == target).first()
        if vm is None:
            vm = VM(
                name=target,
                ip=resolved_ip,
                image_ref="",
                container_port=0,
                port_range=ports,
                status="stopped",
                notes="CLI scan target",
            )
            db.add(vm)
        else:
            vm.ip = resolved_ip
            vm.port_range = ports
        db.commit()
        db.refresh(vm)
        return vm.id


def _wait_for_job(job_id: int) -> Job:
    while True:
        with db_session() as db:
            job = db.get(Job, job_id)
            if job is None:
                raise RuntimeError(f"Job {job_id} was not found")
            if job.status in {"done", "failed", "cancelled"}:
                return job
        time.sleep(0.05)


def _scan(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(AUTHORIZATION_MESSAGE, file=sys.stderr)
        return 2
    try:
        target = validate_target(args.target)
        ports = _valid_ports(args.ports)
        tools = [tool.strip() for tool in args.tools.split(",") if tool.strip()]
        if not tools or any(tool not in TOOLS for tool in tools) or len(set(tools)) != len(tools):
            raise ValueError("--tools must contain nmap and/or nuclei")
        if target.rstrip(".").lower() == PUBLIC_TARGET and "nuclei" in tools:
            raise ValueError("Refusing to run nuclei against scanme.nmap.org")
        hostname, resolved_ip = target_ip(target)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    vm_id = _ensure_vm(target, resolved_ip, ports)
    result = _enqueue_scan(vm_id, target, ports, authorized=True, tools=tools)
    job = _wait_for_job(result["job_id"])
    print(f"target: {target}")
    print(f"resolved IP: {resolved_ip}")
    print("authorized=true")
    if job.message:
        print(job.message)
    print(f"job ID: {job.id}")
    return 0 if job.status == "done" else 1


def _check_jev() -> int:
    health = jev_health()
    fields = ("configured", "reachable", "authenticated", "model_accepted")
    for field in fields:
        print(f"{field}: {'pass' if health.get(field) else 'fail'}")
    if health.get("error_message"):
        print(f"error: {health['error_message']}")
    return 0 if all(health.get(field) for field in fields) else 1


def _arms(question_id: int, names: str) -> int:
    selected = [name.strip() for name in names.split(",") if name.strip()]
    if not selected or any(name not in ARMS for name in selected):
        print(f"Unknown arm; choose from: {', '.join(ARMS)}", file=sys.stderr)
        return 2
    job_id = job_queue.enqueue("experiment", "", lambda: run_experiment(selected, [question_id]))
    job = _wait_for_job(job_id)
    if job.status != "done":
        print(f"job failed: {job.message}", file=sys.stderr)
        print(f"job ID: {job.id}")
        return 1
    with db_session() as db:
        rows = db.query(ArmResult).filter(ArmResult.question_id == question_id).order_by(ArmResult.id.desc()).limit(len(selected)).all()
    for row in reversed(rows):
        print(f"arm={row.arm} answer={row.answer!r} error={row.error!r}")
    print(f"job ID: {job.id}")
    return 0 if job.status == "done" else 1


def main(argv: Sequence[str] | None = None) -> int:
    init_db()
    args = _parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "check-jev":
        return _check_jev()
    if args.command == "download-models":
        from .models import download_models
        for path, digest in download_models():
            print(f"path: {path}\nrevision SHA: {digest}")
        return 0
    if args.command == "build-index":
        from .rag.ingest import build_index_report
        try:
            summary = build_index_report()
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"build-index refused: {exc}", file=sys.stderr)
            return 1
        if summary.new_vectors == 0:
            print("index up to date")
        print(f"documents: {summary.documents}")
        print(f"chunks: {summary.chunks}")
        print(f"vectors: {summary.vectors}")
        print(f"index_version: {summary.index_version}")
        print(f"self-retrieval rate: {summary.self_retrieval_rate:.3f}")
        for doc_type, rate in summary.self_retrieval_by_doc_type.items():
            print(f"self-retrieval rate [{doc_type}]: {rate:.3f}")
        print(f"embedding dimension: {summary.embedding_dimension}")
        print(f"elapsed time: {summary.elapsed_seconds:.2f}s")
        return 0
    if args.command == "retrieval-eval":
        from .eval import run_retrieval
        print(f"results: {run_retrieval()}")
        return 0
    if args.command == "seed":
        return 0 if seed() is not None else 1
    if args.command == "arms":
        return _arms(args.question, args.arms)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
