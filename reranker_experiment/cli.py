from __future__ import annotations

import argparse
from pathlib import Path

from .experiment import (
    run_mock_dry_run,
    run_production_full,
    run_production_pilot,
    validate_dataset,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Research-grade A/B/C reranker experiment.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-dataset")
    dry_run = commands.add_parser("mock-dry-run")
    dry_run.add_argument("--provider", choices=("mock",), required=True)
    dry_run.add_argument("--questions", type=int, choices=range(1, 4), default=3)
    pilot = commands.add_parser("pilot", help="Explicitly authorized small production pilot.")
    pilot.add_argument("--provider", choices=("production",), required=True)
    pilot.add_argument("--questions", type=int, choices=range(1, 4), default=1)
    pilot.add_argument("--resume", action="store_true")
    pilot.add_argument("--output-dir", type=Path)
    full = commands.add_parser("full", help="Reserved for an explicitly authorized real-API run.")
    full.add_argument("--provider", choices=("production",), required=True)
    full.add_argument("--resume", action="store_true")
    full.add_argument("--output-dir", type=Path)
    report_cmd = commands.add_parser("generate-report", help="Generate paper-ready charts, LaTeX tables, and summary.")
    report_cmd.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "validate-dataset":
        print(validate_dataset())
        return 0
    if args.command == "mock-dry-run":
        print(run_mock_dry_run(question_limit=args.questions))
        return 0
    if args.command == "pilot":
        print(run_production_pilot(
            output_dir=args.output_dir,
            question_limit=args.questions,
            resume=args.resume,
        ))
        return 0
    if args.command == "full":
        print(run_production_full(output_dir=args.output_dir, resume=args.resume))
        return 0
    if args.command == "generate-report":
        from .paper_report import generate_paper_artifacts
        print(generate_paper_artifacts(args.output_dir))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

