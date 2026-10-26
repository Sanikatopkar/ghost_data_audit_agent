"""Command-line entry point for the October 2026 challenge agent."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from .audit_engine import AuditEngine


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Audit deletion requests against the supplied challenge evidence.")
    parser.add_argument("--dataset-dir", type=Path, default=root / "dataset", help="Participant dataset directory.")
    parser.add_argument("--output", type=Path, default=root / "output.csv", help="Required challenge output CSV path.")
    parser.add_argument("--case-limit", type=int, default=None, help="Optional small-run limit for development only.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        engine = AuditEngine(args.dataset_dir)
        if args.case_limit is not None:
            requests = engine.requests.head(args.case_limit)
            results = [engine.audit_case(row.to_dict()) for _, row in requests.iterrows()]
            results.sort(key=lambda result: result.case_id)
        else:
            results = engine.audit_all()
        engine.export_csv(results, args.output)
        errors = engine.validate_output(args.output, results)
        if errors:
            for error in errors:
                print(f"validation error: {error}", file=sys.stderr)
            return 2
        statuses = {}
        for result in results:
            statuses[result.deletion_status] = statuses.get(result.deletion_status, 0) + 1
        print(f"Wrote {len(results)} case(s) to {args.output}")
        print("Status counts: " + ", ".join(f"{key}={value}" for key, value in sorted(statuses.items())))
        if engine.reader.warnings:
            print(f"Evidence reader warnings: {len(engine.reader.warnings)}", file=sys.stderr)
            for warning in engine.reader.warnings[:12]:
                print(f"  {warning}", file=sys.stderr)
        return 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
