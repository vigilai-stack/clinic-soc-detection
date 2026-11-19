"""Command line for the clinic detection pack.

Examples:

    python -m clinic_soc run
    python -m clinic_soc generate --out out
    python -m clinic_soc detect --logs out/logs --out out/alerts.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from clinic_soc.clinic import ROOT, load_clinic
from clinic_soc.engine import detect
from clinic_soc.enrich import enrich
from clinic_soc.evaluate import evaluate
from clinic_soc.generate import generate, load_logs, write_logs
from clinic_soc.pipeline import run_pipeline
from clinic_soc.report import build_html, build_summary
from clinic_soc.sigma import load_rules
from clinic_soc.sources import SOURCES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="clinic_soc",
        description="Synthetic detection practice for a small clinic network.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Generate logs, detect, and write the report")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--out", type=Path, default=ROOT / "out")

    gen = sub.add_parser("generate", help="Write synthetic logs and planted-case labels")
    gen.add_argument("--seed", type=int, default=42)
    gen.add_argument("--out", type=Path, default=ROOT / "out")

    detect_cmd = sub.add_parser("detect", help="Run the rules against logs on disk")
    detect_cmd.add_argument("--logs", type=Path, required=True)
    detect_cmd.add_argument("--out", type=Path, required=True)

    report = sub.add_parser("report", help="Render HTML from an alerts file and logs")
    report.add_argument("--alerts", type=Path, required=True)
    report.add_argument("--labels", type=Path, required=True)
    report.add_argument("--logs", type=Path, required=True)
    report.add_argument("--out", type=Path, required=True)
    report.add_argument("--seed", type=int, default=42)

    args = parser.parse_args(argv)
    if args.command == "run":
        result = run_pipeline(seed=args.seed, out=args.out)
        sys.stdout.write(result["summary"])
        return 0
    if args.command == "generate":
        clinic = load_clinic()
        logs, labels = generate(clinic, args.seed)
        log_dir = args.out / "logs"
        write_logs(log_dir, logs)
        label_path = args.out / "labels.json"
        label_path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
        total = sum(len(rows) for rows in logs.values())
        sys.stdout.write(f"Wrote {total} events to {log_dir}\n")
        return 0
    if args.command == "detect":
        clinic = load_clinic()
        events = enrich(load_logs(args.logs), clinic)
        alerts = [alert.to_dict() for alert in detect(events, load_rules())]
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
        sys.stdout.write(f"Wrote {len(alerts)} alerts to {args.out}\n")
        return 0
    if args.command == "report":
        clinic = load_clinic()
        alerts = json.loads(args.alerts.read_text(encoding="utf-8"))
        labels = json.loads(args.labels.read_text(encoding="utf-8"))
        logs = load_logs(args.logs)
        by_source = {name: 0 for name in SOURCES}
        for event in logs:
            by_source[event["_source"]] = by_source.get(event["_source"], 0) + 1
        stats = {
            "seed": args.seed,
            "events": len(logs),
            "by_source": by_source,
            "report_path": str(args.out),
        }
        score = evaluate(alerts, labels)
        args.out.write_text(
            build_html(clinic, stats, alerts, score, load_rules()),
            encoding="utf-8",
        )
        sys.stdout.write(build_summary(clinic, stats, alerts, score))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
