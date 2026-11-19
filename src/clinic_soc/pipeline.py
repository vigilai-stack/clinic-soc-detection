"""Generate, enrich, detect, and write the report."""

from __future__ import annotations

import json
from pathlib import Path

from clinic_soc.clinic import ROOT, load_clinic
from clinic_soc.engine import detect
from clinic_soc.enrich import enrich
from clinic_soc.evaluate import evaluate
from clinic_soc.generate import generate, load_logs, stamp, write_logs
from clinic_soc.report import build_html, build_summary
from clinic_soc.sigma import load_rules
from clinic_soc.sources import SOURCES


def run_pipeline(seed: int = 42, out: Path | None = None, clinic: dict | None = None) -> dict:
    clinic = clinic or load_clinic()
    out = out or (ROOT / "out")
    out.mkdir(parents=True, exist_ok=True)
    logs, labels = generate(clinic, seed)
    log_dir = out / "logs"
    write_logs(log_dir, logs)
    labels_path = out / "labels.json"
    labels_path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")

    events = stamp(logs)
    events = enrich(events, clinic)
    rules = load_rules()
    alerts = detect(events, rules)
    alert_dicts = [alert.to_dict() for alert in alerts]
    alerts_path = out / "alerts.json"
    alerts_path.write_text(json.dumps(alert_dicts, indent=2) + "\n", encoding="utf-8")

    by_source = {name: len(logs[name]) for name in SOURCES}
    stats = {
        "seed": seed,
        "events": sum(by_source.values()),
        "by_source": by_source,
        "report_path": str(out / "report.html"),
    }
    score = evaluate(alert_dicts, labels)
    report = build_html(clinic, stats, alert_dicts, score, rules)
    (out / "report.html").write_text(report, encoding="utf-8")
    summary = build_summary(clinic, stats, alert_dicts, score)
    (out / "summary.txt").write_text(summary, encoding="utf-8")
    return {
        "alerts": alert_dicts,
        "labels": labels,
        "evaluation": score,
        "stats": stats,
        "summary": summary,
        "out": out,
    }


def reload(out: Path) -> list[dict]:
    """Load previously written logs. Used by tests that want the files on disk."""
    return load_logs(out / "logs")
