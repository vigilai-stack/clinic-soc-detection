"""Write the daily packet: a text summary and a single HTML file.

The HTML file has no external images, fonts, or scripts, so it opens
from a laptop with no network. It is a report, not a live console.
"""

from __future__ import annotations

import html
from datetime import datetime
from zoneinfo import ZoneInfo

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def build_summary(clinic: dict, stats: dict, alerts: list[dict], evaluation: list[dict]) -> str:
    counts = _severity_counts(alerts)
    count_text = ", ".join(f"{name} {counts[name]}" for name in SEVERITY_ORDER if counts[name])
    matched = sum(1 for row in evaluation if row["ok"])
    lines = [
        f"{clinic['clinic_name']} — synthetic detection run",
        f"Sample day: {clinic['sample_day']}  Seed: {stats['seed']}",
        f"Events: {stats['events']} ({_source_counts(stats)})",
        f"Alerts: {len(alerts)}" + (f" ({count_text})" if count_text else ""),
        f"Report: {stats['report_path']}",
        f"Planted checks: {matched}/{len(evaluation)} matched",
        "",
    ]
    for alert in _ranked(alerts):
        if alert["severity"] not in {"critical", "high"}:
            continue
        lines.append(f"[{alert['severity']}] {alert['id']} {alert['time']} {alert['title']}")
    return "\n".join(lines) + "\n"


def build_html(
    clinic: dict,
    stats: dict,
    alerts: list[dict],
    evaluation: list[dict],
    rules: list,
) -> str:
    tz = ZoneInfo(clinic["timezone"])
    counts = _severity_counts(alerts)
    matched = sum(1 for row in evaluation if row["ok"])
    parts = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        f"<title>{_esc(clinic['clinic_name'])} detection report</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
        "<p class=\"banner\">Synthetic data. Not a real clinic and not a real incident. "
        "The day includes planted cases so each detection has something to find.</p>",
        f"<h1>{_esc(clinic['clinic_name'])}</h1>",
        "<p class=\"lede\">Detection packet for the sample day "
        f"{_esc(clinic['sample_day'])}. Seed {_esc(stats['seed'])}. "
        f"{stats['events']} events, {len(alerts)} alerts. "
        "Privacy and security lead: "
        f"{_esc(clinic['security_lead']['name'])}, {_esc(clinic['security_lead']['organization'])}.</p>",
        "<section>",
        "<h2>Counts</h2>",
        "<ul class=\"counts\">",
    ]
    for name in SEVERITY_ORDER:
        parts.append(f"<li><span class=\"sev {name}\">{name}</span> {counts[name]}</li>")
    parts.append("</ul>")
    parts.append("<p>Events by source: " + _esc(_source_counts(stats)) + ".</p>")
    parts.append("</section>")
    parts.append("<section><h2>Look at these first</h2><ol>")
    urgent = [alert for alert in _ranked(alerts) if alert["severity"] in {"critical", "high"}]
    if not urgent:
        parts.append("<li>No critical or high alerts in this run.</li>")
    for alert in urgent:
        parts.append(
            "<li><span class=\"sev "
            + alert["severity"]
            + "\">"
            + alert["severity"]
            + "</span> "
            + f"<a href=\"#{_esc(alert['id'])}\">{_esc(alert['id'])}</a> "
            + _esc(alert["title"])
            + "</li>"
        )
    parts.append("</ol></section>")
    parts.append(_planted_section(evaluation, matched))
    parts.append(_timeline(alerts, tz))
    parts.append("<section><h2>Alerts</h2>")
    for alert in sorted(alerts, key=lambda item: item["id"]):
        parts.append(_alert_card(alert, tz))
    parts.append("</section>")
    parts.append(_coverage(rules, alerts))
    parts.append(
        "<footer><p>Generated locally from synthetic logs. "
        "The playbooks are an operations checklist for this sample clinic. "
        "They are not legal advice. HIPAA citations in the rules point at the "
        "sections a clinic reads with its own counsel.</p></footer>"
    )
    parts.append("</main></body></html>")
    return "\n".join(parts)


def _planted_section(evaluation: list[dict], matched: int) -> str:
    rows = [
        "<section>",
        "<h2>Planted cases</h2>",
        "<p>This scorecard is for practice. A live clinic does not have an answer key. "
        f"{matched} of {len(evaluation)} expected rule hits were present.</p>",
        "<table>",
        "<thead><tr><th>Case</th><th>Rule</th><th>Result</th><th>Alerts</th></tr></thead>",
        "<tbody>",
    ]
    seen = set()
    for row in evaluation:
        title = row["title"] if row["scenario"] not in seen else ""
        seen.add(row["scenario"])
        result = "matched" if row["ok"] else "missing"
        rows.append(
            "<tr>"
            f"<td>{_esc(title)}<div class=\"quiet\">{_esc(row['detail'] if title else '')}</div></td>"
            f"<td><code>{_esc(row['rule'])}</code></td>"
            f"<td class=\"{result}\">{result}</td>"
            f"<td>{_esc(', '.join(row['alert_ids']) or '—')}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></section>")
    return "\n".join(rows)


def _timeline(alerts: list[dict], tz: ZoneInfo) -> str:
    rows = ["<section>", "<h2>Timeline</h2>", "<ol class=\"timeline\">"]
    for alert in sorted(alerts, key=lambda item: item["time"]):
        rows.append(
            "<li>"
            f"<time>{_esc(_fmt(alert['time'], tz))}</time> "
            f"<span class=\"sev {alert['severity']}\">{alert['severity']}</span> "
            f"<a href=\"#{_esc(alert['id'])}\">{_esc(alert['title'])}</a>"
            f"<div class=\"quiet\">{_esc(alert['summary'])}</div>"
            "</li>"
        )
    rows.append("</ol></section>")
    return "\n".join(rows)


def _alert_card(alert: dict, tz: ZoneInfo) -> str:
    techniques = ", ".join(
        f"{item['id']} {item['name']} ({item['tactic']})" for item in alert["attack"]
    )
    entities = "".join(
        f"<li><code>{_esc(key)}</code> {_esc(value)}</li>"
        for key, value in alert["entities"].items()
    )
    evidence_rows = []
    for event in alert["evidence"]:
        shown = {key: value for key, value in event.items() if not str(key).startswith("_")}
        evidence_rows.append("<li><code>" + _esc(_compact(shown)) + "</code></li>")
    extra = ""
    if alert["evidence_count"] > len(alert["evidence"]):
        extra = (
            f"<p class=\"quiet\">Showing {len(alert['evidence'])} of "
            f"{alert['evidence_count']} matching events.</p>"
        )
    return "\n".join(
        [
            f"<article id=\"{_esc(alert['id'])}\" class=\"card {alert['severity']}\">",
            f"<h3><span class=\"sev {alert['severity']}\">{alert['severity']}</span> "
            f"{_esc(alert['id'])} {_esc(alert['title'])}</h3>",
            f"<p>{_esc(alert['summary'])}</p>",
            "<dl>",
            f"<dt>When</dt><dd>{_esc(_fmt(alert['match_start'], tz))} – {_esc(_fmt(alert['match_end'], tz))}</dd>",
            f"<dt>ATT&amp;CK</dt><dd>{_esc(techniques)}</dd>",
            f"<dt>Rule</dt><dd><code>{_esc(alert['rule_name'])}</code> {_esc(alert['rule_uid'])}</dd>",
            "</dl>",
            f"<h4>Who and where</h4><ul>{entities}</ul>",
            f"<h4>Triage</h4><p>{_esc(alert['triage'])}</p>",
            "<h4>HIPAA context</h4>",
            f"<p><strong>Concern.</strong> {_esc(alert['hipaa']['concern'])}</p>",
            f"<p><strong>Minimum necessary.</strong> {_esc(alert['hipaa']['minimum_necessary'])}</p>",
            f"<p><strong>Breach notification.</strong> {_esc(alert['hipaa']['breach_notification'])}</p>",
            "<h4>Evidence sample</h4>",
            f"<ul class=\"evidence\">{''.join(evidence_rows)}</ul>",
            extra,
            "<details><summary>Response playbook</summary>",
            _markdownish(alert["playbook_md"]),
            "</details>",
            "</article>",
        ]
    )


def _coverage(rules: list, alerts: list[dict]) -> str:
    fired = {}
    for alert in alerts:
        fired.setdefault(alert["rule_name"], 0)
        fired[alert["rule_name"]] += 1
    rows = [
        "<section>",
        "<h2>ATT&amp;CK coverage</h2>",
        "<p>Techniques this pack has a rule for, and whether this sample day produced an alert. "
        "ATT&amp;CK often lists one technique under several tactics. The tactic shown is the one "
        "this case is using.</p>",
        "<table>",
        "<thead><tr><th>Rule</th><th>Severity</th><th>Technique</th><th>Alerts this run</th></tr></thead>",
        "<tbody>",
    ]
    for rule in rules:
        techniques = ", ".join(
            f"{item['id']} {item['name']}" for item in rule.attack
        )
        count = fired.get(rule.name, 0)
        state = "fired" if count else "missing"
        rows.append(
            "<tr>"
            f"<td><code>{_esc(rule.name)}</code><div class=\"quiet\">{_esc(rule.title)}</div></td>"
            f"<td><span class=\"sev {rule.level}\">{rule.level}</span></td>"
            f"<td>{_esc(techniques)}</td>"
            f"<td class=\"{state}\">{count}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></section>")
    return "\n".join(rows)


def _markdownish(markdown: str) -> str:
    """A small, safe subset: headings, paragraphs, and flat lists."""
    html_parts: list[str] = []
    list_tag = None
    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped:
            if list_tag:
                html_parts.append(f"</{list_tag}>")
                list_tag = None
            continue
        if stripped.startswith("### "):
            if list_tag:
                html_parts.append(f"</{list_tag}>")
                list_tag = None
            html_parts.append(f"<h5>{_esc(stripped[4:])}</h5>")
            continue
        if stripped.startswith("## "):
            if list_tag:
                html_parts.append(f"</{list_tag}>")
                list_tag = None
            html_parts.append(f"<h4>{_esc(stripped[3:])}</h4>")
            continue
        if stripped.startswith("# "):
            if list_tag:
                html_parts.append(f"</{list_tag}>")
                list_tag = None
            html_parts.append(f"<h3>{_esc(stripped[2:])}</h3>")
            continue
        if stripped.startswith("- "):
            if list_tag != "ul":
                if list_tag:
                    html_parts.append(f"</{list_tag}>")
                html_parts.append("<ul>")
                list_tag = "ul"
            html_parts.append(f"<li>{_esc(stripped[2:])}</li>")
            continue
        number = _numbered(stripped)
        if number is not None:
            if list_tag != "ol":
                if list_tag:
                    html_parts.append(f"</{list_tag}>")
                html_parts.append("<ol>")
                list_tag = "ol"
            html_parts.append(f"<li>{_esc(number)}</li>")
            continue
        if list_tag:
            html_parts.append(f"</{list_tag}>")
            list_tag = None
        html_parts.append(f"<p>{_esc(stripped)}</p>")
    if list_tag:
        html_parts.append(f"</{list_tag}>")
    return "\n".join(html_parts)


def _numbered(text: str) -> str | None:
    digits = []
    for char in text:
        if char.isdigit():
            digits.append(char)
            continue
        break
    if not digits:
        return None
    rest = text[len(digits) :]
    if rest.startswith(". "):
        return rest[2:]
    return None


def _fmt(value: str, tz: ZoneInfo) -> str:
    moment = datetime.fromisoformat(value).astimezone(tz)
    hour = moment.strftime("%I").lstrip("0") or "0"
    return moment.strftime(f"%b {moment.day}, %Y, {hour}:%M:%S %p %Z")


def _compact(event: dict) -> str:
    preferred = [
        "EventID",
        "Computer",
        "TargetUserName",
        "SubjectUserName",
        "CommandLine",
        "user",
        "patient_mrn",
        "action",
        "record_type",
        "src_ip",
        "dst_ip",
        "username",
        "result",
        "sender",
        "recipient",
        "attachment_name",
        "country",
        "bytes_out",
        "MemberName",
    ]
    pieces = []
    for key in preferred:
        if key in event and event[key] not in ("", None):
            pieces.append(f"{key}={event[key]}")
    if not pieces:
        pieces = [f"{key}={value}" for key, value in list(event.items())[:8]]
    return " ".join(pieces)


def _severity_counts(alerts: list[dict]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for alert in alerts:
        counts[alert["severity"]] = counts.get(alert["severity"], 0) + 1
    return counts


def _source_counts(stats: dict) -> str:
    return ", ".join(f"{name} {count}" for name, count in stats["by_source"].items())


def _ranked(alerts: list[dict]) -> list[dict]:
    return sorted(alerts, key=lambda alert: (SEVERITY_ORDER.get(alert["severity"], 9), alert["time"]))


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


_CSS = """
:root { color-scheme: light; }
body { margin: 0; background: #f3efe6; color: #1c2430;
  font: 16px/1.5 "Segoe UI", system-ui, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 2rem; line-height: 1.2; margin: 0 0 8px; }
h2 { margin-top: 2rem; font-size: 1.35rem; }
h3 { font-size: 1.1rem; }
a { color: #1f4e3d; }
.banner { background: #1c2430; color: #f3efe6; padding: 10px 14px; border-radius: 6px; }
.lede { font-size: 1.05rem; }
.counts { display: flex; gap: 12px; flex-wrap: wrap; padding: 0; list-style: none; }
.counts li { background: #fffdf8; border: 1px solid #ddd4c4; border-radius: 6px; padding: 8px 12px; }
.sev { display: inline-block; padding: 0 6px; border-radius: 4px; font-size: 0.8rem;
  text-transform: uppercase; letter-spacing: 0.03em; color: #fff; }
.critical { background: #8c1d18; }
.high { background: #9a4d0f; }
.medium { background: #6e5a12; }
.low { background: #1f4e3d; }
.informational { background: #3d4a5c; }
.card { background: #fffdf8; border: 1px solid #ddd4c4; border-left-width: 6px;
  border-radius: 8px; padding: 12px 16px; margin: 16px 0; }
.card.critical { border-left-color: #8c1d18; }
.card.high { border-left-color: #9a4d0f; }
.card.medium { border-left-color: #6e5a12; }
.card.low { border-left-color: #1f4e3d; }
.timeline { list-style: none; padding: 0; border-left: 3px solid #c8b89a; }
.timeline li { padding: 0 0 14px 14px; }
.quiet { color: #5c5346; font-size: 0.92rem; }
table { width: 100%; border-collapse: collapse; background: #fffdf8; }
th, td { text-align: left; vertical-align: top; padding: 8px; border-bottom: 1px solid #e4dccb; }
.matched, .fired { color: #1f4e3d; font-weight: 600; }
.missing, .quiet-state { color: #8c1d18; font-weight: 600; }
code { font-family: ui-monospace, "Cascadia Code", monospace; font-size: 0.9em; }
.evidence code { white-space: pre-wrap; word-break: break-word; }
dl { display: grid; grid-template-columns: 8rem 1fr; gap: 4px 12px; }
dt { color: #5c5346; }
footer { margin-top: 2rem; color: #5c5346; }
"""
