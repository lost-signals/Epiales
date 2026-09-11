"""Report: a ranked, remediation-attached HTML summary + a machine summary dict.

Consumes the unified Finding list, so everything is severity-ranked with a fix
attached. The dashboard renders the same data from the DB; this file is the
static fallback and the thing you open if the dashboard isn't running.
"""
from __future__ import annotations

import html
import statistics
from typing import List, Optional

from .fliphunter import FlipResult
from .metamorphic import InvarianceReport
from .models import Finding, Result

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {"critical": "#ff4d6d", "high": "#ff884d", "medium": "#ffd24d",
              "low": "#4dd2ff", "info": "#8a97b0"}


def summarize(results: List[Result],
              flips: Optional[List[Optional[FlipResult]]] = None,
              invariance: Optional[List[InvarianceReport]] = None,
              findings: Optional[List[Finding]] = None) -> dict:
    total = len(results)
    crashes = [r for r in results if r.finding == "crash"]
    lat = [r.latency_ms for r in results if r.latency_ms]
    flips = [f for f in (flips or []) if f]
    invariance = invariance or []
    findings = findings or []

    drifts = [rep.mean_conf_drift for rep in invariance if rep.tested]
    sev_counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_ORDER}

    return {
        "total_attacks": total,
        "crashes": len(crashes),
        "crash_rate": round(len(crashes) / total, 4) if total else 0.0,
        "latency_p50_ms": round(statistics.median(lat), 1) if lat else 0.0,
        "latency_max_ms": round(max(lat), 1) if lat else 0.0,
        "flip_attempts": len(flips),
        "verified_flips": sum(1 for f in flips if f.verified),
        "invariance_violations": sum(len(r.violations) for r in invariance),
        "avg_invariance_score": round(
            statistics.mean([r.invariance_score for r in invariance]), 4) if invariance else None,
        "mean_confidence_drift": round(statistics.mean(drifts), 4) if drifts else 0.0,
        "max_confidence_drift": round(max((rep.max_conf_drift for rep in invariance), default=0.0), 4),
        "total_findings": len(findings),
        "findings_by_severity": sev_counts,
    }


def write_html(summary: dict, path: str, findings: Optional[List[Finding]] = None,
               methodology: Optional[dict] = None):
    findings = findings or []
    methodology = methodology or {}

    sev_chips = "".join(
        f"<span class=chip style='background:{_SEV_COLOR[s]}22;color:{_SEV_COLOR[s]};"
        f"border:1px solid {_SEV_COLOR[s]}55'>{s}: {summary['findings_by_severity'].get(s,0)}</span>"
        for s in _SEV_ORDER)

    metric_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in summary.items() if k != "findings_by_severity")

    method_rows = "".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in methodology.items())

    finding_cards = "".join(_finding_card(f) for f in findings) or \
        "<p>No findings.</p>"

    doc = f"""<!doctype html><meta charset=utf-8>
<title>Robustness Report</title>
<style>
 body{{font:14px/1.5 system-ui;margin:2rem;max-width:960px;background:#0b1220;color:#dbe4f0}}
 h1,h2{{color:#5eead4}} h1{{margin-bottom:.2rem}}
 table{{border-collapse:collapse;margin:.5rem 0 1.5rem;width:100%}}
 td,th{{border:1px solid #22314f;padding:.4rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#111c33}}
 .chip{{display:inline-block;padding:.15rem .55rem;border-radius:999px;margin:.15rem .3rem .15rem 0;font-size:12px;font-weight:600}}
 .card{{border:1px solid #22314f;border-left-width:4px;border-radius:8px;padding:.8rem 1rem;margin:.6rem 0;background:#0f1a2e}}
 .card h3{{margin:.1rem 0 .3rem;font-size:15px}}
 .sev{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}}
 .ev{{font-family:ui-monospace,monospace;font-size:12px;color:#a9b6cc;white-space:pre-wrap;word-break:break-word}}
 .rem{{margin-top:.5rem;color:#c7f9e9}}
 .rem b{{color:#5eead4}}
</style>
<h1>Adversarial Input Robustness Report</h1>
<div>{sev_chips}</div>
<h2>Findings ({len(findings)}) — ranked by severity</h2>
{finding_cards}
<h2>Metrics</h2><table>{metric_rows}</table>
<h2>Methodology</h2><table>{method_rows}</table>
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def _finding_card(f: Finding) -> str:
    color = _SEV_COLOR.get(f.severity, "#8a97b0")
    ev = "\n".join(f"{k}: {v}" for k, v in f.evidence.items())
    return (
        f"<div class=card style='border-left-color:{color}'>"
        f"<h3>{html.escape(f.title)} "
        f"<span class=sev style='color:{color}'>[{f.severity} {f.severity_score}]</span></h3>"
        f"<div class=ev>{html.escape(ev)}</div>"
        f"<div class=rem><b>Remediation:</b> {html.escape(f.remediation)}</div>"
        f"</div>"
    )
