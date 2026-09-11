"""Findings assembler.

Converts raw results (static suite), flips (sensitivity), and invariance reports
into ONE ranked list of Finding objects, each with a severity score and a
concrete remediation. This is the single source of truth the report and the
dashboard both render.
"""
from __future__ import annotations

from typing import List, Optional

from . import remediation, severity
from .fliphunter import FlipResult
from .metamorphic import InvarianceReport
from .models import Finding, Result


def build_findings(
    results: List[Result],
    flips: List[Optional[FlipResult]],
    invariance: List[InvarianceReport],
    tau: float = 0.85,
    latency_flag_ms: float = 1000.0,
) -> List[Finding]:
    out: List[Finding] = []

    # --- static suite: crashes, rejected inputs, slow responses ---
    for r in results:
        cat = r.category.value if hasattr(r.category, "value") else str(r.category)
        if r.finding == "crash":
            out.append(_finding("crash", f"Endpoint crashed on {cat} input", cat,
                                {"attack_id": r.attack_id, "status": r.status,
                                 "error": r.error, "latency_ms": round(r.latency_ms, 1)}))
        elif not r.ok and r.status and 400 <= r.status < 500:
            out.append(_finding("input_rejected", f"Input rejected ({r.status}) on {cat}", cat,
                                {"attack_id": r.attack_id, "status": r.status}))
        elif r.ok and r.latency_ms >= latency_flag_ms:
            out.append(_finding("high_latency", f"Slow response on {cat} input", cat,
                                {"attack_id": r.attack_id, "latency_ms": round(r.latency_ms, 1)}))

    # --- flip hunter: verified (real) and unverified (self-rejected) ---
    for f in flips:
        if not f:
            continue
        if f.verified:
            out.append(_finding(
                "verified_flip",
                f"Verified adversarial flip: {f.original_label} -> {f.adversarial_label}",
                "adversarial",
                {"original": f.original, "adversarial": f.adversarial,
                 "orig_label": f.original_label, "adv_label": f.adversarial_label,
                 "similarity": round(f.semantic_similarity, 3), "edits": len(f.edits),
                 "queries_used": f.queries_used},
                similarity=f.semantic_similarity, edits=len(f.edits), tau=tau))
        else:
            out.append(_finding(
                "unverified_flip",
                "Flip found but rejected (meaning changed too much)",
                "adversarial",
                {"original": f.original, "adversarial": f.adversarial,
                 "similarity": round(f.semantic_similarity, 3)}))

    # --- invariance oracle: self-inconsistency ---
    for rep in invariance:
        for v in rep.violations:
            ftype = ("invariance_label_flip" if v.kind == "label_flip"
                     else "invariance_confidence_drift")
            out.append(_finding(
                ftype,
                f"Invariance violation ({v.kind}) via {v.operator}",
                "invariance",
                {"seed": rep.seed, "variant": v.variant, "operator": v.operator,
                 "seed_label": rep.seed_label, "variant_label": v.variant_label,
                 "similarity": round(v.similarity, 3), "kind": v.kind},
                similarity=v.similarity, tau=tau))

    # rank: highest severity first
    out.sort(key=lambda f: f.severity_score, reverse=True)
    return out


def _finding(ftype, title, category, evidence, similarity=None, edits=None, tau=0.85) -> Finding:
    s = severity.score(ftype, similarity=similarity, edits=edits, tau=tau)
    return Finding(
        type=ftype, title=title, severity=severity.band(s), severity_score=s,
        category=category, evidence=evidence, remediation=remediation.for_finding(ftype),
    )
