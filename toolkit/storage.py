"""Durable results in SQLite. The dashboard reads straight from this file.

reset=True (the default from main.py) drops and recreates the tables so every
run starts clean — a second run can't double-count. Pass --append on the CLI to
keep history instead.
"""
from __future__ import annotations

import json
import sqlite3
from typing import List

from .fliphunter import FlipResult
from .metamorphic import InvarianceReport
from .models import Finding, Result


class Storage:
    def __init__(self, path: str = "results.db", reset: bool = False):
        self.conn = sqlite3.connect(path)
        if reset:
            self._drop()
        self._init()

    def _drop(self):
        c = self.conn.cursor()
        for t in ("results", "flips", "invariance", "findings"):
            c.execute(f"DROP TABLE IF EXISTS {t}")
        self.conn.commit()

    def _init(self):
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS results(
            attack_id TEXT, category TEXT, ok INTEGER, status INTEGER,
            latency_ms REAL, label TEXT, confidence REAL, error TEXT,
            finding TEXT, severity TEXT, meta TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS flips(
            original TEXT, adversarial TEXT, orig_label TEXT, adv_label TEXT,
            orig_conf REAL, adv_conf REAL, edits INTEGER, queries INTEGER,
            similarity REAL, verified INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS invariance(
            seed TEXT, seed_label TEXT, operator TEXT, variant TEXT,
            variant_label TEXT, variant_conf REAL, similarity REAL, kind TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS findings(
            type TEXT, title TEXT, severity TEXT, severity_score REAL,
            category TEXT, remediation TEXT, evidence TEXT)""")
        self.conn.commit()

    def save_result(self, r: Result):
        cat = r.category.value if hasattr(r.category, "value") else str(r.category)
        self.conn.execute(
            "INSERT INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (r.attack_id, cat, 1 if r.ok else 0, r.status if r.status is not None else -1,
             r.latency_ms, r.prediction.label if r.prediction else None,
             r.prediction.confidence if r.prediction else None, r.error,
             r.finding, r.severity, json.dumps(r.meta)))
        self.conn.commit()

    def save_flip(self, f: FlipResult):
        self.conn.execute(
            "INSERT INTO flips VALUES(?,?,?,?,?,?,?,?,?,?)",
            (f.original, f.adversarial, f.original_label, f.adversarial_label,
             f.original_confidence, f.adversarial_confidence, len(f.edits),
             f.queries_used, f.semantic_similarity, 1 if f.verified else 0))
        self.conn.commit()

    def save_invariance(self, rep: InvarianceReport):
        for v in rep.violations:
            self.conn.execute(
                "INSERT INTO invariance VALUES(?,?,?,?,?,?,?,?)",
                (rep.seed, rep.seed_label, v.operator, v.variant,
                 v.variant_label, v.variant_confidence, v.similarity, v.kind))
        self.conn.commit()

    def save_findings(self, findings: List[Finding]):
        for f in findings:
            self.conn.execute(
                "INSERT INTO findings VALUES(?,?,?,?,?,?,?)",
                (f.type, f.title, f.severity, f.severity_score,
                 f.category, f.remediation, json.dumps(f.evidence)))
        self.conn.commit()

    def close(self):
        self.conn.close()
