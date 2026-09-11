"""Frozen data contracts. FREEZE THESE FIRST.

Everyone on the team codes against these three objects. As long as the shapes
below don't change, your five workstreams never block each other.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Category(str, Enum):
    """The four rubric categories. Add your own if you want more."""
    MALFORMED = "malformed"       # malformed / oversized payloads
    BOUNDARY = "boundary"         # boundary values & type confusion
    ADVERSARIAL = "adversarial"   # adversarial perturbations / prompt injection
    ENCODING = "encoding"         # unicode / nesting / encoding tricks


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Attack:
    """One thing you fire at the target."""
    id: str
    category: Category
    payload: Any                       # usually str; may be int/list/dict for type confusion
    name: str = ""
    meta: dict = field(default_factory=dict)


@dataclass
class Prediction:
    """What the target returns."""
    label: str
    confidence: float
    raw: dict = field(default_factory=dict)


@dataclass
class Result:
    """What happened when an Attack met the target."""
    attack_id: str
    category: Category
    ok: bool                           # did the endpoint answer without error?
    status: Optional[int]
    latency_ms: float
    prediction: Optional[Prediction]
    error: Optional[str] = None
    finding: Optional[str] = None       # "crash" | "flip" | "inconsistency" | "leak" | None
    severity: Optional[str] = None
    meta: dict = field(default_factory=dict)


def make_attack(category: Category, payload: Any, name: str = "", **meta) -> Attack:
    """Convenience constructor — hashes the payload into a stable id."""
    digest = hashlib.sha1(f"{category}:{payload!r}".encode("utf-8", "replace")).hexdigest()[:12]
    return Attack(id=digest, category=category, payload=payload, name=name or digest, meta=meta)


@dataclass
class Finding:
    """A normalized, ranked, JSON-serializable finding.

    This is the unit the report and the dashboard both consume. Everything
    upstream (crashes, flips, invariance violations) is converted into Findings
    so there's ONE ranked list with severity + remediation attached.
    """
    type: str                      # crash | verified_flip | invariance_label_flip | ...
    title: str
    severity: str                  # info | low | medium | high | critical
    severity_score: float          # 0-10
    category: str                  # rubric category, or "adversarial" / "invariance"
    evidence: dict = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "title": self.title,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "category": self.category,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
