"""Metamorphic invariance oracle — the toolkit's unique feature.

Metamorphic testing is a classic software-QA idea: you may not know the correct
output, but you know a RELATION that must hold between related inputs. Here the
relation is invariance:

    If two inputs mean the same thing, the model must give the same label.

So for each seed we apply every *meaning-preserving* operator, verify (via the
semantic gate) that meaning really was preserved, then query the model on each
variant. Any label change is an invariance VIOLATION — the model is
self-inconsistent on inputs a human calls identical. Even a large confidence
swing with no label change is flagged as silent degradation.

Why this is the dual of the flip hunter, and why it's worth talking about:
    - Flip hunter  -> SEARCHES for one small meaning-preserving edit that flips
                      the label (proves the model is over-sensitive).
    - Invariance   -> SYSTEMATICALLY checks that meaning-preserving edits DON'T
                      flip the label (measures how often the model is
                      inconsistent, as a score).

Both run off the *same* operator registry and the *same* semantic gate, and both
turn each seed you add into a whole family of tests for free — which is exactly
why the empty-payload design is a force multiplier here, not a limitation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional

from .registry import OPERATORS, Operator
from .semantic import SemanticGate

if TYPE_CHECKING:  # engine only needs an object with `async predict(text)`
    from .target import TargetClient


@dataclass
class InvarianceViolation:
    operator: str
    variant: str
    variant_label: str
    variant_confidence: float
    similarity: float
    kind: str  # "label_flip" | "confidence_drift"


@dataclass
class InvarianceReport:
    seed: str
    seed_label: str
    seed_confidence: float
    tested: int
    violations: List[InvarianceViolation] = field(default_factory=list)
    invariance_score: float = 1.0  # fraction of variants the model stayed consistent on
    mean_conf_drift: float = 0.0   # avg |confidence change| under meaning-preserving edits
    max_conf_drift: float = 0.0    # worst |confidence change| observed


async def check_invariance(
    client: "TargetClient",
    seed: str,
    semantic_gate: Optional[SemanticGate] = None,
    operators: Optional[List[Operator]] = None,
    conf_drift_threshold: float = 0.15,
    verify_similarity: bool = True,
) -> InvarianceReport:
    ops = [o for o in (operators if operators is not None else OPERATORS) if o.meaning_preserving]
    base = await client.predict(seed)

    violations: List[InvarianceViolation] = []
    drifts: List[float] = []
    tested = 0
    for op in ops:
        for variant in op.apply(seed):
            if variant == seed:
                continue
            sim = semantic_gate.similarity(seed, variant) if semantic_gate else 1.0
            # Guard against a mis-tagged operator that actually changed meaning.
            if verify_similarity and semantic_gate and not semantic_gate.passes(seed, variant):
                continue
            try:
                p = await client.predict(variant)
            except Exception:
                continue
            tested += 1
            drift = abs(base.confidence - p.confidence)
            drifts.append(drift)
            if p.label != base.label:
                violations.append(InvarianceViolation(
                    op.name, variant, p.label, p.confidence, sim, "label_flip"))
            elif drift >= conf_drift_threshold:
                violations.append(InvarianceViolation(
                    op.name, variant, p.label, p.confidence, sim, "confidence_drift"))

    score = 1.0 - (len(violations) / tested) if tested else 1.0
    return InvarianceReport(
        seed=seed, seed_label=base.label, seed_confidence=base.confidence,
        tested=tested, violations=violations, invariance_score=score,
        mean_conf_drift=round(sum(drifts) / len(drifts), 4) if drifts else 0.0,
        max_conf_drift=round(max(drifts), 4) if drifts else 0.0,
    )
