"""Feedback-guided minimal-flip hunter — the sensitivity probe.

Uses the target's OWN confidence as a homing signal (coverage-guided fuzzing,
applied to a black-box model). Steps:

  1. Rank tokens by importance: mask each one, see how far confidence moves.
  2. Greedily perturb the highest-importance tokens first, using your operators,
     until the predicted label flips.
  3. Minimize the edit set: drop any edit that isn't needed to keep the flip.
  4. Gate through the semantic check: a flip only counts if meaning is preserved.

Needs at least one Operator registered (see plugins.py). Assumes the target
returns only the TOP label + its confidence — a realistic black box.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

from .registry import OPERATORS, Operator
from .semantic import SemanticGate

if TYPE_CHECKING:  # engine only needs an object with `async predict(text)`
    from .target import TargetClient


@dataclass
class FlipResult:
    original: str
    adversarial: str
    original_label: str
    adversarial_label: str
    original_confidence: float
    adversarial_confidence: float
    edits: list            # list of (index, old_token, new_token, operator_name)
    queries_used: int
    semantic_similarity: float
    verified: bool         # meaning preserved AND label flipped


class _Budget:
    def __init__(self, n: int):
        self.left = n
        self.used = 0

    def spend(self):
        self.left -= 1
        self.used += 1

    def ok(self) -> bool:
        return self.left > 0


def _tok(text: str) -> List[str]:
    return text.split(" ")


def _detok(tokens: List[str]) -> str:
    return " ".join(tokens)


async def hunt(
    client: "TargetClient",
    seed: str,
    semantic_gate: Optional[SemanticGate] = None,
    operators: Optional[List[Operator]] = None,
    budget: int = 200,
    meaning_preserving_only: bool = True,
) -> Optional[FlipResult]:
    ops = operators if operators is not None else OPERATORS
    ops = [o for o in ops if (o.meaning_preserving or not meaning_preserving_only)]
    if not ops:
        return None  # nothing registered to perturb with

    b = _Budget(budget)
    base = await client.predict(seed); b.spend()
    base_label, base_conf = base.label, base.confidence
    tokens = _tok(seed)

    # 1. importance via masking
    importance = []
    for i in range(len(tokens)):
        if not b.ok():
            break
        masked = tokens[:i] + [""] + tokens[i + 1:]
        try:
            p = await client.predict(_detok(masked)); b.spend()
        except Exception:
            importance.append((i, 0.0)); continue
        importance.append((i, 1e9 if p.label != base_label else base_conf - p.confidence))
    importance.sort(key=lambda x: x[1], reverse=True)

    # 2. greedy perturbation
    cur = list(tokens)
    edits = []
    cur_label = base_label
    for idx, _score in importance:
        if not b.ok() or cur_label != base_label:
            break
        best = None  # (candidate, prediction, op_name, sort_score)
        for op in ops:
            for cand in op.apply(tokens[idx]):
                if not b.ok():
                    break
                trial = list(cur); trial[idx] = cand
                try:
                    p = await client.predict(_detok(trial)); b.spend()
                except Exception:
                    continue
                if p.label != base_label:                 # flip: take it immediately
                    best = (cand, p, op.name, -1.0); break
                if best is None or p.confidence < best[3]:  # else steer toward the boundary
                    best = (cand, p, op.name, p.confidence)
            if best and best[1].label != base_label:
                break
        if best is None:
            continue
        cand, p, op_name, _ = best
        if cand != tokens[idx]:
            cur[idx] = cand
            edits.append((idx, tokens[idx], cand, op_name))
            cur_label = p.label

    if cur_label == base_label:
        return None  # no flip within budget

    # 3. minimize the edit set
    minimized = list(edits)
    i = 0
    while i < len(minimized):
        trial_edits = minimized[:i] + minimized[i + 1:]
        trial = list(tokens)
        for (idx, _old, new, _op) in trial_edits:
            trial[idx] = new
        try:
            p = await client.predict(_detok(trial)); b.spend()
        except Exception:
            i += 1; continue
        if p.label != base_label:
            minimized = trial_edits  # edit i was unnecessary; list shrank, don't advance
        else:
            i += 1

    final_tokens = list(tokens)
    for (idx, _old, new, _op) in minimized:
        final_tokens[idx] = new
    adversarial = _detok(final_tokens)
    final = await client.predict(adversarial); b.spend()

    sim = semantic_gate.similarity(seed, adversarial) if semantic_gate else -1.0
    verified = bool(semantic_gate and semantic_gate.passes(seed, adversarial)) and final.label != base_label

    return FlipResult(
        original=seed, adversarial=adversarial,
        original_label=base_label, adversarial_label=final.label,
        original_confidence=base_conf, adversarial_confidence=final.confidence,
        edits=minimized, queries_used=b.used,
        semantic_similarity=sim, verified=verified,
    )
