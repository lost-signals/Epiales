"""Extension points. THE PAYLOAD SPACE IS INTENTIONALLY EMPTY.

You register two kinds of things here (from plugins.py, not from inside the engine):

  1. PAYLOADS  — the actual attack inputs, grouped by Category.
  2. OPERATORS — text transforms used by the flip hunter and the metamorphic oracle.

The engine ships complete. It just has nothing to fire until you fill these in.
See plugins.py for the exact signatures.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List

from .models import Attack, Category

# --------------------------------------------------------------------------- #
# PAYLOADS — empty by design. Populate via @payload(...) in plugins.py
# --------------------------------------------------------------------------- #
PAYLOADS: dict[Category, List[Callable[[], object]]] = {c: [] for c in Category}


def payload(category: Category):
    """Decorator. Wrap a function that returns an Attack (or an iterable of Attacks)."""
    def deco(fn: Callable[[], object]):
        PAYLOADS[category].append(fn)
        return fn
    return deco


def build_attacks() -> List[Attack]:
    """Flatten every registered payload factory into a list of Attacks."""
    out: List[Attack] = []
    for factories in PAYLOADS.values():
        for factory in factories:
            produced = factory()
            if isinstance(produced, Attack):
                out.append(produced)
            else:
                out.extend(produced)
    return out


# --------------------------------------------------------------------------- #
# OPERATORS — empty by design. Populate via @operator(...) in plugins.py
# --------------------------------------------------------------------------- #
@dataclass
class Operator:
    name: str
    apply: Callable[[str], Iterable[str]]  # text -> candidate variants
    meaning_preserving: bool               # True => used by the invariance oracle too


OPERATORS: List[Operator] = []


def operator(name: str, meaning_preserving: bool):
    """Decorator. Wrap a function `text -> iterable of variant strings`.

    Set meaning_preserving=True for transforms a human would call "the same
    sentence" (whitespace, case, homoglyphs, synonyms). Those feed BOTH the
    flip hunter and the metamorphic invariance oracle. Set it False for
    transforms that legitimately change meaning (used by the flip hunter only).
    """
    def deco(fn: Callable[[str], Iterable[str]]):
        OPERATORS.append(Operator(name=name, apply=fn, meaning_preserving=meaning_preserving))
        return fn
    return deco
