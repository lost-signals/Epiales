"""Input normaliser — the actual fix for the homoglyph / zero-width attack class.

Pure, testable function. This is what the report's remediation advice tells you
to do, implemented: NFKC normalisation, confusable (homoglyph) folding,
zero-width stripping, and a size cap. It maps look-alike characters back to
their plain ASCII form BEFORE the model sees them, so the attacks that relied on
invisible substitutions no longer reach the model.
"""
from __future__ import annotations

import unicodedata

# Common cross-script look-alikes -> Latin. NFKC does NOT handle these (they're
# separate scripts, not compatibility equivalents), so we map them explicitly.
_CONFUSABLES = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b",
    "А": "A", "Е": "E", "О": "O", "С": "C", "Р": "P", "Х": "X", "У": "Y",
    # Greek -> Latin
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "χ": "x", "ι": "i", "κ": "k",
    "μ": "m", "ν": "v", "Ο": "O", "Α": "A", "Ε": "E", "Ρ": "P",
}

_ZERO_WIDTH = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u00ad"]

MAX_LEN = 10_000


def normalize(text, max_len: int = MAX_LEN):
    """Return (clean_text, applied) where `applied` lists which defences fired."""
    applied = []
    s = text if isinstance(text, str) else str(text)

    before = s
    for zw in _ZERO_WIDTH:
        s = s.replace(zw, "")
    if s != before:
        applied.append("zero_width_strip")

    before = s
    s = "".join(_CONFUSABLES.get(ch, ch) for ch in s)
    if s != before:
        applied.append("confusable_fold")

    before = s
    s = unicodedata.normalize("NFKC", s)
    if s != before:
        applied.append("nfkc")

    if len(s) > max_len:
        s = s[:max_len]
        applied.append("size_cap")

    return s, applied
