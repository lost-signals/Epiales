"""Semantic gate: does variant B still MEAN the same as original A?

This is the only ML *inside* the toolkit, and you don't build or train it —
you import it. If sentence-transformers isn't installed, it degrades to a
lexical (character-overlap) fallback so the pipeline never dies. The fallback
is NOT semantic; install the library for real results, and say so to judges.
"""
from __future__ import annotations

import difflib


class SemanticGate:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", tau: float = 0.85):
        self.tau = tau
        self.backend = "lexical-fallback"
        self._model = None
        self._util = None
        try:
            from sentence_transformers import SentenceTransformer, util
            self._model = SentenceTransformer(model_name)
            self._util = util
            self.backend = "sentence-transformers"
        except Exception:
            pass

    def similarity(self, a: str, b: str) -> float:
        if self._model is not None:
            emb = self._model.encode([a, b], convert_to_tensor=True)
            return float(self._util.cos_sim(emb[0], emb[1]))
        return difflib.SequenceMatcher(None, a, b).ratio()

    def passes(self, a: str, b: str) -> bool:
        return self.similarity(a, b) >= self.tau
