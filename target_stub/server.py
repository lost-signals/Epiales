"""The TARGET (punching bag) — NOT part of the toolkit.

This is the AI you attack, wrapped behind one URL. Infra owns this. It's here so
the toolkit has something to hit on Day 1. It deliberately does NOT harden any
input — that's the whole point; your toolkit's job is to find where it breaks.

    pip install fastapi uvicorn
    # optional, for a real model:  pip install transformers torch
    uvicorn target_stub.server:app --port 8000

Contract:  POST /predict  {"text": <anything>}  ->  {"label": str, "confidence": float}
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# Try to load a real classifier; fall back to a trivial rule so it runs anywhere.
_clf = None
try:
    from transformers import pipeline
    _clf = pipeline("sentiment-analysis")
except Exception:
    _clf = None


class Req(BaseModel):
    text: object  # intentionally permissive so type-confusion payloads reach us


@app.post("/predict")
def predict(req: Req):
    text = req.text
    # NOTE: no size cap, no normalisation, no validation — on purpose.
    if _clf is not None:
        out = _clf(str(text))[0]
        return {"label": out["label"].lower(), "confidence": float(out["score"])}
    # Fallback toy model: length-parity "sentiment". Good enough to demo flips.
    s = str(text)
    label = "positive" if len(s) % 2 == 0 else "negative"
    conf = 0.5 + (len(s) % 50) / 100.0
    return {"label": label, "confidence": round(min(conf, 0.99), 4)}
