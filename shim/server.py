"""Remediation shim — a normalising reverse proxy.

Runs on its own port (default 8001), cleans each input with the normaliser,
forwards it to the REAL target, and returns the target's answer. Re-running the
identical attack suite against this URL instead of the target is the "prove the
fix works" step: the character-level attacks are neutralised before the model
sees them.

    pip install fastapi uvicorn httpx
    # target must already be running on 8000
    python3 -m uvicorn shim.server:app --port 8001

Point the toolkit at it:  python3 main.py --url http://127.0.0.1:8001 ...
"""
from __future__ import annotations

import os

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from shim.normalizer import normalize

UPSTREAM = os.environ.get("SHIM_UPSTREAM", "http://127.0.0.1:8000/predict")

app = FastAPI()


class Req(BaseModel):
    text: object  # permissive, so type-confusion payloads reach the normaliser


@app.post("/predict")
async def predict(req: Req):
    clean, applied = normalize(req.text)
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post(UPSTREAM, json={"text": clean})
    data = r.json()
    data["_shim_applied"] = applied  # transparency: what the shim cleaned
    return data
