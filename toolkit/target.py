"""The one door to the target. Everything talks to the AI through here.

Contract:  POST {predict_path}  body: {"text": <payload>}
           200 -> {"label": str, "confidence": float}
           anything else -> a TargetError the runner records as a finding.
"""
from __future__ import annotations

import httpx

from .models import Prediction


class TargetError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.message = message
        self.status = status


class TargetClient:
    def __init__(self, base_url: str, path: str = "/predict", timeout: float = 10.0):
        self.url = base_url.rstrip("/") + path
        self._client = httpx.AsyncClient(timeout=timeout)

    async def predict(self, text) -> Prediction:
        try:
            resp = await self._client.post(self.url, json={"text": text})
        except httpx.TimeoutException as e:
            raise TargetError(f"timeout: {e}")
        except httpx.HTTPError as e:
            raise TargetError(f"transport error: {e}")

        if resp.status_code >= 400:
            raise TargetError(f"http {resp.status_code}: {resp.text[:200]}", status=resp.status_code)

        try:
            data = resp.json()
        except Exception:
            raise TargetError(f"non-JSON response: {resp.text[:200]}", status=resp.status_code)

        try:
            return Prediction(label=str(data["label"]), confidence=float(data["confidence"]), raw=data)
        except Exception:
            raise TargetError(f"unexpected schema: {data}", status=resp.status_code)

    async def aclose(self):
        await self._client.aclose()
