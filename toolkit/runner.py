"""Fires the static suite at the target and records response / error / latency.

A non-answer (timeout, transport error, or HTTP 5xx) is a "crash" finding.
A 4xx means the endpoint rejected the input — noted, but not a crash.
"""
from __future__ import annotations

import asyncio
import time
from typing import Callable, List, Optional

from .models import Attack, Result
from .target import TargetClient, TargetError


async def _run_one(client: TargetClient, attack: Attack) -> Result:
    t0 = time.perf_counter()
    try:
        pred = await client.predict(attack.payload)
        latency = (time.perf_counter() - t0) * 1000
        return Result(
            attack_id=attack.id, category=attack.category, ok=True,
            status=200, latency_ms=latency, prediction=pred,
        )
    except TargetError as e:
        latency = (time.perf_counter() - t0) * 1000
        is_crash = e.status is None or e.status >= 500
        return Result(
            attack_id=attack.id, category=attack.category, ok=False,
            status=e.status, latency_ms=latency, prediction=None,
            error=e.message,
            finding="crash" if is_crash else None,
            severity="high" if is_crash else None,
        )


async def run_suite(
    client: TargetClient,
    attacks: List[Attack],
    concurrency: int = 8,
    on_result: Optional[Callable[[Result], None]] = None,
) -> List[Result]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Result] = []

    async def worker(a: Attack) -> Result:
        async with sem:
            r = await _run_one(client, a)
            if on_result:
                on_result(r)
            return r

    tasks = [asyncio.create_task(worker(a)) for a in attacks]
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    return results
