"""Entrypoint: run the whole pipeline against a target.

    python main.py --url http://127.0.0.1:8000 --seeds seeds.txt

Idempotent by default (wipes its own tables each run so a second run can't
double-count). Pass --append to keep history. Fails gracefully on an empty
seeds file or an unreachable target, and prints its own methodology so the
output is self-justifying.
"""
from __future__ import annotations

import argparse
import asyncio
import sys

import plugins  # noqa: F401  -> registers your payloads/operators on import

from toolkit import severity
from toolkit.config import Config
from toolkit.findings import build_findings
from toolkit.fliphunter import hunt
from toolkit.metamorphic import check_invariance
from toolkit.registry import OPERATORS, build_attacks
from toolkit.report import summarize, write_html
from toolkit.runner import run_suite
from toolkit.semantic import SemanticGate
from toolkit.storage import Storage
from toolkit.target import TargetClient, TargetError


def _load_seeds(path):
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(f"[!] seeds file not found: {path} (continuing with static suite only)")
        return []


async def _preflight(client) -> bool:
    """Confirm the target is reachable before doing real work."""
    try:
        await client.predict("preflight check")
        return True
    except TargetError as e:
        print(f"[!] target unreachable at {client.url}")
        print(f"    {e.message}")
        print("    Is the server running?  python3 -m uvicorn target_stub.server:app --port 8000")
        return False


async def run(cfg: Config, seeds, reset: bool):
    client = TargetClient(cfg.target_url, cfg.predict_path, cfg.timeout_s)
    gate = SemanticGate(cfg.semantic_model, cfg.semantic_tau)

    if not await _preflight(client):
        await client.aclose()
        sys.exit(2)

    # --- self-documenting methodology (printed AND saved to the report) ---
    methodology = {
        "target": client.url,
        "semantic_gate": f"{gate.backend} (tau={cfg.semantic_tau}: a flip counts "
                         f"only if cosine similarity >= {cfg.semantic_tau})",
        "seeds_tested": len(seeds),
        "query_budget_per_seed": cfg.query_budget,
        "operators_registered": ", ".join(o.name for o in OPERATORS) or "(none)",
        "severity_model": severity.DESCRIPTION,
        "reset_each_run": reset,
    }
    print("=== Methodology ===")
    for k, v in methodology.items():
        print(f"  {k}: {v}")
    print("===================")

    if not seeds:
        print("[!] no seeds — flip hunter and invariance oracle will be skipped.")
    if not OPERATORS:
        print("[!] no operators registered — flip hunter and oracle can't perturb. See plugins.py.")

    store = Storage(cfg.db_path, reset=reset)

    # 1) static suite
    attacks = build_attacks()
    print(f"[*] firing {len(attacks)} static attacks ...")
    results = await run_suite(client, attacks, cfg.concurrency, on_result=store.save_result)

    # 2) flip hunter + 3) invariance oracle (each seed guarded independently)
    flips, invs = [], []
    for seed in seeds:
        try:
            flip = await hunt(client, seed, gate, budget=cfg.query_budget)
            if flip:
                store.save_flip(flip)
            flips.append(flip)
        except Exception as e:
            print(f"[!] flip hunter failed on seed {seed!r} -> {type(e).__name__}: {e}")

        try:
            rep = await check_invariance(client, seed, gate,
                                         conf_drift_threshold=cfg.conf_drift_threshold)
            store.save_invariance(rep)
            invs.append(rep)
            print(f"[*] invariance: seed={seed!r} tested={rep.tested} "
                  f"violations={len(rep.violations)} score={rep.invariance_score:.3f} "
                  f"mean_drift={rep.mean_conf_drift:.3f}")
        except Exception as e:
            print(f"[!] invariance failed on seed {seed!r} -> {type(e).__name__}: {e}")

    # 4) unified, ranked findings + report
    findings = build_findings(results, flips, invs, tau=cfg.semantic_tau,
                              latency_flag_ms=cfg.latency_flag_ms)
    store.save_findings(findings)
    summary = summarize(results, flips, invs, findings)
    write_html(summary, cfg.report_path, findings=findings, methodology=methodology)

    print("[*] summary:", summary)
    print(f"[*] {len(findings)} findings ranked; report -> {cfg.report_path}  (db: {cfg.db_path})")

    await client.aclose()
    store.close()


def main():
    ap = argparse.ArgumentParser(description="Adversarial Input Red-Teaming Toolkit")
    ap.add_argument("--url", default=Config.target_url)
    ap.add_argument("--path", default=Config.predict_path)
    ap.add_argument("--seeds", default=None, help="text file, one seed sentence per line")
    ap.add_argument("--budget", type=int, default=Config.query_budget)
    ap.add_argument("--concurrency", type=int, default=Config.concurrency)
    ap.add_argument("--db", default=Config.db_path, help="SQLite output path")
    ap.add_argument("--append", action="store_true",
                    help="keep previous results instead of wiping the DB each run")
    args = ap.parse_args()

    cfg = Config(target_url=args.url, predict_path=args.path,
                 query_budget=args.budget, concurrency=args.concurrency,
                 db_path=args.db)
    asyncio.run(run(cfg, _load_seeds(args.seeds), reset=not args.append))


if __name__ == "__main__":
    main()
