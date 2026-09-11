"""One-command before/after demo of the remediation shim.

Prerequisites (three terminals, all in the venv):
  1) target:  python3 -m uvicorn target_stub.server:app --port 8000
  2) shim:    python3 -m uvicorn shim.server:app --port 8001
  3) this:    python3 demo.py

It runs the identical attack suite twice — once against the raw target (8000)
and once through the shim (8001) — then prints the severity drop and checks that
the shim didn't change any predictions on legitimate (clean) traffic.
"""
from __future__ import annotations

import sqlite3
import subprocess
import sys

import httpx

SEEDS = "seeds.txt"
TARGET = "http://127.0.0.1:8000"
SHIM = "http://127.0.0.1:8001"
SEVS = ["critical", "high", "medium", "low", "info"]


def run_pipeline(url, db):
    print(f"\n=== running suite against {url}  ->  {db} ===")
    subprocess.run([sys.executable, "main.py", "--url", url,
                    "--seeds", SEEDS, "--db", db], check=True)


def sev_counts(db):
    con = sqlite3.connect(db)
    rows = con.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity").fetchall()
    con.close()
    d = {s: 0 for s in SEVS}
    for s, n in rows:
        d[s] = n
    return d


def benign_check(seeds):
    changed = 0
    with httpx.Client(timeout=10.0) as c:
        for s in seeds:
            a = c.post(f"{TARGET}/predict", json={"text": s}).json()
            b = c.post(f"{SHIM}/predict", json={"text": s}).json()
            if a["label"] != b["label"]:
                changed += 1
    return len(seeds), changed


def main():
    run_pipeline(TARGET, "baseline.db")
    run_pipeline(SHIM, "shielded.db")

    b, s = sev_counts("baseline.db"), sev_counts("shielded.db")

    print("\n================  BEFORE  /  AFTER  ================")
    print(f"{'severity':<10}{'baseline':>10}{'shielded':>10}{'drop':>8}")
    for sev in SEVS:
        print(f"{sev:<10}{b[sev]:>10}{s[sev]:>10}{b[sev]-s[sev]:>8}")
    tb, ts = sum(b.values()), sum(s.values())
    print(f"{'TOTAL':<10}{tb:>10}{ts:>10}{tb-ts:>8}")

    chb, chs = b["critical"] + b["high"], s["critical"] + s["high"]
    print(f"\ncritical + high findings:  {chb}  ->  {chs}")

    seeds = [l.strip() for l in open(SEEDS, encoding="utf-8") if l.strip()]
    total, changed = benign_check(seeds)
    pct = 100 * (total - changed) / total if total else 100
    print(f"benign traffic:            {total} clean inputs, {changed} changed by the shim "
          f"({pct:.0f}% unchanged)")

    print("\n---------------------------------------------------")
    verdict = "PASS" if chs < chb else "NO CHANGE"
    tail = "no impact on legitimate traffic" if changed == 0 else f"{changed} legit prediction(s) changed"
    print(f"VERDICT [{verdict}]: shim removed {chb-chs} critical/high finding(s), {tail}.")
    print("---------------------------------------------------")


if __name__ == "__main__":
    main()
