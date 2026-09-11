# Epiales

**Adversarial Input Red-Teaming & Remediation for Text Classifiers**

Epiales fires adversarial and malformed inputs at a deployed AI inference
endpoint, verifies which findings are *real*, ranks them by severity, attaches a
concrete fix to each, and then **proves the fix works** by re-running the
identical suite through a remediation layer — all from a browser dashboard or the
command line.

It is **black-box** (score-based): it only ever sends `{"text": ...}` and reads
`{"label", "confidence"}`. It never touches model weights, gradients, or training
data, so it works against any text-classification endpoint — the toolkit is the
attacker, the model is only a target behind a URL.

> Built for the School of Cyber Defense by **Rochester Institute of Technology Dubai**.

---

## Table of contents
1. [What it does](#what-it-does)
2. [Architecture](#architecture)
3. [Repository layout](#repository-layout)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Quick start (TL;DR)](#quick-start-tldr)
7. [Running each component](#running-each-component)
8. [Using the dashboard](#using-the-dashboard)
9. [Reproducing the results](#reproducing-the-results)
10. [Adding your own attacks](#adding-your-own-attacks)
11. [Configuration](#configuration)
12. [How it works](#how-it-works)
13. [Output files](#output-files)
14. [Troubleshooting](#troubleshooting)
15. [Scope & limitations](#scope--limitations)

---

## What it does

It probes a text classifier for three failure modes:

- **Crash** — malformed, oversized, or wrong-type inputs that error the endpoint.
- **Flip** — a tiny, *meaning-preserving* edit that silently inverts the
  prediction (e.g. one invisible Cyrillic character). Verified by a semantic
  similarity gate; edits that change meaning are automatically rejected.
- **Invariance violation** — meaning-identical inputs receiving different labels,
  found by a metamorphic-testing oracle (no ground-truth label required).

Every finding is scored (0–10, CVSS-style), ranked, and paired with a concrete
remediation. A normalising **shim** implements the character-level fix; re-running
the suite through it demonstrates the drop and confirms legitimate traffic is
unaffected.

---

## Architecture

```
 plugins.py (payloads + operators)
        │
        ▼
 main.py ─► runner ─► TargetClient ──HTTP──► target model (:8000)
        │      │
        │      ├─► fliphunter   ─┐
        │      └─► metamorphic  ─┤  (both use the SemanticGate)
        │                        ▼
        │             findings.build_findings()  →  severity + remediation
        │                        ▼
        │                 SQLite (baseline.db / shielded.db)
        │                        ▼
        └──────────►  report.html   +   dashboard (:8080)   +   demo.py

 remediation shim (:8001) sits between the toolkit and the target to prove fixes.
 The browser only ever talks to the dashboard (:8080); the target and shim are
 proxied server-side, so no endpoint is exposed and there are no CORS issues.
```

---

## Repository layout

```
main.py                 pipeline entrypoint (--url --seeds --db --budget --append)
demo.py                 one-command before/after (baseline vs shielded + benign check)
plugins.py              payloads + operators  (the only file with attack content)
seeds.txt               30 borderline sentences for the flip hunter + oracle
requirements.txt
toolkit/
  models.py             Attack / Prediction / Result / Finding contracts
  registry.py           payload + operator registries
  target.py             async HTTP client for the target
  runner.py             async suite runner (captures response/error/latency)
  fliphunter.py         feedback-guided minimal-flip search
  metamorphic.py        invariance oracle
  semantic.py           semantic gate (sentence-transformers, lexical fallback)
  severity.py           0–10 severity scoring + bands
  remediation.py        finding-type → concrete fix text
  findings.py           unify results/flips/invariance → ranked findings
  storage.py            SQLite persistence
  report.py             static HTML report + summary
  config.py             all thresholds
target_stub/server.py   the target under test (DistilBERT SST-2 behind FastAPI)
shim/
  normalizer.py         NFKC + homoglyph fold + zero-width strip + size cap
  server.py             normalising reverse proxy (:8001 → :8000)
dashboard/
  server.py             FastAPI JSON API + serves the UI + run-from-browser
  static/index.html     single-file Epiales dashboard
```

---

## Prerequisites

- **Python 3.10+** (developed on 3.13)
- **~3 GB free disk** for the two models (downloaded once, then cached)
- **Internet access on first run only** — to download the models. After that it
  runs fully offline.
- Linux/macOS (developed on Kali). Windows works via WSL.

---

## Installation

Debian/Kali block system-wide `pip` (PEP 668), so use a virtual environment.

```bash
git clone https://github.com/lost-signals/Epiales.git && cd Epiales
python3 -m venv .venv
source .venv/bin/activate                 # prompt shows (.venv)
pip install -r requirements.txt           # installs torch — this is the large one
```

**Every terminal that runs any component must have the venv active**, or that
component silently falls back to a toy model / lexical gate with no error. After
the first run, set these so nothing tries to re-download:

```bash
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
```

(Optionally append both `export` lines to `~/.bashrc` / `~/.zshrc`.)

The two models download automatically on first use and cache to
`~/.cache/huggingface`:
- `distilbert-base-uncased-finetuned-sst-2-english` — the target model (~268 MB)
- `all-MiniLM-L6-v2` — the semantic gate (~90 MB)

---

## Quick start (TL;DR)

Three terminals, each with the venv active and offline flags set:

```bash
# common to every terminal:
cd epiales && source .venv/bin/activate && export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1

# Terminal 1 — the target model
python3 -m uvicorn target_stub.server:app --port 8000

# Terminal 2 — the remediation shim
python3 -m uvicorn shim.server:app --port 8001

# Terminal 3 — the dashboard
python3 -m uvicorn dashboard.server:app --port 8080
```

Open **http://127.0.0.1:8080** and drive everything from the browser: run the
suite, watch the live attack lab, and see the before/after.

Prefer the command line? With the target and shim running:

```bash
python3 demo.py            # runs baseline + shielded, prints the before/after + verdict
```

**Sanity check** the target is the real model (not the toy fallback):

```bash
curl -s -X POST http://127.0.0.1:8000/predict \
  -H 'Content-Type: application/json' -d '{"text":"this movie was absolutely fantastic"}'
# expect: {"label":"positive","confidence":0.99...}   (≈0.5 means toy fallback → check the venv)
```

---

## Running each component

**Target** (`:8000`) — the model under test. Serves
`POST /predict {"text": ...} → {"label", "confidence"}`. Deliberately
un-hardened; finding its weaknesses is the point.

**Shim** (`:8001`) — a normalising reverse proxy that cleans inputs (NFKC,
homoglyph folding, zero-width stripping, size cap) then forwards to the target.
Re-running the suite against `:8001` is the "prove the fix" step.

**Dashboard** (`:8080`) — the UI + JSON API. Reads `baseline.db` / `shielded.db`
and can launch runs itself. The browser only talks to `:8080`.

**`demo.py`** — runs the suite against the target and the shim, writes
`baseline.db` / `shielded.db`, and prints the severity before/after plus a
benign-traffic check.

**`main.py`** — a single run against one endpoint:

```bash
python3 main.py --url http://127.0.0.1:8000 --seeds seeds.txt --db baseline.db
# flags: --url  --path (default /predict)  --seeds  --db  --budget (default 200)  --append
```

Runs are **idempotent** by default (each wipes its own tables so a second run
can't double-count); `--append` keeps history.

---

## Using the dashboard

At `http://127.0.0.1:8080`:

- **Run Control** — launch the suite against the target, the shim, or both
  ("Run Full Before/After"), with a live streaming log; the before/after panel
  animates to the new numbers on completion.
- **Live Attack Lab** — type a sentence, pick an operator (or *auto*), and watch
  it flip the raw target and get fixed through the shim, with the similarity
  score shown.
- **Findings Explorer** — ranked findings with severity badges, evidence, and
  remediation; filter by severity/type; toggle Baseline/Shielded.
- **Health panel** — confirms the target/shim are reachable and which model is
  loaded (catches the toy-fallback mistake).

The dashboard reads `baseline.db` / `shielded.db`. If they are absent on first
load, either click **Run Full Before/After** in the UI or run `python3 demo.py`
once to generate them.

---

## Reproducing the results

With all three services up (real models loaded), run:

```bash
python3 demo.py
```

Expected shape (30-seed suite against DistilBERT SST-2; exact counts vary
slightly by environment):

| Metric                | Baseline | Shielded |
|-----------------------|:-------:|:--------:|
| Total findings        | 36      | 4        |
| Critical / High       | 6 / 9   | 1 / 1    |
| Verified flips        | 8       | 1        |
| Invariance violations | 9       | 2        |
| Avg invariance score  | 0.937   | 0.991    |
| Benign traffic changed| —       | 0 / 30   |

Confirm the methodology header prints `semantic_gate: sentence-transformers`
(not `lexical-fallback`). Lexical-fallback means the semantic model didn't load
(usually the venv isn't active) and the numbers are not trustworthy.

---

## Adding your own attacks

All attack content lives in `plugins.py`. Register payloads and operators:

```python
from toolkit.registry import payload, operator
from toolkit.models import Category, make_attack

@payload(Category.ENCODING)
def my_payloads():
    return [ make_attack(Category.ENCODING, "good\u200bmovie", name="zero_width") ]

@operator(name="homoglyph", meaning_preserving=True)     # meaning_preserving feeds BOTH engines
def homoglyph(text):
    for a, b in {"a":"а","e":"е","o":"о"}.items():       # Latin → Cyrillic look-alikes
        if a in text: yield text.replace(a, b, 1)
```

Verify what's registered:

```bash
python3 -c "import plugins; from toolkit.registry import OPERATORS, PAYLOADS; \
print([o.name for o in OPERATORS]); print({k.value:len(v) for k,v in PAYLOADS.items()})"
```

---

## Configuration

Toolkit thresholds live in `toolkit/config.py` (target URL, timeout, concurrency,
flip-hunter `query_budget`, semantic model + `tau=0.85`, `conf_drift_threshold`,
`latency_flag_ms`). The dashboard exposes a single `CONFIG` block at the top of
`dashboard/static/index.html` (branding, ports, theme, severity colours, panel
toggles, sample sentences).

---

## How it works

- **Flip hunter** — gradient-free, score-based black-box search: rank tokens by
  masking importance, greedily perturb the most influential first using the
  registered operators, minimise the edit set, then accept the flip only if the
  semantic gate confirms meaning is preserved (cosine ≥ τ). Bounded by
  `query_budget` calls per seed.
- **Invariance oracle** — the dual test: apply meaning-preserving operators and
  require the label to stay; any change is a self-contradiction. Needs no
  ground-truth label.
- **Semantic gate** — `all-MiniLM-L6-v2`, τ = 0.85. Falls back to lexical
  similarity if unavailable (and says so).
- **Severity** — `base_impact(type) + exploitability` (fewer edits & higher
  stealth score higher), 0–10, banded info/low/medium/high/critical.
- **Shim** — NFKC + confusable folding + zero-width stripping + size cap,
  applied before inference. The model itself is never modified ("a WAF for the
  model").

---

## Output files

| File | What it is |
|------|-----------|
| `baseline.db` | SQLite results from attacking the raw target |
| `shielded.db` | SQLite results from attacking through the shim |
| `results.db`  | default DB when running `main.py` without `--db` |
| `report.html` | static ranked findings report |

Tables in each DB: `findings`, `results`, `flips`, `invariance`. Inspect with:

```bash
sqlite3 -header -column baseline.db \
  "SELECT severity, severity_score, type, title FROM findings ORDER BY severity_score DESC;"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `externally-managed-environment` on pip | PEP 668 (Kali/Debian) | use the venv |
| `ModuleNotFoundError: sentence_transformers` | not in the venv | `source .venv/bin/activate` |
| confidence ≈ 0.5, random labels | server on the toy fallback model | start the server **inside** the venv |
| `semantic_gate: lexical-fallback` in output | semantic model didn't load | activate venv; set `HF_HUB_OFFLINE=1` after first download |
| `[Errno -3] name resolution` on first run | offline before models cached | connect once to download, then set offline flags |
| `address already in use` | old server on that port | `fuser -k 8000/tcp` (or 8001/8080) then restart |
| `ModuleNotFoundError: toolkit` / `dashboard` | run from the wrong directory | run from the repo root |
| dashboard panels say "no data" | DBs not generated yet | run `python3 demo.py` or click **Run Full Before/After** |
| health dot red in dashboard | target/shim not running | start them on 8000 / 8001 in the venv |

---

## Scope & limitations

- The character-normalisation shim addresses **character-level** attacks
  (homoglyph, zero-width, NFKC). **Word-level (synonym) attacks are out of scope
  for the shim by design** and require adversarial training as a separate
  remediation; Epiales reports them transparently rather than hiding them.
- Confusable coverage is the common Cyrillic/Greek set, not the full Unicode
  confusables table — extend `shim/normalizer.py` for production use.
- Demonstrated on a binary sentiment classifier; the engine is label-agnostic but
  assumes the endpoint returns a top label + confidence.
- This is an authorised, defensive testing tool. Only run it against endpoints
  you own or have permission to test.

---

*Rochester Institute of Technology Dubai · 2026*
