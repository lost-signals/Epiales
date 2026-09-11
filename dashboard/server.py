"""Run from the toolkit root: python3 -m uvicorn dashboard.server:app --port 8080.

Read panels only read the four existing SQLite tables. Run Control is the only
writer: it spawns unchanged main.py using this Python interpreter. Use one
uvicorn worker (the documented default); run ownership is process-local.
Install nothing beyond the toolkit's existing FastAPI/uvicorn/httpx.
Operational settings below mirror the documented frontend CONFIG. Paths are
relative to the toolkit root, even if uvicorn is launched from elsewhere.
"""
from __future__ import annotations

import asyncio
import ast
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, asynccontextmanager
import difflib
import html
import importlib
import math
import os
from pathlib import Path
import re
import signal
import sqlite3
import json
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

CONFIG = {
    "productName": "Epiales",
    "baseline_db": "baseline.db",
    "shielded_db": "shielded.db",
    "target_url": "http://127.0.0.1:8000",
    "shim_url": "http://127.0.0.1:8001",
    "tau": 0.85,
    "static_dir": "dashboard/static",
    "seeds_file": "seeds.txt",
    "semantic_model": "all-MiniLM-L6-v2",
    "computeBenignLive": False,
    # Set only to a measured percentage from a known prior demo run.
    "stored_benign_unchanged_pct": None,
    "query_budget": 60,
    "request_timeout_s": 10.0,
    "health_timeout_s": 3.0,
    "attack_timeout_s": 120.0,
    "max_input_chars": 100_000,
    "max_request_bytes": 1_000_000,
    "health_text": "a simple health check",
    "predict_path": "/predict",
    "severity_order": ["critical", "high", "medium", "low", "info"],
    "operators": ["homoglyph", "zero_width", "uppercase", "synonym"],
    # For a graded demo, pre-run once and retain the DBs as a fallback.
    "enableRunFromUI": True,
    "allowSeedEditing": True,
    "run_budget": 200,
    "run_budget_min": 20,
    "run_budget_max": 300,
    "max_seeds": 100,
    "max_seed_chars": 2000,
    "run_log_lines": 400,
    "run_log_line_chars": 3000,
    "run_poll_seconds": 0.75,
    "run_timeout_s": 3600,
    "cancel_grace_s": 2,
    "main_script": "main.py",
    "report_file": "report.html",
    "run_state_file": "dashboard-run-state.json",
    "keep_previous_results": True,
    "previous_db_suffix": ".previous",
    "offline": True,
    "health_probes": ["a good movie", "a very good movie"],
    "health_model_tolerance": 0.0001,
    "start_commands": {
        "target": "python3 -m uvicorn target_stub.server:app --port {port}",
        "shim": "python3 -m uvicorn shim.server:app --port {port}",
    },
}
ROOT = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app):
    if CONFIG["offline"]:
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
    yield
    if _RUN.get("running"):
        await cancel_run()


app = FastAPI(title=CONFIG["productName"], docs_url=None, redoc_url=None, lifespan=lifespan)
_GATE = None
_GATE_TASK = None
# All model operations use one thread: no concurrent encoder calls, UI stays live.
_MODEL_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="semantic-gate")
_ATTACK_LOCK = asyncio.Lock()
_RUN_LOCK = asyncio.Lock()
_RUN = {"running": False, "done": False, "phase": None, "recent_lines": []}
_RUN_TASK = None
_RUN_PROCESS = None
_RUN_EVENTS = deque()
_RUN_SEQUENCE = 0
_RUN_TERMINAL = None


def path_for(value):
    p = Path(value)
    return p if p.is_absolute() else ROOT / p


def db_path(db):
    if db not in ("baseline", "shielded"):
        raise ValueError("db must be baseline or shielded")
    p = path_for(CONFIG[f"{db}_db"])
    if not p.is_file():
        raise FileNotFoundError("database not found")
    return p


def connect(db):
    conn = sqlite3.connect(db_path(db).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def db_error(exc):
    if isinstance(exc, FileNotFoundError):
        return "database not found"
    if isinstance(exc, ValueError):
        return str(exc)
    return "database unavailable or incompatible schema"


def empty_summary(db):
    return {"db": db, "total_findings": 0,
            "findings_by_severity": dict.fromkeys(CONFIG["severity_order"], 0),
            "verified_flips": 0, "invariance_violations": 0,
            "crash_rate": 0.0, "total_attacks": 0}


@app.get("/api/summary")
def summary(db: str = "baseline"):
    result = empty_summary(db)
    try:
        with closing(connect(db)) as conn:
            conn.execute("BEGIN")
            counts = conn.execute("SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity").fetchall()
            result["total_findings"] = sum(r["n"] for r in counts)
            result["findings_by_severity"].update({r["severity"]: r["n"] for r in counts})
            result["verified_flips"] = conn.execute("SELECT COUNT(*) FROM flips WHERE verified=1").fetchone()[0]
            result["invariance_violations"] = conn.execute("SELECT COUNT(*) FROM invariance").fetchone()[0]
            total, crashes = conn.execute("SELECT COUNT(*), COALESCE(SUM(CASE WHEN finding='crash' THEN 1 ELSE 0 END),0) FROM results").fetchone()
            result.update(total_attacks=total, crash_rate=round(crashes / total, 4) if total else 0.0)
            # Invariance stores only violations, without seed confidence or test
            # counts. A flips-only drift would be a different, biased metric.
            result["metric_notes"] = {
                "avg_invariance_score": "Not stored: the DB has no total variant-test count.",
                "confidence_drift": "Not stored: seed confidence and all variant tests are absent.",
                "crash_rate": "Crash findings / static attacks; rejected 4xx inputs are not crashes.",
            }
            meta = run_metadata(db)
            result["run_state"] = meta.get("state", "existing")
            result["partial_run"] = meta.get("state") in ("running", "partial")
            if meta.get("state") == "complete" and meta.get("stamp") == file_stamp(db):
                for key in ("avg_invariance_score", "mean_confidence_drift", "max_confidence_drift"):
                    value = meta.get("suite_summary", {}).get(key)
                    if isinstance(value, (int, float)) and math.isfinite(value):
                        result[key] = value
                result["metric_source"] = "Captured from the toolkit summary for this exact completed DB."
    except (OSError, sqlite3.Error, ValueError) as exc:
        result = {**empty_summary(db), "error": db_error(exc)}
    return result


@app.get("/api/findings")
def findings(db: str = "baseline", severity: str | None = None, type: str | None = None):
    result = {"db": db, "count": 0, "findings": []}
    try:
        with closing(connect(db)) as conn:
            clauses, params = [], []
            for column, value in (("severity", severity), ("type", type)):
                if value:
                    clauses.append(f"{column} = ?")
                    params.append(value)
            sql = "SELECT * FROM findings"
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            sql += " ORDER BY severity_score DESC, title ASC"
            for row in conn.execute(sql, params):
                item = dict(row)
                try:
                    evidence = json.loads(item.get("evidence") or "{}")
                    item["evidence"] = evidence if isinstance(evidence, dict) else {"value": evidence}
                except (ValueError, TypeError):
                    item["evidence"] = {"raw": item.get("evidence"), "warning": "Evidence is not valid JSON"}
                result["findings"].append(item)
            result["count"] = len(result["findings"])
    except (OSError, sqlite3.Error, ValueError) as exc:
        result.update(error=db_error(exc), count=0, findings=[])
    return result


def load_seeds():
    try:
        return [s.strip() for s in path_for(CONFIG["seeds_file"]).read_text(encoding="utf-8").splitlines() if s.strip()]
    except OSError:
        return []


def endpoint(name):
    return CONFIG[f"{name}_url"].rstrip("/") + CONFIG["predict_path"]


async def predict(client, name, text):
    try:
        response = await client.post(endpoint(name), json={"text": text})
        response.raise_for_status()
        data = response.json()
        if not isinstance(data.get("label"), str) or not data["label"]:
            raise ValueError("missing label")
        confidence = float(data["confidence"])
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("invalid confidence")
        data["confidence"] = confidence
        return data
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise RuntimeError(f"{name.title()} unreachable or invalid prediction — start/check {CONFIG[name + '_url']}") from exc


@app.get("/api/health")
async def health():
    async with httpx.AsyncClient(timeout=CONFIG["health_timeout_s"], trust_env=False) as client:
        async def check(name):
            started = time.monotonic()
            port = urlparse(CONFIG[name + "_url"]).port or (443 if CONFIG[name + "_url"].startswith("https") else 80)
            base = {"url": endpoint(name), "start_command": CONFIG["start_commands"][name].format(port=port)}
            try:
                probes = CONFIG["health_probes"]
                predictions = [await predict(client, name, text) for text in probes]
                toy = all(p["label"] == ("positive" if len(text) % 2 == 0 else "negative")
                          and abs(p["confidence"] - min(0.5 + (len(text) % 50) / 100, 0.99)) <= CONFIG["health_model_tolerance"]
                          for text, p in zip(probes, predictions))
                return {**base, "reachable": True, "latency_ms": round((time.monotonic()-started)*1000/len(probes), 1),
                        "model_status": "toy-fallback-likely" if toy else "model-unconfirmed",
                        "model_note": "Matches the toolkit's length-parity fallback on both probes." if toy else "Responding; this prediction API does not expose model identity. Confidence alone cannot confirm DistilBERT.",
                        "probe_confidences": [p["confidence"] for p in predictions]}
            except RuntimeError as exc:
                return {**base, "reachable": False, "latency_ms": None, "model_status": "unreachable", "error": str(exc)}
        target, shim = await asyncio.gather(check("target"), check("shim"))
    return {"target": target, "shim": shim}


@app.get("/api/compare")
async def compare(compute_benign_live: bool = False, snapshot_only: bool = False):
    before, after = await asyncio.gather(asyncio.to_thread(summary, "baseline"), asyncio.to_thread(summary, "shielded"))
    result = {}
    for key, value in (("baseline", before), ("shielded", after)):
        result[key] = {**value["findings_by_severity"], "total": value["total_findings"]}
        result[key]["partial_run"] = value.get("partial_run", False)
        if "error" in value:
            result[key]["error"] = value["error"]
    complete = not (before.get("error") or after.get("error"))
    high_before = sum(before["findings_by_severity"].get(s, 0) for s in ("critical", "high"))
    high_after = sum(after["findings_by_severity"].get(s, 0) for s in ("critical", "high"))
    result.update(critical_high_before=high_before if complete else None,
                  critical_high_after=high_after if complete else None,
                  removed=high_before-high_after if complete else None,
                  total_removed=before["total_findings"]-after["total_findings"] if complete else None,
                  benign_unchanged_pct=CONFIG["stored_benign_unchanged_pct"],
                  benign_source="stored measurement" if CONFIG["stored_benign_unchanged_pct"] is not None else "not measured")
    if (CONFIG["computeBenignLive"] or compute_benign_live) and not snapshot_only:
        seeds = load_seeds()
        result["benign_unchanged_pct"] = None
        result["benign_source"] = "live clean-seed label comparison"
        if not seeds:
            result["benign_error"] = "No seeds available for a live check."
        else:
            try:
                async with asyncio.timeout(CONFIG["attack_timeout_s"]):
                    async with httpx.AsyncClient(timeout=CONFIG["request_timeout_s"], trust_env=False) as client:
                        unchanged = 0
                        for seed in seeds:
                            a, b = await asyncio.gather(predict(client, "target", seed), predict(client, "shim", seed))
                            unchanged += a["label"] == b["label"]
                        result["benign_unchanged_pct"] = round(100 * unchanged / len(seeds), 2)
                        result["benign_seeds_checked"] = len(seeds)
            except (RuntimeError, TimeoutError) as exc:
                result["benign_error"] = str(exc) or "Live benign check timed out."
    return result


def registered_operators():
    importlib.import_module("plugins")
    from toolkit.registry import OPERATORS
    return [o for o in OPERATORS if o.name in CONFIG["operators"]]


def create_gate():
    # Respect the air-gapped contract even when the optional ML library exists.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    from toolkit.semantic import SemanticGate
    return SemanticGate(CONFIG["semantic_model"], tau=CONFIG["tau"])


async def get_gate():
    global _GATE, _GATE_TASK
    if _GATE is None:
        if _GATE_TASK is None:
            _GATE_TASK = asyncio.get_running_loop().run_in_executor(_MODEL_POOL, create_gate)
        _GATE = await asyncio.shield(_GATE_TASK)
    return _GATE


@app.get("/api/methodology")
def methodology():
    try:
        operators = [o.name for o in registered_operators()]
        from toolkit.severity import DESCRIPTION
        error = None
    except ImportError:
        operators, DESCRIPTION, error = [], "Toolkit unavailable", "Place dashboard/ in the toolkit root."
    seeds = load_seeds()
    backend = _GATE.backend if _GATE else "not loaded; cached sentence-transformers or lexical fallback"
    return {"target": endpoint("target"), "shim": endpoint("shim"),
            "semantic_gate": f"{backend} (tau={CONFIG['tau']})", "tau": CONFIG["tau"],
            "seeds_tested": len(seeds), "seeds_note": "Seeds in the current file; historical run count is not stored in the DB.",
            "operators": operators, "severity_model": DESCRIPTION,
            "query_budget": CONFIG["query_budget"], "baseline_db": CONFIG["baseline_db"],
            "shielded_db": CONFIG["shielded_db"], "run_budget": CONFIG["run_budget"],
            "run_budget_min": CONFIG["run_budget_min"], "run_budget_max": CONFIG["run_budget_max"],
            "enableRunFromUI": CONFIG["enableRunFromUI"], "error": error}


@app.get("/api/unicode")
def unicode_names(text: str = ""):
    # Only the displayed non-ASCII characters are sent here, never full evidence.
    return {c: f"{unicodedata.name(c, 'UNNAMED CHARACTER').title()} U+{ord(c):04X}"
            for c in set(text[:1024]) if ord(c) > 127}


class BudgetExhausted(Exception):
    pass


class HuntClient:
    """Bound even the frozen hunter's unbudgeted minimization/failure paths."""
    def __init__(self, client, budget):
        self.client, self.left, self.last = client, budget, None

    async def predict(self, text):
        if self.left <= 0:
            raise BudgetExhausted()
        self.left -= 1
        data = await predict(self.client, "target", text)
        from toolkit.models import Prediction
        self.last = (text, data)
        return Prediction(data["label"], data["confidence"], data)


def token_edits(original, variant):
    # Same unit as the toolkit's edit list: edited space-delimited token slots.
    a, b = original.split(" "), variant.split(" ")
    return sum(max(j-i, l-k) for tag, i, j, k, l in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes() if tag != "equal")


async def perform_attack(text, operator):
    from toolkit.fliphunter import hunt
    ops = registered_operators()
    if operator != "auto" and operator not in [o.name for o in ops]:
        return {"error": "Operator is not registered in the existing toolkit."}
    async with httpx.AsyncClient(timeout=CONFIG["request_timeout_s"], trust_env=False) as client:
        original = await predict(client, "target", text)
        # Fail fast if the shim cannot participate in the demonstration.
        await predict(client, "shim", text)
        gate = await get_gate()
        variant, used, edits = text, operator, 0
        budget = CONFIG["query_budget"]
        hunt_client = HuntClient(client, budget)
        if operator == "auto":
            # hunt is reused unchanged. Gate encoding is done off the event loop
            # after the candidate is selected, using the same SemanticGate.
            try:
                found = await hunt(hunt_client, text, semantic_gate=None, operators=ops, budget=budget)
            except BudgetExhausted:
                found = None
            if found:
                variant = found.adversarial
                used = ", ".join(dict.fromkeys(e[3] for e in found.edits)) or "auto"
                edits = len(found.edits)
            else:
                # A bounded operator pass supplies an honest attacked card if
                # the hunter returned None. It consumes only remaining budget.
                for op in ops:
                    for candidate in op.apply(text):
                        if hunt_client.left <= 0:
                            break
                        p = await hunt_client.predict(candidate)
                        if variant == text:
                            variant, used = candidate, op.name
                        if p.label != original["label"]:
                            variant, used = candidate, op.name
                            break
                    if hunt_client.last and hunt_client.last[1]["label"] != original["label"]:
                        break
                edits = token_edits(text, variant)
                if variant == text and hunt_client.last:
                    # Masking probes are not meaning-preserving attack variants.
                    for op in ops:
                        candidate = next((v for v in op.apply(text) if v != text), None)
                        if candidate is not None:
                            variant, used, edits = candidate, op.name, token_edits(text, candidate)
                            break
        else:
            op = next(o for o in ops if o.name == operator)
            for candidate in op.apply(text):
                if hunt_client.left <= 0:
                    break
                if candidate == text:
                    continue
                if variant == text:
                    variant = candidate
                p = await hunt_client.predict(candidate)
                if p.label != original["label"]:
                    variant = candidate
                    break
            edits = token_edits(text, variant)
        attacked = await predict(client, "target", variant)
        shielded = await predict(client, "shim", variant)
        similarity = await asyncio.get_running_loop().run_in_executor(_MODEL_POOL, gate.similarity, text, variant)
        similarity = float(similarity)
        if not math.isfinite(similarity):
            raise RuntimeError("Semantic gate returned an invalid similarity score.")
        flipped = attacked["label"] != original["label"]
        verified = flipped and similarity >= CONFIG["tau"]
        applied = shielded.get("_shim_applied", [])
        if not isinstance(applied, list):
            applied = []
        result = {
            "original": {"text": text, "label": original["label"], "confidence": original["confidence"]},
            "attacked": {"text": variant, "label": attacked["label"], "confidence": attacked["confidence"],
                         "flipped": flipped, "similarity": similarity, "edits": edits, "operator": used},
            "shielded": {"label": shielded["label"], "confidence": shielded["confidence"],
                         "shim_applied": [str(v) for v in applied], "fixed": shielded["label"] == original["label"]},
            "verified": verified, "semantic_backend": gate.backend,
            "semantic_verified": verified and gate.backend == "sentence-transformers",
            "tau": CONFIG["tau"], "search_queries": budget-hunt_client.left,
            "edit_unit": "token positions",
        }
        if not flipped:
            result["note"] = "Model held (robust on this input within the search budget)."
        elif not verified:
            result["note"] = "Label flipped, but the similarity gate rejected it."
        if gate.backend != "sentence-transformers":
            result["warning"] = "Lexical fallback: character similarity is not semantic verification. Cache the configured sentence-transformers model before an offline demo."
        return result


@app.post("/api/attack")
async def attack(request: Request):
    # Only localhost's configured endpoints can be triggered; request data never
    # selects URLs, filesystem paths, modules or shell commands.
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > CONFIG["max_request_bytes"]:
            return {"error": "Request is too large."}
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return {"error": "Request must be a JSON object."}
    if not isinstance(data, dict):
        return {"error": "Request must be a JSON object."}
    text, operator = data.get("text"), data.get("operator", "auto")
    if not isinstance(text, str) or not text.strip():
        return {"error": "Enter a non-empty sentence."}
    if len(text) > CONFIG["max_input_chars"]:
        return {"error": f"Input exceeds {CONFIG['max_input_chars']:,} characters."}
    if not isinstance(operator, str) or operator not in ["auto", *CONFIG["operators"]]:
        return {"error": "Unknown operator."}
    if _RUN.get("running"):
        return {"error": "A suite is running. Wait or stop it before using the live lab."}
    if _ATTACK_LOCK.locked():
        return {"error": "An attack is already running. Please try again when it finishes."}
    async with _ATTACK_LOCK:
        try:
            async with asyncio.timeout(CONFIG["attack_timeout_s"]):
                return await perform_attack(text, operator)
        except TimeoutError:
            return {"error": "Attack timed out. Try a shorter sentence or a named operator."}
        except ImportError:
            return {"error": "Toolkit unavailable — place dashboard/ inside the existing toolkit root."}
        except RuntimeError as exc:
            return {"error": str(exc)}
        except Exception:
            return {"error": "Live probe failed. Check toolkit availability and endpoint responses."}


@app.get("/")
def index():
    return FileResponse(path_for(CONFIG["static_dir"]) / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    from fastapi import Response
    return Response(status_code=204)


# Run metadata contains provenance/partial markers, never a second findings DB.
# The last complete DB is backed up before main.py resets it. No frozen source
# file is edited. Metadata is atomically replaced only by Run Control.
def file_stamp(db):
    try:
        stat = db_path(db).stat()
        return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    except (OSError, ValueError):
        return None


def all_run_metadata():
    try:
        value = json.loads(path_for(CONFIG["run_state_file"]).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def run_metadata(db):
    return all_run_metadata().get(db, {})


def save_run_metadata(db, data):
    path = path_for(CONFIG["run_state_file"])
    meta = all_run_metadata()
    meta[db] = data
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def backup_results(db):
    path = path_for(CONFIG[db + "_db"])
    if CONFIG["keep_previous_results"] and path.is_file() and run_metadata(db).get("state") not in ("running", "partial"):
        with closing(connect(db)) as source, closing(sqlite3.connect(str(path) + CONFIG["previous_db_suffix"])) as destination:
            source.backup(destination)


def brand_generated_report():
    # Edit only main.py's generated artifact, never toolkit/report.py itself.
    path = path_for(CONFIG["report_file"])
    if path.is_file():
        report = path.read_text(encoding="utf-8")
        product = html.escape(CONFIG["productName"])
        report = report.replace("<title>Robustness Report</title>", f"<title>{product} — Robustness Report</title>")
        report = report.replace("<h1>Adversarial Input Robustness Report</h1>", f"<h1>{product} — Robustness Report</h1>")
        path.write_text(report, encoding="utf-8")


def log_run(line):
    global _RUN_SEQUENCE
    _RUN_SEQUENCE += 1
    line = line.rstrip("\r\n")
    if len(line) > CONFIG["run_log_line_chars"]:
        line = line[:CONFIG["run_log_line_chars"]] + "… [line truncated]"
    _RUN_EVENTS.append({"id": _RUN_SEQUENCE, "line": line})
    while len(_RUN_EVENTS) > CONFIG["run_log_lines"]:
        _RUN_EVENTS.popleft()


def status_snapshot():
    result = {k: v for k, v in _RUN.items() if not k.startswith("_")}
    result["recent_lines"] = [event["line"] for event in _RUN_EVENTS]
    result["last_event_id"] = _RUN_SEQUENCE
    result["elapsed_seconds"] = round((_RUN.get("finished_at") or time.time())-_RUN.get("started_at", time.time()), 1)
    phase = _RUN.get("phase")
    if _RUN.get("running") and _RUN.get("static_started") and phase:
        try:
            with closing(connect(phase)) as conn:
                result["static_attacks_fired"] = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        except (OSError, ValueError, sqlite3.Error):
            pass
    result["partial_databases"] = [db for db in ("baseline", "shielded") if run_metadata(db).get("state") in ("running", "partial")]
    return result


async def kill_run_process():
    """Kill the owned process tree; never return idle while it is still alive."""
    process = _RUN_PROCESS
    if process is None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=CONFIG["cancel_grace_s"])
        except TimeoutError:
            pass
        # Kill descendants too, even if the main parent already exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()
    elif process.returncode is None:
        # Windows taskkill /T terminates the process tree, /F is required for
        # Python workers without a console. No shell is involved.
        killer = await asyncio.create_subprocess_exec("taskkill", "/PID", str(process.pid), "/T", "/F",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await killer.wait()
        await asyncio.wait_for(process.wait(), timeout=CONFIG["cancel_grace_s"])


async def execute_campaign(modes, seeds, budget):
    global _RUN_PROCESS, _RUN_TERMINAL
    temporary_seeds = None
    active_db = None
    try:
        # Always snapshot the accepted seed source so editing seeds.txt halfway
        # through a full before/after cannot change the second suite.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", prefix="epiales-seeds-", encoding="utf-8", delete=False) as handle:
            handle.write("\n".join(seeds) + "\n")
            temporary_seeds = handle.name
        for index, db in enumerate(modes):
            if _RUN.get("cancel_requested"):
                break
            active_db = db
            _RUN.update(phase=db, phase_index=index, seeds_done=0, static_attacks_fired=0,
                        static_attacks_total=None, static_started=False)
            await asyncio.to_thread(backup_results, db)
            save_run_metadata(db, {"state": "running", "run_id": _RUN["run_id"], "started_at": _RUN["started_at"]})
            log_run(f"[Epiales] Starting {db} · budget={budget} · seeds={len(seeds)}")
            command = [sys.executable, "-u", str(path_for(CONFIG["main_script"])),
                       "--url", CONFIG["target_url" if db == "baseline" else "shim_url"],
                       "--path", CONFIG["predict_path"],
                       "--db", str(path_for(CONFIG[db + "_db"])), "--budget", str(budget),
                       "--seeds", temporary_seeds]
            kwargs = {"start_new_session": True} if os.name == "posix" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            _RUN_PROCESS = await asyncio.create_subprocess_exec(*command, cwd=str(ROOT), env=os.environ.copy(),
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                            limit=max(CONFIG["max_seed_chars"]*4, 65536), **kwargs)
            if _RUN.get("cancel_requested"):
                await kill_run_process()
            toolkit_summary, expects_summary = None, False
            async with asyncio.timeout(CONFIG["run_timeout_s"]):
                while True:
                    raw = await _RUN_PROCESS.stdout.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    log_run(line)
                    match = re.search(r"\[\*\] firing (\d+) static attacks", line)
                    if match:
                        _RUN.update(static_attacks_total=int(match.group(1)), static_started=True)
                    if line.startswith("[*] invariance:") or line.startswith("[!] invariance failed on seed"):
                        _RUN["seeds_done"] = min(len(seeds), _RUN["seeds_done"]+1)
                    if line.startswith("[!] flip hunter failed") or line.startswith("[!] invariance failed"):
                        _RUN["seed_errors"] += 1
                    if expects_summary:
                        try:
                            value = ast.literal_eval(line)
                            if isinstance(value, dict):
                                toolkit_summary = value
                        except (ValueError, SyntaxError):
                            pass
                        expects_summary = False
                    if line.startswith("[*] summary:"):
                        inline_summary = line.split(":", 1)[1].strip()
                        expects_summary = not inline_summary
                        if inline_summary:
                            try:
                                value = ast.literal_eval(inline_summary)
                                if isinstance(value, dict):
                                    toolkit_summary = value
                            except (ValueError, SyntaxError):
                                pass
                code = await _RUN_PROCESS.wait()
            _RUN["exit_code"] = code
            if _RUN.get("cancel_requested"):
                break
            if code != 0:
                raise RuntimeError(f"{db} suite exited with code {code}")
            if toolkit_summary is None:
                raise RuntimeError(f"{db} exited without a toolkit summary; results may be partial")
            await asyncio.to_thread(brand_generated_report)
            _RUN.update(seeds_done=len(seeds), static_attacks_fired=toolkit_summary.get("total_attacks", 0))
            save_run_metadata(db, {"state": "complete", "run_id": _RUN["run_id"], "finished_at": time.time(),
                                  "stamp": file_stamp(db), "suite_summary": toolkit_summary, "seeds_count": len(seeds),
                                  "budget": budget, "seed_errors": _RUN["seed_errors"]})
            _RUN["completed_phases"].append(db)
            active_db = None
            _RUN_PROCESS = None
            log_run(f"[Epiales] {db} complete · {toolkit_summary.get('total_findings', 0)} findings")
        _RUN["outcome"] = "cancelled" if _RUN.get("cancel_requested") else "complete"
    except asyncio.CancelledError:
        _RUN.update(outcome="cancelled", cancel_requested=True)
        await kill_run_process()
    except Exception as exc:
        _RUN.update(outcome="failed", error=str(exc) or "Run timed out")
        log_run("[Epiales] Run failed: " + _RUN["error"])
        await kill_run_process()
    finally:
        if active_db:
            try:
                save_run_metadata(active_db, {"state": "partial", "run_id": _RUN["run_id"], "finished_at": time.time()})
            except OSError as exc:
                log_run(f"[Epiales] Could not persist partial marker: {exc}")
        _RUN_PROCESS = None
        if temporary_seeds:
            Path(temporary_seeds).unlink(missing_ok=True)
        _RUN.update(finished_at=time.time())
        log_run("[Epiales] Run " + _RUN.get("outcome", "failed"))
        try:
            last_db = _RUN.get("phase") or modes[-1]
            _RUN_TERMINAL = {"done": True, "run_id": _RUN["run_id"], "mode": _RUN["mode"],
                             "outcome": _RUN.get("outcome"), "error": _RUN.get("error"),
                             "summary": await asyncio.to_thread(summary, last_db), "compare": await compare(snapshot_only=True)}
        except Exception:
            _RUN_TERMINAL = {"done": True, "run_id": _RUN["run_id"], "mode": _RUN["mode"],
                             "outcome": _RUN.get("outcome"), "error": "Unable to refresh results; reload the dashboard."}
        # Keep the single-run guard held through terminal snapshot creation.
        _RUN.update(running=False, done=True)


@app.post("/api/run")
async def start_run(request: Request):
    global _RUN_TASK, _RUN, _RUN_EVENTS, _RUN_SEQUENCE, _RUN_TERMINAL
    if not CONFIG["enableRunFromUI"]:
        return JSONResponse({"error": "Run Control is disabled in server CONFIG."}, status_code=403)
    data_bytes = bytearray()
    async for chunk in request.stream():
        data_bytes.extend(chunk)
        if len(data_bytes) > CONFIG["max_request_bytes"]:
            return JSONResponse({"error": "Request too large"}, status_code=413)
    try:
        data = json.loads(data_bytes)
        if not isinstance(data, dict):
            raise ValueError("Request must be a JSON object")
        mode, budget = data.get("mode"), data.get("budget", CONFIG["run_budget"])
        if mode not in ("baseline", "shielded", "both"):
            raise ValueError("mode must be baseline, shielded or both")
        if type(budget) is not int or not CONFIG["run_budget_min"] <= budget <= CONFIG["run_budget_max"]:
            raise ValueError(f"budget must be an integer from {CONFIG['run_budget_min']} to {CONFIG['run_budget_max']}")
        seeds = data.get("seeds") if "seeds" in data else load_seeds()
        if not isinstance(seeds, list) or not seeds or len(seeds) > CONFIG["max_seeds"]:
            raise ValueError(f"Provide 1–{CONFIG['max_seeds']} seeds, or check seeds.txt")
        if any(not isinstance(seed, str) or not seed.strip() or len(seed) > CONFIG["max_seed_chars"] or '\n' in seed or '\r' in seed for seed in seeds):
            raise ValueError(f"Each seed must be one non-empty line up to {CONFIG['max_seed_chars']} characters")
        seeds = [seed.strip() for seed in seeds]
    except (ValueError, TypeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    async with _RUN_LOCK:
        if _RUN.get("running"):
            return JSONResponse({"error": "run in progress"}, status_code=409)
        if _ATTACK_LOCK.locked():
            return JSONResponse({"error": "A live probe is in progress"}, status_code=409)
        if not path_for(CONFIG["main_script"]).is_file():
            return JSONResponse({"error": "main.py not found in the toolkit root"}, status_code=400)
        status = await health()
        needed = ["target"] if mode == "baseline" else ["target", "shim"]
        down = [status[name]["error"] for name in needed if not status[name]["reachable"]]
        if down:
            return JSONResponse({"error": " · ".join(down)}, status_code=503)
        modes = ["baseline", "shielded"] if mode == "both" else [mode]
        _RUN = {"run_id": uuid.uuid4().hex, "mode": mode, "running": True, "done": False,
                "phase": modes[0], "phase_index": 0, "phases_total": len(modes),
                "seeds_done": 0, "seeds_total": len(seeds), "seed_errors": 0,
                "static_attacks_fired": 0, "static_attacks_total": None, "static_started": False,
                "started_at": time.time(), "completed_phases": [], "cancel_requested": False}
        _RUN_EVENTS, _RUN_SEQUENCE, _RUN_TERMINAL = deque(), 0, None
        _RUN_TASK = asyncio.create_task(execute_campaign(modes, seeds, budget))
        return {"run_id": _RUN["run_id"], "mode": mode, "started": True}


@app.get("/api/run/status")
def run_status():
    result = status_snapshot()
    if _RUN_TERMINAL and not result.get("running"):
        result["terminal"] = _RUN_TERMINAL
    return result


@app.get("/api/run/stream")
async def run_stream(request: Request, run_id: str | None = None):
    """SSE with bounded replay; frontend uses polling for reconnect simplicity."""
    expected_id = run_id or _RUN.get("run_id")
    try:
        last_id = int(request.headers.get("last-event-id", "0"))
    except ValueError:
        last_id = 0

    async def events():
        nonlocal last_id
        while not await request.is_disconnected():
            if expected_id != _RUN.get("run_id") or not expected_id:
                yield 'data: ' + json.dumps({"done": True, "error": "Run unavailable or superseded"}) + '\n\n'
                return
            for event in list(_RUN_EVENTS):
                if event["id"] > last_id:
                    last_id = event["id"]
                    yield f"id: {last_id}\ndata: " + json.dumps({"line": event["line"]}) + '\n\n'
            if _RUN_TERMINAL and not _RUN.get("running"):
                yield 'data: ' + json.dumps(_RUN_TERMINAL) + '\n\n'
                return
            yield 'data: ' + json.dumps({"status": status_snapshot()}) + '\n\n'
            await asyncio.sleep(CONFIG["run_poll_seconds"])
    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/run/cancel")
async def cancel_run():
    async with _RUN_LOCK:
        if not _RUN.get("running"):
            return {"cancelled": False, "running": False}
        _RUN["cancel_requested"] = True
        log_run("[Epiales] STOP requested — terminating the process group")
        await kill_run_process()
        if _RUN_TASK:
            await asyncio.shield(_RUN_TASK)
        return {"cancelled": True, "running": False, "partial_databases": status_snapshot()["partial_databases"]}


@app.get("/api/operator-stats")
def operator_stats(db: str = "baseline"):
    result = {"db": db, "operators": [], "unattributed_verified_flips": 0,
              "note": "The frozen flips table has no operator column. Those verified flips are shown as unattributed; invariance events retain their recorded operator."}
    try:
        with closing(connect(db)) as conn:
            conn.execute("BEGIN")
            rows = conn.execute("SELECT operator, COUNT(*) AS violations, SUM(CASE WHEN kind='label_flip' THEN 1 ELSE 0 END) AS label_flips FROM invariance GROUP BY operator").fetchall()
            result["unattributed_verified_flips"] = conn.execute("SELECT COUNT(*) FROM flips WHERE verified=1").fetchone()[0]
            stats = {o: {"operator": o, "verified_flips": 0, "invariance_violations": 0, "invariance_label_flips": 0} for o in CONFIG["operators"]}
            for row in rows:
                name = row["operator"] or "unattributed"
                stats[name] = {"operator": name, "verified_flips": 0, "invariance_violations": row["violations"], "invariance_label_flips": row["label_flips"]}
            # A future compatible DB may record operator explicitly; never guess.
            columns = {r["name"] for r in conn.execute("PRAGMA table_info(flips)")}
            if "operator" in columns:
                result["unattributed_verified_flips"] = 0
                for row in conn.execute("SELECT operator, COUNT(*) AS n FROM flips WHERE verified=1 GROUP BY operator"):
                    name = row["operator"]
                    if not name:
                        result["unattributed_verified_flips"] += row["n"]
                        continue
                    stats.setdefault(name, {"operator": name, "verified_flips": 0, "invariance_violations": 0, "invariance_label_flips": 0})["verified_flips"] = row["n"]
                result["note"] = "Counts use recorded operator attribution. Invariance violations include label flips and confidence drift."
            result["operators"] = sorted(stats.values(), key=lambda r: -(r["verified_flips"]+r["invariance_violations"]))
    except (OSError, sqlite3.Error, ValueError) as exc:
        result["error"] = db_error(exc)
    return result
