"""
SecureDep v2 — Backend
FastAPI + SQLite + OSV + Semgrep + Bandit + Watchdog

Run:  uvicorn main:app --reload --port 8000
"""

import json, os, shutil, subprocess, tempfile, threading, uuid, zipfile, io
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, BackgroundTasks, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import db
from scanner import run_full_scan
from watcher import FileWatcher

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="SecureDep", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ── Serve frontend ────────────────────────────────────────────────────────────
# Resolve the frontend folder relative to this file (backend/main.py → ../frontend)
_FRONTEND = Path(__file__).parent.parent / "frontend"

@app.get("/", include_in_schema=False)
def serve_index():
    return FileResponse(_FRONTEND / "index.html")

# Mount static assets AFTER the root route so "/" is not swallowed
app.mount("/static", StaticFiles(directory=str(_FRONTEND)), name="static")

db.init()

_watcher: Optional[FileWatcher] = None   # singleton watcher instance

# ── Request models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    path: str

class PolicyRequest(BaseModel):
    scan_id: str
    fail_on: str = "HIGH"   # CRITICAL | HIGH | MEDIUM | LOW

class WatchRequest(BaseModel):
    path: str

class SuppressRequest(BaseModel):
    finding_id: str
    reason: str

# ── Scan endpoints ────────────────────────────────────────────────────────────

@app.post("/scan")
def scan_path(req: ScanRequest, bg: BackgroundTasks):
    """Scan a local directory path."""
    if not os.path.isdir(req.path):
        raise HTTPException(400, f"Directory not found: {req.path}")
    scan_id = _new_scan(req.path)
    bg.add_task(run_full_scan, scan_id, req.path, False)
    return {"scan_id": scan_id}


@app.post("/scan/upload")
async def scan_upload(bg: BackgroundTasks, file: UploadFile = File(...)):
    """Upload a .zip and scan it."""
    tmp = tempfile.mkdtemp()
    try:
        data = await file.read()
        zipfile.ZipFile(io.BytesIO(data)).extractall(tmp)
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise HTTPException(400, f"Bad zip: {e}")
    scan_id = _new_scan(tmp, name=file.filename)
    bg.add_task(run_full_scan, scan_id, tmp, True)
    return {"scan_id": scan_id}


def _new_scan(path: str, name: str = "") -> str:
    scan_id = str(uuid.uuid4())
    db.create_scan(scan_id, path, name or path)
    return scan_id

# ── Results endpoints ─────────────────────────────────────────────────────────

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(404)
    findings = db.get_findings(scan_id)
    counts = _counts(findings)
    return {
        **s,
        "findings": findings,
        "summary": counts,
        "pass": counts["CRITICAL"] == 0 and counts["HIGH"] == 0,
    }


@app.get("/scan/{scan_id}/summary")
def get_summary(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(404)
    findings = db.get_findings(scan_id)
    counts = _counts(findings)
    tools = {}
    for f in findings:
        tools[f["tool"]] = tools.get(f["tool"], 0) + 1
    return {
        **s,
        "summary": counts,
        "by_tool": tools,
        "pass": counts["CRITICAL"] == 0 and counts["HIGH"] == 0,
    }


@app.get("/scans")
def list_scans():
    return db.list_scans()


@app.get("/scans/latest")
def latest_scan():
    scans = db.list_scans()
    return scans[0] if scans else {}

# ── Policy endpoint ───────────────────────────────────────────────────────────

@app.post("/policy")
def check_policy(req: PolicyRequest):
    """Used by CI/CD to gate on severity threshold."""
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    findings = db.get_findings(req.scan_id)
    thr = order.index(req.fail_on.upper()) if req.fail_on.upper() in order else 2
    violations = [f for f in findings if order.index(f["severity"]) >= thr]
    return {
        "passed": len(violations) == 0,
        "violations": len(violations),
        "threshold": req.fail_on.upper(),
        "scan_id": req.scan_id,
    }

# ── Suppression endpoint ──────────────────────────────────────────────────────

@app.post("/suppress")
def suppress_finding(req: SuppressRequest):
    """Mark a finding as accepted risk."""
    db.suppress_finding(req.finding_id, req.reason)
    return {"ok": True}


@app.delete("/suppress/{finding_id}")
def unsuppress_finding(finding_id: str):
    db.unsuppress_finding(finding_id)
    return {"ok": True}

# ── File watcher endpoints ────────────────────────────────────────────────────

@app.post("/watch")
def start_watch(req: WatchRequest, bg: BackgroundTasks):
    """Start watching a directory for dep file changes."""
    global _watcher
    if not os.path.isdir(req.path):
        raise HTTPException(400, f"Directory not found: {req.path}")
    if _watcher:
        _watcher.stop()
    _watcher = FileWatcher(req.path, on_change=_auto_scan)
    _watcher.start()
    return {"watching": req.path}


@app.delete("/watch")
def stop_watch():
    global _watcher
    if _watcher:
        _watcher.stop()
        _watcher = None
    return {"ok": True}


@app.get("/watch")
def watch_status():
    if _watcher and _watcher.running:
        return {"active": True, "path": _watcher.path}
    return {"active": False}


def _auto_scan(path: str):
    """Triggered by watcher when dep files change."""
    scan_id = _new_scan(path, name=f"auto:{Path(path).name}")
    threading.Thread(
        target=run_full_scan, args=(scan_id, path, False), daemon=True
    ).start()

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _counts(findings: list) -> dict:
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if not f.get("suppressed"):
            c[f["severity"]] = c.get(f["severity"], 0) + 1
    c["total"] = sum(c.values())
    return c
