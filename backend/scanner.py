"""
scanner.py — OSV + Semgrep + Bandit pipeline for SecureDep v2
"""

import json, os, subprocess, uuid
from pathlib import Path

import db

RULES = str(Path(__file__).parent / "rules" / "custom.yml")
_SEV = {"CRITICAL":"CRITICAL","HIGH":"HIGH","MODERATE":"MEDIUM","MEDIUM":"MEDIUM","LOW":"LOW"}
_SG  = {"ERROR":"HIGH","WARNING":"MEDIUM","INFO":"LOW"}


def run_full_scan(scan_id: str, project_path: str, cleanup: bool = False):
    """Entry point — runs all scanners and stores results."""
    import shutil
    try:
        db.set_status(scan_id, "running")
        findings = (
            _osv(scan_id, project_path)
            + _semgrep(scan_id, project_path)
            + _bandit(scan_id, project_path)
        )
        for f in findings:
            db.insert_finding(f)
        db.set_status(scan_id, "complete")
    except Exception as e:
        db.set_status(scan_id, f"error: {e}")
    finally:
        if cleanup:
            shutil.rmtree(project_path, ignore_errors=True)


# ── OSV-Scanner ───────────────────────────────────────────────────────────────

def _osv(scan_id: str, path: str) -> list:
    findings = []
    try:
        r = subprocess.run(
            ["osv-scanner", "--format", "json", path],
            capture_output=True, text=True, timeout=90
        )
        data = json.loads(r.stdout or "{}")
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                name    = pkg.get("package", {}).get("name", "?")
                version = pkg.get("package", {}).get("version", "?")
                for vuln in pkg.get("vulnerabilities", []):
                    vid   = vuln.get("id", "UNKNOWN")
                    sev   = _SEV.get(vuln.get("database_specific", {}).get("severity","MEDIUM").upper(), "MEDIUM")
                    fixed = _fixed_ver(vuln)
                    findings.append(_f(scan_id, {
                        "type":         "Dependency Vulnerability",
                        "severity":     sev,
                        "confidence":   "HIGH",
                        "file":         "requirements.txt / package.json",
                        "line":         0,
                        "tool":         "OSV-Scanner",
                        "vuln_id":      vid,
                        "package":      name,
                        "description":  f"[{vid}] {vuln.get('summary','No description.')}",
                        "impact":       f"{name}@{version} has a known vulnerability.",
                        "fix_suggestion": f"Upgrade {name} to {fixed}" if fixed != "unknown" else "Check OSV advisory.",
                        "code_snippet": f"{name}=={version}",
                        "fixed_code":   f"{name}=={fixed}" if fixed != "unknown" else "",
                    }))
    except FileNotFoundError:
        findings.append(_missing(scan_id, "OSV-Scanner",
            "go install github.com/google/osv-scanner/cmd/osv-scanner@latest"))
    except Exception as e:
        print(f"[OSV] error: {e}")
    return findings


def _fixed_ver(vuln: dict) -> str:
    for a in vuln.get("affected", []):
        for r in a.get("ranges", []):
            for e in r.get("events", []):
                if "fixed" in e:
                    return e["fixed"]
    return "unknown"


# ── Semgrep ───────────────────────────────────────────────────────────────────

def _semgrep(scan_id: str, path: str) -> list:
    findings = []
    try:
        r = subprocess.run(
            ["semgrep", "--config", RULES, "--json", path],
            capture_output=True, text=True, timeout=90
        )
        data = json.loads(r.stdout or "{}")
        for hit in data.get("results", []):
            meta  = hit.get("extra", {}).get("metadata", {})
            raw   = hit.get("extra", {}).get("severity", "WARNING")
            findings.append(_f(scan_id, {
                "type":         meta.get("type", hit.get("check_id","").split(".")[-1].replace("-"," ").title()),
                "severity":     _SG.get(raw, "MEDIUM"),
                "confidence":   "HIGH",
                "file":         hit.get("path", "?"),
                "line":         hit.get("start", {}).get("line", 0),
                "tool":         "Semgrep",
                "vuln_id":      hit.get("check_id",""),
                "package":      "",
                "description":  hit.get("extra", {}).get("message",""),
                "impact":       meta.get("impact","Security risk detected."),
                "fix_suggestion": meta.get("fix","Review and remediate."),
                "code_snippet": hit.get("extra", {}).get("lines",""),
                "fixed_code":   meta.get("fixed_code",""),
            }))
    except FileNotFoundError:
        findings.append(_missing(scan_id, "Semgrep", "pip install semgrep"))
    except Exception as e:
        print(f"[Semgrep] error: {e}")
    return findings


# ── Bandit ────────────────────────────────────────────────────────────────────

def _bandit(scan_id: str, path: str) -> list:
    findings = []
    try:
        r = subprocess.run(
            ["bandit", "-r", path, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=90
        )
        data = json.loads(r.stdout or "{}")
        for hit in data.get("results", []):
            cwe = hit.get("issue_cwe", {})
            findings.append(_f(scan_id, {
                "type":         hit.get("issue_text","Bandit Finding").split(".")[0][:60],
                "severity":     hit.get("issue_severity","LOW"),
                "confidence":   hit.get("issue_confidence","MEDIUM"),
                "file":         hit.get("filename","?"),
                "line":         hit.get("line_number",0),
                "tool":         "Bandit",
                "vuln_id":      hit.get("test_id",""),
                "package":      "",
                "description":  hit.get("issue_text",""),
                "impact":       f"CWE-{cwe.get('id','N/A')}: {cwe.get('link','')}",
                "fix_suggestion": hit.get("more_info","See Bandit docs."),
                "code_snippet": hit.get("code","").strip(),
                "fixed_code":   "",
            }))
    except FileNotFoundError:
        findings.append(_missing(scan_id, "Bandit", "pip install bandit"))
    except Exception as e:
        print(f"[Bandit] error: {e}")
    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _f(scan_id: str, d: dict) -> dict:
    return {"id": str(uuid.uuid4()), "scan_id": scan_id, **d}


def _missing(scan_id: str, tool: str, hint: str) -> dict:
    return _f(scan_id, {
        "type": "Tool Not Installed", "severity": "LOW", "confidence": "HIGH",
        "file": "N/A", "line": 0, "tool": tool,
        "description": f"{tool} not found. {hint}",
        "impact": "This scanner was skipped.",
        "fix_suggestion": hint, "code_snippet": "", "fixed_code": "",
    })
