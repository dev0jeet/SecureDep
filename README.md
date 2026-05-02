# SecureDep v2

Static security analysis platform — OSV + Semgrep + Bandit + React dashboard + file watcher.

---

## Deploy in 2 commands

```bash
cd securedep_v2
bash start.sh
```

Then open `frontend/index.html` in your browser. Done.

---

## Manual setup

```bash
# 1. Install Python deps (includes bandit + semgrep)
cd backend
pip install -r requirements.txt

# 2. Start the API
uvicorn main:app --reload --port 8000

# 3. Open frontend (no build step)
open ../frontend/index.html
```

---

## Optional: Full CVE scanning

```bash
# Requires Go 1.21+
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

---

## Project layout

```
securedep_v2/
├── start.sh              ← one-command deploy
├── backend/
│   ├── main.py           ← FastAPI (all endpoints)
│   ├── db.py             ← SQLite layer
│   ├── scanner.py        ← OSV + Semgrep + Bandit pipeline
│   ├── watcher.py        ← file change detector
│   ├── requirements.txt
│   └── rules/
│       └── custom.yml    ← 11 Semgrep rules
├── frontend/
│   └── index.html        ← React dashboard (no build)
└── .github/
    └── workflows/
        └── security.yml  ← GitHub Actions CI gate
```

---

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | `{"path":"/abs/path"}` → scan_id |
| POST | `/scan/upload` | Upload .zip → scan_id |
| GET | `/scan/{id}` | Full results + findings |
| GET | `/scan/{id}/summary` | Counts + pass/fail |
| GET | `/scans` | All scan history |
| GET | `/scans/latest` | Most recent scan |
| POST | `/policy` | CI gate: `{"scan_id","fail_on":"HIGH"}` |
| POST | `/suppress` | `{"finding_id","reason"}` |
| DELETE | `/suppress/{id}` | Unsuppress a finding |
| POST | `/watch` | `{"path":"/abs/path"}` → start watcher |
| DELETE | `/watch` | Stop watcher |
| GET | `/watch` | Watcher status |
| GET | `/health` | Health check |
| GET | `/docs` | Swagger UI |

---

## What gets detected

**OSV-Scanner** — CVEs in requirements.txt / package.json  
**Semgrep (11 rules)** — hardcoded secrets, MD5/SHA-1, SSL verify=False, debug mode, insecure random, yaml.load, JWT none, CORS *, pickle.loads, hardcoded IPs  
**Bandit** — exec/eval, subprocess shell injection, file security, weak crypto  

---

## CI/CD

Copy `.github/workflows/security.yml` to your repo.
Pipeline fails automatically on any CRITICAL or HIGH finding.
