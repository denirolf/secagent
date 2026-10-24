# Autonomous Security Agent Platform

A multi-agent platform for **authorized** security testing against targets you own or have
written permission to test, exercised inside **isolated Docker labs**. Every active
operation is gated by a Scope Engine that denies anything not explicitly authorized, runs
in a hardened sandbox, and is recorded in an append-only audit log.

> This tool is for authorized testing only. Pointing it at infrastructure you do not own
> or have permission to test is misuse, and the Scope Engine is built to refuse it
> (public destinations are never authorized implicitly; DNS is re-resolved and re-checked
> at execution time).

This repository is **Phase 1 (Functional MVP)**. See `design/ARCHITECTURE.md` for the full
design and the phased roadmap.

## What Phase 1 delivers

- **FastAPI backend** — projects, authorized scopes, runs, findings, audit, WebSocket.
- **Master Orchestrator** + **Reconnaissance Agent** + **Vulnerability Analysis Agent**,
  driven by the **Claude Agent SDK** (`claude-agent-sdk==0.2.165`, see `SDK_NOTES.md`).
- **System Execution Engine** (no LLM): Scope Engine, Tool Registry, hardened Docker
  Sandbox, Approval Engine, Audit — the enforced guardrails.
- **PostgreSQL** schema with **Alembic** migrations (15 tables).
- A local **OWASP Juice Shop** lab and a working **end-to-end run** that produces a JSON
  vulnerability report of `suspected` findings.

Findings are strictly `suspected` in Phase 1: a scanner/probe result is a signal, not a
confirmation. Elevation to `lab_confirmed` (Phase 2) and `confirmed_authorized` requires
reproduction in the isolated lab plus human sign-off.

## Phase 2 — Exploit Research & Lab Validation

Adds two agents and the suspected → lab_confirmed path:

- **Exploit Research Agent (Agent 4)** — analyzes each suspected finding and produces a
  `ValidationPlan` (mechanism, preconditions, impact, lab reproduction steps, and a set of
  **bounded, passive, lab-only checks**). It never executes anything against a target.
- **Exploit Validation Agent (Agent 5)** — reproduces findings **inside the isolated lab
  only** using those bounded checks, and elevates a finding from `suspected` to
  `lab_confirmed` when it reproduces. It **hard-refuses any target that is not an
  authorized lab environment** (`matched_is_lab`), only runs passive checks (no
  exploitation primitive exists), optionally resets a dedicated lab container between
  tests, and still routes every check through the SecureExecutor (scope + audit).
  `confirmed_authorized` is never set automatically — it needs validation in the
  authorized environment plus explicit human sign-off.

Trigger Phase 2 on a run with `"validate_in_lab": true` (optionally
`"lab_container": "juiceshop"` to reset between tests). Results populate
`validation_results` and the report's `validations` section and `lab_confirmed` count.

## Phase 3 — Authentication Security, Reasoning & Knowledge Base

- **Authentication Security Agent (Agent 6)** — passive session/auth posture analysis
  (session cookie `HttpOnly` / `Secure` / `SameSite` flags → CWE-1004/614/1275 suspected
  findings). **No** password spraying, credential stuffing, or attempts against unknown
  accounts; any active credential test is lab-only, synthetic-accounts-only, and
  approval-gated (not performed in this phase — this agent only analyzes observed posture).
- **Security Reasoning Agent (Agent 7)** — correlates all findings, enriches them via the
  Knowledge Base (CWE → OWASP Top 10 + remediation), builds a **risk graph** of how
  weaknesses chain (e.g. missing script-restriction headers + a script-readable cookie →
  XSS-to-session-theft), prioritizes findings (severity + confidence + lab-confirmed +
  chain membership), and proposes further safe, lab-only investigations.
- **Knowledge Base** — `GET /knowledge`, `GET /knowledge/search?q=`, `POST /knowledge/seed`
  (mirrors the bundled CWE/OWASP dataset into `knowledge_entries`). Reference data only; it
  never changes permissions.

Trigger on a run with `"auth_check": true` and `"reasoning": true`. The report gains a
`reasoning` block (risk graph, prioritized list, OWASP summary, proposed investigations).

## Phase 4 — Web Dashboard (Next.js + TypeScript)

A read-and-drive dashboard in `dashboard/` (Next.js 14 App Router, TypeScript) over the
FastAPI backend:

- **Overview** — platform stat cards (projects, assets, vulnerabilities, lab-confirmed,
  running/total runs) from `GET /overview`.
- **Projects** — create a project with its authorized scope, then start a run (LLM agents,
  lab validation, auth check, reasoning as toggles) and watch the orchestrator's decision
  log **live over the run WebSocket**.
- **Vulnerabilities** — findings per project with severity, validation status, confidence,
  and remediation.
- **Agents** — the specialized agents and the phase each is implemented in (`GET /agents`).
- **Security Lab** — the authorized isolated-lab scopes, with a reminder that validation is
  lab-only.
- **Reports** — fetch a run's report by id: stat cards, findings, the reasoning/risk-graph
  block, and the raw canonical JSON.

The backend gains the read endpoints the dashboard needs (`GET /projects` list,
`GET /overview`, `GET /agents`, `GET /projects/{id}/runs`, `GET /projects/{id}/assets`) and
a CORS allowance for `localhost:3000`. The dashboard adds **no** execution capability — it
is a client of the same scope-gated, audited API, so every guardrail still applies.

```bash
# backend on :8000 (see Quick start), then:
cd dashboard
cp .env.local.example .env.local      # NEXT_PUBLIC_API_BASE=http://localhost:8000
npm install
npm run dev                            # http://localhost:3000
```

## Phase 5 — Production hardening

Wraps the same scope-gated engine in a production layer. Nothing here can weaken the Scope
Engine, sandbox, approval, or audit guarantees — those live in `app/engine/` and are
unchanged. See **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** for the full operator guide.

- **Authentication + RBAC** — API-key auth with roles `viewer` < `operator` < `admin`
  (reads need viewer, starting runs needs operator, creating projects / seeding the
  knowledge base / managing keys need admin). Only a salted hash is stored; a key is shown
  once. **Off by default** so dev/tests/e2e are unchanged; enable with `AUTH_ENABLED=true`
  and an `API_KEY_PEPPER`. Manage keys via `scripts/create_api_key.py` or `POST /admin/api-keys`.
- **Rate limiting** — token bucket per API key / client IP, `429` + `Retry-After`.
- **Observability** — `GET /health` (liveness), `GET /ready` (503 when the DB is down),
  `GET /metrics` (Prometheus: HTTP, tool calls by decision, scope denials, runs, findings,
  rate-limited), and structured JSON logs (`LOG_JSON=true`) with an `X-Request-ID` per request.
- **Cost control** — per-project `max_iterations` / `max_tool_calls` / `max_budget_usd`
  ceilings; optional per-unit cost estimates make the budget ceiling stop a run before a
  real bill accrues (`0` = off, behaviour unchanged).
- **Secrets** — env, `.env`, or secret files (Docker/K8s) under `SECRETS_DIR`; never logged.
- **CI & ops** — `.github/workflows/ci.yml` (pytest + dashboard build), `scripts/backup.sh`
  / `scripts/restore.sh` (pg_dump with retention), and the `api_keys` Alembic migration.

```bash
export AUTH_ENABLED=true API_KEY_PEPPER="$(openssl rand -hex 32)"
alembic upgrade head
python scripts/create_api_key.py --role admin --name "ops"   # prints the token once
# then call the API with:  Authorization: Bearer sk-...
```

## Reporting Agent (A8) — report exports

The **Reporting Agent (Agent 8)** adds a human-readable **executive narrative** to every
report: a deterministic summary grounded entirely in the findings (it invents nothing — a
scanner signal is never upgraded here). The report downloads in several formats from one
endpoint:

```bash
curl -s  "localhost:8000/runs/$RID/report"             # JSON (canonical)
curl -s  "localhost:8000/runs/$RID/report?format=md"   # Markdown
curl -s  "localhost:8000/runs/$RID/report?format=html" # standalone HTML
curl -so report.pdf "localhost:8000/runs/$RID/report?format=pdf"   # PDF
```

PDF rendering uses `fpdf2` (pure Python, no system libraries), so it behaves the same in CI
and in a minimal container. The dashboard's Reports page shows the executive summary and
links the Markdown / HTML / PDF exports.

## Requirements
- Docker (the execution engine launches sandboxed tool containers)
- Python 3.12+
- An `ANTHROPIC_API_KEY` for the LLM agents (standalone deployment). In a Claude Code
  session the SDK uses the session's ambient CLI auth, so the e2e can run without a key.

## Quick start (Docker Compose)

```bash
cp .env.example .env            # set ANTHROPIC_API_KEY / CLAUDE_MODEL if deploying standalone
docker network create secagent_lab 2>/dev/null || true
docker compose up -d --build    # postgres + redis + migrate + api  (http://localhost:8000)
docker compose -f lab/juice-shop.compose.yml up -d   # start the authorized lab target
curl -s localhost:8000/health
```

## Run an end-to-end assessment

```bash
# Find the lab target's IP on the isolated network
JS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' juiceshop)

# 1) Create a project authorizing only the lab network (autonomy level 3 = Autonomous Lab)
PID=$(curl -s -X POST localhost:8000/projects -H 'content-type: application/json' -d '{
  "name":"Juice Shop Lab","autonomy_level":3,
  "scopes":[{"kind":"cidr","value":"172.18.0.0/16","is_lab_env":true}]
}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# 2) Start a run (use_llm:true drives the Claude agents; false runs deterministically)
# use_llm:true drives the Claude agents; add "validate_in_lab":true for Phase 2 validation
RID=$(curl -s -X POST localhost:8000/projects/$PID/runs -H 'content-type: application/json' -d "{
  \"objective\":\"Assess the authorized Juice Shop lab target\",
  \"target\":\"http://$JS_IP:3000\",\"use_llm\":true,\"validate_in_lab\":true
}" | python3 -c "import sys,json;print(json.load(sys.stdin)['run_id'])")

# 3) Watch live (optional) and fetch the report
#    websocat ws://localhost:8000/ws/runs/$RID
curl -s localhost:8000/runs/$RID/report | python3 -m json.tool
curl -s localhost:8000/projects/$PID/audit | python3 -m json.tool
```

A reproducible version of this flow is in `scripts/e2e.sh`.

## Tests

```bash
pip install -r requirements.txt
pytest -q          # 45 unit/integration tests (scope engine, executor, orchestrator->report, security, reporting)
```

The Scope Engine tests (`tests/test_scope_engine.py`) are the most important: they cover
DNS-rebinding (name in scope, IP out of scope → deny), cloud-metadata hard-deny, and the
"no implicit public" rule.

## Safety model (enforced, not advisory)

| Component | Guarantee |
|---|---|
| Scope Engine | DNS re-resolved and re-checked at execution; redirects re-authorized; link-local/metadata hard-denied; public never implicit. |
| Tool Registry | Typed Pydantic params → fixed argv. The model never composes a command line. |
| Sandbox | `--cap-drop ALL`, `--security-opt no-new-privileges`, CPU/mem/pids caps, lab-only network, `--rm`. No privileged mode, Docker socket never mounted into tool containers. |
| Approval Engine | High-impact ops need a human; autonomy level only reduces friction for low-risk in-scope ops and can never bypass scope or sandbox. |
| Audit | Append-only record of agent, tool, params (redacted), target, scope decision, result. |

## Limitations (Phase 1)
- This section documents the Phase 1 baseline. The Phase 2–4 work above (exploit-validation
  lab, auth/reasoning/knowledge base, and the dashboard) is implemented on the stacked
  branches; production hardening (RBAC, secrets, rate limiting, cost controls) is Phase 5
  (implemented — see the Phase 5 section above and docs/DEPLOYMENT.md).
- The execution engine runs in the API process and uses the host Docker socket. In
  production (Phase 5) it should be split into a separate privileged service so the API
  itself holds no Docker access.
- `nmap` uses a TCP connect scan (`-sT`) so it needs no raw-socket capability under
  `--cap-drop ALL`; UDP/SYN scans are out of scope for Phase 1.
- `nuclei_scan` is registered but defaults to requiring approval and downloads templates
  on first use; the default e2e runs recon + passive probing only.
- Reports are JSON (canonical) with Markdown, HTML, and PDF exports via the Reporting Agent
  (A8); the Phase 4 dashboard shows the executive summary and links the exports.
- Findings are `suspected` only; nothing is auto-promoted to confirmed.
