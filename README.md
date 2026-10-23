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
RID=$(curl -s -X POST localhost:8000/projects/$PID/runs -H 'content-type: application/json' -d "{
  \"objective\":\"Assess the authorized Juice Shop lab target\",
  \"target\":\"http://$JS_IP:3000\",\"use_llm\":true
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
pytest -q          # 18 unit/integration tests (scope engine, executor, orchestrator->report)
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
- Agents 4–8, the exploit-validation lab, auth/reasoning/knowledge base, the Next.js
  dashboard, and production hardening (RBAC, secrets, rate limiting, cost controls) are
  later phases. Their tables/contracts exist but are not wired.
- The execution engine runs in the API process and uses the host Docker socket. In
  production (Phase 5) it should be split into a separate privileged service so the API
  itself holds no Docker access.
- `nmap` uses a TCP connect scan (`-sT`) so it needs no raw-socket capability under
  `--cap-drop ALL`; UDP/SYN scans are out of scope for Phase 1.
- `nuclei_scan` is registered but defaults to requiring approval and downloads templates
  on first use; the default e2e runs recon + passive probing only.
- Reports are JSON (canonical) + a minimal HTML view; rich HTML/PDF arrive in Phase 4.
- Findings are `suspected` only; nothing is auto-promoted to confirmed.
