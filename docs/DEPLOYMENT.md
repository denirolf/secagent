# Deployment & Operations (Phase 5)

This document covers running the platform outside a single developer's laptop: secrets,
authentication, rate limiting, observability, cost control, backups, and the recommended
production topology. None of the hardening here can weaken the execution-engine guarantees
(Scope Engine, sandbox, approval gates, audit) — those are enforced in `app/engine/` and
are independent of this layer.

> Authorized testing only. The Scope Engine still refuses anything not explicitly
> authorized; nothing in this document relaxes it.

## 1. Configuration & secrets

All configuration is environment-driven (`app/config.py`, `pydantic-settings`). See
`.env.example` for the full list. Secrets can be provided three ways, in order of
preference for production:

1. **Secret files** (Docker / Kubernetes secrets). Mount each secret as a file named after
   its setting alias under a directory, and set `SECRETS_DIR` (default `/run/secrets` when
   present). Example: `/run/secrets/API_KEY_PEPPER`, `/run/secrets/ANTHROPIC_API_KEY`.
2. **Environment variables** — `ANTHROPIC_API_KEY`, `DATABASE_URL`, `API_KEY_PEPPER`, …
3. **`.env` file** — local development only; never commit a real one.

Secrets are never written to logs. The access log records the authenticated principal's
name, never its key.

## 2. Authentication & RBAC

Disabled by default so local dev, the test suite, and the e2e run without credentials.
**Enable it for any shared or production deployment:**

```bash
AUTH_ENABLED=true
API_KEY_PEPPER=<a long, random, secret string>   # required when auth is on
```

Keys carry a role with a strict hierarchy:

| Role       | Can do                                                              |
|------------|--------------------------------------------------------------------|
| `viewer`   | Read: overview, projects, findings, reports, knowledge, agents.    |
| `operator` | Everything viewer can, plus **start runs**.                        |
| `admin`    | Everything, plus **create projects**, **seed knowledge**, **manage API keys**. |

Only a SHA-256 hash of `pepper + secret` is stored; the key is shown once at creation and
cannot be recovered. Authentication is constant-time.

### Creating the first admin key

Either run the helper in an operator's terminal (the token prints to stdout, never to
server logs):

```bash
AUTH_ENABLED=true API_KEY_PEPPER=... DATABASE_URL=... \
  python scripts/create_api_key.py --role admin --name "ops laptop"
```

…or, for containerized/IaC deploys, inject a pre-generated `sk-...` token as
`BOOTSTRAP_ADMIN_KEY`: on startup, if no keys exist yet, it is adopted as an admin key
(only its prefix is logged). If auth is on and no key can be established, the API logs a
loud warning and rejects every request until one is created — it never silently runs open.

Thereafter, manage keys over the API (admin only):

```
POST   /admin/api-keys     {"name":"ci","role":"operator"}   # returns the token once
GET    /admin/api-keys                                        # metadata only, no secrets
DELETE /admin/api-keys/{id}                                   # revoke
```

Call the API with `Authorization: Bearer sk-...`. The dashboard (Phase 4) is a browser
client; when auth is on, front it with your SSO/reverse proxy or inject a viewer/operator
key — the WebSocket handshake is not bearer-gated, so restrict `/ws` at the proxy.

## 3. Rate limiting

A token-bucket limiter (`RATE_LIMIT_PER_MINUTE`, `RATE_LIMIT_BURST`) throttles per API key,
or per client IP when unauthenticated, and returns `429` with `Retry-After`. `/health`,
`/ready`, and `/metrics` are exempt. Set `RATE_LIMIT_PER_MINUTE=0` to disable.

The default limiter is in-process (per API instance). For multiple instances behind a load
balancer, back it with Redis (already in the stack) so the budget is shared; the
`RateLimiter` interface is the single swap point.

## 4. Observability

- **Liveness** `GET /health` — process up, tools registered.
- **Readiness** `GET /ready` — returns `503` if the database is unreachable (wire this to
  your orchestrator's readiness probe so traffic isn't routed to an instance that can't
  serve).
- **Metrics** `GET /metrics` — Prometheus exposition (`METRICS_ENABLED=true`). Exposed
  series: `secagent_http_requests_total`, `secagent_http_request_duration_seconds`,
  `secagent_tool_calls_total{tool,decision}`, `secagent_scope_denials_total`,
  `secagent_runs_total{state}`, `secagent_findings_total{status}`,
  `secagent_rate_limited_total`. The `scope_denials` and `tool_calls{decision="..."}`
  series are the security-relevant ones to alert on.
- **Logs** — set `LOG_JSON=true` for structured logs. Every request gets an `X-Request-ID`
  (honored from an inbound header if present) and one access line carrying request id,
  method, route template, status, duration, and principal.

## 5. Cost control

Each project has hard ceilings (`max_iterations`, `max_tool_calls`, `max_budget_usd`),
enforced by the run's `LimitGuard`. Tool-call volume is capped at the runtime; the budget
ceiling is evaluated at phase boundaries. Translate usage into dollars by setting the
per-unit estimates (`EST_COST_PER_ITERATION_USD`, `EST_COST_PER_TOOL_CALL_USD`) to your
model's measured cost; then a run stops once its accrued estimate reaches the project's
`max_budget_usd` (`0` = no ceiling). Replace the estimate with real token accounting when
available — the ceiling semantics are unchanged.

## 6. Database: migrations & backups

Apply migrations on deploy (the compose `migrate` service does this automatically):

```bash
alembic upgrade head        # includes the Phase 5 api_keys table
```

Back up and restore with the provided scripts:

```bash
DATABASE_URL_SYNC=postgresql+psycopg2://... BACKUP_DIR=/var/backups/secagent \
  RETENTION_DAYS=14 scripts/backup.sh          # timestamped, gzipped, auto-pruned

DATABASE_URL_SYNC=postgresql+psycopg2://... scripts/restore.sh /var/backups/secagent/secagent-<stamp>.sql.gz
```

Schedule the backup from cron (store copies off-box):

```cron
15 2 * * *  DATABASE_URL_SYNC=postgresql+psycopg2://... BACKUP_DIR=/var/backups/secagent scripts/backup.sh >> /var/log/secagent-backup.log 2>&1
```

## 7. Production topology

- **Isolate the execution engine.** Today the engine runs in-process and uses the host
  Docker socket to launch sandboxed tool containers. In production, run it as a separate,
  privileged worker service so the public API process holds **no** Docker access; the API
  enqueues work and the worker executes it. The sandbox hardening (`--cap-drop ALL`,
  `--security-opt no-new-privileges`, resource caps, lab-only network, no socket mounted
  into tool containers) stays as-is.
- **Scale out.** Run several stateless API instances behind TLS at a reverse proxy.
  Move the rate limiter and the run event bus (`app/orchestration/events.py`) onto Redis so
  they are shared across instances.
- **Network.** Keep the lab network (`SANDBOX_NETWORK`) isolated from the internet and from
  the control-plane network. Terminate TLS at the proxy; forward `X-Request-ID`.

## 8. CI

`.github/workflows/ci.yml` runs on every push and PR: a backend job (install, byte-compile,
`pytest`) and a dashboard job (`npm ci`, `npm run build`). The test suite needs no database
or Docker, so CI stays fast and hermetic.

## 9. Hardening checklist

- [ ] `AUTH_ENABLED=true` and a strong, unique `API_KEY_PEPPER` (from a secret file).
- [ ] First admin key created; `BOOTSTRAP_ADMIN_KEY` unset or rotated after first boot.
- [ ] `ANTHROPIC_API_KEY` and DB credentials delivered as secret files, not env literals.
- [ ] Rate limits set; Redis-backed if multi-instance.
- [ ] `/ready` wired to the readiness probe; `/metrics` scraped; alerts on
      `secagent_scope_denials_total` and error rates.
- [ ] `LOG_JSON=true` shipping to a log aggregator.
- [ ] Per-project budget ceilings set with real per-unit cost estimates.
- [ ] Nightly backups running and restore tested on a disposable DB.
- [ ] Execution engine split into a privileged worker; API process has no Docker socket.
- [ ] Lab network isolated; TLS terminated at the proxy.
