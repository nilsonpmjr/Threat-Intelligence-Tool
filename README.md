# VANTAGE

[![CI](https://github.com/nilsonpmjr/Vantage/actions/workflows/ci.yml/badge.svg)](https://github.com/nilsonpmjr/Vantage/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://reactjs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-8-47A248.svg)](https://www.mongodb.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)

VANTAGE is a threat intelligence platform for SOC teams that need fast, explainable verdicts for IPs, domains, and file hashes, plus an operational workspace to triage feeds, recon, watchlists, hunting, and exposure in one place.

The project is released under AGPLv3 by design. The goal is to keep the platform transparent, auditable, and collaborative as it grows from an internal workflow accelerator into an independent cybersecurity product.

## Licensing & Distribution

- **Core license**: `AGPLv3`
- **Public core**: this repository and the official runtime shipped here
- **Commercial layer**: support, managed operation, premium extensions, and contract-specific deliverables outside the public core
- **Trademark/brand governance**: handled separately from the code license

This keeps the product open and auditable while preserving a clean open-core boundary for commercial offerings.

## Product Scope

### What ships in v1

- analyst workspaces for `Feed`, `Recon`, `Watchlist`, `Hunting`, `Exposure`, `Dashboard`, `Home`, and single/batch analysis
- administrative control surfaces for `Extensions`, `Threat Ingestion`, `System Health`, `Users & Roles`, and `Security Policies`
- auth, `RBAC`, `MFA`, sessions, audit log, API keys, and guided onboarding
- editorial intelligence ingestion with `RSS`, `MISP`, curated `Fortinet RSS`, and initial `CTI Modeling Readiness`

### What stays post-v1

- ML models trained in production
- enterprise distribution and managed operation layers
- premium extensions and contract-specific deliverables outside this repository

See the full package and roadmap:

- [`docs/VANTAGE/fases/12-consolidacao-produto-e-lancamento-v1/PACOTE-funcional-v1.md`](docs/VANTAGE/fases/12-consolidacao-produto-e-lancamento-v1/PACOTE-funcional-v1.md)
- [`docs/VANTAGE/ROADMAP-core-e-pos-v1.md`](docs/VANTAGE/ROADMAP-core-e-pos-v1.md)
- [`docs/VANTAGE/fases/25-empacotamento-piloto-interno/PRD-empacotamento-piloto-interno.md`](docs/VANTAGE/fases/25-empacotamento-piloto-interno/PRD-empacotamento-piloto-interno.md)
- [`docs/VANTAGE/fases/25-empacotamento-piloto-interno/RUNBOOK-rollout-piloto-interno.md`](docs/VANTAGE/fases/25-empacotamento-piloto-interno/RUNBOOK-rollout-piloto-interno.md)
- [`docs/VANTAGE/fases/25-empacotamento-piloto-interno/CHECKLIST-go-live-piloto-interno.md`](docs/VANTAGE/fases/25-empacotamento-piloto-interno/CHECKLIST-go-live-piloto-interno.md)

## Core Capabilities

- **Parallel Threat Intelligence** — Queries VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise, UrlScan.io, Abuse.ch, Pulsedive, and BlacklistMaster simultaneously
- **AI Reports** — Contextual natural-language summaries in PT-BR, EN, and ES
- **IAM & RBAC** — Role-based access control (admin / manager / tech), JWT + HttpOnly cookies, refresh tokens
- **MFA (TOTP)** — Authenticator-app 2FA with AES-256 encrypted secrets and backup codes
- **Session Management** — Active session list, per-session revocation, 30-min inactivity auto-logout
- **API Keys** — Scoped API keys with SHA-256 hashed storage and configurable TTL
- **Audit Log** — Full audit trail of all user actions with CSV/JSON export
- **Background Worker** — Daily re-scan of known targets for verdict change detection
- **Password Policy** — Configurable complexity, history, expiry, and lockout rules
- **Dark Mode UI** — Glassmorphism design with responsive layout and guided tour

## Architecture

```
┌──────────────────┐     HTTPS      ┌─────────────────────┐
│  React + Vite    │ ◄────────────► │  FastAPI (Python)   │
│  (port 80/443)   │                │  (port 8000)        │
└──────────────────┘                └──────────┬──────────┘
                                               │
                                    ┌──────────▼──────────┐
                                    │  MongoDB 8          │
                                    │  (port 27017)       │
                                    └─────────────────────┘
```

**Backend modules**: `routers/` (auth, users, analyze, stats, admin, mfa, sessions, api_keys) · `analyzer.py` · `scoring.py` · `worker.py` · `mailer.py` · `audit.py`

**Frontend structure**: `components/auth/` · `components/admin/` · `components/dashboard/` · `components/layout/` · `components/shared/` · `context/`

## Who It Is For

- SOC analysts who need a daily workspace, not just a single lookup tool
- technical operators who need visibility into ingestion, policies, sessions, and runtime health
- maintainers who want an open core with a clear path to downstream and commercial layers

## Quick Start (Docker — recommended)

### 1. Clone and configure

```bash
git clone https://github.com/nilsonpmjr/Vantage.git
cd Vantage
cp .env.example .env
```

Edit `.env` and fill in the required values (see [Environment Variables](#environment-variables) below).

If you already cloned the project before the repository rename, you do not need to rename your local folder. Updating the git remotes is enough.

### 2. Start services

```bash
docker compose up -d
```

The app will be available at `http://localhost` (frontend) and `http://localhost:8000` (API).
MongoDB stays on the internal Docker network only; it is no longer published to the host.

### Frontend Runtime

The default Docker stack already serves the canonical interface from [`web`](./web).

Operational note: CI, branding assets, the extension registry, and Docker runtime now treat `web/` as the source of truth for the official interface.

Historical note: `web-legacy/` remains in the repository only as an archived reference and is not used by the official runtime.

For a local rehearsal on an alternate port, use the port override:

```bash
VANTAGE_FRONTEND_PORT=4177 docker compose \
  -f docker-compose.yml \
  -f docker-compose.operational-architect.yml \
  up -d --build
```

The override now changes only the published frontend port. The service definition itself already points to the canonical build.

### Optional: hunting runtime lane

The main stack does not require Kali. Hunting providers can run in three declared lanes:

- `native_local`
- `isolated_container`
- `kali_container`

The current Sherlock provider can fall back to `native_local` when the local binary is available. The optional Kali sidecar is declared in [`docker-compose.hunting-kali.yml`](./docker-compose.hunting-kali.yml) for providers that eventually require that heavier lane.

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.hunting-kali.yml \
  up -d backend hunting_kali_runtime
```

This does not change the default product contract. It only makes the optional Kali lane explicit and observable to the backend and UI.

### Optional: host-specific egress workaround

Some Linux hosts need an extra egress workaround when custom Docker bridges do
not provide outbound connectivity. This is not part of the default pilot path.

```bash
docker compose --profile egress-workaround up -d backend-egress
```

## Internal Pilot Packaging

The first internal pilot is designed for a single Linux host with Docker Engine + Compose, not Kubernetes. The recommended baseline is:

- `Ubuntu 24.04 LTS`
- `4 vCPU / 8 GB RAM / 120 GB SSD`
- reverse proxy or private access layer in front of the frontend (`Cloudflare Tunnel`, `Tailscale`, `Nginx Proxy Manager`, or equivalent)
- daily backup for the `mongodb_data` volume

The stack now exposes lightweight health probes for rollout automation:

- backend live: `GET /health/live` or `GET /api/health/live`
- backend readiness: `GET /health/ready` or `GET /api/health/ready`

Use the phase 25 runbook and checklist before putting analysts on the system.

### 3. Seed initial admin user

```bash
docker compose exec backend python scripts/seed_users.py
```

### Optional: mongo-express (dev only)

```bash
docker compose --profile dev up -d
# mongo-express at http://127.0.0.1:8081
```

## Development Setup (without Docker)

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Copy and fill in .env at repo root, then:
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend

```bash
cd web
npm install
npm run dev
# Available at http://localhost:5173
```

### Run tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Environment Variables

Copy `.env.example` to `.env` and configure the following:

### Required

| Variable | Description |
|---|---|
| `JWT_SECRET` | Random string ≥32 chars for signing JWT tokens |
| `MONGO_URI` | MongoDB connection string for local backend runs (e.g. `mongodb://user:pass@localhost:27017/`) |
| `MONGO_USER` | MongoDB root username (used by docker-compose) |
| `MONGO_PASSWORD` | MongoDB root password (used by docker-compose) |

When you use `docker compose`, the backend receives an internal `MONGO_URI` automatically and connects to the `mongodb` service over the private bridge network.

### Threat Intelligence API Keys

| Variable | Service | Free Tier |
|---|---|---|
| `VT_API_KEY` | VirusTotal | 4 req/min |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | 1000 req/day |
| `SHODAN_API_KEY` | Shodan | Limited |
| `OTX_API_KEY` | AlienVault OTX | Unlimited |
| `GREYNOISE_API_KEY` | GreyNoise | Community |
| `URLSCAN_API_KEY` | UrlScan.io | 100 req/day |
| `IP2LOCATION_API_KEY` | IP2Location.io | 1000 req/day keyless, 50k/mo free with key |
| `PULSEDIVE_API_KEY` | Pulsedive | Free tier |
| `ABUSECH_API_KEY` | Abuse.ch | Free |

Missing keys are gracefully skipped, except `IP2LOCATION`, which can run in public keyless mode with a lower daily limit.

### Optional

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | Set to `production` to enable HSTS and stricter validation |
| `CACHE_TTL_HOURS` | `24` | How long scan results are cached in MongoDB |
| `MFA_ENCRYPTION_KEY` | auto-derived (dev) | Fernet key for TOTP secrets; **required in production** |
| `FRONTEND_URL` | `http://localhost:5173` | Base URL for password-reset email links |
| `SMTP_HOST` | — | SMTP server for password-reset emails |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASS` | — | SMTP password |
| `SMTP_FROM` | `noreply@soc.local` | From address for outgoing emails |
| `LOG_LEVEL` | `INFO` | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

## API Endpoints

The canonical API prefix is `/api`.
`/api/v1` remains temporarily available for backwards compatibility, but responses now include explicit deprecation headers and a `Sunset` date of `2026-09-30`.

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Login (form data: username, password) |
| `POST` | `/api/auth/logout` | Logout (clears cookies) |
| `POST` | `/api/auth/refresh` | Rotate access/refresh tokens |
| `GET` | `/api/auth/me` | Current user info |
| `GET` | `/api/auth/sessions` | List active sessions |
| `DELETE` | `/api/auth/sessions/{id}` | Revoke a session |
| `DELETE` | `/api/auth/sessions/others` | Revoke all other sessions |
| `POST` | `/api/auth/forgot-password` | Request password-reset email |
| `POST` | `/api/auth/reset-password` | Reset password with token |

### MFA

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/mfa/enroll` | Begin TOTP enrollment (returns QR URI) |
| `POST` | `/api/mfa/confirm` | Confirm enrollment with OTP code |
| `POST` | `/api/mfa/verify` | Verify OTP during login (pre-auth token) |
| `DELETE` | `/api/mfa/me` | Disable own MFA |
| `DELETE` | `/api/mfa/{username}` | Admin: revoke user MFA |

### Threat Analysis

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/analyze?target=&lang=` | Analyze an IP, domain, or hash |
| `GET` | `/api/status` | Service availability (which API keys are configured) |

### Users & API Keys

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/users` | List users (admin) |
| `POST` | `/api/users` | Create user (admin) |
| `PUT` | `/api/users/{username}` | Update user |
| `DELETE` | `/api/users/{username}` | Delete user (admin) |
| `GET` | `/api/api-keys/me` | List own API keys |
| `POST` | `/api/api-keys` | Create API key |
| `DELETE` | `/api/api-keys/{id}` | Revoke API key |

### Admin & Stats

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | Dashboard statistics (`?period=day\|week\|month\|all`) |
| `GET` | `/api/admin/overview` | IAM overview metrics |
| `GET` | `/api/admin/audit-logs` | Paginated audit log |
| `GET` | `/api/admin/audit-logs/export` | Export audit log (CSV or JSON) |
| `PUT` | `/api/admin/password-policy` | Update password policy |
| `PUT` | `/api/admin/lockout-policy` | Update lockout policy |

## RBAC — Roles

| Role | Capabilities |
|---|---|
| `admin` | Full access; manage users, policies, audit logs; MFA required |
| `manager` | Dashboard + analysis + stats; read-only on user list; MFA required |
| `tech` | Analysis only; no admin panels |

## CI/CD

GitHub Actions runs on every PR and push to `main`:

- **lint-python** — flake8
- **test-python** — pytest against MongoDB 8
- **lint-frontend** — ESLint
- **test-frontend** — Vitest
- **build-frontend** — Vite production build

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## License

[AGPLv3](LICENSE)
