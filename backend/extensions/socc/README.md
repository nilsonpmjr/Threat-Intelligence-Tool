# SOC Copilot — extension stub

Pre-Fase 4 stub of the SOC Copilot extension. Until the
`ExtensionManager` lands, dev operators wire this up by hand using the
docker compose overlay below.

## Files

| File           | Purpose                                                   |
|----------------|-----------------------------------------------------------|
| `manifest.yaml`| Declarative descriptor (PRD §Extensions Platform schema). |
| `compose.yml`  | Docker overlay defining `socc-copilot` + `socc-mongo`.    |

The manifest is a byte-for-byte twin of
`scratch/socc-plugin/manifest.yaml`. Both will collapse into one
source the moment `@vantagesec/socc-plugin` is published to GHCR.

## Dev activation

The image `socc-plugin:dev` must exist on the host first:

```bash
cd ../socc-plugin
docker compose build       # produces socc-plugin:dev
```

Generate per-environment secrets (32 bytes / 64 hex chars each) and
add them to the Vantage `.env`:

```bash
echo "SOCC_INTERNAL_SECRET=$(openssl rand -hex 32)" >> .env
echo "SOCC_MASTER_KEY=$(openssl rand -hex 32)" >> .env
```

Then launch the overlay alongside the root compose:

```bash
docker compose \
  -f docker-compose.yml \
  -f backend/extensions/socc/compose.yml \
  --profile socc up -d
```

The plugin is reachable inside the docker network at
`http://socc-copilot:7070/v1/*`. **No port is published to the host**
(PRD §Integration Points: nothing exposed beyond the internal bridge).

## Smoke check

From inside any container on `vantage_internal` (e.g. the Vantage
backend container):

```bash
wget -qO- http://socc-copilot:7070/v1/health
# => {"status":"ok","activeSessions":0}
```

Fase 2 (`backend/routers/socc.py`) will be the only legitimate caller
in production — the plugin won't be exposed to host or browsers.

## Tear down

```bash
docker compose \
  -f docker-compose.yml \
  -f backend/extensions/socc/compose.yml \
  --profile socc down -v        # -v also drops socc-mongo-data
```

`-v` is destructive: it removes the encrypted credentials and session
metadata. PRD §US-3 mandates this default for the Fase 4 uninstall
flow ("destrói volume `socc-mongo-data` por padrão").

## What's still missing (Fase 1 done criteria)

- [ ] Cross-user 404 verified against the **container** (not just the
      `app.request` mock in `sessionIsolation.test.ts`). See
      `socc-plugin/docs/TODO.md` Fase 1 section.
- [ ] Fase 2 backend proxy (`backend/routers/socc.py`) is what makes
      this reachable from the browser.
