FROM python:3.12.9-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# theHarvester: distributed via pip only (not in Debian Bookworm apt repos).
# Installed here so it shares the same Python prefix and gets copied to runtime.
# Falls back gracefully — passive module is simply marked unavailable.
RUN pip install --no-cache-dir --prefix=/install 'theHarvester>=4.4.0' \
    || echo "WARNING: theHarvester install failed — passive module will be unavailable"

# Download subfinder binary (pinned version for deterministic builds).
# --fail ensures curl exits non-zero on HTTP errors instead of saving HTML.
# Falls back gracefully — subdomains module is simply marked unavailable.
RUN mkdir -p /install/bin \
    && curl -fsSL --retry 3 --retry-delay 2 \
        https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
        -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip -d /tmp/subfinder-bin \
    && mv /tmp/subfinder-bin/subfinder /install/bin/subfinder \
    && chmod +x /install/bin/subfinder \
    && rm -rf /tmp/subfinder.zip /tmp/subfinder-bin \
    || echo "WARNING: subfinder download failed — subdomains module will be unavailable"

# ── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM python:3.12.9-slim

WORKDIR /app

ARG APP_UID=10001
ARG APP_GID=10001

# System tools required at runtime:
#   - Recon Engine: nmap, whois, traceroute, dnsutils
#   - Extensions Platform: docker CLI (used by ExtensionManager to run
#     `docker compose up/down/start/stop` against docker-socket-proxy)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    traceroute \
    dnsutils \
    ca-certificates \
    curl \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
       https://download.docker.com/linux/debian bookworm stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid ${APP_GID} appuser \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --home-dir /home/appuser --shell /usr/sbin/nologin appuser

# Copy installed Python packages (including subfinder) from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=appuser:appuser . .

# Runtime should not rely on root-owned home paths.
ENV HOME=/home/appuser
ENV PATH=/usr/local/bin:$PATH

EXPOSE 8000

USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
