from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    app_name: str = "VANTAGE"
    core_version: str = "1.0.0"
    local_plugin_root: str = "backend/extensions/local_plugins"
    premium_plugin_roots: str = "backend/extensions/premium_plugins"

    # Authentication — no default; must be set via environment variable
    jwt_secret: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60  # 1 hour (access token)
    refresh_token_expire_days: int = 7     # 7 days (refresh token)

    # Database — no default; must be set via environment variable
    mongo_uri: str
    mongo_db_name: str = "threat_intel"
    mongo_max_pool_size: int = 100
    mongo_min_pool_size: int = 5

    # CORS — list specific origins; never use "*" in production
    # In production set CORS_ORIGINS to your public hostname, e.g.:
    # CORS_ORIGINS=["https://vantage.it-eam.com"]
    cors_origins: List[str] = ["http://localhost", "http://localhost:5173"]

    # Cache
    cache_ttl_hours: int = 24
    analyze_runtime_lease_seconds: int = 30
    analyze_shared_wait_seconds: int = 12

    # Concurrency
    analyze_max_concurrent: int = 80

    # Worker (background rescan job)
    rescan_batch_size: int = 5
    max_rescan_targets: int = 100

    # Batch analysis
    batch_max_targets: int = 50
    batch_inter_target_delay_ms: int = 500  # ms between external calls
    batch_job_ttl_hours: int = 24

    # Rate limiting
    rate_limit_analyze: str = "30/minute"
    rate_limit_batch: str = "5/minute"
    rate_limit_recon: str = "10/hour"
    # SOC Copilot — PRD §Security: 20 msgs/min/user.
    rate_limit_socc_message: str = "20/minute"

    # SOC Copilot extension wiring (PRD §Integration Points).
    # The plugin runs in the same docker network and is reachable via
    # the service DNS name; nothing is exposed to the host.
    socc_plugin_url: str = "http://socc-copilot:7070"
    # 32-byte hex shared secret used to mint scope=socc JWTs (TTL 60s).
    # Empty string disables the SOC Copilot router so the rest of the
    # backend boots even when the extension isn't installed.
    socc_internal_secret: str = ""
    # Admin flag — when False, /api/socc/providers refuses provider=ollama
    # with `local_provider_disabled` even before forwarding to the plugin.
    socc_allow_local_providers: bool = False
    # Outbound timeout for the proxy. Streaming routes ignore this and
    # rely on the plugin's own 90s TURN_TIMEOUT_MS (PRD §Security).
    socc_proxy_timeout_seconds: float = 30.0

    # Recon Engine
    recon_cache_ttl_hours: int = 6
    recon_port_range: str = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888"
    recon_max_concurrent: int = 2

    # MFA
    mfa_encryption_key: str = ""            # Fernet key; auto-derived in dev if empty
    mfa_preauth_secret: str = ""            # Separate JWT secret for MFA pre-auth tokens
    mfa_required_roles: List[str] = ["admin", "manager"]  # roles that MUST enroll MFA

    # SMTP (optional — needed for password reset emails)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = "noreply@soc.local"
    smtp_tls: bool = True

    # Frontend base URL (used to build password reset links)
    frontend_url: str = "http://localhost:5173"

    # Runtime
    environment: str = "development"
    log_level: str = "INFO"

    # Development seed (never use in production)
    dev_seed_users: bool = False
    dev_admin_password: str = ""
    dev_tech_password: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def validate_production(self) -> None:
        """Raise if critical secrets are insecure or missing in production."""
        if self.environment != "production":
            return
        errors = []
        if len(self.jwt_secret) < 64:
            errors.append("JWT_SECRET must be at least 64 characters.")
        if not self.mfa_encryption_key:
            errors.append("MFA_ENCRYPTION_KEY must be set in production.")
        if not self.mfa_preauth_secret:
            errors.append("MFA_PREAUTH_SECRET must be set in production.")
        if self.mfa_preauth_secret and self.mfa_preauth_secret == self.jwt_secret:
            errors.append("MFA_PREAUTH_SECRET must differ from JWT_SECRET.")
        if self.dev_seed_users:
            errors.append(
                "[SECURITY] DEV_SEED_USERS=true is forbidden in production. "
                "Remove this variable from the production environment."
            )
        if errors:
            raise ValueError("Insecure production configuration:\n" + "\n".join(f"  - {e}" for e in errors))


settings = Settings()
