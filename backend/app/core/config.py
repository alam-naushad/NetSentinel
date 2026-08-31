"""Application Configuration and Settings Management.

Loads environment variables and defaults with strict validation via Pydantic Settings.
"""

from __future__ import annotations

from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Application settings schema."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application identity & version
    APP_NAME: str = "AI Network Anomaly Detection Platform"
    APP_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False

    # Environment & Security Configuration (Stage 10 Hardened Capstone Deployment)
    ENVIRONMENT: str = Field(
        default="development",
        description="Deployment mode: 'development', 'staging', 'production'",
    )
    CORS_ORIGINS: str = Field(
        default="http://localhost:5173,http://localhost:80,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:80,http://127.0.0.1:3000",
        description="Comma-separated allowed CORS origins (use '*' only in explicit local development)",
    )
    ENABLE_HTTPS: bool = Field(
        default=False,
        description="Whether HTTPS is active (controls Strict-Transport-Security header emission)",
    )
    RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        description="Whether in-memory process-local rate limiting is enabled",
    )
    RATE_LIMIT_INFERENCE_PER_MIN: int = Field(
        default=60,
        ge=1,
        le=10000,
        description="Maximum inference requests per minute per client IP",
    )
    RATE_LIMIT_UPLOAD_PER_MIN: int = Field(
        default=20,
        ge=1,
        le=1000,
        description="Maximum PCAP and Zeek log upload requests per minute per client IP",
    )
    LOG_FORMAT: str = Field(
        default="console",
        description="Logging output format: 'console' (human-readable) or 'json' (structured)",
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Root logging severity level",
    )
    API_KEY: str | None = Field(
        default=None,
        description="Optional API key for deployment-level request guarding (via X-API-Key header)",
    )
    PCAP_MAX_UPLOAD_SIZE_MB: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum file upload size for PCAP analysis in MB (Stage 6B validated default: 50MB)",
    )
    PCAP_MAX_FLOWS: int = Field(
        default=10_000,
        ge=1,
        le=100_000,
        description="Maximum number of flows to extract and analyze from a single PCAP capture",
    )

    # Database configuration
    # Async connection URL for runtime FastAPI endpoints (asyncpg)
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://soc_user:soc_password@localhost:5432/soc_telemetry",
        description="Async database connection string",
    )
    # Sync connection URL for migrations & batch tools (psycopg)
    DATABASE_SYNC_URL: str = Field(
        default="postgresql+psycopg://soc_user:soc_password@localhost:5432/soc_telemetry",
        description="Sync database connection string for Alembic/tools",
    )
    # Explicit startup enforcement flag
    DATABASE_REQUIRED: bool = Field(
        default=False,
        description="If True, backend startup fails immediately if PostgreSQL is unavailable. If False, runs in explicit ephemeral mode.",
    )
    DB_POOL_SIZE: int = Field(default=10, ge=1, le=100)
    DB_MAX_OVERFLOW: int = Field(default=20, ge=0, le=100)
    DB_POOL_TIMEOUT: float = Field(default=30.0, ge=1.0)

    # Alert Policy configuration (Configurable thresholds, not hard-coded scientific truths)
    ALERT_RISK_THRESHOLD: int = Field(
        default=65,
        ge=0,
        le=100,
        description="Configurable risk score threshold above which security events generate analyst alerts",
    )
    ALERT_CONFIDENCE_THRESHOLD: float = Field(
        default=0.80,
        ge=0.0,
        le=1.0,
        description="Minimum classifier confidence for known attack escalation",
    )
    ALERT_ON_UNKNOWN_ANOMALY: bool = Field(
        default=True,
        description="Whether statistical anomalies with UNKNOWN_ANOMALY triage status escalate to alerts",
    )
    ALERT_POLICY_VERSION: str = "policy-alert-v1.0"

    # Data Retention configuration
    FEATURE_VECTOR_RETENTION_DAYS: int = Field(
        default=90,
        ge=1,
        description="Retention period in days for raw JSONB 48-feature vectors before archival",
    )

    # Zeek Ingestion configuration
    ZEEK_MAX_UPLOAD_SIZE_MB: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum file upload size for Zeek log files in MB",
    )
    ZEEK_MAX_CONNECTIONS: int = Field(
        default=100_000,
        ge=1,
        le=1_000_000,
        description="Maximum number of connections to parse from a single Zeek log file",
    )

    # Zeek Real-Time Spool Ingestion (Stage 9B)
    ZEEK_SPOOL_ENABLED: bool = Field(
        default=False,
        description="Enable real-time spool directory ingestion on startup",
    )
    ZEEK_SPOOL_DIR: str = Field(
        default="/opt/zeek/spool/zeek",
        description="Whitelisted spool directory for Zeek log tailing (absolute path)",
    )
    ZEEK_SPOOL_POLL_INTERVAL_SEC: float = Field(
        default=1.0, ge=0.1, le=30.0,
        description="Filesystem poll interval in seconds",
    )
    ZEEK_SPOOL_FILE_PATTERN: str = Field(
        default="conn*.log",
        description="Glob pattern for Zeek log files to tail within the spool directory",
    )
    ZEEK_QUEUE_MAX_SIZE: int = Field(
        default=4096, ge=64, le=65536,
        description="Bounded asyncio queue capacity for ingestion pipeline",
    )
    ZEEK_BATCH_SIZE: int = Field(
        default=50, ge=1, le=1000,
        description="Records per micro-batch before database flush",
    )
    ZEEK_BATCH_FLUSH_INTERVAL_SEC: float = Field(
        default=2.0, ge=0.1, le=30.0,
        description="Maximum seconds before flushing a partial micro-batch",
    )
    ZEEK_DEDUP_CACHE_SIZE: int = Field(
        default=10_000, ge=100, le=1_000_000,
        description="UID dedup LRU cache capacity",
    )

    # Zeek SSE Streaming (Stage 9B)
    ZEEK_SSE_MAX_CLIENTS: int = Field(
        default=32, ge=1, le=256,
        description="Maximum concurrent SSE connections",
    )
    ZEEK_SSE_REPLAY_BUFFER_SIZE: int = Field(
        default=256, ge=0, le=10_000,
        description="Ring buffer size for Last-Event-ID SSE replay",
    )
    ZEEK_SSE_HEARTBEAT_SEC: float = Field(
        default=15.0, ge=1.0, le=120.0,
        description="SSE heartbeat comment interval in seconds",
    )


settings = Settings()
