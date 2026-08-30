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

    # API Server configuration
    APP_NAME: str = "AI Network Anomaly Detection Platform"
    APP_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False

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


settings = Settings()
