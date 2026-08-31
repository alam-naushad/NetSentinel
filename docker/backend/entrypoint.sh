#!/bin/sh
# ==============================================================================
# Backend Container Entrypoint Script — Stage 11 Hardened Infrastructure
# ==============================================================================
set -e

echo "[+] Starting backend container initialization (User: $(whoami), UID: $(id -u))..."

# ------------------------------------------------------------------------------
# 1. Environment Variable Validation
# ------------------------------------------------------------------------------
echo "[*] Validating environment configuration..."
if [ -z "$DATABASE_URL" ]; then
    echo "[-] ERROR: DATABASE_URL environment variable is not set." >&2
    exit 1
fi

DATABASE_REQUIRED=${DATABASE_REQUIRED:-true}
echo "[*] Environment: ${ENVIRONMENT:-production} | DATABASE_REQUIRED: ${DATABASE_REQUIRED}"

# ------------------------------------------------------------------------------
# 2. Bounded Wait-For-Database Loop
# ------------------------------------------------------------------------------
if [ "$DATABASE_REQUIRED" = "true" ]; then
    echo "[*] Checking PostgreSQL connectivity with bounded backoff..."
    
    # Extract host and port from DATABASE_URL or defaults
    DB_HOST="${POSTGRES_HOST:-postgres}"
    DB_PORT="${POSTGRES_PORT:-5432}"
    
    MAX_RETRIES=30
    RETRY_COUNT=0
    WAIT_INTERVAL=2

    until python3 -c "
import sys
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

async def check():
    url = '${DATABASE_URL}'
    engine = create_async_engine(url, connect_args={'timeout': 3})
    async with engine.connect() as conn:
        await conn.execute(text('SELECT 1'))
    await engine.dispose()

try:
    asyncio.run(check())
    sys.exit(0)
except Exception as e:
    sys.exit(1)
" 2>/dev/null; do
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
            echo "[-] FATAL: PostgreSQL at ${DB_HOST}:${DB_PORT} remained unavailable after $((MAX_RETRIES * WAIT_INTERVAL)) seconds." >&2
            exit 1
        fi
        echo "    - Waiting for PostgreSQL... (attempt ${RETRY_COUNT}/${MAX_RETRIES})"
        sleep "$WAIT_INTERVAL"
    done
    echo "[+] PostgreSQL connection established successfully."
fi

# ------------------------------------------------------------------------------
# 3. Database Schema Migration via Alembic
# ------------------------------------------------------------------------------
if [ "$DATABASE_REQUIRED" = "true" ]; then
    echo "[*] Running database migrations (alembic upgrade head)..."
    cd /app/backend
    if ! alembic upgrade head; then
        echo "[-] FATAL: Alembic migration failed! Refusing to start application." >&2
        exit 1
    fi
    
    # 4. Verify Alembic Migration Head
    echo "[*] Verifying migration head status..."
    CURRENT_HEAD=$(alembic current 2>/dev/null | grep "(head)" || true)
    if [ -z "$CURRENT_HEAD" ]; then
        echo "[-] WARNING: Alembic current revision did not explicitly match head." >&2
    else
        echo "[+] Alembic verified at migration head: ${CURRENT_HEAD}"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Model Artifact Availability & Integrity Verification
# ------------------------------------------------------------------------------
echo "[*] Verifying frozen Stage 3 model artifacts in /app/artifacts/models..."
if ! python3 -c "
import sys
sys.path.insert(0, '/app/backend')
from app.services.model_registry import get_model_registry

registry = get_model_registry()
verified = registry.validate_required_models_exist()
print(f'[+] Verified {len(verified)} required production models with SHA-256 integrity: {list(verified.keys())}')
"; then
    echo "[-] FATAL: Required model artifact validation failed! Refusing to start application." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 6. Launch Application Service via Uvicorn
# ------------------------------------------------------------------------------
echo "[+] Initialization complete. Launching Uvicorn ASGI server on port 8000..."
cd /app/backend
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
