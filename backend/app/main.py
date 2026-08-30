from fastapi import FastAPI

from app.api.routes_decisions import router as decisions_router
from app.api.routes_health import router as health_router

app = FastAPI(
    title="AI Network Anomaly Detection Platform",
    version="0.1.0",
    description=(
        "Defensive network-flow analysis. Model-backed prediction is introduced "
        "after the reproducible training phase."
    ),
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(decisions_router, prefix="/api/v1")
