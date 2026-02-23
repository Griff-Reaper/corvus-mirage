"""
Corvus Mirage — Gateway
Health Route

GET /health — liveness check for load balancers and monitoring
"""
from fastapi import APIRouter
from datetime import datetime

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    return {
        "status":    "ok",
        "component": "gateway",
        "platform":  "corvus-mirage",
        "timestamp": datetime.utcnow().isoformat(),
    }
