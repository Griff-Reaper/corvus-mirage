"""
Corvus Mirage — ARIA
Health Check Route
"""

from fastapi import APIRouter
from datetime import datetime

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "online",
        "component": "aria",
        "platform": "Corvus Mirage",
        "timestamp": datetime.utcnow().isoformat()
    }
