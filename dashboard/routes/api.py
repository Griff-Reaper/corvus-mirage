import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi import APIRouter
from shared.threat_intel import get_recent_events, get_cross_vector_sessions

router = APIRouter()


@router.get("/events")
async def events(limit: int = 50, component: str = "all"):
    all_events = get_recent_events(limit=limit)
    if component != "all":
        all_events = [e for e in all_events if e.get("component") == component]
    return {"events": all_events, "count": len(all_events)}


@router.get("/profiles")
async def profiles():
    cross = get_cross_vector_sessions()
    return {"profiles": cross, "count": len(cross)}


@router.get("/stats")
async def stats():
    all_events = get_recent_events(limit=1000)
    cross = get_cross_vector_sessions()

    aria_count    = sum(1 for e in all_events if e.get("component") == "aria")
    gateway_count = sum(1 for e in all_events if e.get("component") == "gateway")
    high_threat   = sum(1 for e in all_events if e.get("threat_level") == "high")
    malicious     = sum(1 for e in all_events if e.get("is_malicious"))

    return {
        "total_events":        len(all_events),
        "aria_events":         aria_count,
        "gateway_events":      gateway_count,
        "cross_vector_hits":   len(cross),
        "high_threat_count":   high_threat,
        "malicious_count":     malicious,
    }