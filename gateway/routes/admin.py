"""
Corvus Mirage — Gateway
Admin Route
"""
import logging
from fastapi import APIRouter, HTTPException, Request

from core import get_policy_engine, get_detection_engine


logger = logging.getLogger("gateway.routes.admin")
router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/policies")
async def list_policies():
    engine = get_policy_engine()
    return {"policies": engine.list_policies(), "count": len(engine.policies)}


@router.post("/policies")
async def add_policy(request: Request):
    body = await request.json()
    engine = get_policy_engine()
    policy = engine.add_policy(body)
    logger.info(f"Policy added via API: {policy.name}")
    return {"message": f"Policy '{policy.name}' added", "policy": body}


@router.put("/policies/{name}")
async def update_policy(name: str, request: Request):
    body = await request.json()
    engine = get_policy_engine()
    updated = engine.update_policy(name, body)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")
    return {"message": f"Policy '{name}' updated"}


@router.delete("/policies/{name}")
async def remove_policy(name: str):
    engine = get_policy_engine()
    removed = engine.remove_policy(name)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")
    return {"message": f"Policy '{name}' removed"}


@router.get("/stats")
async def get_stats():
    engine = get_detection_engine()
    return {
        "detection_engine": {
            "weights":   engine.weights,
            "threshold": engine.threshold,
        },
        "policy_engine": {
            "policy_count": len(get_policy_engine().policies),
        }
    }


@router.post("/policies/{name}/toggle")
async def toggle_policy(name: str):
    engine = get_policy_engine()
    for p in engine.policies:
        if p.name == name:
            p.enabled = not p.enabled
            state = "enabled" if p.enabled else "disabled"
            return {"message": f"Policy '{name}' {state}", "enabled": p.enabled}
    raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")