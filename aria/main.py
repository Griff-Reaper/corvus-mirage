"""
Corvus Mirage — ARIA
Deception & Detection Engine
Entry point
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

from routes.voice import router as voice_router
from routes.sessions import router as sessions_router
from routes.health import router as health_router
from core.websocket_manager import WebSocketManager

app = FastAPI(
    title="Corvus Mirage — ARIA",
    description="Deception & Detection Engine",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket manager for real-time dashboard streaming
app.state.ws_manager = WebSocketManager()

# Routes
app.include_router(health_router)
app.include_router(voice_router, prefix="/voice")
app.include_router(sessions_router, prefix="/sessions")


@app.on_event("startup")
async def startup():
    from shared.threat_intel_init import init_db
    init_db()
    print("🦅 Corvus Mirage — ARIA online")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=os.getenv("ARIA_HOST", "0.0.0.0"),
        port=int(os.getenv("ARIA_PORT", 8000)),
        reload=True
    )
