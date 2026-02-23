"""
Corvus Mirage — Gateway
FastAPI Entry Point

Model-agnostic AI protection layer. Sits in front of any AI deployment
and inspects all incoming prompts for injection, jailbreaks, adversarial
inputs, and exfiltration attempts.

Usage:
    uvicorn main:app --host 0.0.0.0 --port 8001 --reload

Endpoints:
    POST /inspect            — inspect a prompt
    WS   /inspect/ws         — real-time dashboard event stream
    GET  /admin/policies     — list policies
    POST /admin/policies     — add policy
    PUT  /admin/policies/{n} — update policy
    DEL  /admin/policies/{n} — remove policy
    GET  /health             — liveness check
    GET  /docs               — Swagger UI
"""
import os
import sys
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Add parent directory to path for shared module access
sys.path.insert(0, str(Path(__file__).parent.parent))

load_dotenv(Path(__file__).parent.parent / ".env")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gateway")


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 55)
    logger.info("  CORVUS MIRAGE — GATEWAY")
    logger.info("  AI Protection Layer")
    logger.info("=" * 55)

    # Initialize core components
    from core import get_detection_engine, get_policy_engine, get_sanitizer

    policy_yaml = os.getenv("GATEWAY_POLICY_CONFIG", None)

    engine  = get_detection_engine(threshold=float(os.getenv("GATEWAY_THRESHOLD", "50.0")))
    policy  = get_policy_engine(config_path=policy_yaml)
    _       = get_sanitizer()

    logger.info(f"[✓] Detection engine ready | threshold={engine.threshold}")
    logger.info(f"[✓] Policy engine ready    | {len(policy.policies)} policies loaded")
    logger.info(f"[✓] Sanitizer ready")
    logger.info("-" * 55)
    logger.info("Gateway online. Protecting your AI.")
    logger.info("=" * 55)

    yield

    logger.info("Gateway shutting down.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Corvus Mirage — Gateway",
    description="Model-agnostic AI protection layer. Detects prompt injection, jailbreaks, adversarial inputs, and data exfiltration attempts.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Tighten before production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

from routes.health  import router as health_router
from routes.inspect import router as inspect_router
from routes.admin   import router as admin_router

app.include_router(health_router)
app.include_router(inspect_router)
app.include_router(admin_router)
