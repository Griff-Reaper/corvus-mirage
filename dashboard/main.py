import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI

from dashboard.routes import api, websocket, health

app = FastAPI(title="Corvus Mirage Dashboard", docs_url=None)

app.include_router(health.router)
app.include_router(api.router, prefix="/api")
app.include_router(websocket.router)
