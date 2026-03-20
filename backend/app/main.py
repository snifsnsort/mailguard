import asyncio
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api import tenants, scans, reports, onboarding, vendor_pdfs, auth, google_auth, aggressive_scan
from app.api.v2.router import v2_router
from app.core.config import settings
from app.services.scan_scheduler import scan_schedule_loop
# Import models so SQLAlchemy registers them with Base before create_all
import app.models.aggressive_scan  # noqa: F401
import app.models.scan_schedule    # noqa: F401
import app.models.v2.job           # noqa: F401

app = FastAPI(
    title="MailGuard API",
    description="Email Security Posture Management for Microsoft 365",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def start_scan_scheduler():
    app.state.scan_scheduler_task = asyncio.create_task(scan_schedule_loop())


@app.on_event("shutdown")
async def stop_scan_scheduler():
    task = getattr(app.state, "scan_scheduler_task", None)
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@app.get("/api/config", include_in_schema=False)
def get_config():
    """Frontend reads this to know if auth is required."""
    return {"multi_tenant_mode": settings.multi_tenant_mode}


SERVER_PATHS = set()

app.include_router(tenants.router,          prefix="/api/v1/tenants",          tags=["Tenants"])
app.include_router(scans.router,            prefix="/api/v1/scans",            tags=["Scans"])
app.include_router(reports.router,          prefix="/api/v1/reports",          tags=["Reports"])
app.include_router(auth.router,             prefix="/api/v1/auth",             tags=["Auth"])
app.include_router(google_auth.router,      prefix="/api/v1/google",           tags=["Google"])
app.include_router(onboarding.router,       prefix="/api",                     tags=["Onboarding"])
app.include_router(vendor_pdfs.router,      prefix="/api/v1",                  tags=["Vendor PDFs"])
app.include_router(aggressive_scan.router,  prefix="/api/v1/aggressive-scan",  tags=["Aggressive Scan"])
app.include_router(v2_router,               prefix="/api/v2",                  tags=["V2"])


@app.get("/api/health", tags=["Health"])
async def health():
    return {"status": "ok", "version": "1.0.0"}


FRONTEND = os.path.join(os.path.dirname(__file__), "../../frontend/dist")

if os.path.isdir(FRONTEND):
    app.mount("/assets", StaticFiles(directory=f"{FRONTEND}/assets"), name="assets")


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str):
    if full_path in SERVER_PATHS:
        pass
    if full_path.startswith("api/"):
        return HTMLResponse("Not found", status_code=404)

    index = os.path.join(FRONTEND, "index.html")
    if not os.path.isfile(index):
        return HTMLResponse("<h1>Not found</h1>", status_code=404)

    with open(index, "r") as f:
        content = f.read()

    return Response(
        content=content,
        media_type="text/html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )
