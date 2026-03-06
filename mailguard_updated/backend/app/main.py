from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, Response
import os

from app.api import tenants, scans, reports, onboarding, vendor_pdfs, auth, google_auth
from app.core.config import settings

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

@app.get("/api/config", include_in_schema=False)
def get_config():
    """Frontend reads this to know if auth is required."""
    return {"multi_tenant_mode": settings.MULTI_TENANT_MODE}

# ── Paths served by React SPA ────────────────────────────────────────────────
SERVER_PATHS = set()  # No server-side overrides — all routes handled by React

# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(tenants.router,     prefix="/api/v1/tenants",     tags=["Tenants"])
app.include_router(scans.router,       prefix="/api/v1/scans",       tags=["Scans"])
app.include_router(reports.router,     prefix="/api/v1/reports",      tags=["Reports"])
app.include_router(auth.router,        prefix="/api/v1/auth",         tags=["Auth"])
app.include_router(google_auth.router,  prefix="/api/v1/google",        tags=["Google"])
app.include_router(onboarding.router,  prefix="/api",                 tags=["Onboarding"])
app.include_router(vendor_pdfs.router, prefix="/api/v1",              tags=["Vendor PDFs"])

@app.get("/api/health", tags=["Health"])
async def health():
    return {"status": "ok", "version": "1.0.0"}

# ── React SPA assets ──────────────────────────────────────────────────────────
FRONTEND = os.path.join(os.path.dirname(__file__), "../../frontend/dist")

if os.path.isdir(FRONTEND):
    app.mount("/assets", StaticFiles(directory=f"{FRONTEND}/assets"), name="assets")

# ── SPA index.html — served with no-cache so browser always fetches fresh ────
@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str):
    # Never intercept API or server-owned paths
    if full_path in SERVER_PATHS:
        pass  # Fall through to serve index.html
    if full_path.startswith("api/"):
        return HTMLResponse("Not found", status_code=404)

    index = os.path.join(FRONTEND, "index.html")
    if not os.path.isfile(index):
        return HTMLResponse("<h1>Not found</h1>", status_code=404)

    with open(index, "r") as f:
        content = f.read()

    # No-cache on index.html means the browser ALWAYS fetches from server
    # instead of serving cached copy — this ensures /connect gets onboard.html
    # not the cached React shell
    return Response(
        content=content,
        media_type="text/html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )
