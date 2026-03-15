# MailGuard V2 API package.
# Exposes v2_router for registration in the main FastAPI app.

from .router import v2_router

__all__ = ["v2_router"]