"""
Auth middleware for MailGuard.

In single-org mode (MULTI_TENANT_MODE=false):
  - No authentication required
  - user_id is always None
  - All tenants/scans are shared
"""

from fastapi import Header, Depends
from typing import Optional
from app.core.config import settings


async def get_current_user(authorization: Optional[str] = Header(default=None)) -> Optional[str]:
    """
    Always returns None in single-org mode.
    MULTI_TENANT_MODE is reserved for future SaaS use.
    """
    return None


# Dependency alias
CurrentUser = Depends(get_current_user)
