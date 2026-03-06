from sqlalchemy import Column, String, DateTime, Boolean, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.core.database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(String, nullable=True, index=True)     # Clerk user ID (null in single-org mode)
    display_name  = Column(String, nullable=False)
    domain        = Column(String, nullable=False)                # Primary domain (e.g. contoso.com)
    extra_domains = Column(JSON, nullable=True, default=list)     # Additional verified domains

    # ── Microsoft 365 credentials (optional) ──────────────────────────────────
    tenant_id     = Column(String, nullable=True)                 # Azure AD Tenant ID (GUID)
    client_id     = Column(String, nullable=True)                 # App Registration Client ID
    client_secret = Column(String, nullable=True)                 # Encrypted

    # ── Google Workspace credentials (optional) ────────────────────────────────
    gws_refresh_token = Column(String, nullable=True)             # Encrypted GWS refresh token

    # ── State ──────────────────────────────────────────────────────────────────
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=datetime.utcnow)
    last_scan_at  = Column(DateTime, nullable=True)

    scans = relationship("Scan", back_populates="tenant", cascade="all, delete-orphan")

    @property
    def all_domains(self) -> list[str]:
        """Return the primary domain plus any additional verified domains, deduplicated."""
        domains = [self.domain]
        for d in (self.extra_domains or []):
            if d and d not in domains:
                domains.append(d)
        return domains

    @property
    def has_m365(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    @property
    def has_gws(self) -> bool:
        return bool(self.gws_refresh_token)

    @property
    def platforms(self) -> list[str]:
        """Return list of connected platforms."""
        p = []
        if self.has_m365: p.append("m365")
        if self.has_gws:  p.append("gws")
        return p
