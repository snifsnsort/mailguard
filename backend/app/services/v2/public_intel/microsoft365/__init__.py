# Microsoft 365 public intelligence adapter.
# Exposes M365TenantDiscovery as the primary module for this platform.

from .tenant_discovery import M365TenantDiscovery

__all__ = ["M365TenantDiscovery"]