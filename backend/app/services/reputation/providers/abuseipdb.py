from __future__ import annotations

import ipaddress

import httpx

from app.core.config import settings
from app.services.reputation.common import abuseipdb_label
from app.services.reputation.models import IpReputation


class AbuseIPDBProvider:
    name = "AbuseIPDB"
    base_url = "https://api.abuseipdb.com/api/v2/check"

    @property
    def configured(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY)

    async def check_ip(self, ip: str, max_age_in_days: int = 90) -> IpReputation:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_global:
                return IpReputation(
                    ip=ip,
                    blacklisted=False,
                    abuseConfidenceScore=None,
                    totalReports=None,
                    lastReportedAt=None,
                    usageType=None,
                    isp=None,
                    domain=None,
                    label="unknown",
                    lookupStatus="unavailable",
                    message="Reputation lookup unavailable",
                )
        except ValueError:
            return IpReputation(
                ip=ip,
                blacklisted=False,
                abuseConfidenceScore=None,
                totalReports=None,
                lastReportedAt=None,
                usageType=None,
                isp=None,
                domain=None,
                label="unknown",
                lookupStatus="unavailable",
                message="Reputation lookup unavailable",
            )

        if not self.configured:
            return IpReputation(
                ip=ip,
                blacklisted=False,
                abuseConfidenceScore=None,
                totalReports=None,
                lastReportedAt=None,
                usageType=None,
                isp=None,
                domain=None,
                label="unknown",
                lookupStatus="not_configured",
                message="AbuseIPDB not configured",
            )

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    self.base_url,
                    headers={
                        "Accept": "application/json",
                        "Key": settings.ABUSEIPDB_API_KEY,
                    },
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": max_age_in_days,
                    },
                )
                response.raise_for_status()
                payload = response.json().get("data", {})
        except Exception:
            return IpReputation(
                ip=ip,
                blacklisted=False,
                abuseConfidenceScore=None,
                totalReports=None,
                lastReportedAt=None,
                usageType=None,
                isp=None,
                domain=None,
                label="unknown",
                lookupStatus="unavailable",
                message="Reputation lookup unavailable",
            )

        score = payload.get("abuseConfidenceScore")
        reports = payload.get("totalReports")
        last_reported = payload.get("lastReportedAt")
        usage_type = payload.get("usageType")
        isp = payload.get("isp")
        domain = payload.get("domain")
        label = abuseipdb_label(int(score) if score is not None else None)

        return IpReputation(
            ip=ip,
            blacklisted=False,
            abuseConfidenceScore=int(score) if score is not None else None,
            totalReports=int(reports) if reports is not None else None,
            lastReportedAt=str(last_reported) if last_reported else None,
            usageType=str(usage_type) if usage_type else None,
            isp=str(isp) if isp else None,
            domain=str(domain) if domain else None,
            label=label,
            lookupStatus="ok",
            message=None,
        )
