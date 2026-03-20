from __future__ import annotations

import ipaddress
from typing import Optional

import httpx

from app.core.config import settings
from app.services.reputation.models import SpamhausFinding


DOMAIN_CODE_MAP = {
    2002: "Spamhaus DBL listed",
}

IP_CODE_MAP = {
    1002: "Spamhaus SBL listed",
    1003: "Spamhaus CSS listed",
    1004: "Spamhaus XBL listed",
    1009: "Spamhaus DROP listed",
    1010: "Spamhaus PBL listed",
    1011: "Spamhaus PBL listed",
    1020: "Spamhaus AUTHBL listed",
}


class SpamhausProvider:
    name = "Spamhaus"
    base_url = "https://apibl.spamhaus.net/lookup/v1"

    @property
    def configured(self) -> bool:
        return bool(settings.SPAMHAUS_USERNAME and settings.SPAMHAUS_KEY)

    async def check_domain(self, domain: str) -> SpamhausFinding:
        return await self._check("DBL", "domain", domain, "Spamhaus DBL", DOMAIN_CODE_MAP)

    async def check_ip(self, ip: str) -> SpamhausFinding:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_global:
                return SpamhausFinding(
                    entityType="ip",
                    entity=ip,
                    listed=None,
                    label="unknown",
                    source="Spamhaus ZEN",
                    evidence="Spamhaus lookup unavailable",
                )
        except ValueError:
            return SpamhausFinding(
                entityType="ip",
                entity=ip,
                listed=None,
                label="unknown",
                source="Spamhaus ZEN",
                evidence="Spamhaus lookup unavailable",
            )

        return await self._check("ZEN", "ip", ip, "Spamhaus ZEN", IP_CODE_MAP)

    async def _check(
        self,
        dataset: str,
        entity_type: str,
        value: str,
        source: str,
        code_map: dict[int, str],
    ) -> SpamhausFinding:
        if not self.configured:
            return SpamhausFinding(
                entityType=entity_type,  # type: ignore[arg-type]
                entity=value,
                listed=None,
                label="unknown",
                source=source,
                evidence="Spamhaus not configured",
            )

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{self.base_url}/{dataset}/{value}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {settings.SPAMHAUS_KEY}",
                    },
                )
        except Exception:
            return SpamhausFinding(
                entityType=entity_type,  # type: ignore[arg-type]
                entity=value,
                listed=None,
                label="unknown",
                source=source,
                evidence="Spamhaus lookup unavailable",
            )

        if response.status_code == 404:
            return SpamhausFinding(
                entityType=entity_type,  # type: ignore[arg-type]
                entity=value,
                listed=False,
                label="clean",
                source=source,
                evidence="Not listed",
            )

        if response.status_code != 200:
            return SpamhausFinding(
                entityType=entity_type,  # type: ignore[arg-type]
                entity=value,
                listed=None,
                label="unknown",
                source=source,
                evidence="Spamhaus lookup unavailable",
            )

        try:
            payload = response.json()
            codes = [int(code) for code in (payload.get("resp") or [])]
        except Exception:
            codes = []

        evidence = ", ".join(code_map.get(code, str(code)) for code in codes) if codes else "Listed"
        return SpamhausFinding(
            entityType=entity_type,  # type: ignore[arg-type]
            entity=value,
            listed=True,
            label="listed",
            source=source,
            evidence=evidence,
        )
