from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Iterable, List, Optional

from app.services.lookalike_detector import resolve_domains_bulk
from app.services.reputation.common import combine_labels, extract_ip_candidates, provider_state_map
from app.services.reputation.models import DomainIpReputationSummary, IpReputation, SpamhausFinding, SpamhausSummary
from app.services.reputation.providers import AbuseIPDBProvider, SpamhausProvider


REPUTATION_TTL_SECONDS = 30 * 24 * 60 * 60


@dataclass
class CacheEntry:
    value: IpReputation
    expires_at: float


@dataclass
class SpamhausCacheEntry:
    value: SpamhausFinding
    expires_at: float


class ReputationService:
    def __init__(self) -> None:
        self.abuseipdb = AbuseIPDBProvider()
        self.spamhaus = SpamhausProvider()
        self._cache: Dict[str, CacheEntry] = {}
        self._spamhaus_cache: Dict[str, SpamhausCacheEntry] = {}
        self._inflight: Dict[str, asyncio.Future] = {}
        self._spamhaus_inflight: Dict[str, asyncio.Future] = {}
        self._lock = asyncio.Lock()

    def provider_availability(self) -> Dict[str, str]:
        return provider_state_map(
            [self.abuseipdb.name, self.spamhaus.name],
            [
                name
                for name, configured in (
                    (self.abuseipdb.name, self.abuseipdb.configured),
                    (self.spamhaus.name, self.spamhaus.configured),
                )
                if configured
            ],
        )

    async def summarize_domain(self, domain: str, ips: Optional[Iterable[str]] = None) -> DomainIpReputationSummary:
        clean_domain = str(domain or "").strip().lower()
        resolved_ips = extract_ip_candidates(ips or [])
        if not resolved_ips and clean_domain:
            resolved_ips = await self._resolve_root_ips(clean_domain)

        if not resolved_ips:
            spamhaus_domain = await self._cached_spamhaus_lookup(
                "domain",
                clean_domain,
                lambda clean_domain=clean_domain: self.spamhaus.check_domain(clean_domain),
            ) if clean_domain else None
            spamhaus_summary = SpamhausSummary(
                domain=spamhaus_domain,
                ips=[],
                blacklisted=bool(spamhaus_domain and spamhaus_domain.listed is True),
                lookupStatus="not_configured" if not self.spamhaus.configured else "ok",
                message="Spamhaus not configured" if not self.spamhaus.configured else None,
            ) if clean_domain else None
            return DomainIpReputationSummary(
                domain=clean_domain,
                blacklisted=bool(spamhaus_summary and spamhaus_summary.blacklisted),
                abuseDetected=False,
                flaggedIpCount=0,
                worstScore=None,
                label="unknown",
                ips=[],
                lookupStatus="no_ips",
                message="No resolved IPs",
                spamhaus=spamhaus_summary,
            )

        ip_summaries = await asyncio.gather(
            *[
                self._cached_lookup(
                    ip,
                    lambda ip=ip: self.abuseipdb.check_ip(ip),
                )
                for ip in resolved_ips
            ]
        )
        spamhaus_domain = await self._cached_spamhaus_lookup(
            "domain",
            clean_domain,
            lambda clean_domain=clean_domain: self.spamhaus.check_domain(clean_domain),
        ) if clean_domain else None
        spamhaus_ips = await asyncio.gather(
            *[
                self._cached_spamhaus_lookup(
                    "ip",
                    ip,
                    lambda ip=ip: self.spamhaus.check_ip(ip),
                )
                for ip in resolved_ips
            ]
        )
        spamhaus_summary = SpamhausSummary(
            domain=spamhaus_domain,
            ips=list(spamhaus_ips),
            blacklisted=bool((spamhaus_domain and spamhaus_domain.listed is True) or any(item.listed is True for item in spamhaus_ips)),
            lookupStatus=(
                "not_configured" if not self.spamhaus.configured
                else "unavailable" if spamhaus_domain and spamhaus_domain.label == "unknown" and all(item.label == "unknown" for item in spamhaus_ips)
                else "ok"
            ),
            message=(
                "Spamhaus not configured" if not self.spamhaus.configured
                else "Spamhaus lookup unavailable" if spamhaus_domain and spamhaus_domain.label == "unknown" and all(item.label == "unknown" for item in spamhaus_ips)
                else None
            ),
        )

        labels = [item.label for item in ip_summaries]
        worst_score = max((item.abuseConfidenceScore for item in ip_summaries if item.abuseConfidenceScore is not None), default=None)
        abuse_detected = any((item.abuseConfidenceScore or 0) > 0 for item in ip_summaries)
        flagged_ip_count = sum(1 for item in ip_summaries if (item.abuseConfidenceScore or 0) > 0)
        blacklisted = spamhaus_summary.blacklisted
        lookup_status = "ok"
        message = None

        if all(item.lookupStatus == "not_configured" for item in ip_summaries):
            lookup_status = "not_configured"
            message = "AbuseIPDB not configured"
        elif all(item.lookupStatus == "unavailable" for item in ip_summaries):
            lookup_status = "unavailable"
            message = "Reputation lookup unavailable"

        return DomainIpReputationSummary(
            domain=clean_domain,
            blacklisted=blacklisted,
            abuseDetected=abuse_detected,
            flaggedIpCount=flagged_ip_count,
            worstScore=worst_score,
            label=combine_labels(*labels) if labels else "unknown",
            ips=list(ip_summaries),
            lookupStatus=lookup_status,
            message=message,
            spamhaus=spamhaus_summary,
        )

    async def summarize_many(self, domains: Dict[str, Iterable[str]], root_domain: Optional[str] = None) -> Dict[str, object]:
        normalized = {str(domain).strip().lower(): extract_ip_candidates(ips) for domain, ips in (domains or {}).items() if str(domain).strip()}
        if root_domain and str(root_domain).strip().lower() not in normalized:
            normalized[str(root_domain).strip().lower()] = []

        tasks = {domain: asyncio.create_task(self.summarize_domain(domain, ips)) for domain, ips in normalized.items()}
        summaries = {domain: (await task).to_dict() for domain, task in tasks.items()}

        return {
            "rootDomain": summaries.get(str(root_domain or "").strip().lower()) if root_domain else None,
            "entities": summaries,
            "providerAvailability": self.provider_availability(),
        }

    async def _resolve_root_ips(self, domain: str) -> List[str]:
        try:
            dns_map = await resolve_domains_bulk([domain], concurrency=5)
        except Exception:
            return []
        info = dns_map.get(domain)
        if not info:
            return []
        return extract_ip_candidates([*(info.a_records or []), *(info.aaaa_records or [])])

    async def _cached_lookup(
        self,
        ip: str,
        factory: Callable[[], Awaitable[IpReputation]],
    ) -> IpReputation:
        key = f"AbuseIPDB:ip:{ip}"
        now = time.time()

        async with self._lock:
            cached = self._cache.get(key)
            if cached and cached.expires_at > now:
                return cached.value

            in_flight = self._inflight.get(key)
            if in_flight is None:
                task = asyncio.create_task(factory())
                self._inflight[key] = task
                in_flight = task

        try:
            result = await in_flight
        finally:
            async with self._lock:
                if self._inflight.get(key) is in_flight:
                    self._inflight.pop(key, None)

        async with self._lock:
            self._cache[key] = CacheEntry(value=result, expires_at=time.time() + REPUTATION_TTL_SECONDS)

        return result

    async def _cached_spamhaus_lookup(
        self,
        entity_type: str,
        entity: str,
        factory: Callable[[], Awaitable[SpamhausFinding]],
    ) -> SpamhausFinding:
        key = f"Spamhaus:{entity_type}:{entity}"
        now = time.time()

        async with self._lock:
            cached = self._spamhaus_cache.get(key)
            if cached and cached.expires_at > now:
                return cached.value

            in_flight = self._spamhaus_inflight.get(key)
            if in_flight is None:
                task = asyncio.create_task(factory())
                self._spamhaus_inflight[key] = task
                in_flight = task

        try:
            result = await in_flight
        finally:
            async with self._lock:
                if self._spamhaus_inflight.get(key) is in_flight:
                    self._spamhaus_inflight.pop(key, None)

        async with self._lock:
            self._spamhaus_cache[key] = SpamhausCacheEntry(value=result, expires_at=time.time() + REPUTATION_TTL_SECONDS)

        return result


reputation_service = ReputationService()
