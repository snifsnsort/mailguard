from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Literal, Optional


ReputationLabel = Literal["clean", "suspicious", "high risk", "malicious", "unknown"]
LookupStatus = Literal["ok", "no_ips", "not_configured", "unavailable"]
SpamhausLabel = Literal["listed", "clean", "unknown"]


@dataclass
class IpReputation:
    ip: str
    blacklisted: bool
    abuseConfidenceScore: Optional[int]
    totalReports: Optional[int]
    lastReportedAt: Optional[str]
    usageType: Optional[str]
    isp: Optional[str]
    domain: Optional[str]
    label: ReputationLabel
    lookupStatus: LookupStatus = "ok"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class DomainIpReputationSummary:
    domain: str
    blacklisted: bool
    abuseDetected: bool
    flaggedIpCount: int
    worstScore: Optional[int]
    label: ReputationLabel
    ips: List[IpReputation] = field(default_factory=list)
    lookupStatus: LookupStatus = "ok"
    message: Optional[str] = None
    spamhaus: Optional["SpamhausSummary"] = None

    def to_dict(self) -> Dict[str, object]:
        payload = asdict(self)
        payload["ips"] = [item.to_dict() for item in self.ips]
        payload["spamhaus"] = self.spamhaus.to_dict() if self.spamhaus else None
        return payload


@dataclass
class SpamhausFinding:
    entityType: Literal["domain", "ip"]
    entity: str
    listed: Optional[bool]
    label: SpamhausLabel
    source: str
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class SpamhausSummary:
    domain: Optional[SpamhausFinding]
    ips: List[SpamhausFinding]
    blacklisted: bool
    provider: Literal["Spamhaus"] = "Spamhaus"
    lookupStatus: LookupStatus = "ok"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "domain": self.domain.to_dict() if self.domain else None,
            "ips": [item.to_dict() for item in self.ips],
            "blacklisted": self.blacklisted,
            "provider": self.provider,
            "lookupStatus": self.lookupStatus,
            "message": self.message,
        }
