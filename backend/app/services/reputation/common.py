from __future__ import annotations

import ipaddress
from typing import Dict, Iterable

from .models import ReputationLabel


LABEL_PRIORITY = {
    "unknown": 0,
    "clean": 1,
    "suspicious": 2,
    "high risk": 3,
    "malicious": 4,
}


def abuseipdb_label(score: int | None) -> ReputationLabel:
    if score is None:
        return "unknown"
    if score >= 61:
        return "malicious"
    if score >= 31:
        return "high risk"
    if score >= 11:
        return "suspicious"
    return "clean"


def combine_labels(*labels: ReputationLabel) -> ReputationLabel:
    if not labels:
        return "unknown"
    return max(labels, key=lambda label: LABEL_PRIORITY[label])


def extract_ip_candidates(ips: Iterable[str]) -> list[str]:
    unique: list[str] = []
    seen = set()
    for value in ips:
        try:
            normalized = str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            continue
        if normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return unique


def provider_state_map(provider_names: Iterable[str], configured_names: Iterable[str]) -> Dict[str, str]:
    configured = set(configured_names)
    return {name: ("configured" if name in configured else "not_configured") for name in provider_names}
