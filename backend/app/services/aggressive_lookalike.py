"""
Aggressive Lookalike Scanner — orchestrator.

Runs the full enrichment pipeline for a list of base domains:
  1. Candidate generation (generate_common_squats per domain)
  2. Similarity scoring   (detect_lookalikes)
  3. DNS enrichment       (A, AAAA, MX, NS, TXT via resolve_domains_bulk)
  4. WHOIS/RDAP           (fetch_rdap — registered domains only)
  5. Certificate CT       (fetch_ct_crtsh — scored candidates)
  6. Takeover detection   (detect_subdomain_takeover)
  7. Enriched scoring     (compute_enriched_score)

Unresolved domains are KEPT in results (attackers register before activating).
"""

import asyncio
from typing import List, Dict, Optional

from app.services.lookalike_detector import (
    generate_common_squats,
    detect_lookalikes,
    resolve_domains_bulk,
    fetch_rdap,
    fetch_ct_crtsh,
    detect_subdomain_takeover,
    compute_enriched_score,
    _infer_mutation_type,
    AggressiveResult,
    DnsInfo,
    THRESHOLD_REVIEW,
)


async def run_aggressive_scan(
    domains: List[str],
    min_score: int = THRESHOLD_REVIEW,
    concurrency: int = 40,
) -> List[dict]:
    """
    Full aggressive pipeline for all given base domains.
    Returns serialised AggressiveResult dicts sorted by enriched_score desc.
    """
    # ── Step 1: Generate candidates per domain ────────────────────────────────
    domain_candidates: Dict[str, List[str]] = {}
    for domain in domains:
        domain_candidates[domain] = generate_common_squats(domain)

    # ── Step 2: Score candidates ──────────────────────────────────────────────
    scored_matches = []
    for domain in domains:
        matches = detect_lookalikes(
            base_domains=[domain],
            candidate_domains=domain_candidates[domain],
            min_score=min_score,
        )
        scored_matches.extend(matches)

    if not scored_matches:
        return []

    # Deduplicate by (candidate, base_domain)
    seen: set = set()
    deduped = []
    base_domain_set = set(domains)   # never surface the scanned domains themselves
    for m in scored_matches:
        key = (m.candidate, m.base_domain)
        if key not in seen and m.candidate not in base_domain_set:
            seen.add(key)
            deduped.append(m)

    # ── Step 3: DNS enrichment (ALL scored — not just registered) ─────────────
    unique_candidates = list({m.candidate for m in deduped})
    dns_map = await resolve_domains_bulk(unique_candidates, concurrency)

    # ── Step 4: RDAP enrichment (registered domains only) ────────────────────
    registered = [d for d, info in dns_map.items() if info.is_registered]

    async def _rdap_safe(domain: str):
        try:
            return domain, await fetch_rdap(domain)
        except Exception:
            return domain, None

    rdap_results = await asyncio.gather(
        *[_rdap_safe(d) for d in registered[:60]],
        return_exceptions=True,
    )
    rdap_map: Dict[str, object] = {}
    for item in rdap_results:
        if isinstance(item, tuple):
            rdap_map[item[0]] = item[1]

    # ── Step 5: CT lookup (top scored candidates) ────────────────────────────
    # Sort by similarity score to prioritise CT requests budget
    top_candidates = sorted(
        unique_candidates,
        key=lambda c: max((m.overall_score for m in deduped if m.candidate == c), default=0),
        reverse=True,
    )[:40]

    async def _ct_safe(domain: str):
        try:
            return domain, await fetch_ct_crtsh(domain)
        except Exception:
            return domain, []

    ct_results = await asyncio.gather(
        *[_ct_safe(d) for d in top_candidates],
        return_exceptions=True,
    )
    ct_map: Dict[str, list] = {}
    for item in ct_results:
        if isinstance(item, tuple):
            ct_map[item[0]] = item[1]

    # ── Step 6+7: Takeover detection + enriched scoring ───────────────────────
    results: List[AggressiveResult] = []
    for match in deduped:
        dns_info   = dns_map.get(match.candidate)
        whois_info = rdap_map.get(match.candidate)
        certs      = ct_map.get(match.candidate, [])
        takeover   = detect_subdomain_takeover(dns_info) if dns_info else None

        enriched_score, risk_level = compute_enriched_score(
            similarity_score=match.overall_score,
            dns_info=dns_info,
            whois_info=whois_info,
            certs=certs,
            takeover_risk=takeover,
        )

        results.append(AggressiveResult(
            candidate=match.candidate,
            base_domain=match.base_domain,
            similarity_score=match.overall_score,
            enriched_score=enriched_score,
            risk_level=risk_level,
            mutation_type=_infer_mutation_type(match),
            signals=match.signals,
            reasons=match.reasons,
            has_homoglyphs=match.has_homoglyphs,
            mixed_script=match.mixed_script,
            tld_swap=match.tld_swap,
            is_registered=dns_info.is_registered if dns_info else False,
            dns=dns_info,
            whois=whois_info,
            certs=certs,
            takeover_risk=takeover,
        ))

    results.sort(key=lambda r: (-r.enriched_score, r.candidate))
    return [_serialize(r) for r in results]


def _serialize(r: AggressiveResult) -> dict:
    dns_dict = None
    if r.dns:
        dns_dict = {
            "has_a":        r.dns.has_a,
            "has_aaaa":     r.dns.has_aaaa,
            "has_mx":       r.dns.has_mx,
            "has_ns":       r.dns.has_ns,
            "has_txt":      r.dns.has_txt,
            "a_records":    r.dns.a_records[:5],
            "aaaa_records": r.dns.aaaa_records[:3],
            "mx_records":   r.dns.mx_records[:5],
            "ns_records":   r.dns.ns_records[:5],
            "txt_records":  r.dns.txt_records[:3],
        }

    whois_dict = None
    if r.whois:
        whois_dict = {
            "registered_date":  r.whois.registered_date,
            "age_days":         r.whois.age_days,
            "registrar":        r.whois.registrar,
            "registrant_org":   r.whois.registrant_org,
            "name_servers":     r.whois.name_servers[:4],
        }

    return {
        "candidate":        r.candidate,
        "base_domain":      r.base_domain,
        "similarity_score": r.similarity_score,
        "enriched_score":   r.enriched_score,
        "risk_level":       r.risk_level,
        "mutation_type":    r.mutation_type,
        "is_registered":    r.is_registered,
        "has_homoglyphs":   r.has_homoglyphs,
        "mixed_script":     r.mixed_script,
        "tld_swap":         r.tld_swap,
        "takeover_risk":    r.takeover_risk,
        "reasons":          r.reasons,
        "signals": {
            "levenshtein":   round(r.signals.levenshtein, 3),
            "damerau":       round(r.signals.damerau, 3),
            "jaro_winkler":  round(r.signals.jaro_winkler, 3),
            "ngram2":        round(r.signals.ngram2, 3),
            "ngram3":        round(r.signals.ngram3, 3),
            "keyboard_typo": round(r.signals.keyboard_typo, 3),
            "homoglyph":     round(r.signals.homoglyph, 3),
            "phonetic":      round(r.signals.phonetic, 3),
        },
        "dns":   dns_dict,
        "whois": whois_dict,
        "certs": [
            {
                "domain":     c.domain,
                "issued_at":  c.issued_at,
                "not_before": c.not_before,
                "not_after":  c.not_after,
                "issuer":     c.issuer,
                "san":        c.san[:5],
            }
            for c in r.certs[:5]
        ],
    }
