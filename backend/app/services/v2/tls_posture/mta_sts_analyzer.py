# mta_sts_analyzer.py
#
# MtaStsAnalyzer  — task: mta_sts_check
# TlsrptAnalyzer  — task: tlsrpt_check
#
# DNS-only. No tenant credentials required.
#
# MTA-STS: checks _mta-sts TXT record + fetches policy file from HTTPS.
# TLSRPT:  checks _smtp._tls TXT record for reporting configuration.

import uuid
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple
import dns.asyncresolver
import httpx

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.models.v2.finding import Finding


# ── MTA-STS policy parser ─────────────────────────────────────────────────────

def _parse_mta_sts_policy(text: str) -> dict:
    """
    Parse the MTA-STS policy file content into a structured dict.
    Fields: version, mode, mx (list), max_age
    """
    result: dict = {"version": None, "mode": None, "mx": [], "max_age": None, "raw": text}
    for line in text.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "version":
            result["version"] = val
        elif key == "mode":
            result["mode"] = val
        elif key == "mx":
            result["mx"].append(val)
        elif key == "max_age":
            try:
                result["max_age"] = int(val)
            except ValueError:
                result["max_age"] = val
    return result


async def _resolve_txt(domain: str) -> List[str]:
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        answers = await resolver.resolve(domain, "TXT")
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []


class MtaStsAnalyzer:

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        t0 = datetime.now(timezone.utc)
        findings: List[Finding] = []

        # ── 1. Check _mta-sts TXT record ──────────────────────────────────────
        mta_sts_txt_records = await _resolve_txt(f"_mta-sts.{self.domain}")
        mta_sts_txt = next(
            (r for r in mta_sts_txt_records if r.startswith("v=STSv1")), None
        )

        if not mta_sts_txt:
            findings.append(Finding(
                id=f"tls-mta-sts-missing-{self.domain}",
                category="tls_posture",
                severity="medium",
                title="MTA-STS policy not published",
                description=f"No MTA-STS TXT record was found at _mta-sts.{self.domain}. "
                            f"MTA-STS (RFC 8461) allows mail domain owners to declare that their "
                            f"inbound mail servers support TLS and that sending MTAs should verify "
                            f"TLS before delivering. Without it, sending servers have no policy "
                            f"signal and may deliver over plaintext if TLS is unavailable.",
                recommended_action=f"Publish a TXT record at _mta-sts.{self.domain} with value "
                                   f"'v=STSv1; id=<timestamp>' and host an MTA-STS policy file at "
                                   f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt. "
                                   f"Start with mode=testing before enforcing.",
                evidence={
                    "impact": "Sending MTAs receive no TLS enforcement signal — mail may be downgraded to plaintext.",
                    "mta_sts_record": None,
                },
            ))
            evidence = {
                "domain":         self.domain,
                "mta_sts_record": None,
                "policy":         None,
                "policy_url":     f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt",
            }
            return self._result(findings, evidence, t0)

        # ── 2. Parse the TXT record id ────────────────────────────────────────
        txt_id_match = re.search(r"id=([^;\s]+)", mta_sts_txt)
        txt_id = txt_id_match.group(1) if txt_id_match else None

        # ── 3. Fetch the policy file ──────────────────────────────────────────
        policy_url = f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt"
        policy_text: Optional[str] = None
        policy_fetch_error: Optional[str] = None

        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.get(policy_url)
                if resp.status_code == 200:
                    policy_text = resp.text
                else:
                    policy_fetch_error = f"HTTP {resp.status_code}"
        except Exception as e:
            policy_fetch_error = str(e)

        if policy_fetch_error or not policy_text:
            findings.append(Finding(
                id=f"tls-mta-sts-policy-unreachable-{self.domain}",
                category="tls_posture",
                severity="high",
                title="MTA-STS TXT record exists but policy file is unreachable",
                description=f"A valid MTA-STS TXT record was found at _mta-sts.{self.domain}, "
                            f"but the policy file at {policy_url} could not be fetched "
                            f"(error: {policy_fetch_error}). Sending MTAs that support MTA-STS "
                            f"will treat this as a policy failure and may refuse delivery.",
                recommended_action=f"Host a valid MTA-STS policy file at {policy_url} with content-type "
                                   f"text/plain. The web server must have a valid TLS certificate and "
                                   f"respond on port 443.",
                evidence={
                    "impact": "Sending MTAs that honour MTA-STS may refuse to deliver mail.",
                    "mta_sts_record": mta_sts_txt,
                    "policy_url":     policy_url,
                    "fetch_error":    policy_fetch_error,
                },
            ))
            evidence = {
                "domain":         self.domain,
                "mta_sts_record": mta_sts_txt,
                "policy":         None,
                "policy_url":     policy_url,
                "fetch_error":    policy_fetch_error,
            }
            return self._result(findings, evidence, t0)

        # ── 4. Parse and validate the policy ─────────────────────────────────
        policy = _parse_mta_sts_policy(policy_text)

        if policy["mode"] == "none":
            findings.append(Finding(
                id=f"tls-mta-sts-mode-none-{self.domain}",
                category="tls_posture",
                severity="low",
                title="MTA-STS policy is in 'none' mode — no enforcement",
                description=f"The MTA-STS policy for {self.domain} is set to mode=none. "
                            f"This disables the policy entirely. Sending MTAs will not enforce TLS "
                            f"based on this policy. This is typically a temporary state while "
                            f"migrating, but should not be left permanently.",
                recommended_action=f"Change mode to 'testing' to monitor without enforcement, "
                                   f"then to 'enforce' once you've confirmed all MX hosts support TLS. "
                                   f"Update the policy id in the TXT record when changing the policy.",
                evidence={
                    "impact": "MTA-STS provides no TLS enforcement — equivalent to having no policy.",
                    "mode": policy["mode"],
                },
            ))
        elif policy["mode"] == "testing":
            findings.append(Finding(
                id=f"tls-mta-sts-mode-testing-{self.domain}",
                category="tls_posture",
                severity="info",
                title="MTA-STS policy is in 'testing' mode",
                description=f"The MTA-STS policy for {self.domain} is in testing mode. "
                            f"Sending MTAs will report TLS failures via TLSRPT but will still "
                            f"deliver mail even if TLS validation fails. Review TLSRPT reports "
                            f"and move to 'enforce' once stable.",
                recommended_action="Monitor TLSRPT reports for failures. When no failures are observed "
                                   "over several days, change mode to 'enforce' and update the policy id.",
                evidence={
                    "impact": "TLS failures are reported but not enforced — mail can still be downgraded.",
                    "mode": policy["mode"],
                },
            ))

        # ── 5. Check max_age ──────────────────────────────────────────────────
        if isinstance(policy.get("max_age"), int):
            if policy["max_age"] < 86400:
                findings.append(Finding(
                    id=f"tls-mta-sts-low-max-age-{self.domain}",
                    category="tls_posture",
                    severity="low",
                    title=f"MTA-STS max_age is very short ({policy['max_age']}s)",
                    description=f"The MTA-STS policy max_age is {policy['max_age']} seconds "
                                f"({policy['max_age']//3600} hours). A short max_age reduces the "
                                f"protective window — sending MTAs cache the policy for this duration, "
                                f"so they will re-fetch frequently and downgrade protection if the "
                                f"policy becomes temporarily unavailable.",
                    recommended_action="Set max_age to at least 604800 (7 days) for stable deployments. "
                                       "Use 86400 (1 day) only while still testing.",
                    evidence={
                        "impact": "Short cache lifetime reduces protection window.",
                        "max_age_seconds": policy["max_age"],
                    },
                ))

        # ── 6. Check MX entries in policy ────────────────────────────────────
        if not policy["mx"]:
            findings.append(Finding(
                id=f"tls-mta-sts-no-mx-{self.domain}",
                category="tls_posture",
                severity="high",
                title="MTA-STS policy lists no MX hosts",
                description=f"The MTA-STS policy for {self.domain} contains no 'mx:' entries. "
                            f"The policy is therefore invalid — sending MTAs cannot determine "
                            f"which MX hosts should be TLS-verified.",
                recommended_action=f"Add mx: entries matching your MX hosts. "
                                   f"Wildcards are supported (e.g. mx: *.mail.protection.outlook.com).",
                evidence={
                    "impact": "Invalid policy — sending MTAs cannot enforce TLS against specific hosts.",
                    "policy_mx_entries": policy["mx"],
                },
            ))

        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        evidence = {
            "domain":           self.domain,
            "mta_sts_record":   mta_sts_txt,
            "policy_id":        txt_id,
            "policy_url":       policy_url,
            "policy":           policy,
            "scan_duration_ms": duration_ms,
        }

        return self._result(findings, evidence, t0)

    def _result(self, findings, evidence, t0) -> ScanResult:
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="tls_posture",
            findings=findings,
            score=min(100, len([f for f in findings if f.severity in ("critical","high")]) * 25),
            status="completed",
            timestamp=t0.isoformat(),
            evidence=evidence,
        )


class TlsrptAnalyzer:

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        t0 = datetime.now(timezone.utc)
        findings: List[Finding] = []

        records = await _resolve_txt(f"_smtp._tls.{self.domain}")
        tlsrpt_record = next(
            (r for r in records if r.startswith("v=TLSRPTv1")), None
        )

        if not tlsrpt_record:
            findings.append(Finding(
                id=f"tls-tlsrpt-missing-{self.domain}",
                category="tls_posture",
                severity="low",
                title="TLSRPT reporting not configured",
                description=f"No TLSRPT record was found at _smtp._tls.{self.domain}. "
                            f"TLSRPT (RFC 8460) enables sending MTAs to report TLS negotiation "
                            f"failures when delivering to your domain. Without it, you have no "
                            f"visibility into TLS delivery failures, MTA-STS policy violations, "
                            f"or DANE validation errors.",
                recommended_action=f"Publish a TXT record at _smtp._tls.{self.domain} with value "
                                   f"'v=TLSRPTv1; rua=mailto:tlsrpt@{self.domain}'. "
                                   f"Use a shared mailbox or reporting service that can process "
                                   f"JSON TLSRPT reports.",
                evidence={
                    "impact": "No visibility into TLS delivery failures — issues go undetected.",
                    "tlsrpt_record": None,
                },
            ))
        else:
            # Parse reporting destinations
            rua_match = re.search(r"rua=([^;]+)", tlsrpt_record)
            rua = rua_match.group(1).strip() if rua_match else ""
            destinations = [d.strip() for d in rua.split(",") if d.strip()] if rua else []

            if not destinations:
                findings.append(Finding(
                    id=f"tls-tlsrpt-no-rua-{self.domain}",
                    category="tls_posture",
                    severity="low",
                    title="TLSRPT record exists but has no reporting address",
                    description=f"The TLSRPT record at _smtp._tls.{self.domain} does not contain "
                                f"a valid rua= (reporting URI for aggregate reports) destination. "
                                f"Reports cannot be delivered.",
                    recommended_action=f"Add rua=mailto:tlsrpt@{self.domain} or a valid HTTPS reporting URL.",
                    evidence={
                        "impact": "TLSRPT reports cannot be delivered — no visibility into TLS failures.",
                        "tlsrpt_record": tlsrpt_record,
                    },
                ))

        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        evidence = {
            "domain":           self.domain,
            "tlsrpt_record":    tlsrpt_record,
            "scan_duration_ms": duration_ms,
        }

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="tls_posture",
            findings=findings,
            score=min(100, len([f for f in findings if f.severity in ("critical","high")]) * 25),
            status="completed",
            timestamp=t0.isoformat(),
            evidence=evidence,
        )
