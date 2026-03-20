# starttls_analyzer.py
#
# StarttlsAnalyzer   — task: starttls_probe
# TlsConflictAnalyzer — task: tls_conflict_analysis
# DaneTlsaAnalyzer   — task: dane_tlsa_check (placeholder — DNSSEC not yet required)
#
# StarttlsAnalyzer:
#   Connects to each MX host on port 25, issues EHLO + STARTTLS,
#   negotiates TLS handshake, inspects certificate (validity, expiry, hostname).
#
# TlsConflictAnalyzer:
#   Cross-checks MTA-STS policy MX list vs actual MX records vs STARTTLS probe results.
#   Flags conflicts: enforce mode with untested hosts, MX in policy not in DNS, etc.
#
# DaneTlsaAnalyzer:
#   Placeholder. Checks for TLSA records (_25._tcp.{mx-host}) as a presence signal.
#   Full DNSSEC validation deferred until a DNSSEC-validating resolver is available.

import asyncio
import ssl
import socket
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict
import dns.asyncresolver
import httpx

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.models.v2.finding import Finding
from app.services.v2.tls_posture.mta_sts_analyzer import _parse_mta_sts_policy, _resolve_txt


# ── STARTTLS probe ────────────────────────────────────────────────────────────

async def _starttls_probe(host: str, timeout: int = 10) -> Dict:
    """
    Connect to host:25, negotiate STARTTLS, inspect the certificate.
    Returns a dict with tls_offered, tls_version, cert details.
    """
    result = {
        "host":         host,
        "port":         25,
        "connectable":  False,
        "tls_offered":  False,
        "tls_version":  None,
        "cipher":       None,
        "cert_valid":   None,
        "cert_expired": None,
        "cert_expiry":  None,
        "cert_cn":      None,
        "cert_sans":    [],
        "hostname_match": None,
        "error":        None,
    }

    loop = asyncio.get_event_loop()

    try:
        # Open TCP connection to port 25
        conn = asyncio.open_connection(host, 25, limit=65536)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        result["connectable"] = True

        # Read SMTP greeting
        await asyncio.wait_for(reader.read(1024), timeout=timeout)

        # Send EHLO
        writer.write(b"EHLO mailguard-probe.local\r\n")
        await writer.drain()
        ehlo_resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        ehlo_text = ehlo_resp.decode(errors="replace")

        if "STARTTLS" not in ehlo_text:
            result["tls_offered"] = False
            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            return result

        # Issue STARTTLS
        result["tls_offered"] = True
        writer.write(b"STARTTLS\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(1024), timeout=timeout)

        # Upgrade to TLS
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        tls_transport, tls_proto = await asyncio.wait_for(
            loop.create_connection(
                lambda: asyncio.StreamReaderProtocol(asyncio.StreamReader()),
                sock=writer.get_extra_info("socket"),
                ssl=ctx,
                server_hostname=host,
            ),
            timeout=timeout,
        )

        tls_sock = tls_transport.get_extra_info("ssl_object")
        result["tls_version"] = tls_sock.version()
        result["cipher"]      = tls_sock.cipher()[0] if tls_sock.cipher() else None

        # Inspect cert
        cert = tls_sock.getpeercert()
        if cert:
            # Expiry
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["cert_expiry"]  = expiry.isoformat()
                    result["cert_expired"] = expiry < datetime.now(timezone.utc)
                    result["cert_valid"]   = not result["cert_expired"]
                except Exception:
                    pass

            # CN and SANs
            subject = dict(x[0] for x in cert.get("subject", []))
            result["cert_cn"] = subject.get("commonName", "")
            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            result["cert_sans"] = sans

            # Hostname match
            try:
                ssl.match_hostname(cert, host)
                result["hostname_match"] = True
            except ssl.CertificateError:
                result["hostname_match"] = False

        tls_transport.close()

    except asyncio.TimeoutError:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused on port 25"
    except OSError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = f"Probe failed: {type(e).__name__}: {e}"

    return result


class StarttlsAnalyzer:

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        t0 = datetime.now(timezone.utc)
        findings: List[Finding] = []

        # ── Resolve MX records ────────────────────────────────────────────────
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            answers = await resolver.resolve(self.domain, "MX")
            mx_hosts = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda x: x.preference)]
        except Exception as e:
            return self._result(findings, {"domain": self.domain, "error": str(e)}, t0)

        # ── Probe each MX host concurrently ───────────────────────────────────
        probes = await asyncio.gather(
            *[_starttls_probe(host) for host in mx_hosts[:5]],  # cap at 5 MX hosts
            return_exceptions=True,
        )

        probe_results = []
        for host, probe in zip(mx_hosts[:5], probes):
            if isinstance(probe, Exception):
                probe_results.append({"host": host, "error": str(probe)})
            else:
                probe_results.append(probe)

        # ── Generate findings ─────────────────────────────────────────────────
        for probe in probe_results:
            host = probe.get("host", "unknown")

            if probe.get("error") and not probe.get("connectable"):
                findings.append(Finding(
                    id=f"tls-starttls-unreachable-{host.replace('.', '-')}",
                    category="tls_posture",
                    severity="high",
                    title=f"MX host unreachable on port 25: {host}",
                    description=f"Could not connect to {host}:25 to probe STARTTLS support. "
                                f"Error: {probe.get('error')}. "
                                f"This may indicate the host is behind a firewall blocking port 25, "
                                f"or the host is not operational.",
                    recommended_action=f"Verify {host} is reachable on port 25 from external networks. "
                                       f"Check firewall rules and MX record validity.",
                    evidence={
                        "impact": "Cannot verify TLS posture — this MX host may not be accepting email.",
                        "host":   host,
                        "error":  probe.get("error"),
                    },
                ))
                continue

            if not probe.get("tls_offered"):
                findings.append(Finding(
                    id=f"tls-starttls-not-offered-{host.replace('.', '-')}",
                    category="tls_posture",
                    severity="critical",
                    title=f"STARTTLS not offered by MX host: {host}",
                    description=f"The MX host {host} does not advertise STARTTLS in its EHLO response. "
                                f"Mail delivered to this host will be transmitted in plaintext, "
                                f"exposing message content to interception in transit.",
                    recommended_action=f"Enable STARTTLS on {host}. If this is a SEG or cloud service, "
                                       f"contact the provider to confirm TLS is enabled on their inbound "
                                       f"SMTP listener.",
                    evidence={
                        "impact": "All inbound mail to this MX host is transmitted unencrypted.",
                        "host":   host,
                    },
                ))
                continue

            # STARTTLS offered — check cert validity
            if probe.get("cert_expired"):
                findings.append(Finding(
                    id=f"tls-cert-expired-{host.replace('.', '-')}",
                    category="tls_posture",
                    severity="critical",
                    title=f"Expired TLS certificate on MX host: {host}",
                    description=f"The TLS certificate on {host} expired on {probe.get('cert_expiry', 'unknown')}. "
                                f"Sending MTAs enforcing certificate validation (MTA-STS enforce, DANE) "
                                f"will refuse to deliver mail to this host.",
                    recommended_action=f"Renew the TLS certificate on {host} immediately. "
                                       f"Configure automated renewal (e.g. Let's Encrypt with certbot) "
                                       f"to prevent recurrence.",
                    evidence={
                        "impact": "Mail from MTA-STS/DANE-enforcing senders will be rejected.",
                        "host":         host,
                        "cert_expiry":  probe.get("cert_expiry"),
                        "cert_cn":      probe.get("cert_cn"),
                    },
                ))

            elif probe.get("hostname_match") is False:
                findings.append(Finding(
                    id=f"tls-cert-hostname-mismatch-{host.replace('.', '-')}",
                    category="tls_posture",
                    severity="high",
                    title=f"TLS certificate hostname mismatch on: {host}",
                    description=f"The TLS certificate presented by {host} does not match the hostname. "
                                f"Certificate CN: {probe.get('cert_cn', 'unknown')}, "
                                f"SANs: {', '.join(probe.get('cert_sans', [])) or 'none'}. "
                                f"Sending MTAs verifying certificates (MTA-STS, DANE) will reject delivery.",
                    recommended_action=f"Replace the certificate on {host} with one that includes {host} "
                                       f"in the Subject Alternative Names.",
                    evidence={
                        "impact": "Certificate mismatch causes TLS validation failure — delivery refused by strict senders.",
                        "host":        host,
                        "cert_cn":     probe.get("cert_cn"),
                        "cert_sans":   probe.get("cert_sans"),
                        "cert_expiry": probe.get("cert_expiry"),
                    },
                ))

            # Weak TLS version
            tls_ver = probe.get("tls_version", "") or ""
            if tls_ver in ("TLSv1", "TLSv1.1"):
                findings.append(Finding(
                    id=f"tls-weak-version-{host.replace('.', '-')}",
                    category="tls_posture",
                    severity="medium",
                    title=f"Weak TLS version negotiated on {host}: {tls_ver}",
                    description=f"The highest TLS version negotiated with {host} was {tls_ver}. "
                                f"TLS 1.0 and 1.1 are deprecated (RFC 8996) due to known weaknesses. "
                                f"Modern sending MTAs may refuse to deliver over these versions.",
                    recommended_action=f"Disable TLS 1.0 and 1.1 on {host}. Enable TLS 1.2 as minimum "
                                       f"and prefer TLS 1.3. Update the TLS configuration in your "
                                       f"mail server or gateway.",
                    evidence={
                        "impact": "Deprecated TLS version — known vulnerabilities and compatibility issues with modern senders.",
                        "host":        host,
                        "tls_version": tls_ver,
                        "cipher":      probe.get("cipher"),
                    },
                ))

        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        evidence = {
            "domain":           self.domain,
            "mx_hosts_probed":  mx_hosts[:5],
            "probe_results":    probe_results,
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


class TlsConflictAnalyzer:
    """
    Cross-checks MTA-STS policy vs actual MX records vs STARTTLS probe results.
    Flags discrepancies that create security gaps or delivery failures.
    """

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        t0 = datetime.now(timezone.utc)
        findings: List[Finding] = []

        # ── Gather MTA-STS policy, MX records, STARTTLS probes concurrently ──
        mta_sts_records, mx_answers = await asyncio.gather(
            _resolve_txt(f"_mta-sts.{self.domain}"),
            self._resolve_mx(),
            return_exceptions=True,
        )

        if isinstance(mta_sts_records, Exception):
            mta_sts_records = []
        if isinstance(mx_answers, Exception):
            mx_answers = []

        mta_sts_txt = next(
            (r for r in (mta_sts_records or []) if r.startswith("v=STSv1")), None
        )

        if not mta_sts_txt:
            # No MTA-STS — nothing to conflict-check against
            evidence = {
                "domain":           self.domain,
                "conflict_checks":  "skipped — no MTA-STS record",
                "scan_duration_ms": 0,
            }
            return self._result(findings, evidence, t0)

        # Fetch policy file
        policy_text = None
        try:
            policy_url = f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt"
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.get(policy_url)
                if resp.status_code == 200:
                    policy_text = resp.text
        except Exception:
            pass

        if not policy_text:
            evidence = {
                "domain": self.domain,
                "conflict_checks": "skipped — policy file unreachable",
            }
            return self._result(findings, evidence, t0)

        # Parse policy
        policy = _parse_mta_sts_policy(policy_text)
        mode   = policy.get("mode", "none")
        policy_mx = policy.get("mx", [])

        # ── Conflict 1: MTA-STS enforce but MX not in policy whitelist ───────
        if mode == "enforce" and mx_answers and policy_mx:
            for host in mx_answers:
                host_matched = any(
                    self._mx_matches_pattern(host, pattern)
                    for pattern in policy_mx
                )
                if not host_matched:
                    findings.append(Finding(
                        id=f"tls-conflict-mx-not-in-policy-{host.replace('.', '-')}",
                        category="tls_posture",
                        severity="critical",
                        title=f"MTA-STS enforce: MX host not in policy whitelist — delivery will fail",
                        description=f"MTA-STS is in enforce mode but the MX host '{host}' is not "
                                    f"listed in the policy MX whitelist: {policy_mx}. "
                                    f"Sending MTAs honouring MTA-STS will refuse to deliver mail to "
                                    f"this host, causing bounces.",
                        recommended_action=f"Add '{host}' (or a wildcard matching it) to the mx: "
                                           f"entries in your MTA-STS policy file. Update the policy "
                                           f"id in the TXT record after changing the file.",
                        evidence={
                            "impact": "Delivery failure — sending MTAs enforcing MTA-STS will refuse this MX host.",
                            "mx_host":         host,
                            "policy_mx_list":  policy_mx,
                            "mta_sts_mode":    mode,
                        },
                    ))

        # ── Conflict 2: Policy lists MX not in DNS ────────────────────────────
        if policy_mx and mx_answers:
            dns_hosts_lower = [h.lower() for h in mx_answers]
            for pattern in policy_mx:
                if "*" in pattern:
                    continue  # wildcards are intentionally broad
                if pattern.lower() not in dns_hosts_lower:
                    findings.append(Finding(
                        id=f"tls-conflict-policy-mx-stale-{pattern.replace('.', '-').replace('*', 'wc')}",
                        category="tls_posture",
                        severity="medium",
                        title=f"MTA-STS policy references MX host not in DNS: {pattern}",
                        description=f"The MTA-STS policy file lists '{pattern}' as an allowed MX host, "
                                    f"but this host does not appear in the current DNS MX records for "
                                    f"{self.domain}. This suggests the policy file was not updated "
                                    f"when MX records changed — it contains a stale entry.",
                        recommended_action=f"Remove '{pattern}' from the MTA-STS policy file if it "
                                           f"no longer corresponds to an active MX host. Update the "
                                           f"policy id in the TXT record.",
                        evidence={
                            "impact": "Stale policy entry — no delivery impact, but indicates policy drift.",
                            "stale_policy_entry": pattern,
                            "current_mx_hosts":   mx_answers,
                        },
                    ))

        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        evidence = {
            "domain":           self.domain,
            "mta_sts_mode":     mode,
            "policy_mx_list":   policy_mx,
            "actual_mx_hosts":  mx_answers,
            "conflicts_found":  len(findings),
            "scan_duration_ms": duration_ms,
        }

        return self._result(findings, evidence, t0)

    async def _resolve_mx(self) -> List[str]:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            answers = await resolver.resolve(self.domain, "MX")
            return [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            return []

    def _mx_matches_pattern(self, host: str, pattern: str) -> bool:
        """Check if host matches MTA-STS MX pattern (supports leading wildcard)."""
        host    = host.lower()
        pattern = pattern.lower()
        if pattern.startswith("*."):
            suffix = pattern[1:]  # e.g. ".mail.protection.outlook.com"
            return host.endswith(suffix)
        return host == pattern

    def _result(self, findings, evidence, t0) -> ScanResult:
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="tls_posture",
            findings=findings,
            score=min(100, len([f for f in findings if f.severity in ("critical","high")]) * 30),
            status="completed",
            timestamp=t0.isoformat(),
            evidence=evidence,
        )


class DaneTlsaAnalyzer:
    """
    DANE/TLSA placeholder.

    Checks for the presence of TLSA records at _25._tcp.{mx-host} as a
    signal that DANE is configured. Full DANE validation (DNSSEC chain
    verification, certificate matching) requires a DNSSEC-validating resolver
    and is deferred until one is available in the runtime environment.

    This task produces informational findings only — it never fails a job.
    """

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        t0 = datetime.now(timezone.utc)
        findings: List[Finding] = []
        tlsa_results = []

        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            answers = await resolver.resolve(self.domain, "MX")
            mx_hosts = [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            mx_hosts = []

        for host in mx_hosts[:5]:
            tlsa_name = f"_25._tcp.{host}"
            try:
                answers = await dns.asyncresolver.resolve(tlsa_name, "TLSA")
                tlsa_results.append({
                    "host":           host,
                    "tlsa_name":      tlsa_name,
                    "tlsa_present":   True,
                    "record_count":   len(list(answers)),
                    "validated":      False,  # DNSSEC validation deferred
                    "deferred":       True,
                })
            except Exception:
                tlsa_results.append({
                    "host":         host,
                    "tlsa_name":    tlsa_name,
                    "tlsa_present": False,
                })

        dane_present = any(r.get("tlsa_present") for r in tlsa_results)

        if not dane_present and mx_hosts:
            findings.append(Finding(
                id=f"tls-dane-not-configured-{self.domain}",
                category="tls_posture",
                severity="info",
                title="DANE/TLSA records not detected on MX hosts",
                description=f"No TLSA records were found at _25._tcp.{{mx-host}} for any of the "
                            f"{self.domain} MX hosts. DANE (DNS-Based Authentication of Named Entities, "
                            f"RFC 7672) allows domain owners to pin TLS certificates in DNS, "
                            f"providing an additional layer of authentication beyond MTA-STS. "
                            f"DANE requires DNSSEC to be enabled on the domain.",
                recommended_action="Consider implementing DANE alongside MTA-STS for defense in depth. "
                                   "Prerequisites: DNSSEC signed zone, TLSA records published for each "
                                   "MX host, valid TLS certificate matching the TLSA record. "
                                   "Full DANE validation in MailGuard is pending DNSSEC resolver support.",
                evidence={
                    "impact": "No DANE protection — certificate pinning not available as a backup to MTA-STS.",
                    "mx_hosts_checked": mx_hosts[:5],
                    "tlsa_results":     tlsa_results,
                    "full_validation":  "deferred — DNSSEC resolver not yet available",
                },
            ))
        elif dane_present:
            findings.append(Finding(
                id=f"tls-dane-detected-{self.domain}",
                category="tls_posture",
                severity="info",
                title="DANE/TLSA records detected — full validation deferred",
                description=f"TLSA records were found for one or more MX hosts of {self.domain}. "
                            f"This indicates DANE is configured. Full certificate chain validation "
                            f"against the TLSA records requires DNSSEC verification, which is "
                            f"deferred in the current implementation.",
                recommended_action="No action required. Full DANE validation will be enabled in a "
                                   "future MailGuard release when DNSSEC resolver support is available.",
                evidence={
                    "impact": "DANE detected but not fully validated — treat as informational.",
                    "tlsa_results":    tlsa_results,
                    "full_validation": "deferred",
                },
            ))

        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        evidence = {
            "domain":           self.domain,
            "mx_hosts_checked": mx_hosts[:5],
            "tlsa_results":     tlsa_results,
            "dane_present":     dane_present,
            "full_validation":  "deferred — DNSSEC resolver required",
            "scan_duration_ms": duration_ms,
        }

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="tls_posture",
            findings=findings,
            score=0,  # Informational only — does not affect score
            status="completed",
            timestamp=t0.isoformat(),
            evidence=evidence,
        )
