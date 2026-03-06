# Security Checks Reference

Complete reference for all checks MailGuard performs, what they detect, and how to remediate.

---

## Microsoft 365 Checks

### SPF (Sender Policy Framework)

| Check | What it detects |
|---|---|
| SPF record present | No `v=spf1` TXT record on the domain |
| Single record | Multiple SPF records (RFC 7208 — only one is allowed) |
| Syntax validity | Malformed mechanisms, unknown modifiers |
| DNS lookup count | More than 10 lookups (RFC 7208 §4.6.4 hard limit — causes `permerror`) |
| `~all` vs `-all` | Soft-fail (`~all`) allows spoofed mail through; hard fail (`-all`) rejects it |

**Remediation:** Use a single SPF record with `-all`. Merge all authorized senders into one record. Avoid chains of `include:` that exceed 10 DNS lookups.

---

### DMARC (Domain-based Message Authentication)

| Check | What it detects |
|---|---|
| Record present | No `v=DMARC1` TXT record at `_dmarc.domain` |
| Policy enforcement | `p=none` provides no protection; use `p=quarantine` or `p=reject` |
| Subdomain policy | `sp=` tag — controls unauthenticated subdomains |
| RUA reporting | Missing aggregate report address (`rua=`) |
| Syntax errors | Invalid tags, malformed values |
| Multiple records | Only one DMARC record is allowed |

**Remediation:** Start with `p=none; rua=mailto:dmarc@yourdomain.com` to collect reports, then move to `p=quarantine` and finally `p=reject`.

---

### DKIM (DomainKeys Identified Mail)

| Check | What it detects |
|---|---|
| Key present | No DKIM TXT record found |
| Algorithm | RSA-SHA256 required; SHA-1 is deprecated |
| Key length | 1024-bit minimum; 2048-bit recommended |

**Remediation:** Enable DKIM signing in M365 admin (Protection → DKIM). Use 2048-bit keys where possible.

---

### MX Routing

| Check | What it detects |
|---|---|
| MX records present | No MX records (mail cannot be received) |
| SEG identification | Identifies which Secure Email Gateway is in use |
| Multi-SEG conflict | Multiple competing SEGs (mail may bypass one) |
| Split routing | Mix of SEG and direct Exchange Online MX records |
| Inconsistent routing | Mix of different providers (e.g. EOP + Google) |

**Detected SEGs:** Proofpoint, Mimecast, Microsoft Defender for Office 365, Cisco IronPort, Fortinet FortiMail, Hornetsecurity, Trend Micro, Barracuda, Sophos, and more.

---

### Anti-Spam Policies

| Check | What it detects |
|---|---|
| Policy exists | No custom anti-spam policy |
| Bulk threshold | High BCL threshold (≥7) allows more bulk mail |
| Spam action | Deliver to inbox instead of quarantine/junk |
| High-confidence spam | HCSF action — should quarantine or delete |

---

### Anti-Phishing Policies

| Check | What it detects |
|---|---|
| Policy exists | No custom anti-phishing policy |
| Impersonation protection | User and domain impersonation not configured |
| Mailbox intelligence | AI-based impersonation detection disabled |
| Spoof intelligence | Cross-org spoof protection disabled |

---

### Safe Links

| Check | What it detects |
|---|---|
| Policy exists | No Safe Links policy |
| User coverage | Users not covered by a policy |
| Real-time scanning | URL scanning disabled |
| Internal messages | Internal email links not scanned |

---

### Safe Attachments

| Check | What it detects |
|---|---|
| Policy exists | No Safe Attachments policy |
| User coverage | Users not covered |
| Dynamic Delivery | Attachment delivery not using sandbox mode |

---

### SEG Bypass Risk

Checks whether mail can reach Exchange Online without passing through your configured SEG. Analyzes mail flow rules, connector configurations, and MX records.

---

## Google Workspace Checks

### MX Routing
Validates that all MX records point to Google SMTP servers (`*.google.com`, `*.googlemail.com`). Flags mixed configurations.

### SPF
Same checks as M365 — validates the SPF record on your GWS domain.

### DMARC
Same checks as M365.

### DKIM
Validates DKIM signing is enabled for the domain via Admin SDK.

---

## Risk Levels

| Level | Meaning |
|---|---|
| 🔴 Critical | Immediate action required — significant security gap |
| 🟠 High | Should be addressed soon |
| 🟡 Medium | Best practice recommendation |
| 🟢 Pass | Correctly configured |
| ℹ️ Info | Informational — no action required |

---

## Lookalike Scanner Risk Scoring

The aggressive scanner combines a similarity score with enrichment signals:

| Signal | Score bonus |
|---|---|
| MX record present | +15 (domain is actively receiving email) |
| A / AAAA record | +8 (domain is live) |
| Domain registered < 30 days ago | +20 (very fresh — likely malicious) |
| Domain registered 30–90 days | +12 |
| Domain registered 90–180 days | +6 |
| CT certificate found | +8 (domain is in active use) |
| Subdomain takeover risk | +12 |

Final score → Risk level:
- ≥70 → Critical
- ≥50 → High
- ≥35 → Medium
- <35 → Low
