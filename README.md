# MailGuard — Email Security Posture Management

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB)](https://react.dev)

MailGuard is an open-source email security posture management tool that continuously audits Microsoft 365 and Google Workspace tenants for misconfigurations, policy gaps, and typosquatting threats.

---

## Features

### Security Checks
- **SPF** — syntax validation, multiple-record detection, DNS lookup count (RFC 7208 §4.6.4 limit)
- **DMARC** — policy enforcement, subdomain policy, rua/ruf reporting, syntax errors
- **DKIM** — key presence, algorithm strength, key length
- **MX Routing** — SEG fingerprinting (Proofpoint, Mimecast, Defender, Cisco, Fortinet, Hornetsecurity, Trend Micro, etc.), multi-SEG conflict detection, split/inconsistent routing
- **Anti-Spam** — inbound filter configuration, quarantine thresholds
- **Anti-Phishing** — impersonation protection, mailbox intelligence, spoof settings
- **Safe Links / Safe Attachments** — policy coverage across users
- **SEG Bypass Risk** — detection of mail flows that circumvent your secure email gateway

### Google Workspace
- MX routing validation against Google SMTP
- SPF/DMARC for GWS domains
- DKIM via Admin SDK
- OAuth 2.0 integration with persistent token backup across deployments

### Aggressive Lookalike Scanner
- Generates typosquatting candidates: character omission/insertion/substitution, keyboard typos, homoglyphs, TLD swaps, transpositions, hyphenation attacks, unicode mixed-script
- DNS enrichment (A, AAAA, MX, NS, TXT records)
- WHOIS/RDAP — registration date, domain age, registrar, registrant
- Certificate Transparency lookups via crt.sh
- Subdomain takeover detection (Azure, AWS, GitHub Pages, Netlify, Vercel, and more)
- Enriched risk scoring (Critical / High / Medium / Low)
- CSV and PDF export

### Multi-Tenant
- Manage multiple M365 and GWS tenants from one dashboard
- Per-tenant scan history and PDF reports
- Tenant-level GWS token persistence across deployments

---

## Architecture

```
mailguard/
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── api/              # REST endpoints
│   │   ├── core/             # Auth, config, database, security
│   │   ├── models/           # SQLAlchemy models + Pydantic schemas
│   │   └── services/         # Scan engine, checkers, report generator
│   ├── start.py              # Startup: seed tenant, restore GWS tokens
│   └── requirements.txt
├── frontend/                 # React + Vite SPA
│   └── src/
│       ├── components/       # Sidebar, ConnectModal, DetailPanel, etc.
│       ├── pages/            # Dashboard, Checks, History, LookalikeScan
│       └── utils/api.js      # API client
├── Dockerfile                # Multi-stage build (Node → Python)
├── docker-compose.yml        # Local development
├── Build-And-Deploy.ps1      # Azure Container Apps deployment
├── Setup-Storage.ps1         # One-time Azure File Share setup
└── terraform/                # Infrastructure as code (Azure)
```

---

## Quick Start (Local)

### Prerequisites
- Docker Desktop
- An Azure AD App Registration (for M365) — see [docs/M365_SETUP.md](docs/M365_SETUP.md)
- Or a Google Cloud project (for GWS) — see [docs/GWS_SETUP.md](docs/GWS_SETUP.md)

### 1. Clone and configure

```bash
git clone https://github.com/YOUR_USERNAME/mailguard.git
cd mailguard
cp backend/.env.example backend/.env
```

Edit `backend/.env`:

```env
SECRET_KEY=your-random-secret-key-here
ADMIN_PASSWORD=YourSecurePassword123
SEED_TENANT_DOMAIN=yourdomain.com
SEED_TENANT_ID=<Azure tenant ID>
SEED_CLIENT_ID=<Azure app client ID>
SEED_CLIENT_SECRET=<Azure app client secret>
```

### 2. Run with Docker Compose

```bash
docker compose up --build
```

Open [http://localhost:8000](http://localhost:8000) and log in with `admin` / the password you set.

---

## Azure Deployment

See **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** for the full Azure Container Apps guide.

```powershell
# One-time: create persistent storage
.\Setup-Storage.ps1

# Every deploy
.\Build-And-Deploy.ps1
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key — set to a long random string |
| `ADMIN_PASSWORD` | ✅ | Dashboard login password |
| `SEED_TENANT_DOMAIN` | ✅ | Primary M365 tenant domain (e.g. `contoso.com`) |
| `SEED_TENANT_ID` | ✅ | Azure AD tenant ID (GUID) |
| `SEED_CLIENT_ID` | ✅ | Azure App Registration client ID |
| `SEED_CLIENT_SECRET` | ✅ | Azure App Registration client secret |
| `ENCRYPTION_KEY` | ❌ | GWS token encryption key — auto-derived from `SECRET_KEY` if not set |
| `DATABASE_URL` | ❌ | SQLite path — defaults to `/tmp/mailguard.db` |
| `ALLOWED_ORIGINS` | ❌ | CORS origins — defaults to `*` in dev |
| `MULTI_TENANT_MODE` | ❌ | Set to `true` to allow multiple M365 tenants |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, SQLAlchemy, SQLite |
| Frontend | React 18, Vite, Lucide icons |
| Auth | JWT (PyJWT), bcrypt |
| DNS | dnspython |
| HTTP | httpx (async) |
| Reports | ReportLab (PDF) |
| Encryption | cryptography (Fernet) |
| Container | Docker, Azure Container Apps |
| IaC | Terraform (Azure) |

---

## Feedback & Issues

Found a bug or have a feature request? Please open a GitHub issue with a clear description. For all other inquiries including commercial licensing, contact george@cloud4you.ca.

---

## Disclaimer

MailGuard is provided for informational and operational assistance purposes only. It does not constitute legal, compliance, or security advice.

**The authors accept no liability for:**
- Security incidents or data breaches that occur regardless of scan results
- Misconfigurations this tool failed to detect
- Actions taken or not taken based on this tool's output
- Compliance failures with any regulation or standard (GDPR, HIPAA, ISO 27001, SOC 2, etc.)

Scan results reflect a point-in-time snapshot. Organizations are solely responsible for their own security posture. This tool is an aid, not a substitute for professional security review.

See [LICENSE](LICENSE) for full terms.

---

## Roadmap

- [ ] Password reset UI
- [ ] GWS Admin SDK checks (IMAP/POP, Third-Party OAuth, Alert Center)
- [ ] Scan all tenants in one click
- [ ] Scheduled scans with email alerts
- [ ] Webhook notifications (Slack, Teams)

---

## License

Free to use for personal and internal business purposes. Redistribution, modification, and commercial use require written permission. See [LICENSE](LICENSE) for full terms.
