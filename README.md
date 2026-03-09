# MailGuard — Email Security Posture Management

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB)](https://react.dev)

MailGuard is a free email security posture management tool that continuously audits Microsoft 365 and Google Workspace tenants for misconfigurations, policy gaps, and typosquatting threats.

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
├── Deploy-MailGuard-Local-M365.ps1   # One-command local M365 setup
├── deploy.ps1                # One-command Azure deployment (first time)
├── update.ps1                # Redeploy after code changes
└── terraform/                # Infrastructure as code (Azure)
```

---

## Quick Start — Local Deployment (Microsoft 365)

### Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 | Script is PowerShell-based |
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Must be running before setup starts |
| Azure CLI | Installed automatically via winget if not found |
| M365 Global Admin account | Required to grant admin consent during setup |

### One-Command Setup

```powershell
git clone https://github.com/snifsnsort/mailguard.git
cd mailguard
.\Deploy-MailGuard-Local-M365.ps1
```

The script will:

1. Check and install prerequisites (Azure CLI via winget if missing)
2. Prompt for your M365 tenant domain, a friendly name, and a dashboard admin password
3. Log you into Azure CLI
4. Create an Entra app registration with read-only Microsoft Graph and Exchange Online permissions
5. Open your browser for admin consent — sign in as Global Admin and click **Accept**
6. Generate a client secret and verify it with two live token tests before writing any files
7. Write `backend\.env` with all credentials
8. Stop any running containers, wipe the old data volume, and start fresh

Once complete, MailGuard opens at **http://localhost:8000**. Log in with username `admin` and the password you set.

> **Note:** `backend\.env` is required every time the container starts. Do not delete it. Do not commit it to git — it is already in `.gitignore`.

### Adding Google Workspace

After the M365 setup completes, add your GWS OAuth credentials to `backend\.env` before starting the container:

```ini
GWS_CLIENT_ID=<your Google OAuth client ID>
GWS_CLIENT_SECRET=<your Google OAuth client secret>
GWS_REDIRECT_URI=http://localhost:8000/api/v1/google/callback
```

Then start the container:

```powershell
docker compose up --build -d
```

---

## Starting and Stopping

```powershell
# Start
docker compose up -d

# Stop
docker compose down

# View logs
docker compose logs app

# Rebuild after a code change
docker compose up --build -d
```

---

## Wipe Everything and Start Clean

Use this if you need a completely fresh deployment — new credentials, clean database, no cached images or volumes.

```powershell
cd <mailguard folder>

# Stop containers
docker compose down

# Remove the data volume (SQLite database)
docker volume ls --format "{{.Name}}" | Where-Object { $_ -match "mailguard" } | ForEach-Object { docker volume rm $_ }

# Remove the built image
docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -match "mailguard" } | ForEach-Object { docker rmi $_ -f }

# Clear the Docker build cache
docker builder prune -f

# Delete all project files and re-clone
cd ..
Remove-Item -Recurse -Force mailguard
git clone https://github.com/snifsnsort/mailguard.git
cd mailguard

# Run setup from scratch
.\Deploy-MailGuard-Local-M365.ps1
```

---

## Deploy to Azure

```powershell
# First time — creates all Azure resources and deploys the app
.\deploy.ps1

# After code changes — rebuilds and redeploys
.\update.ps1

# Tear everything down
.\deploy.ps1 -Destroy
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full guide.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key — set to a long random string |
| `ADMIN_PASSWORD` | ✅ | Dashboard login password |
| `SEED_TENANT_NAME` | ✅ | Friendly name for the auto-registered tenant |
| `SEED_TENANT_DOMAIN` | ✅ | Primary M365 tenant domain (e.g. `contoso.com`) |
| `SEED_TENANT_ID` | ✅ | Azure AD tenant ID (GUID) |
| `SEED_CLIENT_ID` | ✅ | Azure App Registration client ID |
| `SEED_CLIENT_SECRET` | ✅ | Azure App Registration client secret |
| `GWS_CLIENT_ID` | ❌ | Google OAuth client ID (required for GWS integration) |
| `GWS_CLIENT_SECRET` | ❌ | Google OAuth client secret (required for GWS integration) |
| `GWS_REDIRECT_URI` | ❌ | Google OAuth redirect URI |
| `ENCRYPTION_KEY` | ❌ | GWS token encryption key — auto-derived from `SECRET_KEY` if not set |
| `DATABASE_URL` | ❌ | SQLite path — defaults to `/data/mailguard.db` |
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

Found a bug or have a feature request? Please open a GitHub issue with a clear description. For all other inquiries including commercial licensing, contact [your email].

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
- [ ] Local deployment script for Google Workspace
- [ ] Scan all tenants in one click
- [ ] Scheduled scans with email alerts
- [ ] Webhook notifications (Slack, Teams)

---

## License

Free to use for personal and internal business purposes. Redistribution, modification, and commercial use require written permission. See [LICENSE](LICENSE) for full terms.
