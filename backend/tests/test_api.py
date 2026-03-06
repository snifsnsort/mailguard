"""
MailGuard test suite.
Run: pytest tests/ -v --tb=short
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
from app.main import app
from app.core.database import init_db, Base, engine

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    init_db()
    yield
    Base.metadata.drop_all(bind=engine)


client = TestClient(app)


def _auth_header():
    """Login and return Authorization header."""
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "changeme123"})
    if r.status_code != 200:
        return {}
    token = r.json().get("token") or r.json().get("access_token", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


# ── Health ────────────────────────────────────────────────────────────────────

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Auth ──────────────────────────────────────────────────────────────────────

def test_login_wrong_password():
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_login_unknown_user():
    r = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "x"})
    assert r.status_code == 401


# ── Tenants ───────────────────────────────────────────────────────────────────

def test_list_tenants_empty():
    r = client.get("/api/v1/tenants/")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_create_tenant_missing_fields():
    r = client.post("/api/v1/tenants/", json={"display_name": "Test"})
    assert r.status_code == 422


def test_tenant_schema_has_extra_domains():
    """TenantOut must include extra_domains field."""
    from app.models.schemas import TenantOut
    fields = TenantOut.model_fields if hasattr(TenantOut, "model_fields") else TenantOut.__fields__
    assert "extra_domains" in fields


def test_tenant_all_domains_property():
    """Tenant.all_domains returns deduplicated list of primary + extras."""
    from app.models.tenant import Tenant
    t = Tenant(
        display_name="Acme",
        tenant_id="tid",
        domain="acme.com",
        extra_domains=["acme.co.uk", "acme.de", "acme.com"],  # acme.com duplicate
        client_id="cid",
        client_secret="secret",
    )
    domains = t.all_domains
    assert domains[0] == "acme.com"
    assert "acme.co.uk" in domains
    assert "acme.de" in domains
    assert domains.count("acme.com") == 1  # deduplicated


# ── Scoring (penalty model) ───────────────────────────────────────────────────

def test_compute_score_all_pass():
    from app.services.scan_engine import _compute_score, CHECK_PENALTIES
    findings = [
        MagicMock(check_id="mfa_admins",        status="pass", name="MFA Admins"),
        MagicMock(check_id="dmarc_policy",       status="pass", name="DMARC"),
        MagicMock(check_id="legacy_auth_blocked",status="pass", name="Legacy Auth"),
    ]
    score, breakdown = _compute_score(findings, CHECK_PENALTIES)
    assert score == 100
    assert breakdown == []


def test_compute_score_critical_fail():
    from app.services.scan_engine import _compute_score, CHECK_PENALTIES
    findings = [
        MagicMock(check_id="mfa_admins",  status="fail", name="MFA Admins"),
        MagicMock(check_id="dmarc_policy",status="pass", name="DMARC"),
    ]
    score, breakdown = _compute_score(findings, CHECK_PENALTIES)
    assert score == 100 - 15   # mfa_admins penalty = 15
    assert len(breakdown) == 1
    assert breakdown[0]["check_id"] == "mfa_admins"
    assert breakdown[0]["penalty_applied"] == 15


def test_compute_score_warn_half_penalty():
    from app.services.scan_engine import _compute_score, CHECK_PENALTIES
    findings = [
        MagicMock(check_id="dmarc_policy", status="warn", name="DMARC"),
    ]
    score, breakdown = _compute_score(findings, CHECK_PENALTIES)
    assert score == 100 - (15 // 2)   # warn = half of 15 = 7
    assert breakdown[0]["penalty_applied"] == 7


def test_compute_score_multiple_fails():
    from app.services.scan_engine import _compute_score, CHECK_PENALTIES
    findings = [
        MagicMock(check_id="mfa_admins",         status="fail", name="MFA"),
        MagicMock(check_id="legacy_auth_blocked", status="fail", name="Legacy"),
        MagicMock(check_id="dmarc_policy",        status="fail", name="DMARC"),
    ]
    score, breakdown = _compute_score(findings, CHECK_PENALTIES)
    expected = 100 - 15 - 15 - 15   # all three are CRITICAL tier
    assert score == max(0, expected)
    assert len(breakdown) == 3


def test_score_never_negative():
    from app.services.scan_engine import _compute_score, CHECK_PENALTIES
    # Fail everything
    findings = [MagicMock(check_id=k, status="fail", name=k) for k in CHECK_PENALTIES]
    score, _ = _compute_score(findings, CHECK_PENALTIES)
    assert score >= 0


def test_check_penalties_tiers():
    """Verify critical-tier checks have penalty == 15."""
    from app.services.scan_engine import CHECK_PENALTIES
    critical_checks = ["mfa_admins", "legacy_auth_blocked", "dmarc_policy", "mx_bypass_risk"]
    for c in critical_checks:
        assert CHECK_PENALTIES.get(c) == 15, f"{c} should be penalty 15"


def test_grade_boundaries():
    from app.services.scan_engine import _grade
    assert _grade(100) == "A"
    assert _grade(90)  == "A"
    assert _grade(89)  == "B"
    assert _grade(75)  == "B"
    assert _grade(74)  == "C"
    assert _grade(60)  == "C"
    assert _grade(59)  == "D"
    assert _grade(45)  == "D"
    assert _grade(44)  == "F"
    assert _grade(0)   == "F"


# ── Schema fields ─────────────────────────────────────────────────────────────

def test_finding_result_has_domain_field():
    from app.models.schemas import FindingResult, Severity
    f = FindingResult(
        check_id="spf_record", name="SPF", category="SPF/DKIM/DMARC",
        severity=Severity.pass_, status="pass",
        description="OK", current_value="v=spf1 -all",
        expected_value="v=spf1 -all", remediation=[],
        reference_url="", benchmark="CIS",
        domain="contoso.com",
    )
    assert f.domain == "contoso.com"


def test_finding_result_domain_optional():
    from app.models.schemas import FindingResult, Severity
    f = FindingResult(
        check_id="mfa_admins", name="MFA", category="MFA & Admin",
        severity=Severity.pass_, status="pass",
        description="OK", current_value=True,
        expected_value=True, remediation=[],
        reference_url="", benchmark="CIS",
    )
    assert f.domain is None


def test_scan_out_has_penalty_breakdown():
    from app.models.schemas import ScanOut
    fields = ScanOut.model_fields if hasattr(ScanOut, "model_fields") else ScanOut.__fields__
    assert "penalty_breakdown" in fields
    assert "domains_scanned" in fields


# ── New checks present in engine ─────────────────────────────────────────────

def test_teams_sharepoint_checks_registered():
    from app.services.scan_engine import CHECK_PENALTIES
    assert "teams_guest_access" in CHECK_PENALTIES
    assert "teams_external_access" in CHECK_PENALTIES
    assert "sharepoint_external_sharing" in CHECK_PENALTIES


def test_teams_sharepoint_penalties():
    from app.services.scan_engine import CHECK_PENALTIES
    # sharepoint external sharing is HIGH tier (10)
    assert CHECK_PENALTIES["sharepoint_external_sharing"] == 10
    # teams checks are MEDIUM tier (7)
    assert CHECK_PENALTIES["teams_guest_access"] == 7
    assert CHECK_PENALTIES["teams_external_access"] == 7


# ── Report generator ─────────────────────────────────────────────────────────

def test_report_generates_pdf_bytes():
    from app.services.report_generator import generate_report
    tenant = {"display_name": "Acme Corp", "domain": "acme.com", "extra_domains": []}
    scan = {
        "score": 72,
        "grade": "C",
        "platform": "Microsoft 365",
        "domains_scanned": ["acme.com", "acme.co.uk"],
        "penalty_breakdown": [
            {"check_id": "mfa_admins", "name": "MFA Admins", "status": "fail",
             "penalty_applied": 15, "max_penalty": 15},
            {"check_id": "dmarc_policy", "name": "DMARC", "status": "warn",
             "penalty_applied": 7, "max_penalty": 15},
        ],
        "findings": [
            {"check_id": "mfa_admins", "name": "MFA Admins", "category": "MFA & Admin",
             "status": "fail", "severity": "critical", "description": "No MFA.",
             "current_value": False, "expected_value": True,
             "remediation": ["Enable MFA."], "reference_url": "", "benchmark": "CIS",
             "domain": None},
            {"check_id": "spf_record", "name": "SPF", "category": "SPF/DKIM/DMARC",
             "status": "pass", "severity": "pass", "description": "SPF ok.",
             "current_value": "v=spf1 -all", "expected_value": "v=spf1 -all",
             "remediation": [], "reference_url": "", "benchmark": "CIS",
             "domain": "acme.com"},
        ],
    }
    pdf = generate_report(tenant, scan)
    assert isinstance(pdf, bytes)
    assert len(pdf) > 5000   # must be a real PDF, not empty
    assert pdf[:4] == b"%PDF"


def test_report_with_empty_findings():
    from app.services.report_generator import generate_report
    pdf = generate_report(
        {"display_name": "Empty Tenant", "domain": "empty.com", "extra_domains": []},
        {"score": 100, "grade": "A", "platform": "Microsoft 365",
         "domains_scanned": ["empty.com"], "penalty_breakdown": [], "findings": []},
    )
    assert pdf[:4] == b"%PDF"
