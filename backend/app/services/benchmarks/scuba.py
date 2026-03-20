from datetime import datetime

from app.models.schemas import BenchmarkSummary
from app.services.benchmarks.common import build_result, clone_benchmark_finding
from app.services.benchmarks.types import ScanContext


SCUBA_CHECK_MAP = {
    "mfa_admins": {
        "benchmark_label": "SCuBA - Entra ID",
        "category": "SCuBA - Entra ID",
    },
    "legacy_auth_blocked": {
        "benchmark_label": "SCuBA - Entra ID",
        "category": "SCuBA - Entra ID",
    },
    "security_defaults_ca": {
        "benchmark_label": "SCuBA - Entra ID",
        "category": "SCuBA - Entra ID",
    },
    "antiphishing_impersonation": {
        "benchmark_label": "SCuBA - Defender for Office 365",
        "category": "SCuBA - Defender for Office 365",
    },
    "antispam_outbound": {
        "benchmark_label": "SCuBA - Exchange Online",
        "category": "SCuBA - Exchange Online",
    },
    "safe_links_assigned": {
        "benchmark_label": "SCuBA - Defender for Office 365",
        "category": "SCuBA - Defender for Office 365",
    },
    "safe_attachments_mode": {
        "benchmark_label": "SCuBA - Defender for Office 365",
        "category": "SCuBA - Defender for Office 365",
    },
    "direct_send_restricted": {
        "benchmark_label": "SCuBA - Exchange Online",
        "category": "SCuBA - Exchange Online",
    },
    "teams_guest_access": {
        "benchmark_label": "SCuBA - Microsoft Teams",
        "category": "SCuBA - Microsoft Teams",
    },
    "teams_external_access": {
        "benchmark_label": "SCuBA - Microsoft Teams",
        "category": "SCuBA - Microsoft Teams",
    },
    "sharepoint_external_sharing": {
        "benchmark_label": "SCuBA - SharePoint Online & OneDrive",
        "category": "SCuBA - SharePoint Online & OneDrive",
    },
}


class ScubaBenchmarkModule:
    key = "scuba"
    name = "SCuBA"
    enabled_by_default = True

    async def run(self, context: ScanContext):
        started_at = datetime.utcnow()
        if not context.evidence.get("has_m365"):
            return build_result(
                benchmark_key=self.key,
                benchmark_name=self.name,
                findings=[],
                started_at=started_at,
                empty_status="skipped",
                empty_summary=BenchmarkSummary(not_applicable=1),
            )

        scuba_findings = []
        for finding in context.findings:
            mapping = SCUBA_CHECK_MAP.get(finding.check_id)
            if not mapping:
                continue
            scuba_findings.append(
                clone_benchmark_finding(
                    finding,
                    benchmark_label=mapping["benchmark_label"],
                    category=mapping["category"],
                    name=finding.name,
                )
            )

        return build_result(
            benchmark_key=self.key,
            benchmark_name=self.name,
            findings=scuba_findings,
            started_at=started_at,
        )


SCUBA_BENCHMARK = ScubaBenchmarkModule()
