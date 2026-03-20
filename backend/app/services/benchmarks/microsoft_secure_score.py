from datetime import datetime

from app.models.schemas import BenchmarkSummary
from app.services.benchmarks.common import build_result, clone_benchmark_finding
from app.services.benchmarks.types import ScanContext


SECURE_SCORE_CHECK_MAP = {
    "legacy_auth_blocked": {
        "benchmark_label": "Microsoft Secure Score - Identity & Access",
        "category": "Secure Score - Identity & Access",
    },
    "antiphishing_impersonation": {
        "benchmark_label": "Microsoft Secure Score - Threat Protection",
        "category": "Secure Score - Threat Protection",
    },
    "antispam_outbound": {
        "benchmark_label": "Microsoft Secure Score - Exchange Online",
        "category": "Secure Score - Exchange Online",
    },
    "safe_links_assigned": {
        "benchmark_label": "Microsoft Secure Score - Threat Protection",
        "category": "Secure Score - Threat Protection",
    },
    "safe_attachments_mode": {
        "benchmark_label": "Microsoft Secure Score - Threat Protection",
        "category": "Secure Score - Threat Protection",
    },
    "direct_send_restricted": {
        "benchmark_label": "Microsoft Secure Score - Exchange Online",
        "category": "Secure Score - Exchange Online",
    },
    "spf_record": {
        "benchmark_label": "Microsoft Secure Score - Email Authentication",
        "category": "Secure Score - Email Authentication",
    },
    "dkim_enabled": {
        "benchmark_label": "Microsoft Secure Score - Email Authentication",
        "category": "Secure Score - Email Authentication",
    },
    "dmarc_policy": {
        "benchmark_label": "Microsoft Secure Score - Email Authentication",
        "category": "Secure Score - Email Authentication",
    },
}


class MicrosoftSecureScoreBenchmarkModule:
    key = "microsoft_secure_score"
    name = "Microsoft Secure Score"
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

        secure_score_findings = []
        for finding in context.findings:
            mapping = SECURE_SCORE_CHECK_MAP.get(finding.check_id)
            if not mapping:
                continue
            secure_score_findings.append(
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
            findings=secure_score_findings,
            started_at=started_at,
        )


MICROSOFT_SECURE_SCORE_BENCHMARK = MicrosoftSecureScoreBenchmarkModule()
