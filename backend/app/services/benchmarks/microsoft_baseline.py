from datetime import datetime

from app.models.schemas import BenchmarkSummary
from app.services.benchmarks.common import build_result, clone_benchmark_finding
from app.services.benchmarks.types import ScanContext


MICROSOFT_BASELINE_CHECK_MAP = {
    "legacy_auth_blocked": {
        "benchmark_label": "Microsoft Security Baseline - Exchange Online",
        "category": "Security Baseline - Exchange Online",
    },
    "antiphishing_impersonation": {
        "benchmark_label": "Microsoft Security Baseline - Exchange Online Protection",
        "category": "Security Baseline - Exchange Online Protection",
    },
    "antispam_outbound": {
        "benchmark_label": "Microsoft Security Baseline - Exchange Online Protection",
        "category": "Security Baseline - Exchange Online Protection",
    },
    "safe_links_assigned": {
        "benchmark_label": "Microsoft Security Baseline - Defender for Office 365",
        "category": "Security Baseline - Defender for Office 365",
    },
    "safe_attachments_mode": {
        "benchmark_label": "Microsoft Security Baseline - Defender for Office 365",
        "category": "Security Baseline - Defender for Office 365",
    },
    "direct_send_restricted": {
        "benchmark_label": "Microsoft Security Baseline - Exchange Online",
        "category": "Security Baseline - Exchange Online",
    },
    "spf_record": {
        "benchmark_label": "Microsoft Security Baseline - Email Authentication",
        "category": "Security Baseline - Email Authentication",
    },
    "dkim_enabled": {
        "benchmark_label": "Microsoft Security Baseline - Email Authentication",
        "category": "Security Baseline - Email Authentication",
    },
    "dmarc_policy": {
        "benchmark_label": "Microsoft Security Baseline - Email Authentication",
        "category": "Security Baseline - Email Authentication",
    },
    "mx_bypass_risk": {
        "benchmark_label": "Microsoft Security Baseline - Mail Flow Hardening",
        "category": "Security Baseline - Mail Flow Hardening",
    },
    "mx_gateway": {
        "benchmark_label": "Microsoft Security Baseline - Mail Flow Hardening",
        "category": "Security Baseline - Mail Flow Hardening",
    },
}


class MicrosoftBaselineBenchmarkModule:
    key = "microsoft_baseline"
    name = "Microsoft Baseline"
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

        baseline_findings = []
        for finding in context.findings:
            mapping = MICROSOFT_BASELINE_CHECK_MAP.get(finding.check_id)
            if not mapping:
                continue
            baseline_findings.append(
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
            findings=baseline_findings,
            started_at=started_at,
        )


MICROSOFT_BASELINE_BENCHMARK = MicrosoftBaselineBenchmarkModule()
