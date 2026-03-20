from datetime import datetime

from app.models.schemas import BenchmarkFinding
from app.services.benchmarks.common import build_result, clone_benchmark_finding
from app.services.benchmarks.types import ScanContext


class CisBenchmarkModule:
    key = "cis"
    name = "CIS"
    enabled_by_default = True

    async def run(self, context: ScanContext):
        started_at = datetime.utcnow()
        cis_findings: list[BenchmarkFinding] = [
            clone_benchmark_finding(
                finding,
                benchmark_label=str(finding.benchmark or self.name),
                category=finding.category,
                name=finding.name,
            )
            for finding in context.findings
            if "CIS" in str(finding.benchmark or "")
        ]
        return build_result(
            benchmark_key=self.key,
            benchmark_name=self.name,
            findings=cis_findings,
            started_at=started_at,
        )


CIS_BENCHMARK = CisBenchmarkModule()
