from datetime import datetime
from typing import List

from app.models.schemas import BenchmarkRunResult, BenchmarkSummary
from app.services.benchmarks.base import BenchmarkModule
from app.services.benchmarks.cis import CIS_BENCHMARK
from app.services.benchmarks.microsoft_baseline import MICROSOFT_BASELINE_BENCHMARK
from app.services.benchmarks.microsoft_secure_score import MICROSOFT_SECURE_SCORE_BENCHMARK
from app.services.benchmarks.scuba import SCUBA_BENCHMARK
from app.services.benchmarks.types import ScanContext

BENCHMARK_REGISTRY: List[BenchmarkModule] = [
    CIS_BENCHMARK,
    SCUBA_BENCHMARK,
    MICROSOFT_SECURE_SCORE_BENCHMARK,
    MICROSOFT_BASELINE_BENCHMARK,
]


async def run_registered_benchmarks(context: ScanContext) -> List[BenchmarkRunResult]:
    results: List[BenchmarkRunResult] = []
    for module in BENCHMARK_REGISTRY:
        started_at = datetime.utcnow()
        try:
            if not module.enabled_by_default:
                result = BenchmarkRunResult(
                    benchmark_key=module.key,
                    benchmark_name=module.name,
                    execution_status="skipped",
                    summary=BenchmarkSummary(not_applicable=1),
                    findings=[],
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                )
            else:
                result = await module.run(context)
        except Exception as exc:
            result = BenchmarkRunResult(
                benchmark_key=module.key,
                benchmark_name=module.name,
                execution_status="failed",
                summary=BenchmarkSummary(),
                findings=[],
                started_at=started_at,
                completed_at=datetime.utcnow(),
                error=str(exc),
            )
        results.append(result)
    return results
