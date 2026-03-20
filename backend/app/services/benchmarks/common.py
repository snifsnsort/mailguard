from datetime import datetime
from typing import Iterable, Optional

from app.models.schemas import BenchmarkFinding, BenchmarkRunResult, BenchmarkSummary, FindingResult


def grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def summarize_findings(findings: Iterable[BenchmarkFinding]) -> BenchmarkSummary:
    finding_list = list(findings)
    return BenchmarkSummary(
        passed=sum(1 for finding in finding_list if finding.status == "pass"),
        failed=sum(1 for finding in finding_list if finding.status == "fail"),
        warning=sum(1 for finding in finding_list if finding.status == "warn"),
    )


def score_from_summary(summary: BenchmarkSummary) -> Optional[int]:
    applicable = summary.passed + summary.failed + summary.warning
    if applicable == 0:
        return None
    return round(((summary.passed + (summary.warning * 0.5)) / applicable) * 100)


def clone_benchmark_finding(
    finding: FindingResult,
    *,
    benchmark_label: str,
    category: Optional[str] = None,
    name: Optional[str] = None,
) -> BenchmarkFinding:
    payload = finding.dict()
    payload["benchmark"] = benchmark_label
    if category:
        payload["category"] = category
    if name:
        payload["name"] = name
    return BenchmarkFinding(**payload)


def build_result(
    *,
    benchmark_key: str,
    benchmark_name: str,
    findings: list[BenchmarkFinding],
    started_at: datetime,
    empty_status: str = "skipped",
    empty_summary: Optional[BenchmarkSummary] = None,
) -> BenchmarkRunResult:
    completed_at = datetime.utcnow()
    if not findings:
        return BenchmarkRunResult(
            benchmark_key=benchmark_key,
            benchmark_name=benchmark_name,
            execution_status=empty_status,
            summary=empty_summary or BenchmarkSummary(not_applicable=1),
            findings=[],
            started_at=started_at,
            completed_at=completed_at,
        )

    summary = summarize_findings(findings)
    score = score_from_summary(summary)
    return BenchmarkRunResult(
        benchmark_key=benchmark_key,
        benchmark_name=benchmark_name,
        execution_status="completed",
        score=score,
        max_score=100,
        grade=grade_from_score(score) if score is not None else None,
        summary=summary,
        findings=findings,
        started_at=started_at,
        completed_at=completed_at,
    )
