from typing import Protocol

from app.models.schemas import BenchmarkRunResult
from app.services.benchmarks.types import ScanContext


class BenchmarkModule(Protocol):
    key: str
    name: str
    enabled_by_default: bool

    async def run(self, context: ScanContext) -> BenchmarkRunResult:
        ...
