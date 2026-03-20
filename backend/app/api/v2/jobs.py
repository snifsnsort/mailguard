# jobs.py
#
# V2 Jobs API router.
#
# Execution model:
#   POST /api/v2/jobs        — creates a job record synchronously, returns 202
#                              immediately with {job_id, status: "queued"}.
#                              Task execution runs in a FastAPI BackgroundTask.
#                              Client must poll GET /api/v2/jobs/{job_id}.
#
#   GET  /api/v2/jobs/latest — latest job for domain + family (or 404)
#   GET  /api/v2/jobs/{id}   — full job with all task results (for polling)
#   GET  /api/v2/jobs/{id}/task/{task_type} — single task result
#
# The 202 status is honest: the response arrives before execution completes.
# Pages must poll until job.status is "completed" or "failed".

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.services.v2.scan_orchestrator.orchestrator import (
    create_job,
    run_job,
    get_job_with_tasks,
    get_latest_job,
    get_task_result,
    _serialize_job,
)

jobs_router = APIRouter(tags=["V2 Jobs"])


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------

class CreateJobRequest(BaseModel):
    domain: str
    scan_family: str
    tenant_id: Optional[str] = None
    platform: Optional[str] = "global"
    triggered_by: Optional[str] = "api"   # scope_change | manual | api


# ---------------------------------------------------------------------------
# POST /api/v2/jobs
# ---------------------------------------------------------------------------

@jobs_router.post("/jobs", status_code=202)
async def create_job_endpoint(
    req: CreateJobRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Create a scan job for a domain/family.

    Returns 202 Accepted immediately. Job execution runs in the background.
    Poll GET /api/v2/jobs/{job_id} until status is "completed" or "failed".

    Latest-job reuse policy is applied by trigger source:
      - triggered_by=scope_change or api: reuse recent completed job within TTL
      - triggered_by=manual: always create a fresh job
    """
    domain = req.domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain.")

    try:
        job, is_new = create_job(
            domain=domain,
            family=req.scan_family,
            db=db,
            tenant_id=req.tenant_id,
            platform=req.platform or "global",
            triggered_by=req.triggered_by or "api",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Job creation failed: {exc}")

    if is_new:
        # Schedule background execution only for newly created jobs
        background_tasks.add_task(run_job, job.id)

    return _serialize_job(job)


# ---------------------------------------------------------------------------
# GET /api/v2/jobs/latest
# NOTE: this route must be declared before /jobs/{job_id} to avoid
#       FastAPI treating "latest" as a job_id path parameter.
# ---------------------------------------------------------------------------

@jobs_router.get("/jobs/latest")
def get_latest_job_endpoint(
    domain: str = Query(..., description="Domain to look up"),
    family: str = Query(..., description="Scan family, e.g. dns_posture"),
    db: Session = Depends(get_db),
):
    """
    Return the most recent job for (domain, family), or 404.

    Pages call this on mount to load prior results without triggering
    a new scan. If 404, the page should offer to start a new job.
    """
    domain = domain.strip().lower()
    job = get_latest_job(domain, family, db)
    if not job:
        raise HTTPException(
            status_code=404,
            detail=f"No job found for domain='{domain}' family='{family}'.",
        )
    return get_job_with_tasks(job.id, db)


# ---------------------------------------------------------------------------
# GET /api/v2/jobs/{job_id}
# ---------------------------------------------------------------------------

@jobs_router.get("/jobs/{job_id}")
def get_job_endpoint(
    job_id: str,
    db: Session = Depends(get_db),
):
    """
    Return a job and all its tasks with results.

    Poll this endpoint until job.status is "completed" or "failed".
    Individual task results are available under each task's "result" field.
    """
    result = get_job_with_tasks(job_id, db)
    if not result:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    return result


# ---------------------------------------------------------------------------
# GET /api/v2/jobs/{job_id}/task/{task_type}
# ---------------------------------------------------------------------------

@jobs_router.get("/jobs/{job_id}/task/{task_type}")
def get_task_endpoint(
    job_id: str,
    task_type: str,
    db: Session = Depends(get_db),
):
    """
    Return the result payload for one specific task within a job.

    Pages that display one task type use this to retrieve only what they need:
      - Auth Health page  → task_type=authentication_status
      - MX Analysis page  → task_type=mx_health
    """
    result = get_task_result(job_id, task_type, db)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"Task '{task_type}' not found in job '{job_id}'.",
        )
    return result
