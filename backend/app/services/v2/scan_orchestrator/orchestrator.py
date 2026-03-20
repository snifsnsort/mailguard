# orchestrator.py
#
# Central V2 scan orchestration service.
#
# Design decisions:
#
# 1. Session isolation
#    Every function that touches the DB either receives a caller-owned session
#    (for synchronous create_job) or creates its own SessionLocal() and closes
#    it in a try/finally (for background run_job and per-task execution).
#    No session is shared across asyncio.gather coroutines.
#
# 2. Execution model
#    create_job()  — synchronous, called in the request path.
#                    Creates ScanJob + ScanTask rows. Returns immediately.
#    run_job()     — async background coroutine, called via FastAPI BackgroundTasks.
#                    Opens its own sessions. Executes tasks concurrently.
#                    Never called from within a request that needs a response.
#
# 3. Status lifecycle
#    derive_and_persist_job_status() is called after every individual task
#    state change, not only at the end of the job.
#    Transitions:
#      create_job()       → job queued,   tasks queued
#      run_job() starts   → job running   (derive called)
#      each task starts   → task running  (derive called → job stays running)
#      each task ends     → task completed/failed (derive called → may flip job)
#    The last task to finish triggers the final derive that marks the job terminal.

import asyncio
import dataclasses
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.v2.job import JobTaskStatus, ScanJob, ScanTask
from app.models.v2.scan_request import ScanRequest
from app.services.v2.scan_orchestrator.task_registry import (
    get_family_tasks,
    resolve_scanner,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

# For scope_change / api triggers: reuse a completed job younger than this.
COMPLETED_JOB_REUSE_TTL_SECONDS = 300


# ---------------------------------------------------------------------------
# Job status derivation
# ---------------------------------------------------------------------------

def derive_job_status(tasks: list) -> JobTaskStatus:
    """
    Derive canonical job status from its child tasks.

    Rules (strict failure policy):
      all queued               → queued
      any running              → running
      any failed, rest terminal → failed
      all completed            → completed
    """
    if not tasks:
        return JobTaskStatus.queued

    statuses = {t.status for t in tasks}

    if statuses == {JobTaskStatus.queued}:
        return JobTaskStatus.queued
    if JobTaskStatus.running in statuses:
        return JobTaskStatus.running
    if JobTaskStatus.failed in statuses:
        return JobTaskStatus.failed
    if statuses == {JobTaskStatus.completed}:
        return JobTaskStatus.completed

    # Mixed terminal with no running — strict: failed
    return JobTaskStatus.failed


def derive_and_persist_job_status(job_id: str, db: Session) -> JobTaskStatus:
    """
    Reload job + tasks from DB, derive status, persist it.

    Called after every individual task state change so that
    ScanJob.status always reflects the current task set.
    """
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        return JobTaskStatus.failed

    db.refresh(job)
    status = derive_job_status(job.tasks)
    job.status = status

    if status in (JobTaskStatus.completed, JobTaskStatus.failed):
        if job.completed_at is None:
            job.completed_at = datetime.now(timezone.utc)
        if status == JobTaskStatus.failed:
            failed = [t for t in job.tasks if t.status == JobTaskStatus.failed]
            job.error_summary = "; ".join(
                f"{t.task_type}: {t.error or 'unknown error'}"
                for t in failed
            )
    db.commit()
    return status


# ---------------------------------------------------------------------------
# Latest-job policy
# ---------------------------------------------------------------------------

def get_latest_job(domain: str, family: str, db: Session) -> Optional[ScanJob]:
    """Return the most recent job for (domain, family), or None."""
    return (
        db.query(ScanJob)
        .filter(ScanJob.domain == domain, ScanJob.scan_family == family)
        .order_by(ScanJob.started_at.desc().nullslast())
        .first()
    )


def should_reuse_job(existing: ScanJob, triggered_by: str) -> bool:
    """
    Apply latest-job reuse policy by trigger source.

    triggered_by=manual       → never reuse; always create fresh
    triggered_by=scope_change
    triggered_by=api          → reuse if queued/running or completed within TTL
    """
    if triggered_by == "manual":
        return False

    if existing.status in (JobTaskStatus.queued, JobTaskStatus.running):
        return True

    if existing.status == JobTaskStatus.completed:
        if existing.completed_at is None:
            return False
        completed_at = existing.completed_at
        if completed_at.tzinfo is None:
            completed_at = completed_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - completed_at).total_seconds()
        return age < COMPLETED_JOB_REUSE_TTL_SECONDS

    # failed → do not reuse
    return False


# ---------------------------------------------------------------------------
# Platform resolution
# ---------------------------------------------------------------------------

def _resolve_platform(tenant_id: Optional[str], requested_platform: str, db: Session) -> str:
    """Determine effective platform. Reads tenant flags if tenant_id provided."""
    if not tenant_id:
        return requested_platform or "global"
    try:
        from app.models.tenant import Tenant
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if tenant is None:
            return requested_platform or "global"
        if tenant.has_m365:
            return "microsoft365"
        if tenant.has_gws:
            return "google_workspace"
    except Exception:
        pass
    return requested_platform or "global"


# ---------------------------------------------------------------------------
# Task result normalization
# ---------------------------------------------------------------------------

def _normalize_task_result(
    scan_result,
    task_type: str,
    family: str,
    job_id: str,
    domain: str,
    tenant_id: Optional[str],
) -> dict:
    """
    Normalize a scanner's ScanResult into the standard task result payload.

    Required fields: task_type, family, job_id, domain, tenant_id,
                     completed_at, status, score, findings, evidence
    """
    findings = []
    try:
        raw = dataclasses.asdict(scan_result).get("findings", [])
        findings = raw if isinstance(raw, list) else []
    except Exception:
        try:
            findings = [dataclasses.asdict(f) for f in (scan_result.findings or [])]
        except Exception:
            findings = []

    evidence = {}
    try:
        evidence = scan_result.evidence or {}
    except Exception:
        pass

    score = None
    try:
        score = scan_result.score
    except Exception:
        pass

    return {
        "task_type":    task_type,
        "family":       family,
        "job_id":       job_id,
        "domain":       domain,
        "tenant_id":    tenant_id,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "status":       "completed",
        "score":        score,
        "findings":     findings,
        "evidence":     evidence,
    }


# ---------------------------------------------------------------------------
# Per-task execution  —  each call owns its own SessionLocal
# ---------------------------------------------------------------------------

async def _execute_task(
    task_id: str,
    task_type: str,
    platform: str,
    domain: str,
    family: str,
    tenant_id: Optional[str],
) -> None:
    """
    Execute one task.

    Opens and closes its own DB session. Never shares a session with
    other concurrent tasks or with the caller.

    Status transitions performed here (each followed by derive_and_persist):
      queued → running  (on start)
      running → completed | failed  (on finish)
    """
    from app.core.database import SessionLocal

    # ── Mark task running ─────────────────────────────────────────────────────
    db = SessionLocal()
    try:
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            logger.error("Task %s not found in DB", task_id)
            return
        job_id = task.job_id
        task.status = JobTaskStatus.running
        task.started_at = datetime.now(timezone.utc)
        db.commit()
        # Derive job status now that at least one task is running
        derive_and_persist_job_status(job_id, db)
    except Exception as exc:
        logger.error("Failed to mark task %s running: %s", task_id, exc)
        db.close()
        return
    finally:
        db.close()

    # ── Run scanner ───────────────────────────────────────────────────────────
    result_payload: Optional[dict] = None
    task_error: Optional[str] = None

    try:
        scanner_cls = resolve_scanner(task_type, platform)
        if scanner_cls is None:
            raise NotImplementedError(
                f"No scanner registered for ({task_type}, {platform}) "
                f"or ({task_type}, global)"
            )
        scanner = scanner_cls(domain)
        request = ScanRequest(
            domain=domain,
            platform=platform,
            tenant_id=tenant_id or "",
            families=[family],
        )
        scan_result = await scanner.run(request)
        result_payload = _normalize_task_result(
            scan_result=scan_result,
            task_type=task_type,
            family=family,
            job_id=job_id,
            domain=domain,
            tenant_id=tenant_id,
        )
    except Exception as exc:
        logger.error(
            "Task %s (%s) failed for domain %s: %s",
            task_type, task_id, domain, exc,
        )
        task_error = str(exc)

    # ── Persist outcome + derive job status ───────────────────────────────────
    db = SessionLocal()
    try:
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            return
        task.completed_at = datetime.now(timezone.utc)
        if task_error is None:
            task.status = JobTaskStatus.completed
            task.result = result_payload
        else:
            task.status = JobTaskStatus.failed
            task.error = task_error
        db.commit()
        # Derive job status after this task's terminal state
        derive_and_persist_job_status(task.job_id, db)
    except Exception as exc:
        logger.error("Failed to persist outcome for task %s: %s", task_id, exc)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Public interface — create_job (sync, request path)
# ---------------------------------------------------------------------------

def create_job(
    domain: str,
    family: str,
    db: Session,
    tenant_id: Optional[str] = None,
    platform: str = "global",
    triggered_by: str = "api",
) -> tuple:
    """
    Apply latest-job policy and either return an existing job or create a new one.

    Synchronous — called in the HTTP request path. Does NOT execute tasks.
    Returns (job, is_new: bool).

    The caller is responsible for scheduling run_job(job.id) as a BackgroundTask
    when is_new=True.
    """
    # Latest-job policy
    existing = get_latest_job(domain, family, db)
    if existing and should_reuse_job(existing, triggered_by):
        logger.info(
            "Reusing job %s (status=%s) for domain=%s family=%s",
            existing.id, existing.status, domain, family,
        )
        return existing, False

    # Resolve effective platform
    effective_platform = _resolve_platform(tenant_id, platform, db)

    # Create job record
    job = ScanJob(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        domain=domain,
        scan_family=family,
        status=JobTaskStatus.queued,
        triggered_by=triggered_by,
    )
    db.add(job)
    db.flush()  # populate job.id before child tasks

    # Create task records
    task_types = get_family_tasks(family)
    if not task_types:
        job.status = JobTaskStatus.failed
        job.error_summary = f"No tasks registered for family '{family}'"
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        return job, False

    for task_type in task_types:
        task = ScanTask(
            id=str(uuid.uuid4()),
            job_id=job.id,
            task_type=task_type,
            platform=effective_platform,
            status=JobTaskStatus.queued,
        )
        db.add(task)

    db.commit()
    return job, True


# ---------------------------------------------------------------------------
# Public interface — run_job (async, background path)
# ---------------------------------------------------------------------------

async def run_job(job_id: str) -> None:
    """
    Execute all tasks for a job. Intended to run as a BackgroundTask.

    Opens its own sessions. Never called from within a request path.
    Each child task also opens its own session — no session sharing.
    """
    from app.core.database import SessionLocal

    # ── Mark job running ──────────────────────────────────────────────────────
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            logger.error("run_job: job %s not found", job_id)
            return
        job.status = JobTaskStatus.running
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        # Snapshot task data — do not pass ORM objects across session boundaries
        tasks_snapshot = [
            (t.id, t.task_type, t.platform)
            for t in job.tasks
        ]
        domain     = job.domain
        family     = job.scan_family
        tenant_id  = job.tenant_id
    finally:
        db.close()

    if not tasks_snapshot:
        db = SessionLocal()
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if job:
                job.status = JobTaskStatus.failed
                job.error_summary = "Job had no tasks"
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
        return

    # ── Execute tasks concurrently — each owns its own session ────────────────
    await asyncio.gather(
        *[
            _execute_task(
                task_id=task_id,
                task_type=task_type,
                platform=platform,
                domain=domain,
                family=family,
                tenant_id=tenant_id,
            )
            for task_id, task_type, platform in tasks_snapshot
        ]
    )
    # Final derive is already handled by the last task to finish.
    # No additional action needed here.


# ---------------------------------------------------------------------------
# Retrieval helpers (used by jobs API)
# ---------------------------------------------------------------------------

def get_job_with_tasks(job_id: str, db: Session) -> Optional[dict]:
    """Return a job and all its tasks serialized for the API."""
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        return None
    return _serialize_job(job)


def get_task_result(job_id: str, task_type: str, db: Session) -> Optional[dict]:
    """Return the result payload for one specific task within a job."""
    task = (
        db.query(ScanTask)
        .filter(ScanTask.job_id == job_id, ScanTask.task_type == task_type)
        .first()
    )
    if not task:
        return None
    return {
        "job_id":       task.job_id,
        "task_type":    task.task_type,
        "platform":     task.platform,
        "status":       task.status.value,
        "started_at":   task.started_at.isoformat() if task.started_at else None,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
        "error":        task.error,
        "result":       task.result,
    }


def _serialize_job(job: ScanJob) -> dict:
    return {
        "id":            job.id,
        "tenant_id":     job.tenant_id,
        "domain":        job.domain,
        "scan_family":   job.scan_family,
        "status":        job.status.value,
        "triggered_by":  job.triggered_by,
        "started_at":    job.started_at.isoformat() if job.started_at else None,
        "completed_at":  job.completed_at.isoformat() if job.completed_at else None,
        "error_summary": job.error_summary,
        "tasks": [
            {
                "id":           t.id,
                "task_type":    t.task_type,
                "platform":     t.platform,
                "status":       t.status.value,
                "started_at":   t.started_at.isoformat() if t.started_at else None,
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                "error":        t.error,
                "result":       t.result,
            }
            for t in job.tasks
        ],
    }
