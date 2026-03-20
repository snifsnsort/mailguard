# job.py
#
# SQLAlchemy models for V2 orchestrated scan jobs and tasks.
#
# Tables:
#   v2_scan_jobs   — one row per scan family execution against a domain
#   v2_scan_tasks  — one row per task within a job
#
# ScanJob.status is always persisted. It is derived via
# derive_job_status(tasks) and written back on every task state change.
# No code other than derive_and_persist_job_status() should write
# ScanJob.status after initial job creation.
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Enum as SAEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from app.core.database import Base


class JobTaskStatus(str, enum.Enum):
    queued    = "queued"
    running   = "running"
    completed = "completed"
    failed    = "failed"


class ScanJob(Base):
    __tablename__ = "v2_scan_jobs"

    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id     = Column(String, nullable=True)          # FK to tenants.id; null for ad-hoc scans
    domain        = Column(String, nullable=False)
    scan_family   = Column(String, nullable=False)         # e.g. "dns_posture"
    status        = Column(SAEnum(JobTaskStatus), default=JobTaskStatus.queued, nullable=False)
    triggered_by  = Column(String, nullable=False, default="api")  # scope_change | manual | api
    started_at    = Column(DateTime, nullable=True)
    completed_at  = Column(DateTime, nullable=True)
    error_summary = Column(String, nullable=True)

    tasks = relationship("ScanTask", back_populates="job", cascade="all, delete-orphan")


class ScanTask(Base):
    __tablename__ = "v2_scan_tasks"

    id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id       = Column(String, ForeignKey("v2_scan_jobs.id"), nullable=False)
    task_type    = Column(String, nullable=False)     # e.g. "mx_health"
    platform     = Column(String, nullable=False, default="global")
    status       = Column(SAEnum(JobTaskStatus), default=JobTaskStatus.queued, nullable=False)
    started_at   = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error        = Column(String, nullable=True)
    result       = Column(JSON, nullable=True)        # Normalized task result payload

    job = relationship("ScanJob", back_populates="tasks")
