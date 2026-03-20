from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from app.core.database import Base


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending)
    score = Column(Integer, nullable=True)
    grade = Column(String, nullable=True)
    platform = Column(String, nullable=True)
    findings = Column(JSON, default=list)
    benchmark_results = Column(JSON, default=list)
    benchmark_findings = Column(JSON, default=dict)
    domains_scanned = Column(JSON, default=list)
    penalty_breakdown = Column(JSON, default=list)
    error = Column(String, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    tenant = relationship("Tenant", back_populates="scans")
