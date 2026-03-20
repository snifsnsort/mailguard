from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Integer, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.core.database import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, unique=True)
    frequency = Column(String, nullable=False, default="weekly")
    time_of_day = Column(String, nullable=False, default="08:00")
    timezone = Column(String, nullable=False, default="UTC")
    weekdays = Column(JSON, nullable=False, default=list)
    day_of_month = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tenant = relationship("Tenant", back_populates="scan_schedule")
