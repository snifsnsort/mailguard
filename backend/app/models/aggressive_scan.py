from sqlalchemy import Column, String, DateTime, JSON, Enum
from datetime import datetime
import uuid
import enum

from app.core.database import Base


class AggressiveScanStatus(str, enum.Enum):
    pending   = "pending"
    running   = "running"
    completed = "completed"
    failed    = "failed"


class AggressiveScan(Base):
    __tablename__ = "aggressive_scans"

    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    status      = Column(Enum(AggressiveScanStatus), default=AggressiveScanStatus.pending)
    domains     = Column(JSON, default=list)    # List[str] — all domains scanned
    results     = Column(JSON, default=list)    # List[serialized AggressiveResult]
    error       = Column(String, nullable=True)
    started_at  = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
