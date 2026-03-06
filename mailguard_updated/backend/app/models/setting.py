from sqlalchemy import Column, String, DateTime
from datetime import datetime
from app.core.database import Base


class Setting(Base):
    __tablename__ = "settings"

    key        = Column(String, primary_key=True)
    value      = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
