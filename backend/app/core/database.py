from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from app.models import tenant, scan, setting, aggressive_scan, scan_schedule  # noqa - registers models
    import app.models.v2.job  # noqa - registers v2 ScanJob/ScanTask with Base
    Base.metadata.create_all(bind=engine)
    _migrate()


def _migrate():
    """Add missing columns to existing tables. Safe to run on every startup."""
    migrations = [
        ("scans", "domains_scanned", "TEXT DEFAULT '[]'"),
        ("scans", "penalty_breakdown", "TEXT DEFAULT '[]'"),
        ("scans", "error", "TEXT"),
        ("scans", "platform", "TEXT DEFAULT 'Microsoft 365'"),
        ("scans", "benchmark_results", "TEXT DEFAULT '[]'"),
        ("scans", "benchmark_findings", "TEXT DEFAULT '{}'"),
        ("tenants", "extra_domains", "TEXT DEFAULT '[]'"),
        ("tenants", "user_id", "TEXT"),
        ("tenants", "gws_refresh_token", "TEXT"),
    ]
    with engine.connect() as conn:
        for table, column, col_def in migrations:
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
                conn.commit()
                print(f"[migrate] Added column {table}.{column}")
            except Exception:
                pass
