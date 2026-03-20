import asyncio
import calendar
from datetime import datetime, timedelta, timezone
from typing import Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.scan import Scan, ScanStatus
from app.models.scan_schedule import ScanSchedule
from app.models.tenant import Tenant
from app.services.scan_runner import create_pending_scan, run_scan_task

VALID_FREQUENCIES = {"daily", "weekly", "monthly", "custom"}
VALID_WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
WEEKDAY_TO_INDEX = {day: index for index, day in enumerate(VALID_WEEKDAYS)}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_frequency(value: str) -> str:
    normalized = (value or "weekly").strip().lower()
    if normalized not in VALID_FREQUENCIES:
        raise ValueError("Frequency must be daily, weekly, monthly, or custom.")
    return normalized


def normalize_weekdays(days: Iterable[str] | None) -> list[str]:
    result = []
    for day in days or []:
        normalized = str(day).strip().lower()[:3]
        if normalized not in WEEKDAY_TO_INDEX:
            raise ValueError(f"Invalid weekday '{day}'.")
        if normalized not in result:
            result.append(normalized)
    return result


def parse_timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("Invalid timezone.") from exc


def parse_time_of_day(value: str) -> tuple[int, int]:
    try:
        hour_text, minute_text = (value or "08:00").split(":", 1)
        hour = int(hour_text)
        minute = int(minute_text)
    except Exception as exc:
        raise ValueError("Time must be in HH:MM format.") from exc
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        raise ValueError("Time must be in HH:MM format.")
    return hour, minute


def compute_next_run_at(
    frequency: str,
    time_of_day: str,
    timezone_name: str,
    weekdays: list[str] | None = None,
    day_of_month: int | None = None,
    from_dt: datetime | None = None,
) -> datetime:
    frequency = normalize_frequency(frequency)
    weekdays = normalize_weekdays(weekdays)
    tz = parse_timezone(timezone_name)
    hour, minute = parse_time_of_day(time_of_day)
    current_utc = from_dt.astimezone(timezone.utc) if from_dt else utc_now()
    local_now = current_utc.astimezone(tz)

    def make_candidate(local_date):
        return datetime(local_date.year, local_date.month, local_date.day, hour, minute, tzinfo=tz)

    if frequency == "daily":
        candidate = make_candidate(local_now.date())
        if candidate <= local_now:
            candidate = candidate + timedelta(days=1)
        return candidate.astimezone(timezone.utc)

    if frequency in {"weekly", "custom"}:
        target_days = weekdays or [VALID_WEEKDAYS[local_now.weekday()]]
        target_indexes = {WEEKDAY_TO_INDEX[day] for day in target_days}
        for offset in range(0, 15):
            candidate_date = local_now.date() + timedelta(days=offset)
            if candidate_date.weekday() not in target_indexes:
                continue
            candidate = make_candidate(candidate_date)
            if candidate > local_now:
                return candidate.astimezone(timezone.utc)
        raise ValueError("Unable to compute next weekly run.")

    schedule_day = day_of_month or local_now.day
    schedule_day = max(1, min(31, schedule_day))
    for month_offset in range(0, 14):
        month_index = local_now.month - 1 + month_offset
        year = local_now.year + (month_index // 12)
        month = (month_index % 12) + 1
        days_in_month = calendar.monthrange(year, month)[1]
        candidate_day = min(schedule_day, days_in_month)
        candidate = datetime(year, month, candidate_day, hour, minute, tzinfo=tz)
        if candidate > local_now:
            return candidate.astimezone(timezone.utc)
    raise ValueError("Unable to compute next monthly run.")


def apply_schedule_payload(schedule: ScanSchedule, payload: dict):
    now = utc_now()
    frequency = normalize_frequency(payload.get("frequency"))
    weekdays = normalize_weekdays(payload.get("weekdays"))
    timezone_name = payload.get("timezone") or "UTC"
    parse_timezone(timezone_name)
    time_of_day = payload.get("time_of_day") or "08:00"
    parse_time_of_day(time_of_day)

    if frequency in {"weekly", "custom"} and not weekdays:
        weekdays = [VALID_WEEKDAYS[now.astimezone(parse_timezone(timezone_name)).weekday()]]

    day_of_month = payload.get("day_of_month")
    if frequency == "monthly":
        local_now = now.astimezone(parse_timezone(timezone_name))
        day_of_month = int(day_of_month or local_now.day)
    else:
        day_of_month = None

    schedule.frequency = frequency
    schedule.time_of_day = time_of_day
    schedule.timezone = timezone_name
    schedule.weekdays = weekdays
    schedule.day_of_month = day_of_month
    schedule.is_active = bool(payload.get("is_active", True))
    schedule.updated_at = now
    schedule.next_run_at = compute_next_run_at(
        frequency=frequency,
        time_of_day=time_of_day,
        timezone_name=timezone_name,
        weekdays=weekdays,
        day_of_month=day_of_month,
        from_dt=now,
    ) if schedule.is_active else None
    return schedule


def serialize_schedule(schedule: ScanSchedule | None) -> dict | None:
    if not schedule:
        return None
    return {
        "id": schedule.id,
        "tenant_id": schedule.tenant_id,
        "frequency": schedule.frequency,
        "time_of_day": schedule.time_of_day,
        "timezone": schedule.timezone,
        "weekdays": schedule.weekdays or [],
        "day_of_month": schedule.day_of_month,
        "is_active": schedule.is_active,
        "last_run_at": schedule.last_run_at,
        "next_run_at": schedule.next_run_at,
        "created_at": schedule.created_at,
        "updated_at": schedule.updated_at,
    }


async def process_due_scan_schedules():
    db = SessionLocal()
    try:
        now = utc_now()
        due_schedules = (
            db.query(ScanSchedule)
            .filter(ScanSchedule.is_active == True)
            .filter(ScanSchedule.next_run_at.isnot(None))
            .filter(ScanSchedule.next_run_at <= now)
            .all()
        )

        for schedule in due_schedules:
            tenant = db.query(Tenant).filter(Tenant.id == schedule.tenant_id, Tenant.is_active == True).first()
            if not tenant:
                schedule.is_active = False
                schedule.next_run_at = None
                continue

            active_scan = (
                db.query(Scan)
                .filter(Scan.tenant_id == tenant.id)
                .filter(Scan.status.in_([ScanStatus.pending, ScanStatus.running]))
                .first()
            )

            schedule.next_run_at = compute_next_run_at(
                frequency=schedule.frequency,
                time_of_day=schedule.time_of_day,
                timezone_name=schedule.timezone,
                weekdays=schedule.weekdays or [],
                day_of_month=schedule.day_of_month,
                from_dt=now + timedelta(seconds=1),
            )

            if active_scan:
                continue

            scan = create_pending_scan(db, tenant.id)
            schedule.last_run_at = now
            db.commit()
            asyncio.create_task(run_scan_task(scan.id, tenant.id))

        db.commit()
    finally:
        db.close()


async def scan_schedule_loop(poll_interval_seconds: int = 30):
    while True:
        try:
            await process_due_scan_schedules()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[scan_scheduler] Poll failed: {exc}", flush=True)
        await asyncio.sleep(poll_interval_seconds)
