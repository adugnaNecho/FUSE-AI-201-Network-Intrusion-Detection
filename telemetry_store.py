"""Persistent, privacy-minimizing storage for authenticated live NIDS predictions."""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import DateTime, Float, Index, Integer, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from nids_core import CLASS_NAMES, SEVERITY


class Base(DeclarativeBase):
    pass


class PredictionEvent(Base):
    __tablename__ = "live_nids_predictions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    predicted_class: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)


Index("ix_live_nids_time_class", PredictionEvent.received_at, PredictionEvent.predicted_class)
_engine = None
_engine_url = None


def _url() -> str:
    value = os.getenv("TELEMETRY_DATABASE_URL", "sqlite:///./data/telemetry.db").strip()
    if value.startswith("postgres://"):
        value = "postgresql+psycopg://" + value[len("postgres://"):]
    elif value.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value[len("postgresql://"):]
    if value.startswith("sqlite:///") and ":memory:" not in value:
        Path(value.removeprefix("sqlite:///")).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    return value


def engine():
    global _engine, _engine_url
    url = _url()
    if _engine is None or _engine_url != url:
        if _engine is not None:
            _engine.dispose()
        _engine = create_engine(url, pool_pre_ping=True,
                                connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
        _engine_url = url
    return _engine


def reset_engine_for_tests():
    global _engine, _engine_url
    if _engine is not None:
        _engine.dispose()
    _engine = _engine_url = None


def init_store():
    Base.metadata.create_all(engine())


def validate_source_id(value: str) -> str:
    value = str(value).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", value):
        raise ValueError("source_id must be 1–64 characters using letters, numbers, dot, underscore, colon, or hyphen.")
    return value


def store_predictions(predictions: list[dict], source_id: str) -> int:
    source_id = validate_source_id(source_id)
    if not predictions:
        return 0
    now = datetime.now(timezone.utc)
    events = []
    for row in predictions:
        label = row.get("predicted_class")
        confidence = float(row.get("confidence", -1))
        if label not in CLASS_NAMES or not 0 <= confidence <= 1:
            raise ValueError("Prediction event contains an invalid class or confidence.")
        events.append(PredictionEvent(received_at=now, source_id=source_id, predicted_class=label,
                                      confidence=confidence, severity=SEVERITY[label]))
    init_store()
    Session = sessionmaker(bind=engine())
    with Session() as session:
        session.add_all(events)
        session.commit()
    return len(events)


def _iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_live_stats(window_hours: int = 24) -> dict:
    if not 1 <= int(window_hours) <= 720:
        raise ValueError("window_hours must be between 1 and 720.")
    init_store()
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=int(window_hours))
    one_hour_ago = now - timedelta(hours=1)
    Session = sessionmaker(bind=engine())
    with Session() as session:
        total_all = int(session.scalar(select(func.count()).select_from(PredictionEvent)) or 0)
        total_window = int(session.scalar(select(func.count()).select_from(PredictionEvent)
                                           .where(PredictionEvent.received_at >= since)) or 0)
        last_received = session.scalar(select(func.max(PredictionEvent.received_at)))
        source_count = int(session.scalar(select(func.count(func.distinct(PredictionEvent.source_id)))
                                           .where(PredictionEvent.received_at >= since)) or 0)
        class_rows = session.execute(select(PredictionEvent.predicted_class, func.count())
                                      .where(PredictionEvent.received_at >= since)
                                      .group_by(PredictionEvent.predicted_class)).all()
        severity_rows = session.execute(select(PredictionEvent.severity, func.count())
                                         .where(PredictionEvent.received_at >= since)
                                         .group_by(PredictionEvent.severity)).all()
        recent = session.execute(select(PredictionEvent.received_at, PredictionEvent.predicted_class)
                                  .where(PredictionEvent.received_at >= one_hour_ago)
                                  .order_by(PredictionEvent.received_at.desc()).limit(20000)).all()

    classes = {name: 0 for name in CLASS_NAMES}
    classes.update({name: int(count) for name, count in class_rows})
    severities = {name: 0 for name in ("Low", "Medium", "High", "Critical")}
    severities.update({name: int(count) for name, count in severity_rows})
    start = int(one_hour_ago.timestamp())
    bucket_seconds = 300
    bucket_starts = list(range(start - start % bucket_seconds,
                               int(now.timestamp()) + bucket_seconds, bucket_seconds))
    buckets = {ts: {"timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z"),
                    **{name: 0 for name in CLASS_NAMES}} for ts in bucket_starts}
    for stamp, label in recent:
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        ts = int(stamp.timestamp())
        key = ts - ts % bucket_seconds
        if key in buckets and label in CLASS_NAMES:
            buckets[key][label] += 1
    return {
        "status": "live" if total_window else "no_live_data",
        "data_origin": "authenticated external producer submissions; source provenance is not independently verified",
        "window_hours": int(window_hours), "generated_at": _iso(now),
        "last_received_at": _iso(last_received), "total_events_window": total_window,
        "total_events_all_time": total_all, "active_sources_window": source_count,
        "class_counts": classes, "severity_counts": severities,
        "timeline_5m_last_hour": list(buckets.values()),
        "timeline_truncated": len(recent) >= 20000,
        "ground_truth_available": False, "live_accuracy_available": False,
    }
