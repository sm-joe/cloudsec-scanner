"""Transactional platform storage. PostgreSQL is recommended; SQLite for local development."""
from datetime import datetime, UTC
from uuid import uuid4

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, MetaData, String, Table, Text, create_engine, event, select, update
from sqlalchemy.engine import Engine

metadata = MetaData()
projects = Table(
    "projects", metadata,
    Column("id", String(36), primary_key=True),
    Column("owner", String(128), nullable=False, index=True),
    Column("name", String(128), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
scans = Table(
    "scans", metadata,
    Column("id", String(36), primary_key=True),
    Column("project_id", ForeignKey("projects.id"), nullable=False),
    Column("idempotency_key", String(128), nullable=True),
    Column("target", String(512), nullable=False),
    Column("status", String(32), nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("started_at", DateTime(timezone=True)),
    Column("finished_at", DateTime(timezone=True)),
    Column("complete", Boolean, nullable=False, default=False),
    Column("report", JSON),
    Column("error", Text),
)
Index("ix_scan_queue", scans.c.status, scans.c.created_at)
Index("uq_scan_idempotency", scans.c.project_id, scans.c.idempotency_key, unique=True)


def now():
    return datetime.now(UTC)


def identifier():
    return str(uuid4())


def initialize(url: str) -> Engine:
    engine = create_engine(url, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
    metadata.create_all(engine)
    return engine


def owned_project(connection, project_id, owner):
    return connection.execute(select(projects).where(projects.c.id == project_id, projects.c.owner == owner)).mappings().first()


def owned_scan(connection, scan_id, owner):
    return connection.execute(select(scans).join(projects, projects.c.id == scans.c.project_id).where(scans.c.id == scan_id, projects.c.owner == owner)).mappings().first()


def claim_scan(engine):
    with engine.begin() as conn:
        query = select(scans).where(scans.c.status == "QUEUED").order_by(scans.c.created_at, scans.c.id).limit(1)
        if engine.dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        row = conn.execute(query).mappings().first()
        if row is None:
            return None
        claimed = conn.execute(update(scans).where(scans.c.id == row["id"], scans.c.status == "QUEUED").values(status="RUNNING", started_at=now(), attempts=scans.c.attempts + 1))
        if claimed.rowcount != 1:
            return None
        owner = conn.execute(select(projects.c.owner).where(projects.c.id == row["project_id"])).scalar_one()
        return {**row, "owner": owner}


def finish_scan(engine, scan_id, report=None, error=None):
    complete = report is not None and report.get("coverage_complete") is True and not report.get("errors")
    with engine.begin() as conn:
        conn.execute(update(scans).where(scans.c.id == scan_id, scans.c.status == "RUNNING").values(status="SUCCEEDED" if complete else "FAILED", complete=complete, report=report, error=error or (None if complete else "scan incomplete"), finished_at=now()))
