"""Versioned API foundation. All project resources are scoped to the authenticated principal."""
import os
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.exc import IntegrityError

from cloudsec_scanner.platform.security import authenticate, load_tokens, resolve_target
from cloudsec_scanner.platform.store import initialize, identifier, now, owned_project, owned_scan, projects, scans


Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Target = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class ProjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Name


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: Target


def create_app(database_url=None, workspace=None, tokens=None):
    root = Path(workspace or os.environ.get("CLOUDSEC_WORKSPACE", "./workspace")).resolve()
    if not root.is_dir():
        raise ValueError("platform workspace must exist")
    principals = load_tokens(tokens if tokens is not None else os.environ.get("CLOUDSEC_API_TOKENS", "{}"))
    engine = initialize(database_url or os.environ.get("CLOUDSEC_DATABASE_URL", "sqlite:///cloudsec-platform.db"))
    app = FastAPI(title="CloudSec Scanner Platform", version="0.1.0")
    app.state.engine = engine
    bearer = HTTPBearer(auto_error=False)

    def owner(credential: HTTPAuthorizationCredentials | None = Depends(bearer)):
        principal = authenticate(principals, credential.credentials if credential else None)
        if principal is None:
            raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})
        return principal

    @app.get("/health/live")
    def live():
        return {"status": "ok"}

    @app.get("/health/ready")
    def ready():
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            raise HTTPException(503, "database unavailable") from None
        return {"status": "ok"}

    @app.post("/api/v1/projects", status_code=201)
    def create_project(request: ProjectRequest, principal: str = Depends(owner)):
        row = {"id": identifier(), "owner": principal, "name": request.name, "created_at": now()}
        with engine.begin() as conn:
            conn.execute(insert(projects).values(**row))
        return row

    @app.get("/api/v1/projects")
    def list_projects(principal: str = Depends(owner), limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        with engine.connect() as conn:
            return [dict(row) for row in conn.execute(select(projects).where(projects.c.owner == principal).order_by(projects.c.created_at.desc(), projects.c.id).limit(limit).offset(offset)).mappings()]

    @app.post("/api/v1/projects/{project_id}/scans", status_code=202)
    def enqueue(project_id: str, request: ScanRequest, principal: str = Depends(owner), idempotency_key: Annotated[str | None, Header(max_length=128)] = None):
        with engine.connect() as conn:
            if owned_project(conn, project_id, principal) is None:
                raise HTTPException(404, "project not found")
        try:
            target = resolve_target(root / principal, request.target)
        except (ValueError, OSError):
            raise HTTPException(400, "invalid workspace target") from None
        relative = target.relative_to(root / principal).as_posix()
        if relative == ".":
            raise HTTPException(400, "select an explicit target")
        row = {"id": identifier(), "project_id": project_id, "target": relative, "idempotency_key": idempotency_key, "status": "QUEUED", "created_at": now(), "complete": False, "attempts": 0}
        try:
            with engine.begin() as conn:
                conn.execute(insert(scans).values(**row))
        except IntegrityError:
            if not idempotency_key:
                raise
            with engine.connect() as conn:
                existing = conn.execute(select(scans).where(scans.c.project_id == project_id, scans.c.idempotency_key == idempotency_key)).mappings().first()
                if existing is None or existing["target"] != relative:
                    raise HTTPException(409, "idempotency key conflict") from None
                return {key: value for key, value in existing.items() if key != "report"}
        return row

    @app.get("/api/v1/projects/{project_id}/scans")
    def list_scans(project_id: str, principal: str = Depends(owner), limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        with engine.connect() as conn:
            if owned_project(conn, project_id, principal) is None:
                raise HTTPException(404, "project not found")
            rows = conn.execute(select(scans).where(scans.c.project_id == project_id).order_by(scans.c.created_at.desc(), scans.c.id).limit(limit).offset(offset)).mappings()
            return [{key: value for key, value in row.items() if key != "report"} for row in rows]

    @app.get("/api/v1/scans/{scan_id}")
    def get_scan(scan_id: str, principal: str = Depends(owner)):
        with engine.connect() as conn:
            row = owned_scan(conn, scan_id, principal)
            if row is None:
                raise HTTPException(404, "scan not found")
            return {key: value for key, value in row.items() if key != "report"}

    @app.get("/api/v1/scans/{scan_id}/report")
    def get_report(scan_id: str, principal: str = Depends(owner)):
        with engine.connect() as conn:
            row = owned_scan(conn, scan_id, principal)
            if row is None:
                raise HTTPException(404, "scan not found")
            if row["report"] is None:
                raise HTTPException(409, "report not available")
            return row["report"]

    @app.post("/api/v1/scans/{scan_id}/cancel")
    def cancel(scan_id: str, principal: str = Depends(owner)):
        with engine.begin() as conn:
            row = owned_scan(conn, scan_id, principal)
            if row is None:
                raise HTTPException(404, "scan not found")
            outcome = conn.execute(update(scans).where(scans.c.id == scan_id, scans.c.status == "QUEUED").values(status="CANCELLED", finished_at=now()))
            if outcome.rowcount != 1:
                raise HTTPException(409, "only queued scans can be cancelled")
        return {"id": scan_id, "status": "CANCELLED"}

    @app.get("/api/v1/dashboard")
    def dashboard(principal: str = Depends(owner)):
        with engine.connect() as conn:
            count = conn.execute(select(func.count()).select_from(projects).where(projects.c.owner == principal)).scalar_one()
            rows = conn.execute(select(scans.c.status, func.count()).join(projects, scans.c.project_id == projects.c.id).where(projects.c.owner == principal).group_by(scans.c.status)).all()
        return {"projects": count, "scans_by_status": dict(rows)}

    return app
