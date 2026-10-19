from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router as scan_router
from app.api.diff_endpoints import router as diff_router
from app.api.report_endpoints import router as report_router
from app.api.schedule_endpoints import router as schedule_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    import os
    import subprocess
    import sys
    import time
    import psycopg2
    from app.core.database import engine

    db_url = os.getenv("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
    if db_url:
        try:
            conn = psycopg2.connect(db_url)
            cur = conn.cursor()
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='alembic_version')"
            )
            has_alembic = cur.fetchone()[0]
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='projects')"
            )
            has_projects = cur.fetchone()[0]
            cur.close()
            conn.close()
            if not has_alembic and has_projects:
                subprocess.run(
                    [sys.executable, "-m", "alembic", "stamp", "0001"],
                    check=False,
                )
        except Exception:
            pass

    for attempt in range(1, 11):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            check=False,
        )
        if result.returncode == 0:
            break
        if attempt < 10:
            time.sleep(3)

    yield

    await engine.dispose()


app = FastAPI(
    title="Pulse SecOps API",
    description="AI-Driven Vulnerability Analysis & Remediation Pipeline",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(diff_router, prefix="/api/v1/scans", tags=["Diff"])
app.include_router(report_router, prefix="/api/v1/scans", tags=["Reports"])
app.include_router(schedule_router, prefix="/api/v1/schedules", tags=["Schedules"])


@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "Pulse API Gateway", "version": "2.0.0"}
