"""
EthioSec Scanner - FastAPI Application Entry Point.

Serves the REST API and static frontend assets (SRS Section 2.1, 3.1).
"""

import datetime
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, get_db
from app.core.error_handlers import register_error_handlers
from app.core.security import get_jwt_secret
from app.core.settings import settings
from app.models import Scan
from app.scanner.masking import mask_exception_detail
from app.schemas.common import HealthResponse

logger = logging.getLogger("ethiosec.app")


def _documentation_urls(environment: str) -> dict[str, str | None]:
    if environment == "production":
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json",
    }


def _configured_cors_origins(origins_setting: str) -> list[str]:
    return [origin.strip() for origin in origins_setting.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Enforces AUTH-6, SEC-2: Validates JWT_SECRET_KEY on startup across all environments.
    Enforces SCN-10: Scans left in running state at server start are marked failed.
    """
    # Enforce startup validation of JWT secret key
    get_jwt_secret()

    db: Session = SessionLocal()
    try:
        updated_count = (
            db.query(Scan)
            .filter(Scan.status == "running")
            .update(
                {
                    Scan.status: "failed",
                    Scan.error_message: "Scan marked failed due to server restart",
                    Scan.finished_at: datetime.datetime.now(datetime.timezone.utc),
                },
                synchronize_session=False,
            )
        )
        if updated_count > 0:
            db.commit()
            logger.info("Reset %d orphan running scan(s) to 'failed' on startup.", updated_count)
    except Exception as exc:
        db.rollback()
        logger.warning("Could not reset orphan scans on startup: %s", mask_exception_detail(exc))
    finally:
        db.close()

    yield


# Initialize FastAPI application
app = FastAPI(
    title="EthioSec Scanner API",
    description="Web vulnerability scanner API with ownership verification and SSRF protection",
    version="1.0.0",
    **_documentation_urls(settings.ENVIRONMENT),
    lifespan=lifespan,
)

# CORS Configuration
origins = _configured_cors_origins(settings.CORS_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register standardized error handlers (SRS Section 7)
register_error_handlers(app)

# Include API Routers
from app.routers import auth as auth_router
from app.routers import dashboard as dashboard_router
from app.routers import findings as findings_router
from app.routers import reports as reports_router
from app.routers import scans as scans_router
from app.routers import targets as targets_router
from app.routers import user as user_router

app.include_router(auth_router.router)
app.include_router(scans_router.router)
app.include_router(findings_router.router)
app.include_router(dashboard_router.router)
app.include_router(reports_router.router)
app.include_router(user_router.router)
app.include_router(targets_router.router)


# Core Health Check Endpoint (No authentication required)
@app.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check(db: Session = Depends(get_db)):
    """Service health and database connectivity check."""
    db.execute(text("SELECT 1"))
    return {"status": "healthy", "database": "connected"}


# Frontend Static Files & Pages Mount (SRS Section 2.1, 3.1)
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    pages_dir = frontend_dir / "pages"
    if (pages_dir / "index.html").exists():

        @app.get("/", include_in_schema=False)
        def read_root():
            return FileResponse(pages_dir / "index.html")
