"""
Pytest Fixtures for EthioSec Scanner Database Tests.

Enforces strict separation: all tests run against TEST_DATABASE_URL (ethiosec_test)
and will refuse to run against the production or development database.
"""

import os
import socket
import sys
import threading
import time
import pytest
from contextlib import contextmanager
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

# Set explicit test JWT secret before importing settings (SRS AUTH-6, SEC-2)
os.environ["JWT_SECRET_KEY"] = "test-secret-key-at-least-32-characters-long-for-pytest-safety-verification-token"

# Ensure backend directory is in sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)
repository_path = os.path.abspath(os.path.join(backend_path, ".."))
if repository_path not in sys.path:
    sys.path.insert(0, repository_path)

from app.core.settings import settings
settings.JWT_SECRET_KEY = "test-secret-key-at-least-32-characters-long-for-pytest-safety-verification-token"
from app.models import Base


@pytest.fixture(autouse=True)
def disable_polite_delay_in_tests(monkeypatch):
    """Keep production pacing but avoid artificial sleeps in the test suite."""
    from app.scanner import engine

    monkeypatch.setattr(engine, "POLITE_DELAY_SECONDS", 0)


@contextmanager
def _serve_local_app(test_app, server_header=True):
    import uvicorn

    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            test_app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            server_header=server_header,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("Local test target failed to start.")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def test_engine():
    """Create test engine connected strictly to TEST_DATABASE_URL."""
    test_url = settings.sync_test_database_url
    assert "test" in test_url, f"Safety check failed: TEST_DATABASE_URL must point to a test DB, got: {test_url}"

    engine = create_engine(test_url, pool_pre_ping=True)

    with engine.connect() as conn:
        current_db = conn.execute(text("SELECT current_database();")).scalar()
        assert current_db == "ethiosec_test_db", f"Safety check failed: connected to '{current_db}' instead of 'ethiosec_test_db'!"

    # Prepare clean tables for the test session
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield engine

    # Teardown
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(test_engine):
    """Provide a transactional database session per test function."""
    connection = test_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()

from fastapi.testclient import TestClient
from app.main import app
from app.core.database import get_db


@pytest.fixture(scope="function")
def client(db_session):
    """Provide a TestClient with overridden get_db dependency."""
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def demo_target_url(monkeypatch):
    """Run the demo target in a thread on an available loopback port."""
    from demo_target.main import app as demo_app

    monkeypatch.setattr(settings, "ALLOW_LOCAL_TARGETS", True)
    with _serve_local_app(demo_app) as url:
        yield url


@pytest.fixture
def clean_target_url(monkeypatch):
    """Run a benign local app with no risky methods, version banners, or CORS policy."""
    clean_app = FastAPI()

    @clean_app.middleware("http")
    async def add_clean_security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=()"
        return response

    @clean_app.get("/")
    def clean_home():
        return HTMLResponse(
            '<html><body><a href="/safe-search?q=demo">Search</a>'
            '<a href="/safe-product?id=1">Product</a>'
            '<form action="/safe-search" method="get"><input name="q"></form>'
            '<form action="/post-form" method="post"><input name="value"></form>'
            "</body></html>"
        )

    @clean_app.get("/safe-search", response_class=HTMLResponse)
    def clean_search(q: str = ""):
        from html import escape

        return f"<html><body>{escape(q, quote=True)}</body></html>"

    @clean_app.get("/safe-product")
    def clean_product(item_id: str = "1"):
        return f"Product {item_id}"

    @clean_app.options("/")
    def clean_options():
        return Response(status_code=200, headers={"Allow": "GET, HEAD, OPTIONS"})

    monkeypatch.setattr(settings, "ALLOW_LOCAL_TARGETS", True)
    with _serve_local_app(clean_app, server_header=False) as url:
        yield url
