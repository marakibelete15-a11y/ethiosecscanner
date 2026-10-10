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
    import uvicorn
    from demo_target.main import app as demo_app

    monkeypatch.setattr(settings, "ALLOW_LOCAL_TARGETS", True)
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]

    server = uvicorn.Server(
        uvicorn.Config(demo_app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, "Demo target did not start before the test timeout."
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
