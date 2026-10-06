"""
Pytest Fixtures for EthioSec Scanner Database Tests.

Enforces strict separation: all tests run against TEST_DATABASE_URL (ethiosec_test)
and will refuse to run against the production or development database.
"""

import os
import sys
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

# Ensure backend directory is in sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.core.settings import settings
from app.models import Base


@pytest.fixture(scope="session")
def test_engine():
    """Create test engine connected strictly to TEST_DATABASE_URL."""
    test_url = settings.sync_test_database_url
    assert "test" in test_url, f"Safety check failed: TEST_DATABASE_URL must point to a test DB, got: {test_url}"

    engine = create_engine(test_url, pool_pre_ping=True)

    with engine.connect() as conn:
        current_db = conn.execute(text("SELECT current_database();")).scalar()
        assert current_db == "ethiosec_test", f"Safety check failed: connected to '{current_db}' instead of 'ethiosec_test'!"

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
