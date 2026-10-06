"""Application Settings using pydantic-settings."""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    SECRET_KEY: str = "replace-with-a-secure-random-secret-in-production"
    JWT_SECRET_KEY: str = "replace-with-a-strong-jwt-secret-in-production"
    JWT_ACCESS_TOKEN_EXPIRES_MINUTES: int = 1440

    DATABASE_URL: str = "postgresql+psycopg2://maraki@/ethiosec?host=/home/maraki/pgdata_local&port=5433"
    TEST_DATABASE_URL: str = "postgresql+psycopg2://maraki@/ethiosec_test?host=/home/maraki/pgdata_local&port=5433"

    CORS_ORIGINS: str = "http://127.0.0.1:8000,http://localhost:8000"
    ALLOW_LOCAL_TARGETS: bool = False

    SCANNER_MAX_CONCURRENT_REQUESTS: int = 5
    SCANNER_REQUEST_TIMEOUT_SECONDS: int = 10

    model_config = SettingsConfigDict(
        env_file=os.getenv("ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def sync_database_url(self) -> str:
        """Ensure psycopg2 driver is explicitly used for PostgreSQL sync connections."""
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url

    @property
    def sync_test_database_url(self) -> str:
        """Ensure psycopg2 driver is explicitly used for PostgreSQL test connections."""
        url = self.TEST_DATABASE_URL
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url


settings = Settings()
