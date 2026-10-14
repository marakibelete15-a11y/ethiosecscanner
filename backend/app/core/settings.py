"""
Application Settings using pydantic-settings and python-dotenv.
"""

from pathlib import Path
from dotenv import load_dotenv
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Locate root .env relative to this file: backend/app/core/settings.py -> root .env
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
ENV_FILE_PATH = ROOT_DIR / ".env"

# Load environment variables into os.environ
if ENV_FILE_PATH.exists():
    load_dotenv(dotenv_path=ENV_FILE_PATH)


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    JWT_SECRET_KEY: str = ""
    JWT_ACCESS_TOKEN_EXPIRES_MINUTES: int = 1440

    DATABASE_URL: str = "postgresql://ethiosec_user:password@localhost:5432/ethiosec_db"
    TEST_DATABASE_URL: str = "postgresql://ethiosec_user:password@localhost:5432/ethiosec_test_db"

    CORS_ORIGINS: str = ""
    ALLOW_LOCAL_TARGETS: bool = False

    SCANNER_MAX_CONCURRENT_REQUESTS: int = 5
    SCANNER_REQUEST_TIMEOUT_SECONDS: int = 10

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE_PATH) if ENV_FILE_PATH.exists() else ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret_key(cls, v: str) -> str:
        if (
            not v
            or v == "replace-with-a-strong-jwt-secret-in-production"
            or len(v) < 32
            or len(set(v)) < 16
        ):
            raise ValueError(
                "JWT_SECRET_KEY must be at least 32 characters and contain at least 16 distinct characters."
            )
        return v

    @model_validator(mode="after")
    def validate_production_settings(self):
        if self.ENVIRONMENT == "production" and self.ALLOW_LOCAL_TARGETS:
            raise ValueError("ALLOW_LOCAL_TARGETS must be false in production.")
        return self

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
