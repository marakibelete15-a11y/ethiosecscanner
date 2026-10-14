# EthioSec Scanner

EthioSec Scanner is a FastAPI and PostgreSQL web security scanner with target ownership verification, SSRF protections, scan results, findings, reports, and a deliberately vulnerable local demo target.

## Requirements

- Python 3.14 (pinned dependencies are tested with Python 3.14).
- PostgreSQL 14 or newer, running locally or at a reachable development address.
- Git and a shell.

## Fresh Clone Setup

Run commands from the repository root unless noted.

1. Install and start PostgreSQL. Open a PostgreSQL shell as an administrator and create an application role plus separate development and test databases:

   ```sql
   CREATE USER ethiosec_user WITH PASSWORD 'replace-with-a-local-password';
   CREATE DATABASE ethiosec_db OWNER ethiosec_user;
   CREATE DATABASE ethiosec_test_db OWNER ethiosec_user;
   ```

   For example, where `psql` is available:

   ```bash
   psql -U postgres
   ```

2. Copy the environment template and edit `.env`. Replace the database password and generate a unique JWT secret of at least 32 characters and 16 distinct characters. Keep `.env` local; do not commit it.

   ```bash
   cp .env.example .env
   ```

   Set at least these values:

   ```dotenv
   ENVIRONMENT=development
   JWT_SECRET_KEY=<unique-secret-at-least-32-characters>
   DATABASE_URL=postgresql://ethiosec_user:your-local-password@localhost:5432/ethiosec_db
   TEST_DATABASE_URL=postgresql://ethiosec_user:your-local-password@localhost:5432/ethiosec_test_db
   CORS_ORIGINS=
   ALLOW_LOCAL_TARGETS=false
   ```

3. Create and activate the virtual environment, then install pinned requirements:

   ```bash
   python3.14 -m venv venv
   source venv/bin/activate
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Apply database migrations:

   ```bash
   venv/bin/alembic upgrade head
   ```

5. For development only, optionally seed the demo account, target, completed scan, findings, and report. The idempotent script removes/recreates its fixed demo account on each run. Credentials: `demo@ethiosec.local` / `EthioSec2026!`. Do not seed production.

   ```bash
   venv/bin/python database/seed/seed.py
   ```

6. Run all backend tests. They use `TEST_DATABASE_URL` and create/drop tables in the database named `ethiosec_test_db`; never point it at production.

   ```bash
   venv/bin/pytest backend/tests/ -q
   ```

7. Start the API in one terminal:

   ```bash
   cd backend
   ../venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

   API: `http://127.0.0.1:8000`. Development OpenAPI docs: `http://127.0.0.1:8000/docs`.

8. Start the demo target in a second terminal from the repository root:

   ```bash
   venv/bin/uvicorn demo_target.main:app --host 127.0.0.1 --port 5000
   ```

   Demo target: `http://127.0.0.1:5000`. It is intentionally vulnerable and must never be exposed to untrusted networks. To scan it locally, set `ALLOW_LOCAL_TARGETS=true` only outside production; production settings reject that value.

## Configuration and Documentation

See [`.env.example`](.env.example) for all settings. `CORS_ORIGINS` is an empty comma-separated allowlist by default because the frontend is served from the API origin. Production disables `/docs`, `/redoc`, and `/openapi.json`.

- [API specification](docs/api_spec.md)
- [Security controls and limitations](docs/security_controls.md)
- [Architecture](docs/architecture.md)
- [Project progress](docs/PROGRESS.md)
