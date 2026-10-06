# EthioSec Scanner

EthioSec Scanner is a web vulnerability scanner designed to detect common web application security flaws while enforcing strict target ownership verification and SSRF protections.

## Project Structure
- `backend/app/`: FastAPI REST API serving JSON endpoints and static frontend pages.
  - `routers/`: Modular route handlers (`auth`, `targets`, `scans`, `findings`, `reports`, `dashboard`, `user`).
  - `models/`: SQLAlchemy 2 database models.
  - `schemas/`: Pydantic v2 request and response schemas.
  - `services/`: Business logic for verification, reports, and AI placeholder.
  - `scanner/`: Engine, safe HTTP client, crawler, and 11 vulnerability check modules.
  - `core/`: Application settings, security, dependencies, and error handlers.
  - `utils/`: Central vocabulary and allowed values.
- `database/`: Alembic migrations, database seed scripts, and exported `schema.sql`.
- `frontend/`: Plain HTML, CSS, and vanilla JavaScript (served directly by FastAPI).
- `demo_target/`: Deliberately vulnerable testbed application for safe testing.
- `docs/`: Architecture, API specification, and security controls documentation.

## Getting Started
1. Activate virtual environment:
   ```bash
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy environment configuration:
   ```bash
   cp .env.example .env
   ```
4. Run migrations:
   ```bash
   alembic upgrade head
   ```
5. Start development server:
   ```bash
   uvicorn app.main:app --reload
   ```
