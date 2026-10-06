# EthioSec Scanner - Architecture Overview

EthioSec Scanner is built as a single-process web application where FastAPI serves both the JSON REST API and the static frontend assets.

## Architectural Layers

1. **Frontend Layer (`frontend/`)**:
   - Plain HTML5, CSS3, and vanilla JavaScript (no build step, no frontend frameworks).
   - Shared client utilities: `api.js` for authenticated API calls, `auth.js` for session validation and route guards, and `config.js` for endpoint discovery.
   - Served directly by FastAPI as static files.

2. **API & Routing Layer (`backend/app/routers/`)**:
   - Built on FastAPI with standard synchronous route functions (`def`) executed within FastAPI's thread pool.
   - Pydantic v2 schemas (`backend/app/schemas/`) strictly validate incoming request bodies and serialize outgoing responses.
   - Route authentication enforced via FastAPI dependencies (`Depends(get_current_user)`).

3. **Core Services & Utilities (`backend/app/core/`, `backend/app/services/`)**:
   - Application configuration managed through `pydantic-settings`.
   - Direct `bcrypt` password hashing and `PyJWT` token issuance/verification.
   - Dedicated ownership verification service (DNS TXT, meta tag, HTTP challenge).
   - Dedicated report generation service and an isolated placeholder for the future AI assistant.

4. **Scanner Engine (`backend/app/scanner/`)**:
   - Executes scans inside background threads within the server process.
   - Enforces SSRF protection and DNS-rebinding defenses via pinned IP connections.
   - Coordinates crawling and runs 11 non-destructive vulnerability check modules.
   - Updates live execution progress (`module_progress`) in PostgreSQL.

5. **Data Layer (`backend/app/models/`, `database/`)**:
   - Local PostgreSQL database managed through SQLAlchemy 2 ORM and Alembic migrations.
   - Single vocabulary authority (`backend/app/utils/vocabulary.py`) enforcing data integrity with SQL `CHECK` constraints.
