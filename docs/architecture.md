# EthioSec Scanner - Architecture & Mapping

## Old to New File Mapping

| Old Path (`/home/maraki/Ethiosec scanner/EthioSec-Scanner/`) | New Path (`/home/maraki/ethiosecscanner/`) | Purpose & Rationale |
|-------------------------------------------------------------|-------------------------------------------|---------------------|
| `backend/main.py`, `backend/routers.py` | `backend/app/__init__.py`, `backend/app/blueprints/*` | Migrated from FastAPI monolithic file to Flask Application Factory with modular blueprints (`auth`, `targets`, `scans`, `findings`, `reports`). |
| `backend/models.py` | `backend/app/models/*.py` | Decomposed into single-responsibility models (`user.py`, `target.py`, `scan.py`, `finding.py`, `report.py`) with PostgreSQL VARCHAR + CHECK constraints. |
| `backend/database.py` | `backend/app/extensions.py`, `backend/app/config.py` | Flask-SQLAlchemy and Flask-Migrate initialized in extensions, DB URL loaded from `.env`. |
| `backend/security.py` | `backend/app/services/auth_service.py` | Replaces `passlib` with direct `bcrypt` hashing and standard `PyJWT`. |
| `backend/scanner/engine.py` | `backend/app/scanner/engine.py` | Central scanning engine orchestrating crawl and checks. |
| `backend/scanner/safety.py`, `backend/scanner/http_client.py` | `backend/app/scanner/safety.py`, `backend/app/scanner/http_client.py` | Dedicated SSRF and DNS-rebinding prevention layer. |
| `backend/scanner/checks/sqli.py` | `backend/app/scanner/modules/sqli.py` | SQL injection detection module. |
| `backend/scanner/checks/xss.py` | `backend/app/scanner/modules/xss.py` | Cross-site scripting detection module. |
| `backend/scanner/checks/headers.py` | `backend/app/scanner/modules/headers.py` | Security headers check module. |
| `backend/scanner/checks/cookies.py` | `backend/app/scanner/modules/cookies.py` | Cookie security attributes check module. |
| `backend/scanner/checks/cors.py` | `backend/app/scanner/modules/cors.py` | CORS policy validation module. |
| `backend/scanner/checks/http_methods.py` | `backend/app/scanner/modules/http_methods.py` | Dangerous HTTP methods check module. |
| `backend/scanner/checks/https.py` | `backend/app/scanner/modules/https.py` | TLS/HTTPS configuration check module. |
| `backend/scanner/checks/info_disclosure.py` | `backend/app/scanner/modules/info_disclosure.py` | Sensitive information disclosure check module. |
| `backend/scanner/checks/exposed_files.py` | `backend/app/scanner/modules/exposed_files.py` | Exposed sensitive files/directories check module. |
| `backend/scanner/checks/access_control.py` | `backend/app/scanner/modules/access_control.py` | Broken access control / IDOR check module. |
| `backend/scanner/checks/auth.py` | `backend/app/scanner/modules/auth_checks.py` | Authentication endpoint check module. |
| `backend/ai/` | `backend/app/services/ai_placeholder/` | Explicitly marked OUT OF SCOPE for current phase. |
| `backend/vulnerable_app.py` | `demo_target/` | Standalone vulnerable testbed application for safe local scanner testing. |
| `database/migrations/*.sql` | `database/migrations/`, `backend/app/models/` | Replaces manual Supabase-specific SQL with Flask-Migrate (Alembic) migrations generated from SQLAlchemy models. |
| `ETHIOSEC SCANNER 2/index.html` | `frontend/pages/index.html` | Cleaned landing page. |
| `ETHIOSEC SCANNER 2/features.html`, `contact.html` | `frontend/pages/features.html`, `contact.html` | Informational public pages. |
| `ETHIOSEC SCANNER 2/login.html`, `loginjava.js`, `logistyle.css` | `frontend/pages/login.html`, `frontend/js/auth.js`, `frontend/css/auth.css` | Replaces ad-hoc naming and inline scripts with shared auth module. |
| `ETHIOSEC SCANNER 2/signup.html`, `signupjava.js`, `signupstyle.css` | `frontend/pages/signup.html`, `frontend/js/auth.js`, `frontend/css/auth.css` | Unified user registration interface and styles. |
| `ETHIOSEC SCANNER 2/dashboardfinal.html`, `.js`, `.css` | `frontend/pages/dashboard.html`, `frontend/js/dashboard.js`, `frontend/css/dashboard.css` | Standardized naming; removed localStorage-only route guards. |
| `ETHIOSEC SCANNER 2/scanfinal.html`, `.js`, `.css` | `frontend/pages/new_scan.html`, `frontend/js/new_scan.js`, `frontend/css/scan.css` | Clean scan setup with mandatory target ownership check. |
| `ETHIOSEC SCANNER 2/livescan.html`, `livejava.js`, `livestyle.css` | `frontend/pages/live_scan.html`, `frontend/js/live_scan.js`, `frontend/css/scan.css` | Live scan progress and status streaming. |
| `ETHIOSEC SCANNER 2/results.html`, `resultsjava.js`, `resultsstyle.css` | `frontend/pages/results.html`, `frontend/js/results.js`, `frontend/css/results.css` | Finding details and severity breakdown with Critical support. |
| `ETHIOSEC SCANNER 2/scan_history.html`, `scan_historyjava.js`, `scan_historystyle.css` | `frontend/pages/history.html`, `frontend/js/history.js`, `frontend/css/dashboard.css` | Historical scan audit records. |
| `ETHIOSEC SCANNER 2/reports.html`, `reportjava.js`, `reportstyle.css` | `frontend/pages/reports.html`, `frontend/js/reports.js`, `frontend/css/reports.css` | Report export (PDF/HTML/JSON). |
| `ETHIOSEC SCANNER 2/settings.html`, `settingsjava.js`, `settingsstyle.css` | `frontend/pages/settings.html`, `frontend/js/settings.js`, `frontend/css/dashboard.css` | User profile & configuration settings. |
| `ETHIOSEC SCANNER 2/assistant.html` | `frontend/pages/ai_assistant.html` | Marked OUT OF SCOPE for now. |
| `ETHIOSEC SCANNER 2/mockapi.js` | *Removed* | Completely eliminated mock API in favor of genuine Flask REST endpoints. |
| N/A (New requirement) | `frontend/pages/target_verify.html`, `frontend/js/target_verify.js` | Dedicated workflow to verify target ownership (DNS TXT, meta tag, well-known file). |
| N/A (New requirement) | `frontend/js/config.js` | Single source of truth for API base URL (no hardcoded URLs). |
| N/A (New requirement) | `frontend/js/api.js` | Centralized authenticated fetch wrapper with automatic 401 handling. |
