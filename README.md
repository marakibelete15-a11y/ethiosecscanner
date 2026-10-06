# EthioSec Scanner

EthioSec Scanner is a modular web vulnerability scanner designed to detect common web application security flaws while enforcing strict authorization, ownership verification, and SSRF protections.

## Project Structure
- `backend/`: Python Flask REST API structured with the Application Factory pattern and modular blueprints.
- `database/`: Schema migrations, SQL definitions, and seed data.
- `frontend/`: Plain HTML5, CSS3, and vanilla JavaScript (no framework overhead).
- `docs/`: Architectural specifications, API contracts, and security controls.

## Setup Instructions (Phase 1)
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
