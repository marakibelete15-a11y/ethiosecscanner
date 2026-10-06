# EthioSec Scanner - API Contract Specification

All endpoints are prefixed with `/api` and adhere to the shared error format:
`{"error": {"code": "...", "message": "..."}}`.

Interactive OpenAPI documentation is available during development at `/docs`.

## Endpoints Summary

- **Authentication (`/api/auth`)**:
  - `POST /api/auth/register` - Create user account
  - `POST /api/auth/login` - Authenticate and retrieve JWT
  - `GET /api/auth/me` - Validate session and retrieve profile

- **Targets (`/api/targets`)**:
  - `GET /api/targets` - List verified/unverified targets for current user
  - `POST /api/targets` - Register a target URL
  - `GET /api/targets/{id}` - Retrieve target details and verification instructions
  - `DELETE /api/targets/{id}` - Delete target and cascade associated scans/findings
  - `POST /api/targets/{id}/verify` - Trigger ownership verification check

- **Scans (`/api/scans`)**:
  - `POST /api/scans` - Launch scan in background thread
  - `GET /api/scans` - List user scan history (with status and target filters)
  - `GET /api/scans/{id}` - Retrieve scan details
  - `DELETE /api/scans/{id}` - Delete scan record and its findings
  - `GET /api/scans/{id}/status` - Polling endpoint for live progress and module states
  - `POST /api/scans/{id}/cancel` - Request cancellation of active scan
  - `GET /api/scans/{id}/results` - Retrieve scan findings, summary counts, and verdict

- **Findings (`/api/findings`)**:
  - `PATCH /api/findings/{id}` - Update finding status (`open`, `confirmed`, `false_positive`, `resolved`)

- **Reports (`/api/reports`)**:
  - `GET /api/reports` - List saved reports
  - `POST /api/reports` - Generate report for completed scan
  - `GET /api/reports/{id}` - Read full report

- **Dashboard & User (`/api/dashboard`, `/api/user`)**:
  - `GET /api/dashboard/summary` - Aggregate metrics, scan count, severity distribution
  - `GET /api/user/profile` - Read user profile
  - `PUT /api/user/profile` - Update user profile
  - `PUT /api/user/password` - Change password (verifies current password)
  - `GET /api/user/settings` - Read user scan preferences
  - `PUT /api/user/settings` - Update user scan preferences
