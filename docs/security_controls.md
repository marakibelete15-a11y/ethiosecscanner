# EthioSec Scanner - Security Controls & Ethical Guardrails

## Core Security Controls

1. **Authentication & Password Security (SEC-1, SEC-2, SEC-3)**:
   - Direct `bcrypt` hashing with salt. Passwords longer than 72 bytes are rejected.
   - JWT secret strictly loaded from environment (`JWT_SECRET_KEY`); application refuses to boot in production without it.
   - Frontend route guards validate tokens against `GET /api/auth/me` on every navigation.

2. **Authorization & Tenant Isolation (SEC-4, SEC-5)**:
   - Every database query filters by the authenticated user's ID (`Depends(get_current_user)`).
   - Unauthorized access attempts to resources owned by other users return `404 Not Found` (never `403 Forbidden`) to prevent resource enumeration.
   - SQLAlchemy ORM bound parameters prevent SQL injection.

3. **SSRF & DNS-Rebinding Defenses (SEC-6)**:
   - Target URLs must resolve to publicly routable IPs. Requests to loopback (`127.0.0.0/8`), RFC 1918 private subnets, link-local, and cloud metadata (`169.254.169.254`) are strictly blocked.
   - Outbound scanner requests pin connections directly to the pre-validated IP address to eliminate DNS-rebinding race conditions. Every redirect is independently validated.

4. **Target Ownership Verification (SEC-6, SEC-13)**:
   - Scans cannot run against targets until the user proves ownership via DNS TXT record, HTML meta tag, or `/.well-known/ethiosec-challenge.txt`.
   - Clear legal and authorization warning displayed prior to initiating scans.

5. **Scanned Content Sanitization & Safe Probes (SEC-7, SEC-10, SEC-11)**:
   - All response excerpts and finding evidence are treated as untrusted and rendered solely as text in the UI (never parsed as raw HTML).
   - Sensitive headers, session tokens, and passwords in evidence snippets are masked.
   - Scanning probes are non-destructive: read-only payloads, strict rate limiting, and modest depth ceilings.

6. **Unauthenticated Access Checks (Step 3D-4)**:
   - Access-control probes request a bounded list of common paths without credentials and report only HTTP 200 responses that are neither login pages nor soft-404 content.
   - The second-user/IDOR context check is deferred. It requires stored test-user credentials and a schema change to manage those credentials safely; neither is part of this step, and no user data or schema is invented.
   - Login-form probes inspect no more than two crawled password forms and perform at most six submissions per form, using only synthetic credentials and the safe HTTP client.
   - Probes never delete or modify data, brute-force passwords, or generate load. Evidence is masked before persistence.

7. **Local Vulnerable Demo Target**:
   - The deliberately vulnerable `/admin`, `/dashboard`, and `/login` routes contain fake content and synthetic authentication behavior only. `/safe-admin` redirects to `/safe-login`; the safe login responds generically and returns HTTP 429 on its third submission.
   - The demo server must be bound to `127.0.0.1`; it is a local test fixture, not a production service.
