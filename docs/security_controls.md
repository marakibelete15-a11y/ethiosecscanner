# Security Controls and Limitations

The referenced SRS is not present. This map records implemented behavior and known gaps without assigning unprovided requirements to SEC identifiers. Errors use `{"error":{"code":"...","message":"..."}}`; unexpected client responses are generic.

## Controls

| ID | Control and implementation | Status / boundary |
|---|---|---|
| SEC-1 | [security.py](../backend/app/core/security.py): `hash_password`, `verify_password`, and `validate_password_complexity` use bcrypt directly and reject passwords over 72 UTF-8 bytes. | Implemented. Pytest lowers bcrypt rounds only inside the test fixture; production hashing is unchanged. |
| SEC-2 | [settings.py](../backend/app/core/settings.py) validates JWT secret length/diversity; [security.py](../backend/app/core/security.py) `get_jwt_secret` enforces it at startup/use. | Implemented basic checks, not a managed secret store or formal entropy estimator. |
| SEC-3 | [dependencies.py](../backend/app/core/dependencies.py) validates Bearer JWT signature/expiry, loads the user, and rejects inactive users. | Implemented. Password change does not revoke existing tokens; they remain valid until expiration. |
| SEC-4 | Routers scope user records to `current_user.id`; tenant-owned resource lookups return 404. | Implemented across available endpoints. Profile/settings expose no user-id parameter. |
| SEC-5 | Routers/services use SQLAlchemy ORM expressions; health check uses fixed SQL text. | Implemented; no SQL is assembled from user text in audited application code. |
| SEC-6 | [safety.py](../backend/app/scanner/safety.py) blocks loopback/private except the development override and always blocks metadata/link-local/special addresses. [http_client.py](../backend/app/scanner/http_client.py) validates addresses, pins sockets, and revalidates redirects. [scans.py](../backend/app/routers/scans.py) requires an owned verified target. | Implemented. Production refuses `ALLOW_LOCAL_TARGETS=true`. |
| SEC-7 | Scanner response content is treated as untrusted; evidence and finding text are rendered strictly as text nodes or textContent. | Implemented. All dynamic data insertion uses textContent or DOM node creation; innerHTML is never used for data rendering. |
| SEC-8 | [main.py](../backend/app/main.py) parses comma-separated `CORS_ORIGINS`; [settings.py](../backend/app/core/settings.py) rejects `*` in every environment because credentialed CORS is enabled. | Implemented fail-closed; the default is empty, and wildcard origins cannot be configured. |
| SEC-9 | [`.gitignore`](../.gitignore) excludes `.env`, keys, local databases, and virtualenvs. Current Git index audit found only `.env.example` among those patterns. | Verified for current index, not a guarantee against future commits. |
| SEC-10 | Scanner modules use bounded, mostly read-only probes, depth/request ceilings, and pacing; login-form probes use synthetic credentials. | Weak by nature: up to six synthetic submissions per form may still trigger target logging, lockouts, or state changes. Scan only with authorization. |
| SEC-11 | [masking.py](../backend/app/scanner/masking.py) sanitizes stored evidence and formats masked exception details for logs; [engine.py](../backend/app/scanner/engine.py), [verification_service.py](../backend/app/services/verification_service.py), [main.py](../backend/app/main.py), and [error_handlers.py](../backend/app/core/error_handlers.py) use it for exception logs. | Cookies, Set-Cookie, Authorization, credential fields, URL query strings, and file paths are redacted before logging. Unhandled API errors return a generic 500 envelope. Scanner failures persist fixed messages and categories; raw exception text is log-only and masked. |
| SEC-12 | The vanilla-JavaScript frontend stores its Bearer token in `localStorage` for simple access from the shared API wrapper. Any XSS on the page could read and steal it. Mitigations include rendering untrusted/API text only with `textContent` or DOM nodes, no inline scripts, server-side token validation on every protected API request, and the 24-hour token lifetime. Production should prefer `HttpOnly`, `Secure`, `SameSite` cookies so JavaScript cannot read the credential. | Implemented for the current frontend. `localStorage` remains an XSS-sensitive tradeoff, not equivalent to an HttpOnly cookie. |
| SEC-13 | Target verification supports DNS TXT, HTML meta tag, or HTTP challenge file in [verification_service.py](../backend/app/services/verification_service.py); scans require verification. | Verification gate implemented. A separate enforced legal-consent workflow cannot be confirmed from the missing SRS. |

## Frontend Controls

- **Shared API and Authentication Layer**: All network communication routes exclusively through `/static/js/api.js` using relative endpoints (`/api/...`). Authentication lifecycle, token storage, and redirection are encapsulated in `/static/js/auth.js`.
- **Session Verification on Protected Pages**: Every authenticated page invokes `auth.requireAuth()` on load, which performs an active `/api/auth/me` request against the backend before revealing content. Invalid or expired tokens trigger automatic storage clearance and redirect to `login.html`.
- **Safe DOM Rendering (No `innerHTML`)**: Dynamic data from API responses, URL query parameters, and user inputs is rendered strictly via `document.createElement`, `textContent`, and safe DOM node composition. No `innerHTML` is used anywhere in frontend code.
- **No Inline Scripts or Inline Event Handlers**: HTML pages load logic exclusively through external `.js` files via `<script src="...">`. Zero inline `<script>` tags without `src` exist. Event handling is registered dynamically with `addEventListener`—no inline event attributes (`onclick`, `onload`, `onsubmit`, etc.) are permitted.
- **Strict Link Safety**: URLs rendered into hyperlinks are validated against `isSafeHttpUrl()`, strictly restricting protocols to `http:` and `https:`. Dynamic `javascript:`, `data:`, `file:`, or scheme-less protocols are rejected to prevent script execution vulnerabilities.
- **Zero Third-Party External Scripts or CDNs**: All scripts, stylesheets, and assets are hosted locally under `/static/`. No external CDNs, third-party JavaScript libraries, or external font stylesheets are loaded, preventing supply chain tampering and unauthorized third-party telemetry.
- **`localStorage` Token Storage Trade-Off**: The Bearer token is retained in `localStorage` to support client-side API requests. While vulnerable to potential token theft if an XSS vulnerability exists, this risk is mitigated by strict `textContent` rendering, absence of inline scripts, rigorous URL validation, and server-side token expiration. Production deployments should transition to `HttpOnly`, `Secure`, `SameSite` cookies.

## Known Limitations

- Second-user-context access-control/IDOR scanning is deferred; no second-user credentials are stored for probes.
- Cancellation uses a process-local in-memory flag, so it requires a single worker and cannot interrupt a blocking request immediately.
- Scans run in daemon threads, not a durable queue. Startup marks running scans failed; queued scans are not resumed.
- `auth_checks` submits made-up credentials to at most two forms and six attempts per form on verified targets; even bounded probes can trigger target-side logging or account controls.
- The JWT secret strength check is a length/diversity heuristic, not a formal entropy test; sufficiently long predictable values may pass.
- Password changes do not revoke existing JWTs; this avoids session invalidation until token expiry but leaves old tokens usable during that period.
- The application’s own login API has no rate limit; brute-force throttling is not implemented.
- Report `pdf` and `html` formats are labels; the API returns structured JSON. PDF export is expected to use the browser print dialog.
- Notification settings are stored preferences only; email delivery is not implemented.
- The frontend uses localStorage for its Bearer token; any XSS can steal it. The API wrapper validates protected sessions with `/api/auth/me` and clears browser storage on an invalid session or network failure.
- `ALLOW_LOCAL_TARGETS` permits loopback/private targets outside production for development/tests. Metadata and link-local remain blocked.
- No production deployment topology, distributed worker controls, or operations monitoring are documented in this build.
- The SRS is absent; requirements beyond the explicit project instructions remain unverified.

## Production and Demo Notes

- Production startup rejects `ALLOW_LOCAL_TARGETS=true` and weak/predictable JWT secrets.
- Production disables `/docs`, `/redoc`, and `/openapi.json`.
- Empty `CORS_ORIGINS` permits no cross-origin browser origins. Explicit comma-separated origins are supported, but `*` is rejected in every environment.
- Bind the intentionally vulnerable demo target to `127.0.0.1`; never expose it to an untrusted network.
