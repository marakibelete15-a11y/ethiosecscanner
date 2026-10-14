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
| SEC-7 | Scanner response content is treated as untrusted; evidence should be rendered as text. | Partially verified. Frontend auth/API scripts remain placeholders; end-to-end rendering safety is not established. |
| SEC-8 | [main.py](../backend/app/main.py) parses comma-separated `CORS_ORIGINS`; empty default means no cross-origin origins are allowed. | Implemented fail-closed; no wildcard fallback. |
| SEC-9 | [`.gitignore`](../.gitignore) excludes `.env`, keys, local databases, and virtualenvs. Current Git index audit found only `.env.example` among those patterns. | Verified for current index, not a guarantee against future commits. |
| SEC-10 | Scanner modules use bounded, mostly read-only probes, depth/request ceilings, and pacing; login-form probes use synthetic credentials. | Weak by nature: up to six synthetic submissions per form may still trigger target logging, lockouts, or state changes. Scan only with authorization. |
| SEC-11 | [masking.py](../backend/app/scanner/masking.py) sanitizes evidence before storage in [engine.py](../backend/app/scanner/engine.py). [error_handlers.py](../backend/app/core/error_handlers.py) returns generic 500 text to clients. | Stored evidence is masked. Logging is weak: scanner, verification, and catch-all handlers log exception strings/tracebacks without sanitization. Client responses do not contain those details. |
| SEC-12 | No SEC-12 definition is available in the supplied project context. | NOT SPECIFIED; no behavior is attributed without the SRS. |
| SEC-13 | Target verification supports DNS TXT, HTML meta tag, or HTTP challenge file in [verification_service.py](../backend/app/services/verification_service.py); scans require verification. | Verification gate implemented. A separate enforced legal-consent workflow cannot be confirmed from the missing SRS. |

## Known Limitations

- Second-user-context access-control/IDOR scanning is deferred; no second-user credentials are stored for probes.
- Cancellation uses process-local in-memory events and cooperative checks. It is not shared across workers and cannot guarantee immediate interruption of a blocking request.
- Scans run in daemon threads, not a durable queue. Startup marks running scans failed; queued scans are not resumed.
- The API login endpoint has no rate limiter. Scanner `auth_checks` examines the target’s login behavior and does not protect this application’s own login.
- Password changes do not revoke existing JWTs; tokens persist until expiration.
- Exception strings and tracebacks may enter logs without masking. Keep logs access-controlled and do not place secrets in exception text.
- `auth_checks` sends bounded synthetic form submissions and may cause side effects on the authorized target.
- Report `pdf` and `html` formats are labels; the API returns structured JSON. PDF export is expected to use the browser print dialog.
- Notification settings are stored preferences only; email delivery is not implemented.
- Frontend `auth.js` and `api.js` remain placeholders; no implemented localStorage/sessionStorage token flow was found.
- `ALLOW_LOCAL_TARGETS` permits loopback/private targets outside production for development/tests. Metadata and link-local remain blocked.
- No production deployment topology, distributed worker controls, or operations monitoring are documented in this build.
- The SRS is absent; requirements beyond the explicit project instructions remain unverified.

## Production and Demo Notes

- Production startup rejects `ALLOW_LOCAL_TARGETS=true` and weak/predictable JWT secrets.
- Production disables `/docs`, `/redoc`, and `/openapi.json`.
- Empty `CORS_ORIGINS` permits no cross-origin browser origins. Set explicit comma-separated origins only for a separate frontend origin.
- Bind the intentionally vulnerable demo target to `127.0.0.1`; never expose it to an untrusted network.
