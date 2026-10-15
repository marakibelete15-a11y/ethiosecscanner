# Project Progress

## Step 3D-1a: Audit

- Existing baseline: `venv/bin/pytest backend/tests/ -v` passed all 44 tests.
- `backend/app/scanner/scoring.py` already implements the required severity penalties, clamps the score to zero, and applies Critical-first verdict ordering; unit tests were missing.
- `backend/app/scanner/masking.py` already provides mask-before-truncate helpers, but cookie and authorization formats need broader coverage and finding persistence must enforce sanitization centrally.
- `backend/app/scanner/modules/headers.py` has six header checks and uses the safe client, but was not called by an engine and had no tests.
- The scan engine, crawler, scan schemas, and scans router were placeholders. Existing Scan/Finding fields support this step without model or database changes.
- The referenced `docs/SRS.pdf` is not present in the workspace; implementation follows the explicit requirements in the task.

Scoring and masking unit tests pass. Masking covers all Authorization header schemes, all Cookie header pairs, Set-Cookie values, token/password fields, and truncation. Focused check: `venv/bin/pytest backend/tests/test_scanner_unit.py -v` passed all 3 tests.

## Step 3D-1a: Scanner and Scan API

- Added a same-origin crawler with quick/standard/deep page limits of 5/25/100; outbound requests use `SafeHttpClient` and are separated by a polite delay.
- Added a single-module scan engine (headers only) with per-module timeout/error isolation, persisted progress telemetry, in-memory cancellation, and evidence masking immediately before each Finding insert. Findings receive the scan and target IDs from the owning Scan.
- Added authenticated `POST /api/scans`, `GET /api/scans/{id}/status`, `GET /api/scans/{id}/results`, and `POST /api/scans/{id}/cancel`. Target ownership, verification, and SSRF validation are checked before a scan is queued. Unknown modules return `422`; known, unimplemented modules return `400`.
- Results include severity counts, passed checks, module error count, score, Critical-first sorting, and FND-3 verdict priority.
- Added unit/integration tests for score boundaries, masking, verdict priority, header findings, module error isolation, progress, cancellation, target verification, tenant isolation, module validation, and result ordering.
- The demo target already sends no security headers; no change to its finished verification behavior was needed.
- Focused scan and scanner unit checks: 11 passed.

## Final Validation

- Full command: `venv/bin/pytest backend/tests/ -v`
- Result: **55 passed, 5 warnings in 51.60s**.
- Warnings: Starlette deprecation for httpx-backed TestClient; deprecated `HTTP_422_UNPROCESSABLE_ENTITY` in existing validation responses and the new unknown-module response.
- `git diff --check` passed; editor diagnostics found no errors in changed Python files.
- Next step: implement additional scanner modules one at a time. Other recognized keys intentionally return `MODULE_NOT_IMPLEMENTED`.

## Step 3D-1b: HTTPS and Cookie Modules

- Audited the prior HTTPS draft: it covered only HTTP redirection and HSTS on HTTPS; it did not check HTTPS availability or validate certificates. The cookies module was a placeholder.
- Added an opt-in `verify_tls` path to `SafeHttpClient`, preserving IP pinning, safe redirects, timeout, and response bounds. Responses now retain separate Set-Cookie header values for attribute checks.
- Implemented HTTPS availability, HTTP-to-HTTPS redirection, certificate validity/expiry verification, and HSTS checks. Every finding uses the standard finding fields and non-sensitive evidence.
- Implemented Secure, HttpOnly, and SameSite checks for each Set-Cookie header. Cookie values are never used in cookie-module finding evidence; central engine sanitization remains in place before saving all findings.
- New scans default to `headers`, `https`, and `cookies`. Other recognized modules remain rejected as not implemented.
- The demo homepage now sets a deliberately insecure cookie. Added a test fixture that starts the demo app on an available loopback port in a thread; its local-target allowance is fixture-scoped.
- Focused command `venv/bin/pytest backend/tests/test_scanner_unit.py backend/tests/test_scans.py -v`: 16 passed.

## Final Validation

- Full command: `venv/bin/pytest backend/tests/ -v`
- Result: **60 passed, 5 warnings in 94.47s**.
- Warnings: Starlette deprecation for the httpx-backed TestClient and deprecated `HTTP_422_UNPROCESSABLE_ENTITY` usage in existing validation responses and the unknown-module test.
- `git diff --check` passed; editor diagnostics found no errors in changed Python files.
- Next step: proceed to the next explicitly selected scanner modules; do not infer further SRS requirements without the SRS text.

## Step 3D-2: CORS, HTTP Methods, and Information Disclosure

- Added `cors`, `http_methods`, and `info_disclosure` to the engine registry. New scans default to all six built modules: headers, https, cookies, cors, http_methods, info_disclosure.
- CORS sends a synthetic invalid Origin and reports wildcard ACAO or reflected origin with credential permission (High).
- HTTP methods uses only OPTIONS and TRACE; it reports risky Allow values and accepted TRACE. No PUT or DELETE request is sent.
- Information disclosure checks Server/X-Powered-By/X-AspNet-Version and safely requests missing, malformed, and explicit error paths.
- Demo target now reflects Origin with credentials, advertises risky methods, accepts TRACE, returns version headers, and has a fake stack-trace route. Its start command binds to loopback.
- Added clean-target integration tests for all three modules and all-module scan totals. The all-six demo scan records 2 High, 7 Medium, 7 Low findings and score 45.
- Tests run against local PostgreSQL plus loopback HTTP only. Existing SSRF network tests mock DNS/HTTP transport; no public internet call is part of the suite.
- Test-only fixture disables the scanner's 250 ms polite-request delay; production pacing remains unchanged.
- Full profiled command: `venv/bin/pytest backend/tests/ -v --durations=20`
- Result: **68 passed, 5 warnings in 47.83s**. Slowest tests: two-user target tests 2.45–2.58s; two-user scan isolation 2.33s; all-six scan 1.70s. Scanner integration cases were generally 1.2–1.7s, largely including per-test registration/login and password hashing.
- The earlier 94.47s run was not profiled, so its exact extra time cannot be apportioned. Current durations identify repeated auth setup and multi-user database tests as the slowest measured cases; the test-only delay removal keeps production politeness intact and brings this profiled full run below 48s.
- `git diff --check` passed; no editor diagnostics in changed Python files.

## Step 3D-3: Exposed Files, SQLi, XSS, and Crawler

- Upgraded the crawler to collect same-origin HTML links and form action/method/input names, enforce depth limits, skip non-HTML bodies, and avoid auto-following redirects. Redirect destinations and form actions are restricted to the original scheme/host/port.
- Quick depth crawls only the home page; exposed-files checks only `/.well-known/security.txt`; SQLi and XSS are recorded `done` with zero checks and no probes.
- Added 25 sensitive-file checks plus a well-known path. Findings require HTTP 200 plus path-specific content signatures, and evidence stores only a short centrally masked sample.
- Added GET-only SQLi checks with a single-quote response comparison and harmless true/false pair; no extraction, mutation, brute force, or time-based payloads. POST forms are recorded as not tested and never submitted. Standard/deep limits are capped by probe rounds.
- Added XSS checks using a unique harmless marker containing quote/angle characters; only exact unencoded reflection in HTML is reported.
- New scans default to all nine built modules. `access_control` and `auth_checks` remain recognized but unimplemented and return 400.
- Demo target now contains clearly fake `.env`/`.git/HEAD`, inert fake SQL error behavior, vulnerable/safe product and search endpoints, GET/POST forms, and a 200 soft-404 fallback.
- Added local integration and unit coverage for every new module, clean targets, quick-depth behavior, no POST submission, off-origin redirect prevention, soft-404 filtering, masked evidence, all-nine totals, and Critical verdict priority.
- Full command: `venv/bin/pytest backend/tests/ -v --durations=20`
- Result: **80 passed, 5 warnings in 51.84s**, within the one-minute target. The five warnings remain deprecations for Starlette TestClient/httpx and `HTTP_422_UNPROCESSABLE_ENTITY`.
- Slowest measured tests: two-user target flows 2.76–2.89s; two-user scan isolation 2.43s; all-nine standard scan 2.25s. No public internet calls occur; scanner requests in integration tests target loopback, and SSRF transport tests mock outbound/DNS behavior.
- Tests disable the polite inter-request delay through an autouse fixture; production delay behavior remains unchanged.
- `git diff --check` and editor diagnostics pass; no database/model files were changed.

## Next

## Step 3D-4: Merged Findings, Access Control, and Authentication Checks

- Merged the site-wide modules `headers`, `cookies`, `https`, `cors`, `http_methods`, and `info_disclosure` by module and title before persistence. One row now contains the distinct affected-page total and at most five URLs; exposed-files, SQLi, and XSS findings remain distinct by path/parameter. Severity counts, score, and module finding totals use persisted merged findings.
- The all-eleven integration test derives expected findings from deliberate demo content: five missing browser headers; HTTPS unavailable and no HTTP-to-HTTPS redirect; three missing cookie flags; permissive credentialed CORS; advertised risky methods and accepted TRACE; two version headers and one fake stack trace; the fake `.env` and `.git/HEAD`; a SQL error on `/product`; reflected input on two distinct search URLs; public `/admin` and `/dashboard`; and two HTTP login forms, one with account enumeration and no throttling. Its counts and score are computed from that explicit inventory rather than a copied scanner result.
- Implemented unauthenticated access checks for 15 common paths. Only HTTP 200 responses that are not a login page or soft-404 are findings; no second-user/IDOR test is attempted.
- Implemented password-form-only auth checks. At most two forms per scan and six submissions per form are allowed (named constants); only synthetic `.invalid` email addresses and a generated non-real password are used. Enumeration requires clearly distinct unknown-account versus wrong-password responses; rate limiting is reported only if all six requests are unblocked, undelayed, and not HTTP 429.
- Deferred the second-user-context access-control check because it needs safely stored test credentials and a schema change. Per instruction, neither credentials nor models/database schema are added.
- Extended the loopback-only demo with fake public `/admin` and `/dashboard` routes, `/safe-admin` redirect, vulnerable `/login`, and `/safe-login` with identical errors and HTTP 429 on attempt three.
- Added issue and clean-target coverage for all eleven modules, merge behavior, 15-path access probes, per-form/per-scan login caps, the safe login throttle, and a complete default all-eleven scan. All outbound scanner requests remain on `SafeHttpClient`; evidence is masked immediately before persistence.
- Full command: `venv/bin/pytest backend/tests/ -v --durations=20`
- Result: **86 passed, 5 warnings in 36.70s**. Warnings are existing Starlette deprecations: httpx-backed `TestClient` and `HTTP_422_UNPROCESSABLE_ENTITY`.
- `git diff --check` and Pylance checks on changed Python files pass. No package was installed, and no database or model files were changed.
- SRS was not present; no additional behavior has been inferred from it.

## Step 3E-1: Scan History, Finding Status, and Dashboard

- Added authenticated `GET /api/scans` with user-scoped status/target filters, page/page_size paging (maximum 100), newest-first ordering, total count, and per-severity finding counts. Added full user-scoped scan details at `GET /api/scans/{id}`.
- Added authenticated `DELETE /api/scans/{id}`. Queued or running scans return 409 with `SCAN_ACTIVE` and instruct the owner to cancel first. Finished scans are deleted through existing ORM cascades, including findings and reports.
- Added authenticated `PATCH /api/findings/{id}`. The finding is tenant-checked through its scan; only the vocabulary-defined status can be changed. Invalid values and extra fields return the shared 422 error envelope.
- Finding lifecycle status does not change scan-result counts, score, or verdict: all persisted findings continue to count, including false positives. In particular, setting a Critical finding to `false_positive` does not remove it from the Critical verdict or alter the stored score.
- Added authenticated `GET /api/dashboard/summary`. Severity distribution is the open findings in each target's newest completed scan; this represents the user's current open queue. Recent scans are the five newest scans of any status. Latest security score is from the newest completed scan across the user's targets.
- Added offline integration coverage for filters, paging, tenant isolation, active-delete conflict, finding/report deletion cascades, invalid status, Critical verdict stability, dashboards with and without scans, and authentication on every new endpoint.
- No database/model files were changed and no packages were installed. The SRS was not present; implementation follows only the explicit requirements supplied for this step.
- Full command: `/usr/bin/time -p venv/bin/pytest backend/tests/ -q`
- Result: **91 passed, 8 warnings; pytest 31.19s, wall-clock 33.35s**. Warnings are Starlette TestClient/httpx and deprecated 422 status constant notices.
- `git diff --check` and editor diagnostics pass.

## Step 3E-2: Reports, Profile, Password, and Settings

- Added authenticated report create/list/detail endpoints. Reports are generated on demand as structured JSON; format is stored as a label. Repeating a scan/format regenerates the summary and returns 200; new reports return 201. Only completed scans owned by the current user can be reported.
- Report summaries include scan target/dates/depth/score, shared Critical-first verdict, all severity counts, passed checks summed from `module_progress.checks_passed`, scanner errors, per-module execution data, and total finding count. Detail results sort findings Critical-first. Existing JSONB summary and current finding fields suffice; no columns were invented.
- Added authenticated profile read/update with only trimmed, non-empty `full_name` (maximum 150 characters); password changes verify the current bcrypt hash, apply registration complexity/72-byte rules, reject reuse, and never return credentials or hashes. Wrong current password returns 400 `INVALID_CURRENT_PASSWORD`.
- Added authenticated settings read/update for existing scan-depth and three notification preference fields. Preferences are stored only; email delivery is out of scope.
- Existing access tokens are not revoked when a password changes and remain valid until expiration; documented in `docs/security_controls.md`.
- Corrected dashboard severity distribution to count `open` and `confirmed` findings from each target's latest completed scan; `false_positive` and `resolved` are excluded. Updated the dashboard test to cover confirmed findings.
- Added tests for report create/regenerate, completed-scan requirement, passed-count summation, Critical verdict, report tenant isolation, invalid format, profile validation, password-change cases/login, settings validation, and unauthenticated endpoint access.
- No database/model files were changed and no packages were installed. The SRS remains absent; implementation follows only the supplied rules.
- Full command: `/usr/bin/time -p venv/bin/pytest backend/tests/ -q`
- Result: **97 passed, 12 warnings; pytest 56.60s, wall-clock 59.69s**. Warnings are Starlette TestClient/httpx and deprecated 422 status constant notices.
- `git diff --check` and editor diagnostics pass.

## Step 3F: Backend Wrap-Up

- Production settings now reject `ALLOW_LOCAL_TARGETS=true` and JWT secrets under 32 characters or with fewer than 16 distinct characters. This is a baseline strength heuristic, not an entropy estimator or secret-management system.
- Production disables `/docs`, `/redoc`, and `/openapi.json`. CORS now has an empty default allowlist and no wildcard fallback; configured comma-separated origins are parsed explicitly. `.env.example` uses an empty `CORS_ORIGINS` value.
- Added direct pin `httpcore==1.0.9`, which is imported by the safe HTTP transport. Existing venv `pip check` is clean.
- Made the private-redirect SSRF test deterministic by mocking DNS, eliminating an accidental public DNS dependency.
- Reduced bcrypt cost to four rounds only within the pytest autouse fixture; production `hash_password` still uses bcrypt defaults. Full suite runtime decreased from 59.69s wall-clock (97 tests before this step; a later network-flaky run took 108s) to 21.74s wall-clock with expanded coverage.
- Replaced the API endpoint index with a method/path/login/request/success/errors contract for all registered API routes. Expanded the security guide with SEC-1 through SEC-13, implementation references, and presentation limitations. Rewrote README with PostgreSQL role/database setup, env setup, venv install, migrations, dev-only seed, tests, API and demo start commands.
- No model/database files changed. No package installed. The SRS remains absent; SEC-12’s intended definition is not guessed.
- Full command: `/usr/bin/time -p venv/bin/pytest backend/tests/ -q`
- Result: **102 passed, 12 warnings; pytest 16.22s, wall-clock 19.73s**. Warnings are Starlette TestClient/httpx and deprecated 422 status constant notices.
- `venv/bin/pip check`, `git diff --check`, and editor diagnostics pass.

## Step 3F Follow-Up: Settings Error Redaction

- Enabled Pydantic `hide_input_in_errors` for application Settings so rendered validation messages omit invalid input values, including JWT secrets.
- Added a regression test that constructs Settings with a deliberately invalid JWT secret and asserts the secret is absent from the validation message.
- Focused check: `venv/bin/pytest backend/tests/test_auth.py::test_settings_validation_error_does_not_expose_jwt_secret -q` passed.
- Full command: `venv/bin/pytest backend/tests/ -q`
- Result: **103 passed, 12 warnings in 8.63s**. Warnings are the existing Starlette TestClient/httpx and deprecated 422 status constant notices.
- No database or model files were changed.

## Step 3F Follow-Up: Error Hygiene, CORS, and Regression Tests

- Exception-bearing logs now use the existing evidence masker plus redaction for arbitrary URL query strings and filesystem paths. The exception detail is formatted before logging rather than emitted through raw `logger.exception` traceback handling.
- Scanner module and worker failures persist fixed messages with error categories; exception detail is not returned in status/results. The catch-all continues to return the generic shared 500 envelope.
- `CORS_ORIGINS` rejects wildcard `*` in every environment.
- Added tests for sanitized module/worker failures and logs, generic unhandled 500 responses, wildcard CORS, per-user settings, lifespan restart recovery, and loopback/private/link-local/metadata policy.
- Added a direct exception-masker test for cookies, Set-Cookie, Authorization, passwords, tokens, URL query strings, and paths.
- Focused regression checks pass. Full command: `venv/bin/pytest backend/tests/ -q`.
- Full result: **110 passed, 12 warnings in 9.14s**. Warnings remain the existing Starlette TestClient/httpx and deprecated 422 status constant notices.
- No database or model files were changed.

## Phase 4A: Shared Authentication and Protected Dashboard Shell

- Added same-origin API configuration and a single fetch wrapper that attaches the localStorage Bearer token and reads the API `error.code` / `error.message` envelope. Unauthorized and network failures clear all localStorage credentials; login's invalid-credential response remains visible without redirecting.
- Added shared auth helpers for login, registration, logout, `/api/auth/me` route checks, validated public navigation, and one generated sidebar navigation. The login page validates an existing token with `/api/auth/me` rather than trusting localStorage.
- Wired registration and login forms with server-mirroring email/password checks, accessible pending status, and API error messages. Registration redirects to sign-in because the register endpoint returns a user record, not an access token.
- Reduced the dashboard to its authenticated shell and account display. Removed Chart.js: the import report confirms the old dashboard used Canvas 2D directly and never instantiated Chart.js.
- Added SEC-12 localStorage/XSS documentation, a manual browser checklist, and built-in Node tests for client-side validation. No packages installed.
- Focused validation: `node --test frontend/tests/auth.test.cjs` passed (2 tests); `node --check` passed for all frontend JS files.
- Full backend command: `venv/bin/pytest backend/tests/ -q`
- Result: **110 passed, 12 existing deprecation warnings in 19.38s**. No backend, database, or model files were changed.

## Next

Await the next explicitly requested step. Do not infer unprovided SRS requirements.

## Phase 4B: Target Verification Frontend

- Completed the target ownership page with the imported sidebar/layout, legal notice, responsive add-target form, user-scoped target list, and empty/loading/error states.
- Wired target list/create/detail/verify/delete through `api.js`; page access is gated by `Auth.requireAuth()`. Proof values are created with DOM nodes and `textContent`, filtered to the selected method, and each has a clipboard action with a plain-text fallback.
- Verification status is only marked successful when the API returns `is_verified: true`; failures show the API detail and updated last-checked timestamp. Delete confirmation warns that associated scans and findings are removed. Verified targets link to the Step 4C scan URL.
- Added Node unit tests for proof filtering, timestamps, and API error fallbacks, plus the target verification browser checklist.
- Validation: `node --test frontend/tests/*.test.cjs` passed (5 tests); `venv/bin/pytest backend/tests/ -q` passed (110 tests, 12 existing deprecation warnings).
- `git diff --check`, editor diagnostics, JavaScript syntax, and static asset/policy checks pass. No backend, database, or model files were changed; no packages were installed.

## Phase 4C: Scan Setup and Live Progress

- Replaced the imported new-scan placeholder behavior with user-scoped target/settings loading, verified-target selection, query preselection, saved depth defaults, all eleven module choices, authorization reminder, and guarded scan creation through `api.js`.
- Replaced live-scan placeholder behavior with UUID query validation, authenticated status polling through chained timeouts, slower background polling, bounded network retries, module progress states, cancellation handling, and terminal-state links. Polling stops on terminal state and page exit.
- Kept the imported shell and scanner styles; added page-scoped responsive styles. No inline scripts, inline event handlers, external scripts, or dynamic HTML injection were added.
- Added Node helper tests and manual checklist coverage for setup, progress, cancellation, module errors, invalid/other-user IDs, network retries, and duplicate submissions.
- Validation: `node --test frontend/tests/*.test.cjs` passed (13 tests); `venv/bin/pytest backend/tests/ -q` passed (110 tests, 12 existing deprecation warnings). `node --check` for both controllers and `git diff --check` pass.
- No backend, database, or model files were changed; no packages were installed.