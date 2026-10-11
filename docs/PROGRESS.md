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

Await the next explicitly requested step. Do not infer unprovided SRS requirements.