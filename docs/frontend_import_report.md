# EthioSec Scanner — Frontend Import & Wiring Specification Report

This document records the complete import and audit of the EthioSec Scanner frontend, ported from the legacy project (`/home/maraki/Ethiosec scanner/EthioSec-Scanner/ETHIOSEC SCANNER 2`) to the target architecture (`/home/maraki/ethiosecscanner/frontend`).

This operation was an **IMPORT ONLY** migration with zero new features. Visual designs, layouts, color tokens, typography, element classes, and markup structures have been preserved exactly. Legacy client-side JavaScript—which contained critical security flaws, mock shims, and hardcoded local endpoints—was quarantined in `docs/old_frontend_reference/` and excluded from `frontend/`.

---

## 1. Master File Mapping Table

| Original File (Old Project) | New Location / Action | Status / Migration Reason |
|:---|:---|:---|
| `dashboardfinal.html` | `frontend/pages/dashboard.html` | Migrated. Cleaned inline auth/logout scripts, added `data-action` hooks, updated relative links and CSS/JS paths. |
| `scanfinal.html` | `frontend/pages/new_scan.html` | Migrated. Cleaned inline scripts, added `data-action` hooks, updated relative links. |
| `livescan.html` | `frontend/pages/live_scan.html` | Migrated. Cleaned inline runtime shim, added `data-action` hooks, updated relative links. |
| `scan_history.html` | `frontend/pages/history.html` | Migrated. Cleaned inline mobile script, added `data-action` hooks, updated relative links. |
| `assistant.html` | `frontend/pages/ai_assistant.html` | Migrated. Cleaned inline runtime shim, added `data-action` hooks, updated relative links. |
| `login.html` | `frontend/pages/login.html` | Migrated. Replaced inline `onclick` alerts with `data-action="oauth-*"`, updated CSS/JS paths. |
| `signup.html` | `frontend/pages/signup.html` | Migrated. Repaired malformed toggle password tag, added `data-action` hooks, updated CSS/JS paths. |
| `index.html` | `frontend/pages/index.html` | Migrated. Removed inline mock bridge script, updated navigation links and CSS/JS paths. |
| `features.html` | `frontend/pages/features.html` | Migrated. Removed inline mock bridge script, updated navigation links and CSS/JS paths. |
| `contact.html` | `frontend/pages/contact.html` | Migrated. Removed inline mock bridge script, added `data-action` hooks, updated links and paths. |
| `results.html` | `frontend/pages/results.html` | Migrated. Removed inline bridge and modal keydown scripts, added `data-action` hooks. |
| `reports.html` | `frontend/pages/reports.html` | Migrated. Preserved print stylesheet, removed inline scripts, added `data-action` hooks. |
| `settings.html` | `frontend/pages/settings.html` | Migrated. Removed inline runtime shim, added `data-action` hooks, updated links. |
| *(None in old project)* | `frontend/pages/target_verify.html` | Created. Aligned with shared layout shell and standard script tags for target ownership verification. |
| `shell.css` | `frontend/css/global.css` | Migrated & Consolidated. Serves as global design system, resets, layout shell, `:root` color tokens and unified severity tokens. |
| `sty.css` | `frontend/css/landing.css` | Migrated. Dedicated stylesheet for public pages (`index`, `features`, `contact`). |
| `logistyle.css` | `frontend/css/auth.css` | Migrated & Consolidated. Combined with `signupstyle.css` for unified login and signup flows. |
| `signupstyle.css` | `frontend/css/auth.css` | Migrated & Consolidated into `auth.css`. |
| `dashboardfinal.css` | `frontend/css/dashboard.css` | Migrated. Extracted page-specific cards, charts, and telemetry grids; shell rules moved to `global.css`. |
| `scanstylefinal.css` | `frontend/css/scan.css` | Migrated & Consolidated. Combined with `livestyle.css` and `scan_historystyle.css`. |
| `livestyle.css` | `frontend/css/scan.css` | Migrated & Consolidated into `scan.css`. |
| `scan_historystyle.css` | `frontend/css/scan.css` | Migrated & Consolidated into `scan.css`. |
| `resultsstyle.css` | `frontend/css/results.css` | Migrated. Dedicated findings summary, gauges, and vulnerability modal styles. |
| `reportstyle.css` | `frontend/css/reports.css` | Migrated. Dedicated formal assessment document and report preview styles. |
| `assistantstyle.css` | `frontend/css/ai_assistant.css` | Migrated. Dedicated chat container, context chips, suggestion pills, and composer styles. |
| `settingsstyle.css` | `frontend/css/settings.css` | Migrated. Dedicated profile settings, preferences, password strength meter, and tab styles. |
| `dashboardfinal.js` | `docs/old_frontend_reference/dashboardfinal.js` | Archived unexecuted. Replaced in `frontend/js/dashboard.js` with empty placeholder comment. |
| `scanjavafinal.js` | `docs/old_frontend_reference/scanjavafinal.js` | Archived unexecuted. Replaced in `frontend/js/new_scan.js` with empty placeholder comment. |
| `livejava.js` | `docs/old_frontend_reference/livejava.js` | Archived unexecuted. Replaced in `frontend/js/live_scan.js` with empty placeholder comment. |
| `scan_historyjava.js` | `docs/old_frontend_reference/scan_historyjava.js` | Archived unexecuted. Replaced in `frontend/js/history.js` with empty placeholder comment. |
| `resultsjava.js` | `docs/old_frontend_reference/resultsjava.js` | Archived unexecuted. Replaced in `frontend/js/results.js` with empty placeholder comment. |
| `reportjava.js` | `docs/old_frontend_reference/reportjava.js` | Archived unexecuted. Replaced in `frontend/js/reports.js` with empty placeholder comment. |
| `assistantjava.js` | `docs/old_frontend_reference/assistantjava.js` | Archived unexecuted. Replaced in `frontend/js/ai_assistant.js` with empty placeholder comment. |
| `settingsjava.js` | `docs/old_frontend_reference/settingsjava.js` | Archived unexecuted. Replaced in `frontend/js/settings.js` with empty placeholder comment. |
| `loginjava.js` | `docs/old_frontend_reference/loginjava.js` | Archived unexecuted. Replaced in `frontend/js/login.js` with empty placeholder comment. |
| `signupjava.js` | `docs/old_frontend_reference/signupjava.js` | Archived unexecuted. Replaced in `frontend/js/signup.js` with empty placeholder comment. |
| `script.js` | `docs/old_frontend_reference/script.js` | Archived unexecuted. Replaced in `frontend/js/landing.js` with empty placeholder comment. |
| `mockapi.js` | **DROPPED** | Dropped. Fake mock API with client-side bypasses and fake data. |
| `nav_updater.py` | **DROPPED** | Dropped. One-off patch utility that injected duplicate inline logout scripts into HTML. |
| `protect_routes.py` | **DROPPED** | Dropped. One-off patch utility that injected fragile inline redirect scripts into HTML. |
| `fix.py` | **DROPPED** | Dropped. One-off ad-hoc patch script. |
| `.vscode/settings.json` | **DROPPED** | Dropped. Local IDE configuration file. |

---

## 2. Page Wiring Specifications

### 2.1 Login (`pages/login.html`)
- **Purpose**: Authenticates existing users via email/password credentials or presents OAuth options.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `form#loginForm`: Captures submit event.
  - `input#email`: Email input field.
  - `input#password`: Password input field.
  - `input#remember`: Remember-me checkbox.
  - `button#togglePasswordBtn` (`data-action="toggle-password"`): Toggles password field masking.
  - `button#loginBtn` (`data-action="login"`): Form submission button.
  - `button.social-btn.google` (`data-action="oauth-google"`): Google OAuth action.
  - `button.social-btn.github` (`data-action="oauth-github"`): GitHub OAuth action.
  - `div#formError`: Banner for validation or server error display (`<!-- DATA: form error message populated by login.js -->`).
- **Legacy API Endpoints Called**:
  - `POST http://127.0.0.1:8000/api/auth/login` with body `{"email": "...", "password": "..."}`.
- **Legacy Response Handling**:
  - On 200: Stored `res.token` or `res.access_token` and `res.user.email` into `localStorage`. Set `localStorage.setItem("isLoggedIn", "true")`. Navigated to `dashboardfinal.html` or `scanfinal.html?target=...`.
  - On error: Extracted `data.message` or `data.detail` and set `formError.textContent`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - Spec defines `POST /api/auth/login` taking `{"email": "...", "password": "..."}`.
  - Response is `200` with `{"access_token": "...", "token_type": "bearer"}`. Notice the user object is NOT returned here; user identity must be fetched via `GET /api/auth/me`.
  - Standard errors return `{"error": {"code": "...", "message": "..."}}`.
- **Old Bugs Discovered**:
  - Relied on `localStorage.setItem("isLoggedIn", "true")` which was checked on client side to allow bypassing auth entirely.
  - Inline `onclick="alert(...)"` handlers on OAuth buttons.
  - Hardcoded absolute URL `http://127.0.0.1:8000`.
- **Visual Differences**: None. Layout, styling, fonts, and inputs match 100%.

---

### 2.2 Sign Up (`pages/signup.html`)
- **Purpose**: Registers a new user account with full name, email, and password.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `form#signupForm`: Form submit handler.
  - `input#fullname`: Full name input.
  - `input#email`: Email input.
  - `input#password`: Password input.
  - `input#confirm-password`: Password confirmation.
  - `input#terms`: Terms agreement checkbox.
  - `input#newsletter`: Newsletter opt-in checkbox.
  - `button#togglePasswordBtn` (`data-action="toggle-password"`): Toggle password visibility.
  - `button#toggleConfirmPasswordBtn` (`data-action="toggle-confirm-password"`): Toggle confirm password visibility.
  - `button#signupBtn` (`data-action="signup"`): Account creation button.
  - `button#googleBtn` (`data-action="oauth-google"`): Google OAuth button.
  - `button#githubBtn` (`data-action="oauth-github"`): GitHub OAuth button.
  - `div#formError`: Banner for displaying error messages (`<!-- DATA: form error message populated by signup.js -->`).
- **Legacy API Endpoints Called**:
  - `POST http://127.0.0.1:8000/api/auth/register` with `{"email": "...", "password": "...", "full_name": "..."}`.
- **Legacy Response Handling**:
  - On success: Immediately called `POST http://127.0.0.1:8000/api/auth/login` with credentials, saved token, and redirected to `scanfinal.html`.
  - On error: Set `formError.textContent`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - Spec defines `POST /api/auth/register` returning `201` with user object `{id, email, full_name, role, is_active, created_at, updated_at}`.
  - Password must follow registration policy (at least 8 characters).
- **Old Bugs Discovered**:
  - Malformed HTML tag in legacy markup: `<button type="button" class="show-password" id="togglePasswordBtn" </div>` on the confirm password line, causing duplicated ID and unclosed attribute syntax. Cleaned and fixed.
  - Trust in `isLoggedIn` flag. Hardcoded base URLs.
- **Visual Differences**: None.

---

### 2.3 Landing Page (`pages/index.html`)
- **Purpose**: Public homepage introducing EthioSecScan, demonstrating scanner value, and offering a quick URL entry bar to initiate scans.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#menuBtn` (`data-action="toggle-menu"`): Mobile hamburger navigation toggle.
  - `form#scanForm`: Quick scan URL form.
  - `input#urlInput`: Website target URL entry.
  - `button#scanBtn` (`data-action="start-scan"`): Submit scan button.
  - `span#scannerStatus`: Dynamic badge (`<!-- DATA: status updated by landing.js -->`).
  - `a#openDashboard`: Dashboard navigation link (shown if authenticated).
  - `a#openLogin`: Login / register navigation link.
  - `div#notification`: Toast notification element (`<!-- DATA: toast notifications rendered by landing.js -->`).
- **Legacy API Endpoints Called**:
  - None directly; checked `localStorage.getItem("isLoggedIn") === "true"` and stored target in `sessionStorage` or passed via query parameters to `scanfinal.html?target=...` or `login.html?target=...`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - Can optionally ping `GET /health` to reflect live backend engine status.
- **Old Bugs Discovered**:
  - Inline `<script>` block hardcoding client authentication check and redirect logic.
- **Visual Differences**: None.

---

### 2.4 Features (`pages/features.html`)
- **Purpose**: Explains core scanning capabilities (crawler, OWASP checks, AI explanation, executive reporting).
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#menuBtn` (`data-action="toggle-menu"`): Mobile navigation toggle.
  - `nav#navLinks`: Mobile nav drawer.
  - `a#openDashboard`, `a#openLogin`, `a#footerLogin`: Auth-dependent links.
- **Legacy API Endpoints Called**: None.
- **Old Bugs Discovered**:
  - Inline `<script>` block checking `localStorage.getItem("isLoggedIn")` and modifying DOM links.
- **Visual Differences**: None.

---

### 2.5 Contact (`pages/contact.html`)
- **Purpose**: Public contact and support inquiry form.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#menuBtn` (`data-action="toggle-menu"`): Mobile nav toggle.
  - `form#contactForm`: Contact inquiry submission.
  - `input#contactName`: Name input.
  - `input#contactEmail`: Email input.
  - `input#contactSubject`: Subject input.
  - `textarea#contactMessage`: Message body.
  - `button.submit-btn` (`data-action="send-contact"`): Form submission.
  - `div#notification`: Toast notification element.
- **Legacy API Endpoints Called**:
  - Handled purely client-side; displayed toast notification and reset the form.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - No contact submission endpoint exists in API spec.
- **Old Bugs Discovered**:
  - Inline mock bridge script block.
- **Visual Differences**: None.

---

### 2.6 Dashboard (`pages/dashboard.html`)
- **Purpose**: Central command center displaying aggregated vulnerability posture, security score, scan metrics, daily scan activity charts, and recent scans table.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile sidebar toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Overlay back-click closer.
  - `a.side-link[data-action="logout"]`: Sidebar nav logout link.
  - `button#logoutBtn` (`data-action="logout"`): Sidebar footer logout button.
  - `span#userEmailDisplay`: User email label (`<!-- DATA: filled by auth.js / dashboard.js -->`).
  - `div#scoreValue`: Large security score gauge number (`<!-- DATA: score filled by dashboard.js -->`).
  - `circle#scoreProgress`: SVG stroke progress ring.
  - `div#statTotalScans`: Total scan count (`<!-- DATA: total scans filled by dashboard.js -->`).
  - `div#statActiveScans`: Active running scans (`<!-- DATA: active scans filled by dashboard.js -->`).
  - `div#statHighAlerts`: High/Critical severity issues (`<!-- DATA: high alerts filled by dashboard.js -->`).
  - `div#statAvgScore`: Average system score (`<!-- DATA: avg score filled by dashboard.js -->`).
  - `canvas#scansChart`: Daily scans bar chart (`<!-- DATA: scans chart canvas rendered by dashboard.js -->`).
  - `canvas#trendChart`: Requests handled trend line chart (`<!-- DATA: trend chart canvas rendered by dashboard.js -->`).
  - `div#scansList`: Recent scan item cards (`<!-- DATA: recent scans filled by dashboard.js -->`).
  - `button.filter-btn` (`data-action="filter-scans"`): Range filter buttons.
- **Legacy API Endpoints Called**:
  - `GET http://127.0.0.1:8000/api/dashboard/summary` with `Authorization: Bearer <token>`.
  - `GET http://127.0.0.1:8000/api/scans?limit=5` with `Authorization: Bearer <token>`.
- **Legacy Response Handling**:
  - Populated stats cards from `total_scans`, `completed_scans`, `latest_security_score`, `severity_distribution`.
  - Populated canvas charts using raw 2D canvas context functions (`createScansChart`, `createTrendChart`).
  - Rendered recent scans list via `scansList.innerHTML = recentScans.map(renderScanRow).join("")`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - `GET /api/dashboard/summary` matches spec: returns `{total_targets, verified_targets, total_scans, completed_scans, recent_scans, latest_security_score, severity_distribution}`.
  - Legacy called `GET /api/scans?limit=5`; the real API spec uses `GET /api/scans?page=1&page_size=5`. Query parameter `limit` is invalid and ignored by FastAPI pagination schema.
- **Old Bugs Discovered**:
  - Loaded `https://cdn.jsdelivr.net/npm/chart.js` in `<head>` but never used it; all charts were drawn with raw 2D canvas primitives.
  - Multiple duplicated logout functions injected into `<aside>`.
  - Used `innerHTML` with template strings containing unescaped scan data.
  - `logout()` did not invalidate tokens on the server or clear `token` from `localStorage` consistently.
- **Visual Differences**: None.

---

### 2.7 New Scan (`pages/new_scan.html`)
- **Purpose**: Configures and launches a security scan against a verified target, specifying scan depth and active vulnerability check modules.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Mobile overlay.
  - `a.side-link[data-action="logout"]`: Logout link.
  - `form#scanForm`: Scan submission form.
  - `input#targetUrl`: Target URL input.
  - `div.depth-options input[name="depth"]`: Quick, standard, deep radio options.
  - `div.module-grid input[type="checkbox"]`: Module toggles (`headers`, `cookies`, `https`, `cors`, `http_methods`, `info_disclosure`, `exposed_files`, `sqli`, `xss`, `access_control`, `auth`).
  - `button#startScanBtn` (`data-action="start-scan"`): Primary launch button.
  - `strong#lastScan`: Last scan timestamp (`<!-- DATA: last scan timestamp filled by new_scan.js -->`).
  - `strong#totalScans`: Total scan counter (`<!-- DATA: total scans count filled by new_scan.js -->`).
  - `div#recentTargets`: Quick-target pill container (`<!-- DATA: recent targets filled by new_scan.js -->`).
  - `div#historyList`: Mini recent scans listing (`<!-- DATA: recent scans filled by new_scan.js -->`).
  - `div#toast`: Toast container.
- **Legacy API Endpoints Called**:
  - `GET http://127.0.0.1:8000/api/user/settings` to load default scan depth.
  - `POST http://127.0.0.1:8000/api/targets` with `{"url": target, "verification_method": "meta_tag"}`.
  - `POST http://127.0.0.1:8000/api/scans` with `{"target_id": ..., "depth": ..., "modules": [...]}`.
  - `POST http://127.0.0.1:8000/api/scans/${scanId}/start` (attempted launch).
  - `GET http://127.0.0.1:8000/api/scans?limit=6`.
- **Legacy Response Handling**:
  - Saved scan ID and navigated immediately to `livescan.html?id=${scanId}&target=${target}`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - Endpoint `POST /api/scans/{scanId}/start` **DOES NOT EXIST** in the API spec! In the finished backend, creating a scan via `POST /api/scans` automatically queues and starts background execution.
  - Target must be verified before scanning! `POST /api/scans` returns `400 TARGET_NOT_VERIFIED` if the target domain ownership is unverified. The old script assumed creating a target was sufficient to scan.
  - Query parameter `limit=6` does not match spec (`page_size=6`).
- **Old Bugs Discovered**:
  - Called non-existent `/api/scans/{scanId}/start` route.
  - Attempted to scan targets without ownership challenge verification (`POST /api/targets/{id}/verify`).
  - Interpolated unescaped target URLs directly into `recentTargets.innerHTML`.
- **Visual Differences**: None.

---

### 2.8 Live Scan Telemetry (`pages/live_scan.html`)
- **Purpose**: Displays real-time progress for a queued or executing vulnerability scan, including progress ring, stage explanation, active module indicators, and cancellation.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Mobile overlay.
  - `a.side-link[data-action="logout"]`: Logout link.
  - `p#scanTarget`: Target URL label (`<!-- DATA: scan target filled by live_scan.js -->`).
  - `circle#ringProgress`: SVG circular progress bar.
  - `span#progressPercent`: Percentage text (`<!-- DATA: progress filled by live_scan.js -->`).
  - `small#statusLabel`: Status badge text.
  - `h2#stageText`: Stage header (`<!-- DATA: stage text filled by live_scan.js -->`).
  - `p#stageHint`: Stage detail description.
  - `div#progressFill`: Linear progress bar fill.
  - `strong#scanIdLabel`: Scan UUID.
  - `strong#depthLabel`: Scan depth mode.
  - `strong#elapsed`: Elapsed scan duration.
  - `div#checkGrid`: Container of 7 module status items (`misconfig`, `https`, `access_control`, `auth`, `sqli`, `xss`, `headers`).
  - `ul#log`: Pipeline event log list (`<!-- DATA: pipeline logs filled by live_scan.js -->`).
  - `button#cancelScan` (`data-action="cancel-scan"`): Cancellation button.
  - `a#viewResults` (`data-action="view-results"`): Completion link to `results.html?id=...`.
  - `div#toast`: Notification toast.
- **Legacy API Endpoints Called**:
  - `GET http://127.0.0.1:8000/api/scans/${scanId}/status` polled periodically.
  - `POST http://127.0.0.1:8000/api/scans/${scanId}/cancel` on cancel button click.
- **Legacy Response Handling**:
  - Updated `progressPercent`, stroke dash offset, and `current_module`.
  - Simulated simulated logs if backend returned empty telemetry.
  - On `status === "completed"`: Redirected to `results.html?id=${scanId}`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - Spec defines `GET /api/scans/{scan_id}/status` returning `{"id": "...", "status": "...", "progress": n, "module_progress": {...}, "error_message": ...}`.
  - Spec defines `POST /api/scans/{scan_id}/cancel` returning `200` with `status: "queued|running"`.
- **Old Bugs Discovered**:
  - Hardcoded local IP `http://127.0.0.1:8000`.
  - Client-side mock fallback when backend returned 404 or 401.
  - Duplicated inline logout functions in sidebar.
- **Visual Differences**: None.

---

### 2.9 Scan History (`pages/history.html`)
- **Purpose**: Paginated audit table of all previous scans executed by the user with filtering and status indicators.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Mobile overlay.
  - `a.side-link[data-action="logout"]`: Logout link.
  - `div#statTotalScans`: Total scan counter (`<!-- DATA: total scans filled by history.js -->`).
  - `div#statCompleted`: Completed scan counter (`<!-- DATA: completed scans filled by history.js -->`).
  - `div#statAvgScore`: Average score (`<!-- DATA: avg score filled by history.js -->`).
  - `div#statIssuesFound`: Total issues found count (`<!-- DATA: issues count filled by history.js -->`).
  - `select#filterStatus`: Filter by status (`all`, `completed`, `running`, `failed`).
  - `input#filterSearch`: Target search box.
  - `span#resultCount`: Current view count (`<!-- DATA: count filled by history.js -->`).
  - `tbody#tableBody`: Table body rows (`<!-- DATA: scan history rows filled by history.js -->`).
  - `button#prevBtn` (`data-action="prev-page"`): Previous page button.
  - `button#nextBtn` (`data-action="next-page"`): Next page button.
  - `span#pageInfo`: Pagination label (`<!-- DATA: pagination filled by history.js -->`).
  - `div#toast`: Toast container.
- **Legacy API Endpoints Called**:
  - `GET http://127.0.0.1:8000/api/scans` (or with filters).
  - `DELETE http://127.0.0.1:8000/api/scans/${scanId}` for scan deletion.
- **Legacy Response Handling**:
  - Computed summary stats on client side from returned scans.
  - Rendered table rows using `tableBody.innerHTML = rows.map(...)`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - `GET /api/scans` accepts `status`, `target_id`, `page`, and `page_size` query parameters.
  - Returns `{"total": n, "page": 1, "page_size": 20, "scans": [...]}`.
  - `DELETE /api/scans/{scan_id}` returns `200` with `{"id": "...", "message": "..."}`. Returns `409 SCAN_ACTIVE` if scan is queued/running.
- **Old Bugs Discovered**:
  - Rendered user target URLs and finding counts directly into `tableBody.innerHTML` without strict sanitization.
  - Filter logic ran in-memory instead of leveraging server-side `?status=` and pagination parameters.
- **Visual Differences**: None.

---

### 2.10 Results (`pages/results.html`)
- **Purpose**: Detailed technical findings breakdown of an individual scan, including score gauge, severity breakdown, finding cards with evidence, and detailed vulnerability modal.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Mobile overlay.
  - `a.side-link[data-action="logout"]`: Logout link.
  - `p#resultTarget`: Scanned target header (`<!-- DATA: target URL filled by results.js -->`).
  - `a#openReport`: Link to view formal report (`reports.html?id=...`).
  - `span#scoreValue`: Security score (`<!-- DATA: score filled by results.js -->`).
  - `circle#ringProgress`: SVG score gauge ring.
  - `h2#verdict`: Verdict header (`<!-- DATA: verdict filled by results.js -->`).
  - `button.count` (`data-action="filter-severity"`): Severity pill filter buttons (`#cHigh`, `#cMedium`, `#cLow`, `#cPassed`, `#cError`).
  - `strong#scanIdLabel`, `strong#depthLabel`, `strong#finishedLabel`: Scan metadata.
  - `select#severityFilter`: Dropdown filter.
  - `select#moduleFilter`: Dropdown module filter (`<!-- DATA: module filter options filled by results.js -->`).
  - `input#findingSearch`: Finding search input.
  - `div#findingList`: Findings list container (`<!-- DATA: findings cards populated by results.js -->`).
  - `div#detailModal`: Vulnerability detail modal (`<!-- DATA: modal details filled by results.js -->`).
  - `button#modalClose` (`data-action="close-modal"`): Modal close button.
  - `button#modalDone` (`data-action="close-modal"`): Modal done button.
  - `a#askAi`: AI assistant contextual deep link (`ai_assistant.html?scan_id=...&finding_id=...`).
- **Legacy API Endpoints Called**:
  - `GET http://127.0.0.1:8000/api/scans?limit=1` (if no ID specified in URL).
  - `GET http://127.0.0.1:8000/api/scans/${id}/results`.
- **Legacy Response Handling**:
  - Rendered finding cards via `findingList.innerHTML = rows.map(...)`.
  - When a finding was clicked, populated `#detailModal` and stripped `hidden`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - Matches `GET /api/scans/{scan_id}/results`: returns `{id, status, score, verdict, counts, passed_count, scanner_error_count, findings: [...]}`.
- **Old Bugs Discovered**:
  - Rendered unescaped properties in `findingList.innerHTML`.
  - Did not handle token expiry gracefully (displayed mock findings instead of prompting login).
  - Used inline event listeners that clashed with modal ESC key handler.
- **Visual Differences**: None.

---

### 2.11 Reports (`pages/reports.html`)
- **Purpose**: Formal assessment report generator and previewer, rendering executive summaries, methodology, and print-ready vulnerability reports.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Mobile overlay.
  - `a.side-link[data-action="logout"]`: Logout link.
  - `span#reportCount`: Count badge (`<!-- DATA: count filled by reports.js -->`).
  - `div#reportList`: Left-hand report list (`<!-- DATA: reports list filled by reports.js -->`).
  - `section#reportDoc`: Main document view (`<!-- DATA: assessment report doc rendered by reports.js -->`).
  - `button#btnJson`: Export JSON report.
  - `button#btnHtml`: Export HTML report.
  - `button#btnPdf`: Print/PDF export button (`window.print()`).
- **Legacy API Endpoints Called**:
  - `GET http://127.0.0.1:8000/api/reports`.
  - `GET http://127.0.0.1:8000/api/reports/${id}`.
  - `POST http://127.0.0.1:8000/api/ai/chat` (attempted AI executive summary synthesis).
- **Legacy Response Handling**:
  - Rendered document via `docEl.innerHTML = renderDoc(report)`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - `GET /api/reports` returns `{"total": n, "page": 1, "page_size": 20, "reports": [...]}`.
  - `POST /api/reports` creates or regenerates a report for a completed scan: `{"scan_id": "...", "report_format": "json"}`.
  - `GET /api/reports/{report_id}` returns full report object.
  - Calling `POST /api/ai/chat` **DOES NOT EXIST** in the API spec! The old script attempted to fetch an AI summary from an endpoint that is not implemented in the backend.
- **Old Bugs Discovered**:
  - Called non-existent `/api/ai/chat`.
  - Used `innerHTML` for full document rendering with interpolated finding evidence and URLs.
  - Duplicated logout script blocks.
- **Visual Differences**: None. Print styles are preserved.

---

### 2.12 AI Assistant (`pages/ai_assistant.html`)
- **Purpose**: Conversational interface explaining findings already produced by the scanner, with guardrails preventing hallucinated vulnerabilities.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Mobile overlay.
  - `a.side-link[data-action="logout"]`: Logout link.
  - `a#backLink`: Link returning to results if deep-linked.
  - `div#contextRow`: Active scan/finding chips (`<!-- DATA: focus chips filled by ai_assistant.js -->`).
  - `div#chat`: Chat conversation history (`<!-- DATA: conversation bubbles rendered by ai_assistant.js -->`).
  - `div#suggestions button.suggestion` (`data-action="suggestion"`): Prompt suggestion pills.
  - `form#composer`: Message composer form.
  - `input#message`: Text input field.
  - `button#sendBtn` (`data-action="send-message"`): Send button.
  - `div#toast`: Toast notification element.
- **Legacy API Endpoints Called**:
  - `GET http://127.0.0.1:8000/api/findings/${findingId}` (when deep-linked).
  - `POST http://127.0.0.1:8000/api/ai/chat` with `{"message": "...", "scan_id": "...", "finding_id": "..."}`.
- **Legacy Response Handling**:
  - Appended message bubbles into `#chat` via `bubble.innerHTML = role === "ai" ? formatMessage(text) : UI.escapeHTML(text)`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - Neither `GET /api/findings/{finding_id}` nor `POST /api/ai/chat` exist in `api_spec.md`!
  - `findings` router only provides `PATCH /api/findings/{finding_id}` to toggle status (`open`, `confirmed`, `false_positive`, `resolved`).
  - Per architecture documentation, AI assistant service is an isolated placeholder. The legacy script called non-existent routes and fell back to inline mock responses.
- **Old Bugs Discovered**:
  - Complete mock fallback allowing conversation even when offline.
  - Formatted message HTML using regex replacements that could be vulnerable if markdown had unescaped HTML entities.
- **Visual Differences**: None.

---

### 2.13 Settings (`pages/settings.html`)
- **Purpose**: User profile management, password updates, scan default configurations, theme toggling, and notification preferences.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Mobile overlay.
  - `a.side-link[data-action="logout"]`: Logout link.
  - `button#themeToggle` (`data-action="toggle-theme"`): Light/Dark theme toggle.
  - `div#settingsTabs button.tab-btn` (`data-action="switch-tab"`): Section navigation (`profile`, `security`, `scanning`, `preferences`, `notifications`).
  - `h3#previewName`, `p#previewEmail`, `span#previewRole`, `span#avatarLetter`: Profile cards (`<!-- DATA: profile metadata rendered by settings.js -->`).
  - `input#fullName`: Full name field (`<!-- DATA: user profile values populated by settings.js -->`).
  - `input#currentPassword`, `input#newPassword`, `input#confirmPassword`: Password fields.
  - `button.password-toggle` (`data-action="toggle-password"`): Password mask toggles.
  - `select#defaultDepth`: Scan depth default select.
  - `input#notifyComplete`, `input#notifyFailed`, `input#notifyCritical`: Notification preference toggles.
  - `span#saveStatus`: Auto-save status indicator (`<!-- DATA: settings save indicator updated by settings.js -->`).
  - `button#resetDefaults` (`data-action="reset-defaults"`): Reset button.
  - `button#saveChanges` (`data-action="save-settings"`): Primary save changes button.
  - `div#toast`: Toast container.
- **Legacy API Endpoints Called**:
  - `GET http://127.0.0.1:8000/api/user/profile`.
  - `PUT http://127.0.0.1:8000/api/user/profile` with `{"full_name": "..."}`.
  - `GET http://127.0.0.1:8000/api/user/settings`.
  - `PUT http://127.0.0.1:8000/api/user/settings` with preferences.
- **Legacy Response Handling**:
  - Updated form inputs, showed toast notification, updated `#saveStatus`.
- **API Spec Analysis (`docs/api_spec.md`)**:
  - `GET /api/user/profile` returns `{id, email, full_name, role, is_active}`. Matches.
  - `PUT /api/user/profile` only accepts `{"full_name": "..."}` (max 150 chars). Note: Username and email updates are rejected by the backend.
  - `PUT /api/user/password` requires `{"current_password": "...", "new_password": "..."}`.
  - `GET /api/user/settings` returns `{default_scan_depth, notify_scan_completed, notify_scan_failed, notify_critical_finding}`.
  - `PUT /api/user/settings` requires all 4 fields. Matches.
- **Old Bugs Discovered**:
  - Legacy script attempted to send `username` and `email` in profile update requests, which causes `422 VALIDATION_ERROR` against FastAPI Pydantic schema.
  - Did not wire `PUT /api/user/password` properly.
  - Inline runtime shim masked failures.
- **Visual Differences**: None.

---

### 2.14 Target Verification (`pages/target_verify.html`)
- **Purpose**: Enforces domain ownership challenge verification (DNS TXT, meta tag, or HTTP file challenge) prior to initiating scans.
- **IDs & `data-action` Attributes Requiring Behavior**:
  - `button#sidebarToggle` (`data-action="toggle-sidebar"`): Mobile toggle.
  - `div#sidebarOverlay` (`data-action="close-sidebar"`): Mobile overlay.
  - `a.side-link[data-action="logout"]`: Logout link.
  - `div#targetVerifyContainer`: Dynamic verification instructions, token display, and challenge verification controls (`<!-- DATA: target verification details filled by target_verify.js -->`).
- **Required API Endpoints (`docs/api_spec.md`)**:
  - `GET /api/targets`: Lists user targets.
  - `POST /api/targets`: Adds target domain (`{"url": "...", "verification_method": "meta_tag|http_file|dns_txt"}`).
  - `GET /api/targets/{target_id}`: Retrieves verification instructions and verification token.
  - `POST /api/targets/{target_id}/verify`: Triggers server-side domain verification check.
- **Visual Differences**: Clean layout consistent with the volcano theme shell.

---

## 3. External Resources & CDN Audit

| Resource URL | Resource Type | Where Loaded | Status / Usage Assessment |
|:---|:---|:---|:---|
| `https://fonts.googleapis.com` | Font CDN Preconnect | `contact.html`, `features.html`, `index.html` | Active. Preconnects to Google Fonts for performance. |
| `https://fonts.gstatic.com` | Font CDN Preconnect | `contact.html`, `features.html`, `index.html` | Active. Cross-origin font asset preconnect. |
| `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap` | Font Stylesheet | `contact.html`, `features.html`, `index.html`, and imported in `sty.css` (`landing.css`) | Active. Primary typography font faces (`Inter` and `Space Grotesk`). |
| `https://cdn.jsdelivr.net/npm/chart.js` | JavaScript CDN | `dashboard.html` (`dashboardfinal.html`) | **FLAGGED: LOADED BUT NOT USED**. `dashboardfinal.js` implements its own custom Canvas 2D rendering pipeline (`createScansChart`, `createTrendChart`, `roundedBar`, `dashedLine`). Chart.js is never instantiated or invoked anywhere in the codebase. Preserved in `<head>` per migration instructions. |

---

## 4. `innerHTML` Dynamic Data Audit

The legacy frontend frequently interpolated server responses and user-controlled strings into `innerHTML`. Below is every identified occurrence:

| Legacy Source File | Line | Element / Context | Interpolated Data / Security Risk |
|:---|:---|:---|:---|
| `dashboardfinal.js` | 197 | `list.innerHTML` | Interpolated `scan.target_url`, `scan.status`, timestamps into table rows without full HTML escaping. |
| `scanjavafinal.js` | 369 | `historyList.innerHTML` | Interpolated `s.target_url`, `s.status`, `s.started_at` into HTML string template. |
| `scanjavafinal.js` | 402 | `recentTargets.innerHTML` | Interpolated unique URL strings directly into target chip buttons. |
| `scan_historyjava.js` | 218 | `tableBody.innerHTML` | Interpolated `scan.target_url`, `scan.id`, finding severity counters, and dates into `<tr>` rows. |
| `resultsjava.js` | 287 | `list.innerHTML` | Interpolated finding titles, affected URLs, and module categories into card accordions. |
| `resultsjava.js` | 402 | `steps.innerHTML` | Interpolated remediation recommendation strings directly into `<li>` elements. |
| `reportjava.js` | 99 | `listEl.innerHTML` | Interpolated report IDs, target hosts, scores, and dates into report selection list. |
| `reportjava.js` | 149 | `docEl.innerHTML` | Comprehensive document renderer interpolating target host, findings array, evidence strings, and OWASP tags into assessment document. |
| `reportjava.js` | 311 | `summaryEl.innerHTML` | Interpolated simulated AI executive summary text directly into summary container. |
| `assistantjava.js` | 109 | `bubble.innerHTML` | Conditional interpolation: user message was escaped, but AI response underwent regex replacements (`formatMessage`) and was injected as raw HTML. |
| `settingsjava.js` | 264 | `$("saveStatus").innerHTML` | Injected status indicator markup. |

---

## 5. Backend Mount & Routing Architecture

Inspecting `backend/app/main.py`:
```python
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    pages_dir = frontend_dir / "pages"
    if (pages_dir / "index.html").exists():
        @app.get("/", include_in_schema=False)
        def read_root():
            return FileResponse(pages_dir / "index.html")
```

### Exact URL Routes for Each Page

| Page | Exact URL Route |
|:---|:---|
| Landing / Home | `http://127.0.0.1:8000/` or `http://127.0.0.1:8000/static/pages/index.html` |
| Dashboard | `http://127.0.0.1:8000/static/pages/dashboard.html` |
| New Scan | `http://127.0.0.1:8000/static/pages/new_scan.html` |
| Live Scan | `http://127.0.0.1:8000/static/pages/live_scan.html` |
| Scan History | `http://127.0.0.1:8000/static/pages/history.html` |
| Scan Results | `http://127.0.0.1:8000/static/pages/results.html` |
| Reports | `http://127.0.0.1:8000/static/pages/reports.html` |
| AI Assistant | `http://127.0.0.1:8000/static/pages/ai_assistant.html` |
| Settings | `http://127.0.0.1:8000/static/pages/settings.html` |
| Login | `http://127.0.0.1:8000/static/pages/login.html` |
| Sign Up | `http://127.0.0.1:8000/static/pages/signup.html` |
| Features | `http://127.0.0.1:8000/static/pages/features.html` |
| Contact Us | `http://127.0.0.1:8000/static/pages/contact.html` |
| Target Verification | `http://127.0.0.1:8000/static/pages/target_verify.html` |
