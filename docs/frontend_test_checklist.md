# Frontend Manual Test Checklist

Run the API and serve the frontend from the same origin, then open the URLs listed in `README.md`.

- [ ] Register a new account with a valid email and password. Confirm the app returns to sign-in with an account-created message.
- [ ] Log out using the dashboard button. Confirm the login page appears and browser localStorage is empty.
- [ ] Log in with the new email and a wrong password. Confirm the API error is visible and the page does not redirect.
- [ ] Log in with the correct password. Confirm the dashboard opens and shows the validated account name and email.
- [ ] Log out, then open the dashboard URL directly. Confirm the login page appears.
- [ ] Sign in, edit the `token` value in localStorage to a fake token, and reload the dashboard. Confirm the login page appears and all localStorage credentials are cleared.
- [ ] Open the browser Network tab while signing in and visiting the dashboard. Confirm requests are limited to the expected `/api/auth/login` and `/api/auth/me` API calls; no third-party script request is made by the dashboard.

## Target Verification (`/static/pages/target_verify.html`)

- [ ] Open target verification while signed out. Confirm the protected-page auth check redirects to sign-in; sign in and return to the page.
- [ ] Confirm the legal authorization notice is visible above the add-target form at desktop and phone widths.
- [ ] Add a valid HTTPS URL using each method (meta tag, DNS TXT, verification file). Confirm the target appears with its method, unverified badge, and timestamps, and the new target's instructions open automatically.
- [ ] Confirm the proof area shows the token and only the selected method's proof fields. Use each Copy button and verify the copied value; repeat with clipboard permissions unavailable to exercise the fallback.
- [ ] Select an existing target. Confirm the page fetches its detail endpoint and displays the method-correct proof and token.
- [ ] Submit a malformed URL, a duplicate URL, and private, loopback, and metadata-service addresses. Confirm the server's error message is shown without clearing the form or navigating away.
- [ ] Publish the indicated proof at the target, select Verify now, and confirm the button disables with a visible pending state. Confirm the badge becomes Verified only when the response has `is_verified: true`.
- [ ] Attempt verification without publishing the proof. Confirm the server failure reason and updated last-checked time are shown, with no success message or verified badge.
- [ ] Delete a target and cancel once; confirm it remains. Delete again and confirm the prompt warns that scans and findings will be deleted, then confirm the target is removed and the list refreshes.
- [ ] Confirm a verified target has a Scan this target link to `new_scan.html?target=<id>`.
- [ ] With no targets, confirm the friendly empty state. Confirm API/network errors appear visibly and the Refresh action retries the list.
- [ ] Confirm no inline scripts, inline event handlers, `innerHTML`, or external scripts are used on this page.

## New Scan (`/static/pages/new_scan.html`)

- [ ] Open the page signed in. Confirm verified targets are selectable, unverified targets are disabled, and the verification link is present. With no verified targets, confirm the friendly empty state and link.
- [ ] Open `new_scan.html?target=<verified-target-id>` and confirm only a matching verified target from the user's list is preselected. Try an invalid or unowned ID and confirm it is ignored.
- [ ] Confirm quick, standard, and deep descriptions match their scan behavior and the preference from `/api/user/settings` is selected by default.
- [ ] Confirm all eleven module choices start checked, Select all/none works, and an empty selection blocks submission with a clear message.
- [ ] Confirm the legal notice appears above Start scan and the ownership/permission reminder checkbox is required to submit.
- [ ] Start a scan against the demo target verified in Step 4B, selecting only a few modules. Confirm one `POST /api/scans` request contains `target_id`, `depth`, and the selected `modules`, then opens `live_scan.html?id=<id>`.
- [ ] Double-click Start scan while the request is pending. Confirm only one create request is sent.
- [ ] Try to select an unverified target and confirm it cannot be selected. Confirm server validation errors are shown using the API's message.
- [ ] Confirm the page remains usable at phone width and has no inline scripts, inline event handlers, `innerHTML`, or external scripts.

## Live Scan (`/static/pages/live_scan.html`)

- [ ] Open a valid scan URL and confirm progress percentage, status, current module, and per-module pending/running/done/error states update as the scan progresses.
- [ ] Start a demo-target scan with a few modules and watch progress move. Confirm requests to status are chained at about two-second intervals and never overlap; background tabs poll more slowly.
- [ ] Cancel a queued/running scan and confirm the confirmation prompt, request result, and terminal cancelled state. Confirm polling stops after completion, failure, or cancellation.
- [ ] Stop the demo target and start a scan; confirm a module error state is shown without breaking the page.
- [ ] Open `live_scan.html` with a missing or malformed ID and confirm an error plus a link to scan history. Open a syntactically valid but nonexistent UUID and a scan ID belonging to another user; confirm “Scan not found”.
- [ ] Simulate a temporary network failure. Confirm a few retries occur, then a clear message and Retry status button appear; confirm Retry resumes polling. Confirm a 401 is handled by shared `api.js` authentication.
- [ ] On completion, confirm a clear completion message and View results link. On failed/cancelled status, confirm the status, fixed API error message when present, and links to new scan and results.
- [ ] Confirm both pages remain usable at phone width and use no inline scripts, inline event handlers, `innerHTML`, or external scripts.

## Scan Results (`/static/pages/results.html`)

- [ ] Run the demo target scan with findings, open its results, and confirm the Critical count appears first and prominently. With a Critical finding, confirm the verdict is Critical and the page never shows safe/no-vulnerabilities copy.
- [ ] Confirm target URL, scan start/finish times, depth, score, verdict, Critical/High/Medium/Low/Info counts, Passed count, and scanner-error count are shown.
- [ ] Filter findings by severity, module, status, and title/URL search. Confirm top-level severity totals do not change when filters change.
- [ ] Change a finding status and confirm the API update and status badge; confirm the score and verdict remain unchanged after marking false positive.
- [ ] Expand evidence and confirm it is in a `<pre>`, masked, and contains no cookie values. Confirm demo fake XSS/stack-trace strings are plain text and never execute.
- [ ] Try affected URLs beginning with `javascript:` and `data:` in a finding fixture; confirm they remain plain text. Confirm valid HTTP(S) URLs use safe new-tab links.
- [ ] Open results with a malformed ID, a valid made-up UUID, and another user's scan ID. Confirm malformed input shows an ID error, and missing/other-user scans show the same not-found message.
- [ ] Open a queued/running scan's results and confirm its status and live-scan link; confirm failed/cancelled scans show status and fixed API error text.
- [ ] Confirm clean scans say only that checks which ran found nothing and include the Passed count; when scanner errors exist, confirm the page says checks could not run.
- [ ] Confirm Run another scan carries the target ID when available. On completed scans, confirm the Create report button is visible. Select Create report and confirm it disables with a visible pending state, issues POST /api/reports {scan_id, report_format: "pdf"}, and navigates to reports.html?id=<report id> on 200/201. Confirm non-completed scans keep Create report hidden, and any API failure (such as 409) shows the server's error message. Check the page at phone width.

## Scan History (`/static/pages/history.html`)

- [ ] Confirm history requests use page/page_size=10, and status and target filters are sent to the API. Verify targets populate the target filter.
- [ ] Page forward and backward; confirm total and page labels, end-state disabling, and disabled controls while loading.
- [ ] Confirm each row shows target URL, status, depth, progress or score, start time, and severity counts with Critical first. At phone width, confirm rows stack without horizontal scrolling.
- [ ] Open a completed row to results and a queued/running row to live scan.
- [ ] Delete a finished scan and confirm its findings/reports warning, deletion, and refreshed list. Delete a running scan and confirm the API 409 message advises cancelling first.
- [ ] Delete the only row on a later page and confirm the list moves back to the previous page. Confirm an empty history links to New Scan.
- [ ] Confirm API errors are visible and repeated delete/page clicks do not send duplicate actions.
- [ ] Confirm both pages use no inline scripts, inline event handlers, `innerHTML`, or external scripts.

## Security Dashboard (`/static/pages/dashboard.html`)

- [ ] Open the dashboard while signed in. Confirm the loading state appears politely and the page loads `/api/dashboard/summary`.
- [ ] Verify the five summary counters display total targets, verified targets, total scans, completed scans, and latest security score (or "—" if none).
- [ ] With a fresh user account having no scans, confirm the empty state is displayed with zeros, the friendly message, and working links to `target_verify.html` and `new_scan.html`.
- [ ] Confirm severity distribution renders 5 plain HTML/CSS bars in exact order: Critical, High, Medium, Low, Info, with numbers printed beside each bar. Confirm the exact note is present beneath: "Counts open and confirmed findings from the latest completed scan of each target. Findings marked false positive or resolved are not counted."
- [ ] Confirm recent scans display up to 5 scans with target URL, status badge, score, and started time. Confirm queued/running scans link to `live_scan.html?id=<id>` and completed/failed/cancelled scans link to `results.html?id=<id>`.
- [ ] Confirm API errors show the server's message visibly, and the dashboard remains fully usable at phone widths without layout breakages.
- [ ] Confirm no inline scripts, inline event handlers, `innerHTML`, or external scripts are used on this page.

## Assessment Reports (`/static/pages/reports.html`)

- [ ] Open `/static/pages/reports.html` while signed in. Confirm the page requests `GET /api/reports?page=1&page_size=10` and renders past reports newest first with target URL, scan date, score badge, verdict, and link to open.
- [ ] When no reports exist, confirm the friendly empty state explaining how to create a report from a completed scan with a link to Scan History.
- [ ] Page forward and backward using Previous/Next buttons; confirm buttons disable on boundaries and while requests are running.
- [ ] Open a report via `reports.html?id=<valid-id>`. Confirm `GET /api/reports/{id}` loads target URL, scan dates, depth, score, verdict message, severity breakdown (Critical first, High, Medium, Low, Info, Passed, Errors).
- [ ] Confirm the per-module summary table displays module name, status, checks run, checks passed, and findings count.
- [ ] Confirm findings are rendered in API order with title, severity, safe affected URL link (`target="_blank" rel="noopener noreferrer"`), OWASP and CWE tags, description, evidence in `<pre>`, and remediation.
- [ ] Open a report with a malformed ID and confirm an invalid ID error plus a link to the reports list. Open a syntactically valid nonexistent UUID or another user's report ID; confirm the same "Report not found." message and link.
- [ ] Click Export PDF and confirm `window.print()` is triggered. Confirm `@media print` styles hide navigation, sidebar, and buttons, render black on white, keep findings expanded without page breaks inside findings, and display severity as text.
- [ ] Confirm the page remains responsive and usable at phone width, and uses no inline scripts, inline event handlers, `innerHTML`, or external scripts.