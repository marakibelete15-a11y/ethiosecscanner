# EthioSec Scanner API Specification

Base URL for local development: `http://127.0.0.1:8000`. Protected routes require `Authorization: Bearer <access_token>`. Unless stated otherwise, errors use `{"error":{"code":"...","message":"..."}}`. Schema validation failures return `422 VALIDATION_ERROR`; missing/invalid credentials return `401 UNAUTHORIZED`; unexpected server errors return generic `500 INTERNAL_SERVER_ERROR`.

Page-number endpoints default to `page=1&page_size=20` and allow page sizes from 1 to 100. IDs are UUIDs. Finding severity values are `critical`, `high`, `medium`, `low`, and `info`.

## Authentication

| Method and path | Login | Request | Success | Endpoint errors |
|---|---|---|---|---|
| `POST /api/auth/register` | No | `{"email":"person@example.com","password":"StrongPass123!","full_name":"Optional name"}` | `201`; user `{id,email,full_name,role,is_active,created_at,updated_at}`. Password/hash are never returned. | `400 EMAIL_ALREADY_EXISTS`; `422 VALIDATION_ERROR`. |
| `POST /api/auth/login` | No | `{"email":"person@example.com","password":"StrongPass123!"}` | `200`; `{"access_token":"...","token_type":"bearer"}` | `401 UNAUTHORIZED` for unknown email/wrong password; `401 ACCOUNT_INACTIVE`; `422 VALIDATION_ERROR`. |
| `GET /api/auth/me` | Yes | None | `200`; user `{id,email,full_name,role,is_active,created_at,updated_at}`. | `401 UNAUTHORIZED`. |

## Targets

| Method and path | Login | Request | Success | Endpoint errors |
|---|---|---|---|---|
| `GET /api/targets` | Yes | None | `200`; array of the user’s target objects `{id,url,normalized_url,verification_method,verification_token,is_verified,verified_at,last_checked_at,created_at,updated_at,instructions}`. | `401 UNAUTHORIZED`. |
| `POST /api/targets` | Yes | `{"url":"https://example.com","verification_method":"meta_tag"}`; method may be `meta_tag`, `http_file`, or `dns_txt`. | `201`; target object including verification instructions and token. | `400 INVALID_URL`, `SSRF_ERROR`, or `TARGET_ALREADY_EXISTS`; `422 VALIDATION_ERROR`; `401 UNAUTHORIZED`. |
| `GET /api/targets/{target_id}` | Yes | None | `200`; target object and verification instructions. | `404 TARGET_NOT_FOUND` for absent or another user’s target; `401 UNAUTHORIZED`. |
| `DELETE /api/targets/{target_id}` | Yes | None | `200`; `{"message":"Target and all associated data deleted successfully.","target_id":"<uuid>"}`. Related scans, findings, and reports cascade. | `404 TARGET_NOT_FOUND`; `401 UNAUTHORIZED`. |
| `POST /api/targets/{target_id}/verify` | Yes | None | `200`; target verification state, `message`, and optional `details`. | `404 TARGET_NOT_FOUND`; `401 UNAUTHORIZED`. |

## Scans

| Method and path | Login | Request | Success | Endpoint errors |
|---|---|---|---|---|
| `POST /api/scans` | Yes | `{"target_id":"<uuid>","depth":"standard","modules":["headers"]}`. Depth may be omitted or be `quick`, `standard`, `deep`; modules may be omitted to select all implemented modules. | `201`; `{"id":"<uuid>","status":"queued","progress":0,"depth":"standard","selected_modules":[...]}`. | `404 TARGET_NOT_FOUND`; `400 TARGET_NOT_VERIFIED`, `SSRF_ERROR`, `INVALID_URL`, or `MODULE_NOT_IMPLEMENTED`; `422 UNKNOWN_MODULE`, `MODULES_REQUIRED`, or `VALIDATION_ERROR`; `401 UNAUTHORIZED`. |
| `GET /api/scans` | Yes | Query: optional `status`, `target_id`, `page`, `page_size`. | `200`; `{"total":n,"page":1,"page_size":20,"scans":[{id,target_url,status,depth,progress,security_score,started_at,finished_at,finding_counts}]}`. Counts include all persisted findings. | `422 INVALID_SCAN_STATUS` or `VALIDATION_ERROR`; `401 UNAUTHORIZED`. |
| `GET /api/scans/{scan_id}` | Yes | None | `200`; scan detail including `target_id`, `target_url`, status/depth/progress, `current_module`, `security_score`, `selected_modules`, `module_progress`, `error_message`, and timestamps. | `404 SCAN_NOT_FOUND`; `401 UNAUTHORIZED`. |
| `DELETE /api/scans/{scan_id}` | Yes | None | `200`; `{"id":"<uuid>","message":"Scan and associated data deleted successfully."}`. Findings and reports cascade. | `404 SCAN_NOT_FOUND`; `409 SCAN_ACTIVE` (cancel first); `401 UNAUTHORIZED`. |
| `GET /api/scans/{scan_id}/status` | Yes | None | `200`; scan state, progress, module progress, error, and timestamps. | `404 SCAN_NOT_FOUND`; `401 UNAUTHORIZED`. |
| `GET /api/scans/{scan_id}/results` | Yes | None | `200`; `{"id":"<uuid>","status":"completed","score":n,"verdict":"critical|high|medium|low|info|scanner_error|safe","counts":{...},"passed_count":n,"scanner_error_count":n,"findings":[...]}`. Critical findings take precedence. | `404 SCAN_NOT_FOUND`; `401 UNAUTHORIZED`. |
| `POST /api/scans/{scan_id}/cancel` | Yes | None | `200`; `{"id":"<uuid>","status":"queued|running","message":"Cancellation requested."}`. | `404 SCAN_NOT_FOUND`; `409 SCAN_NOT_ACTIVE`; `401 UNAUTHORIZED`. |

## Findings

| Method and path | Login | Request | Success | Endpoint errors |
|---|---|---|---|---|
| `PATCH /api/findings/{finding_id}` | Yes | `{"status":"open"}`; values: `open`, `confirmed`, `false_positive`, `resolved`. No other fields accepted. | `200`; full finding representation. Changing status does not alter scan counts, score, or verdict. | `404 FINDING_NOT_FOUND` for absent/other-user finding; `422 VALIDATION_ERROR`; `401 UNAUTHORIZED`. |

## Reports

| Method and path | Login | Request | Success | Endpoint errors |
|---|---|---|---|---|
| `POST /api/reports` | Yes | `{"scan_id":"<uuid>","report_format":"json"}`; format: `pdf`, `html`, `json`. | `201` new, `200` regeneration. Returns `{id,scan_id,report_format,created_at,summary}`. Summary includes target/dates/depth/score/verdict/counts/passed count/scanner errors/per-module data/total findings. Format is a label; API returns JSON. | `404 SCAN_NOT_FOUND`; `409 SCAN_NOT_COMPLETED`; `422 VALIDATION_ERROR`; `401 UNAUTHORIZED`. |
| `GET /api/reports` | Yes | Query: `page`, `page_size`. | `200`; `{"total":n,"page":1,"page_size":20,"reports":[{id,scan_id,report_format,created_at,summary}]}`. | `422 VALIDATION_ERROR`; `401 UNAUTHORIZED`. |
| `GET /api/reports/{report_id}` | Yes | None | `200`; report plus Critical-first findings with severity, title, description, evidence, remediation, affected URL, OWASP category, and CWE ID. | `404 REPORT_NOT_FOUND`; `401 UNAUTHORIZED`. |

## Dashboard and User

| Method and path | Login | Request | Success | Endpoint errors |
|---|---|---|---|---|
| `GET /api/dashboard/summary` | Yes | None | `200`; `{total_targets,verified_targets,total_scans,completed_scans,recent_scans,latest_security_score,severity_distribution}`. Distribution counts `open` and `confirmed` findings from each target’s newest completed scan. | `401 UNAUTHORIZED`. |
| `GET /api/user/profile` | Yes | None | `200`; `{id,email,full_name,role,is_active}`. | `401 UNAUTHORIZED`. |
| `PUT /api/user/profile` | Yes | `{"full_name":"New Name"}`; only this field is accepted, trimmed, non-empty, maximum 150 characters. | `200`; profile object. | `422 VALIDATION_ERROR`; `401 UNAUTHORIZED`. |
| `PUT /api/user/password` | Yes | `{"current_password":"CurrentPass123!","new_password":"NewPass456!"}`. New password follows registration rules, differs from current, and is at most 72 UTF-8 bytes. | `200`; `{"message":"Password updated successfully."}`. Existing tokens remain valid until expiration. | `400 INVALID_CURRENT_PASSWORD`; `422 VALIDATION_ERROR`; `401 UNAUTHORIZED`. |
| `GET /api/user/settings` | Yes | None | `200`; `{default_scan_depth,notify_scan_completed,notify_scan_failed,notify_critical_finding}`. | `401 UNAUTHORIZED`. |
| `PUT /api/user/settings` | Yes | All four fields required; depth is `quick`, `standard`, or `deep`; notification fields are booleans. | `200`; updated settings object. Preferences are stored only; no email is sent. | `422 VALIDATION_ERROR`; `401 UNAUTHORIZED`. |

## Health

| Method and path | Login | Request | Success | Endpoint errors |
|---|---|---|---|---|
| `GET /health` | No | None | `200`; `{"status":"healthy","database":"connected"}`. | Generic shared `500 INTERNAL_SERVER_ERROR` on unexpected failure. |
