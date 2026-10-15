const assert = require("node:assert/strict");
const test = require("node:test");

const {
	SEVERITY_ORDER,
	filterFindings,
	getVerdictKey,
	getVerdictMessage,
	getSeverityCount,
	isSafeHttpUrl,
	parseScanId,
	severityClass
} = require("../js/results.js");

test("results query parser accepts only UUID scan IDs", () => {
	assert.equal(parseScanId("?id=550e8400-e29b-41d4-a716-446655440000"), "550e8400-e29b-41d4-a716-446655440000");
	assert.equal(parseScanId("?id=bad-id"), null);
	assert.equal(parseScanId("?other=550e8400-e29b-41d4-a716-446655440000"), null);
});

test("severity order and badge classes keep Critical first", () => {
	assert.deepEqual(SEVERITY_ORDER, ["critical", "high", "medium", "low", "info"]);
	assert.equal(severityClass("critical"), "severity-critical");
	assert.equal(severityClass("untrusted"), "severity-info");
});

test("severity totals fall back to findings when a partial response omits counts", () => {
	assert.equal(getSeverityCount({ findings: [{ severity: "critical" }, { severity: "high" }] }, "critical"), 1);
	assert.equal(getSeverityCount({ counts: { critical: 3 }, findings: [{ severity: "critical" }] }, "critical"), 3);
});

test("verdict precedence cannot mask Critical or scanner errors with a safe message", () => {
	assert.equal(getVerdictKey({ verdict: "safe", counts: { critical: 1 } }), "critical");
	assert.equal(getVerdictKey({ verdict: "safe", findings: [{ severity: "critical" }] }), "critical");
	assert.equal(getVerdictKey({ verdict: "safe", counts: {}, scanner_error_count: 2 }), "scanner_error");
	assert.match(getVerdictMessage("critical"), /Critical vulnerabilities/);
	assert.match(getVerdictMessage("scanner_error"), /checks could not run/);
	assert.match(getVerdictMessage("safe", 4), /checks that ran found nothing.*Passed checks: 4/);
});

test("finding filters compose severity, module, status, and title or URL search", () => {
	const findings = [
		{ severity: "critical", module: "xss", status: "open", title: "Reflected text", affected_url: "https://demo.test/search" },
		{ severity: "high", module: "headers", status: "confirmed", title: "Header missing", affected_url: "https://demo.test/" },
		{ severity: "critical", module: "xss", status: "false_positive", title: "Other issue", affected_url: "https://demo.test/other" }
	];
	assert.deepEqual(filterFindings(findings, { severity: "critical", module: "xss", status: "open", query: "search" }), [findings[0]]);
	assert.deepEqual(filterFindings(findings, { query: "demo.test/" }), findings);
	assert.deepEqual(filterFindings(findings, { status: "resolved" }), []);
});

test("only valid HTTP and HTTPS URLs may become links", () => {
	assert.equal(isSafeHttpUrl("https://example.test/path"), true);
	assert.equal(isSafeHttpUrl("HTTP://example.test"), true);
	assert.equal(isSafeHttpUrl("javascript:alert(1)"), false);
	assert.equal(isSafeHttpUrl("data:text/html,hi"), false);
	assert.equal(isSafeHttpUrl("https://"), false);
});