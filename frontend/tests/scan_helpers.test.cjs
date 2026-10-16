const assert = require("node:assert/strict");
const test = require("node:test");

const {
	SEVERITY_ORDER,
	formatTimestamp,
	getSeverityCount,
	getVerdictKey,
	getVerdictMessage,
	isSafeHttpUrl,
	isValidUuid,
	parseIdFromQuery,
	parseScanId,
	severityClass
} = require("../js/scan_helpers.js");

test("scan_helpers exports canonical severity ordering with Critical first", () => {
	assert.deepEqual(SEVERITY_ORDER, ["critical", "high", "medium", "low", "info"]);
	assert.equal(severityClass("critical"), "severity-critical");
	assert.equal(severityClass("HIGH"), "severity-high");
	assert.equal(severityClass("unknown"), "severity-info");
});

test("scan_helpers validates UUID formats and query parameters", () => {
	const validUuid = "550e8400-e29b-41d4-a716-446655440000";
	assert.equal(isValidUuid(validUuid), true);
	assert.equal(isValidUuid("not-a-uuid"), false);
	assert.equal(isValidUuid(null), false);
	assert.equal(parseIdFromQuery(`?id=${validUuid}`), validUuid);
	assert.equal(parseIdFromQuery(`?custom_id=${validUuid}`, "custom_id"), validUuid);
	assert.equal(parseIdFromQuery("?id=invalid"), null);
	assert.equal(parseScanId(`?id=${validUuid}`), validUuid);
	assert.equal(parseScanId(""), null);
});

test("scan_helpers strictly validates safe HTTP and HTTPS URLs", () => {
	assert.equal(isSafeHttpUrl("https://example.com/test"), true);
	assert.equal(isSafeHttpUrl("http://example.com/"), true);
	assert.equal(isSafeHttpUrl("ftp://example.com"), false);
	assert.equal(isSafeHttpUrl("javascript:alert(1)"), false);
	assert.equal(isSafeHttpUrl("data:text/html,test"), false);
	assert.equal(isSafeHttpUrl(null), false);
	assert.equal(isSafeHttpUrl(""), false);
});

test("scan_helpers derives verdict precedence prioritizing critical findings", () => {
	assert.equal(getVerdictKey({ findings: [{ severity: "critical" }] }), "critical");
	assert.equal(getVerdictKey({ counts: { critical: 1 } }), "critical");
	assert.equal(getVerdictKey({ verdict: "safe", counts: { high: 2 } }), "high");
	assert.equal(getVerdictKey({ verdict: "safe", scanner_error_count: 1 }), "scanner_error");
	assert.equal(getVerdictKey({ verdict: "safe" }), "safe");
	assert.match(getVerdictMessage("critical"), /Critical vulnerabilities/);
	assert.match(getVerdictMessage("safe", 5), /Passed checks: 5/);
});

test("scan_helpers aggregates severity counts and handles missing data", () => {
	assert.equal(getSeverityCount({ counts: { critical: 4 } }, "critical"), 4);
	assert.equal(getSeverityCount({ findings: [{ severity: "high" }, { severity: "high" }] }, "high"), 2);
	assert.equal(getSeverityCount(null, "critical"), 0);
});

test("scan_helpers safely formats timestamps with invalid input protection", () => {
	assert.equal(formatTimestamp(null), "Not available");
	assert.equal(formatTimestamp("invalid-date"), "Not available");
	assert.match(formatTimestamp("2026-10-16T08:00:00Z"), /2026/);
});
