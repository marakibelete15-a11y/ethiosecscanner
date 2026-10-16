const assert = require("node:assert/strict");
const test = require("node:test");

const helpers = require("../js/report_helpers.js");
const { PAGE_SIZE, getReportPageCount, getReportPageState, getReportSummaryValues, parseReportId } = require("../js/reports.js");

test("report IDs must be valid UUIDs", () => {
	assert.equal(parseReportId("?id=550e8400-e29b-41d4-a716-446655440000"), "550e8400-e29b-41d4-a716-446655440000");
	assert.equal(parseReportId("?id=bad-id"), null);
	assert.equal(parseReportId("?other=550e8400-e29b-41d4-a716-446655440000"), null);
});

test("report pagination uses ten rows and clamps to valid pages", () => {
	assert.equal(PAGE_SIZE, 10);
	assert.equal(getReportPageCount(25), 3);
	assert.deepEqual(getReportPageState(25, 9), { page: 3, pageCount: 3, canPrevious: true, canNext: false });
});

test("report summary formats counts and derives passed checks from module data", () => {
	const values = getReportSummaryValues({ summary: {
		target_url: "https://demo.test",
		depth: "standard",
		security_score: 42,
		verdict: "safe",
		counts: { critical: 1, high: 2 },
		module_summary: { headers: { checks_passed: 3 }, cookies: { checks_passed: 4 } },
		scanner_error_count: 0
	} });
	assert.equal(values.verdict, "critical");
	assert.equal(values.passedCount, 7);
	assert.deepEqual(Object.keys(values.counts), ["critical", "high", "medium", "low", "info"]);
	assert.equal(values.counts.critical, 1);
});

test("shared verdict sentences and URL checks match Results", () => {
	assert.equal(helpers.getVerdictMessage("critical"), "Critical vulnerabilities were found. Review and address them before proceeding.");
	assert.equal(helpers.getVerdictKey({ verdict: "safe", counts: { critical: 1 } }), "critical");
	assert.equal(helpers.isSafeHttpUrl("https://example.test/path"), true);
	assert.equal(helpers.isSafeHttpUrl("javascript:alert(1)"), false);
});