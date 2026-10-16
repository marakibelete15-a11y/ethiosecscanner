const assert = require("node:assert/strict");
const test = require("node:test");

const {
	PAGE_SIZE,
	formatFindingMeta,
	getModuleRows,
	getReportPageBounds,
	getScoreClass,
	hasReportIdParam,
	parseReportId
} = require("../js/reports.js");

test("reports constants and query parser validate UUIDs and param presence", () => {
	assert.equal(PAGE_SIZE, 10);
	const validUuid = "550e8400-e29b-41d4-a716-446655440000";
	assert.equal(parseReportId(`?id=${validUuid}`), validUuid);
	assert.equal(parseReportId("?id=bad-uuid"), null);
	assert.equal(parseReportId(""), null);

	assert.equal(hasReportIdParam(`?id=${validUuid}`), true);
	assert.equal(hasReportIdParam("?id=bad-uuid"), true);
	assert.equal(hasReportIdParam("?other=val"), false);
	assert.equal(hasReportIdParam(""), false);
});

test("score classes map numeric ranges correctly", () => {
	assert.equal(getScoreClass(95), "score-good");
	assert.equal(getScoreClass(80), "score-good");
	assert.equal(getScoreClass(79), "score-mid");
	assert.equal(getScoreClass(50), "score-mid");
	assert.equal(getScoreClass(49), "score-bad");
	assert.equal(getScoreClass(0), "score-bad");
	assert.equal(getScoreClass("—"), "score-mid");
});

test("report pagination computes page boundaries and button availability", () => {
	assert.deepEqual(getReportPageBounds(25, 1, 10), {
		page: 1,
		pageCount: 3,
		total: 25,
		canPrevious: false,
		canNext: true
	});
	assert.deepEqual(getReportPageBounds(25, 2, 10), {
		page: 2,
		pageCount: 3,
		total: 25,
		canPrevious: true,
		canNext: true
	});
	assert.deepEqual(getReportPageBounds(25, 3, 10), {
		page: 3,
		pageCount: 3,
		total: 25,
		canPrevious: true,
		canNext: false
	});
	assert.deepEqual(getReportPageBounds(0, 1, 10), {
		page: 1,
		pageCount: 1,
		total: 0,
		canPrevious: false,
		canNext: false
	});
});

test("module rows parser extracts array and dictionary formats", () => {
	const arrayData = {
		summary: {
			modules: [
				{ module: "headers", status: "completed", checks_run: 6, checks_passed: 5, findings_count: 1 },
				{ module: "cookies", status: "completed", checks_run: 4, checks_passed: 4, findings_count: 0 }
			]
		}
	};
	const arrayRows = getModuleRows(arrayData);
	assert.equal(arrayRows.length, 2);
	assert.equal(arrayRows[0].module, "headers");
	assert.equal(arrayRows[0].checksRun, 6);
	assert.equal(arrayRows[0].checksPassed, 5);
	assert.equal(arrayRows[0].findingsCount, 1);

	const objectData = {
		summary: {
			module_progress: {
				cors: { status: "completed", checks_run: 2, checks_passed: 1, findings_count: 1 }
			}
		}
	};
	const objRows = getModuleRows(objectData);
	assert.equal(objRows.length, 1);
	assert.equal(objRows[0].module, "cors");
	assert.equal(objRows[0].checksPassed, 1);

	assert.deepEqual(getModuleRows(null), []);
	assert.deepEqual(getModuleRows({}), []);
});

test("finding metadata formats OWASP and CWE tags", () => {
	assert.equal(formatFindingMeta({ owasp_category: "A03", cwe_id: "CWE-89" }), "OWASP: A03 · CWE: CWE-89");
	assert.equal(formatFindingMeta({ owasp_category: "A01" }), "OWASP: A01");
	assert.equal(formatFindingMeta({ cwe_id: "CWE-79" }), "CWE: CWE-79");
	assert.equal(formatFindingMeta({}), "");
});
