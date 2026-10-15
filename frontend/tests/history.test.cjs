const assert = require("node:assert/strict");
const test = require("node:test");

const { PAGE_SIZE, buildScansQuery, getPageBounds, getPageCount, getScanDestination, getStatusClass } = require("../js/history.js");

test("history uses ten rows and computes page boundaries", () => {
	assert.equal(PAGE_SIZE, 10);
	assert.equal(getPageCount(0), 0);
	assert.equal(getPageCount(21), 3);
	assert.deepEqual(getPageBounds(21, 2), { page: 2, pageCount: 3, canPrevious: true, canNext: true, start: 11, end: 20 });
	assert.deepEqual(getPageBounds(11, 9), { page: 2, pageCount: 2, canPrevious: true, canNext: false, start: 11, end: 11 });
	assert.deepEqual(getPageBounds(0, 1), { page: 1, pageCount: 0, canPrevious: false, canNext: false, start: 0, end: 0 });
});

test("history query includes supported filters and fixed page size", () => {
	const params = new URLSearchParams(buildScansQuery({ page: 3, status: "running", targetId: "target-id" }));
	assert.equal(params.get("page"), "3");
	assert.equal(params.get("page_size"), "10");
	assert.equal(params.get("status"), "running");
	assert.equal(params.get("target_id"), "target-id");
	assert.equal(new URLSearchParams(buildScansQuery({ status: "all", targetId: "all" })).has("status"), false);
});

test("history links active scans to live view and other scans to results", () => {
	assert.equal(getScanDestination("scan-1", "running"), "live_scan.html?id=scan-1");
	assert.equal(getScanDestination("scan 1", "completed"), "results.html?id=scan%201");
	assert.equal(getStatusClass("failed"), "history-status-failed");
	assert.equal(getStatusClass("unexpected"), "history-status-unknown");
});