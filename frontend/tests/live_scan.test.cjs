const assert = require("node:assert/strict");
const test = require("node:test");

const {
	MAX_NETWORK_RETRIES,
	POLL_INTERVAL_MS,
	clampProgress,
	getModuleRows,
	getModuleStateLabel,
	getPollingInterval,
	getStateLabel,
	isNetworkError,
	isTerminalState,
	parseScanId
} = require("../js/live_scan.js");

test("scan query parser accepts a UUID and rejects missing or malformed IDs", () => {
	assert.equal(parseScanId("?id=550e8400-e29b-41d4-a716-446655440000"), "550e8400-e29b-41d4-a716-446655440000");
	assert.equal(parseScanId("?id=bad-id"), null);
	assert.equal(parseScanId("?scan_id=550e8400-e29b-41d4-a716-446655440000"), null);
});

test("progress is rounded and clamped to the API percentage range", () => {
	assert.equal(clampProgress(45.6), 46);
	assert.equal(clampProgress(-3), 0);
	assert.equal(clampProgress(130), 100);
	assert.equal(clampProgress("unknown"), 0);
});

test("module rows map backend states and tolerate partial or unknown data", () => {
	assert.deepEqual(getModuleRows({ headers: { status: "done" }, custom_check: { status: "invalid" }, sqli: null }), [
		{ key: "headers", label: "Security headers", state: "done" },
		{ key: "custom_check", label: "custom check", state: "pending" },
		{ key: "sqli", label: "SQL injection", state: "pending" }
	]);
	assert.deepEqual(getModuleRows(null), []);
	assert.deepEqual(["pending", "running", "done", "error"].map(getModuleStateLabel), ["Pending", "Running", "Done", "Error"]);
});

test("scan state labels, terminal states, and polling intervals are stable", () => {
	assert.equal(getStateLabel("running"), "Running");
	assert.equal(getStateLabel("unexpected"), "Unknown");
	assert.equal(isTerminalState("completed"), true);
	assert.equal(isTerminalState("failed"), true);
	assert.equal(isTerminalState("cancelled"), true);
	assert.equal(isTerminalState("running"), false);
	assert.equal(getPollingInterval(false), POLL_INTERVAL_MS);
	assert.ok(getPollingInterval(true) > POLL_INTERVAL_MS);
});

test("network failures are bounded for retry messaging", () => {
	assert.equal(isNetworkError({ status: 0 }), true);
	assert.equal(isNetworkError({ code: "NETWORK_ERROR" }), true);
	assert.equal(isNetworkError({ status: 404 }), false);
	assert.equal(MAX_NETWORK_RETRIES, 3);
});