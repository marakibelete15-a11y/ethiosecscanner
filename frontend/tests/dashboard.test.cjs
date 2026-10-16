const assert = require("node:assert/strict");
const test = require("node:test");

const { SEVERITIES, getBarWidth, getDashboardText, getScanLink } = require("../js/dashboard.js");

test("dashboard metric text tolerates null and partial fields", () => {
	assert.deepEqual(getDashboardText({ total_targets: 4, verified_targets: 2, total_scans: 7, completed_scans: 5, latest_security_score: 81 }), {
		totalTargets: 4, verifiedTargets: 2, totalScans: 7, completedScans: 5, latestScore: "81"
	});
	assert.deepEqual(getDashboardText(null), {
		totalTargets: 0, verifiedTargets: 0, totalScans: 0, completedScans: 0, latestScore: "—"
	});
});

test("dashboard severity bars keep critical first and make small nonzero counts visible", () => {
	assert.deepEqual(SEVERITIES, ["critical", "high", "medium", "low", "info"]);
	assert.equal(getBarWidth(0, 0), 0);
	assert.equal(getBarWidth(1, 20), 6);
	assert.equal(getBarWidth(10, 20), 50);
	assert.equal(getBarWidth(30, 20), 100);
});

test("recent scan links route active scans to live progress", () => {
	assert.equal(getScanLink({ id: "a b", status: "running" }), "live_scan.html?id=a%20b");
	assert.equal(getScanLink({ id: "abc", status: "completed" }), "results.html?id=abc");
});