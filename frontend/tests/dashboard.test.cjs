const assert = require("node:assert/strict");
const test = require("node:test");

const {
	SEVERITIES,
	formatDate,
	formatStatus,
	getBarWidth,
	getDashboardText,
	getScanLink,
	getStatusBadgeClass
} = require("../js/dashboard.js");

test("severity order preserves Critical first across all five tiers", () => {
	assert.deepEqual(SEVERITIES, ["critical", "high", "medium", "low", "info"]);
});

test("bar width scales relative to maximum and clamps between bounds", () => {
	assert.equal(getBarWidth(0, 0), 0);
	assert.equal(getBarWidth(0, 10), 0);
	assert.equal(getBarWidth(10, 0), 0);
	assert.equal(getBarWidth(-5, 10), 0);
	assert.equal(getBarWidth(10, 10), 100);
	assert.equal(getBarWidth(5, 10), 50);
	// Small non-zero count gets minimum visible bar width of 6%
	assert.equal(getBarWidth(1, 100), 6);
	// Clamped at 100% even if value exceeds maximum
	assert.equal(getBarWidth(15, 10), 100);
});

test("dashboard text formats numbers safely and handles empty or missing data", () => {
	assert.deepEqual(getDashboardText({}), {
		totalTargets: 0,
		verifiedTargets: 0,
		totalScans: 0,
		completedScans: 0,
		latestScore: "—"
	});
	assert.deepEqual(getDashboardText(null), {
		totalTargets: 0,
		verifiedTargets: 0,
		totalScans: 0,
		completedScans: 0,
		latestScore: "—"
	});
	assert.deepEqual(
		getDashboardText({
			total_targets: 4,
			verified_targets: 3,
			total_scans: 12,
			completed_scans: 10,
			latest_security_score: 85
		}),
		{
			totalTargets: 4,
			verifiedTargets: 3,
			totalScans: 12,
			completedScans: 10,
			latestScore: "85"
		}
	);
	assert.deepEqual(
		getDashboardText({
			total_targets: -1,
			verified_targets: "invalid",
			total_scans: null,
			completed_scans: undefined,
			latest_security_score: null
		}),
		{
			totalTargets: 0,
			verifiedTargets: 0,
			totalScans: 0,
			completedScans: 0,
			latestScore: "—"
		}
	);
});

test("scan link routes queued and running scans to live view and finished scans to results", () => {
	const scanId = "550e8400-e29b-41d4-a716-446655440000";
	assert.equal(getScanLink({ id: scanId, status: "queued" }), `live_scan.html?id=${scanId}`);
	assert.equal(getScanLink({ id: scanId, status: "running" }), `live_scan.html?id=${scanId}`);
	assert.equal(getScanLink({ id: scanId, status: "RUNNING" }), `live_scan.html?id=${scanId}`);
	assert.equal(getScanLink({ id: scanId, status: "completed" }), `results.html?id=${scanId}`);
	assert.equal(getScanLink({ id: scanId, status: "failed" }), `results.html?id=${scanId}`);
	assert.equal(getScanLink({ id: scanId, status: "cancelled" }), `results.html?id=${scanId}`);
	assert.equal(getScanLink({ id: scanId, status: "unknown" }), `results.html?id=${scanId}`);
	assert.equal(getScanLink(null), "results.html?id=");
});

test("date formatting provides safe readable text or fallback", () => {
	assert.equal(formatDate(null), "Not available");
	assert.equal(formatDate(""), "Not available");
	assert.equal(formatDate("not-a-date"), "Not available");
	const formatted = formatDate("2026-10-15T12:00:00Z");
	assert.notEqual(formatted, "Not available");
	assert.match(formatted, /2026/);
});

test("status labels and badge classes map recognized and unknown states", () => {
	assert.equal(formatStatus("completed"), "Completed");
	assert.equal(formatStatus("running"), "Running");
	assert.equal(formatStatus(""), "Unknown");
	assert.equal(formatStatus(null), "Unknown");

	assert.equal(getStatusBadgeClass("queued"), "status-queued");
	assert.equal(getStatusBadgeClass("running"), "status-running");
	assert.equal(getStatusBadgeClass("completed"), "status-completed");
	assert.equal(getStatusBadgeClass("failed"), "status-failed");
	assert.equal(getStatusBadgeClass("cancelled"), "status-cancelled");
	assert.equal(getStatusBadgeClass("other"), "status-unknown");
	assert.equal(getStatusBadgeClass(null), "status-unknown");
});
