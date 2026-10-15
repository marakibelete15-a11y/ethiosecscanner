const assert = require("node:assert/strict");
const test = require("node:test");

const { DEPTHS, MODULES, getDefaultDepth, parseTargetId, selectedModuleKeys } = require("../js/new_scan.js");

test("depth defaults use the account preference and fall back to standard", () => {
	assert.equal(getDefaultDepth({ default_scan_depth: "deep" }), "deep");
	assert.equal(getDefaultDepth({ default_scan_depth: "invalid" }), "standard");
	assert.equal(getDefaultDepth(null), "standard");
	assert.match(DEPTHS.quick, /passive checks only/);
	assert.match(DEPTHS.standard, /limited crawl/);
	assert.match(DEPTHS.deep, /takes longest/);
});

test("module list covers all eleven backend keys and selection preserves canonical order", () => {
	assert.deepEqual(MODULES.map(({ key }) => key), [
		"headers", "https", "cookies", "cors", "http_methods", "info_disclosure",
		"exposed_files", "sqli", "xss", "access_control", "auth_checks"
	]);
	assert.deepEqual(selectedModuleKeys(["xss", "headers", "not_a_module"]), ["headers", "xss"]);
	assert.deepEqual(selectedModuleKeys([]), []);
});

test("target query parser accepts only a UUID target parameter", () => {
	assert.equal(parseTargetId("?target=550e8400-e29b-41d4-a716-446655440000"), "550e8400-e29b-41d4-a716-446655440000");
	assert.equal(parseTargetId("?target=not-a-uuid"), null);
	assert.equal(parseTargetId("?other=550e8400-e29b-41d4-a716-446655440000"), null);
});