const assert = require("node:assert/strict");
const test = require("node:test");

const { DEPTHS, normalizeProfileName, validateNewPassword, validatePasswordForm } = require("../js/settings.js");

test("profile names are trimmed", () => {
	assert.equal(normalizeProfileName("  Ada Lovelace  "), "Ada Lovelace");
	assert.equal(normalizeProfileName("  "), "");
});

test("password checks mirror registration complexity and byte limits", () => {
	assert.deepEqual(DEPTHS, ["quick", "standard", "deep"]);
	assert.equal(validateNewPassword("StrongPass123"), "");
	assert.match(validateNewPassword("weakpass"), /uppercase/);
	assert.match(validateNewPassword("Abcdef1"), /8 characters/);
	assert.match(validateNewPassword("Ā".repeat(36) + "Aa1"), /72 bytes/);
});

test("password form requires current password and matching confirmation", () => {
	assert.match(validatePasswordForm({ newPassword: "StrongPass123", confirmPassword: "StrongPass123" }), /current password/);
	assert.match(validatePasswordForm({ currentPassword: "OldPass123", newPassword: "StrongPass123", confirmPassword: "OtherPass123" }), /do not match/);
	assert.equal(validatePasswordForm({ currentPassword: "OldPass123", newPassword: "StrongPass123", confirmPassword: "StrongPass123" }), "");
});