const assert = require("node:assert/strict");
const test = require("node:test");

const {
	checkPasswordStrength,
	getPasswordErrorMessage,
	validateFullName,
	validatePasswordInputs,
	validateSettingsPayload
} = require("../js/settings.js");

test("validateFullName validates 1-150 character bounds and trims whitespace", () => {
	// Valid names
	const valid1 = validateFullName("A");
	assert.equal(valid1.valid, true);
	assert.equal(valid1.value, "A");

	const validTrim = validateFullName("  Maraki Belete  ");
	assert.equal(validTrim.valid, true);
	assert.equal(validTrim.value, "Maraki Belete");

	const exactly150 = "A".repeat(150);
	const valid150 = validateFullName(exactly150);
	assert.equal(valid150.valid, true);
	assert.equal(valid150.value.length, 150);

	// Invalid names
	assert.equal(validateFullName("").valid, false);
	assert.equal(validateFullName("   ").valid, false);
	assert.equal(validateFullName("").error, "Full name is required.");
	assert.equal(validateFullName(null).valid, false);
	assert.equal(validateFullName(undefined).valid, false);

	const exactly151 = "A".repeat(151);
	const invalid151 = validateFullName(exactly151);
	assert.equal(invalid151.valid, false);
	assert.equal(invalid151.error, "Full name cannot exceed 150 characters.");
});

test("validatePasswordInputs enforces presence, complexity, match, and difference from current", () => {
	const validCurrent = "CurrentPass1!";
	const validNew = "NewStrongPass2!";

	// Valid password change
	const validResult = validatePasswordInputs({
		currentPassword: validCurrent,
		newPassword: validNew,
		confirmPassword: validNew
	});
	assert.equal(validResult.valid, true);
	assert.equal(validResult.error, "");

	// Missing current password
	assert.equal(
		validatePasswordInputs({ currentPassword: "", newPassword: validNew, confirmPassword: validNew }).error,
		"Current password is required."
	);
	assert.equal(
		validatePasswordInputs({ currentPassword: "   ", newPassword: validNew, confirmPassword: validNew }).error,
		"Current password is required."
	);

	// Missing new password
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: "", confirmPassword: validNew }).error,
		"New password is required."
	);

	// Missing confirm password
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: validNew, confirmPassword: "" }).error,
		"Please confirm your new password."
	);

	// Passwords mismatch
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: validNew, confirmPassword: "Mismatch123!" }).error,
		"New passwords do not match."
	);

	// New password same as current password
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: validCurrent, confirmPassword: validCurrent }).error,
		"New password must be different from current password."
	);

	// Complexity: Length < 8
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: "Short1!", confirmPassword: "Short1!" }).error,
		"Password must be at least 8 characters long."
	);

	// Complexity: Missing uppercase
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: "lowercase123!", confirmPassword: "lowercase123!" }).error,
		"Password must contain at least one uppercase letter."
	);

	// Complexity: Missing lowercase
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: "UPPERCASE123!", confirmPassword: "UPPERCASE123!" }).error,
		"Password must contain at least one lowercase letter."
	);

	// Complexity: Missing digit
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: "NoDigitsHere!", confirmPassword: "NoDigitsHere!" }).error,
		"Password must contain at least one digit."
	);

	// Complexity: Exceeds 72 bytes
	const longPassword = "A1a!".repeat(19); // 76 chars/bytes
	assert.equal(
		validatePasswordInputs({ currentPassword: validCurrent, newPassword: longPassword, confirmPassword: longPassword }).error,
		"Password cannot exceed 72 bytes."
	);
});

test("getPasswordErrorMessage correctly handles INVALID_CURRENT_PASSWORD and fallbacks", () => {
	// Error code INVALID_CURRENT_PASSWORD
	assert.equal(
		getPasswordErrorMessage({ code: "INVALID_CURRENT_PASSWORD", message: "Bad pass" }),
		"The current password is incorrect."
	);

	// Status 400 with code INVALID_CURRENT_PASSWORD
	assert.equal(
		getPasswordErrorMessage({ status: 400, code: "INVALID_CURRENT_PASSWORD", message: "Server message" }),
		"The current password is incorrect."
	);

	// Generic server error
	assert.equal(
		getPasswordErrorMessage({ code: "VALIDATION_ERROR", message: "Password too weak" }),
		"Password too weak"
	);

	// Missing message fallback
	assert.equal(getPasswordErrorMessage({ code: "UNKNOWN" }), "Failed to update password.");
	assert.equal(getPasswordErrorMessage(null), "Failed to update password.");
});

test("validateSettingsPayload normalizes scan depth and ensures boolean flags", () => {
	// Valid standard payload
	const result1 = validateSettingsPayload({
		default_scan_depth: "deep",
		notify_scan_completed: true,
		notify_scan_failed: false,
		notify_critical_finding: true
	});
	assert.equal(result1.valid, true);
	assert.deepEqual(result1.payload, {
		default_scan_depth: "deep",
		notify_scan_completed: true,
		notify_scan_failed: false,
		notify_critical_finding: true
	});

	// Quick depth with uppercase and whitespace
	const result2 = validateSettingsPayload({
		default_scan_depth: " QUICK  ",
		notify_scan_completed: 1,
		notify_scan_failed: 0,
		notify_critical_finding: "yes"
	});
	assert.equal(result2.valid, true);
	assert.deepEqual(result2.payload, {
		default_scan_depth: "quick",
		notify_scan_completed: true,
		notify_scan_failed: false,
		notify_critical_finding: true
	});

	// Invalid depth falls back to standard
	const result3 = validateSettingsPayload({
		default_scan_depth: "ultra_deep",
		notify_scan_completed: false,
		notify_scan_failed: false,
		notify_critical_finding: false
	});
	assert.equal(result3.valid, true);
	assert.equal(result3.payload.default_scan_depth, "standard");

	// Non-object input
	assert.equal(validateSettingsPayload(null).valid, false);
	assert.equal(validateSettingsPayload("invalid").valid, false);
});

test("checkPasswordStrength scores rules and provides labels", () => {
	// Invalid or empty input
	assert.deepEqual(checkPasswordStrength(""), {
		length: false,
		case: false,
		number: false,
		symbol: false,
		score: 0,
		label: "Not checked"
	});

	// Weak password (short, only lowercase)
	const weak = checkPasswordStrength("abc");
	assert.equal(weak.score, 0);
	assert.equal(weak.label, "Weak");

	// Strong password meeting all 4 rules
	const strong = checkPasswordStrength("StrongP@ss1");
	assert.equal(strong.length, true);
	assert.equal(strong.case, true);
	assert.equal(strong.number, true);
	assert.equal(strong.symbol, true);
	assert.equal(strong.score, 4);
	assert.equal(strong.label, "Strong");
});
