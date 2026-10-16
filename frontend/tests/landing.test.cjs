const assert = require("node:assert/strict");
const test = require("node:test");

const {
	getDemoConfirmationMessage,
	getLegalNoticeText,
	validateContactForm
} = require("../js/landing.js");

test("validateContactForm enforces name, valid email, and 10-1000 message length", () => {
	const validData = {
		name: "Security Analyst",
		email: "analyst@ethiosec.local",
		message: "We would like to test our web application against OWASP checks."
	};

	// Valid form submission
	const validResult = validateContactForm(validData);
	assert.equal(validResult.valid, true);
	assert.equal(validResult.error, "");

	// Trimmed valid input
	const trimmedResult = validateContactForm({
		name: "  Analyst Name  ",
		email: "  analyst@domain.com  ",
		message: "   This message has leading and trailing spaces.   "
	});
	assert.equal(trimmedResult.valid, true);
	assert.equal(trimmedResult.error, "");

	// Boundary: exactly 10 characters
	const boundary10 = validateContactForm({
		name: "Analyst",
		email: "analyst@domain.com",
		message: "1234567890"
	});
	assert.equal(boundary10.valid, true);

	// Boundary: exactly 1000 characters
	const boundary1000 = validateContactForm({
		name: "Analyst",
		email: "analyst@domain.com",
		message: "A".repeat(1000)
	});
	assert.equal(boundary1000.valid, true);

	// Missing name
	assert.equal(
		validateContactForm({ ...validData, name: "" }).error,
		"Please enter your name."
	);
	assert.equal(
		validateContactForm({ ...validData, name: "   " }).error,
		"Please enter your name."
	);
	assert.equal(
		validateContactForm({ ...validData, name: null }).error,
		"Please enter your name."
	);

	// Missing email
	assert.equal(
		validateContactForm({ ...validData, email: "" }).error,
		"Please enter your email address."
	);
	assert.equal(
		validateContactForm({ ...validData, email: "   " }).error,
		"Please enter your email address."
	);

	// Invalid email format
	assert.equal(
		validateContactForm({ ...validData, email: "notanemail" }).error,
		"Please enter a valid email address."
	);
	assert.equal(
		validateContactForm({ ...validData, email: "missing@domain" }).error,
		"Please enter a valid email address."
	);
	assert.equal(
		validateContactForm({ ...validData, email: "spaces in@email.com" }).error,
		"Please enter a valid email address."
	);

	// Missing message
	assert.equal(
		validateContactForm({ ...validData, message: "" }).error,
		"Please enter a message."
	);
	assert.equal(
		validateContactForm({ ...validData, message: "   " }).error,
		"Please enter a message."
	);

	// Message too short (< 10 characters)
	assert.equal(
		validateContactForm({ ...validData, message: "123456789" }).error,
		"Message must be at least 10 characters long."
	);

	// Message too long (> 1000 characters)
	assert.equal(
		validateContactForm({ ...validData, message: "A".repeat(1001) }).error,
		"Message cannot exceed 1000 characters."
	);
});

test("getDemoConfirmationMessage returns expected demo disclaimer", () => {
	const message = getDemoConfirmationMessage();
	assert.equal(message, "This contact form is a demo; no message was sent.");
});

test("getLegalNoticeText returns exact SEC-13 legal notice", () => {
	const notice = getLegalNoticeText();
	assert.equal(
		notice,
		"Only scan websites you own or have written permission to test. Scanning systems without permission may be illegal."
	);
});
