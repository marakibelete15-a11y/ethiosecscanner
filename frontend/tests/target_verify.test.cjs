const assert = require("node:assert/strict");
const test = require("node:test");

const { formatTimestamp, getErrorMessage, getProofValues } = require("../js/target_verify.js");

test("proof values include the token and only the selected verification method", () => {
	const instructions = {
		method: "dns_txt",
		token: "secret-token",
		meta_tag: "<meta proof>",
		file_url: "https://example.test/.well-known/proof.txt",
		file_content: "file proof",
		dns_record_name: "_ethiosec-challenge.example.test",
		dns_record_value: "ethiosec-verification=secret-token"
	};

	assert.deepEqual(getProofValues({
		verification_method: "dns_txt",
		verification_token: "secret-token",
		instructions
	}), [
		{ label: "Verification token", value: "secret-token" },
		{ label: "DNS record name", value: "_ethiosec-challenge.example.test" },
		{ label: "DNS record value", value: "ethiosec-verification=secret-token" }
	]);
});

test("proof values fall back to the target token and support each proof format", () => {
	assert.deepEqual(getProofValues({
		verification_method: "meta_tag",
		verification_token: "meta-token",
		instructions: { meta_tag: "<meta name=proof>" }
	}), [
		{ label: "Verification token", value: "meta-token" },
		{ label: "Meta tag", value: "<meta name=proof>" }
	]);
	assert.deepEqual(getProofValues({
		verification_method: "http_file",
		instructions: { token: "file-token", file_url: "/proof.txt", file_content: "file-token" }
	}), [
		{ label: "Verification token", value: "file-token" },
		{ label: "File URL", value: "/proof.txt" },
		{ label: "File content", value: "file-token" }
	]);
});

test("timestamps and API errors have safe readable fallbacks", () => {
	assert.equal(formatTimestamp(null), "Not checked");
	assert.equal(formatTimestamp("not-a-date"), "Not checked");
	assert.notEqual(formatTimestamp("2026-10-15T12:00:00Z"), "Not checked");
	assert.equal(getErrorMessage({ message: "Target already exists." }), "Target already exists.");
	assert.match(getErrorMessage(null), /request could not be completed/i);
});