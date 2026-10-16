(() => {
	const SEVERITY_ORDER = Object.freeze(["critical", "high", "medium", "low", "info"]);
	const FINDING_STATUSES = Object.freeze(["open", "confirmed", "false_positive", "resolved"]);
	const SCAN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	const VERDICT_MESSAGES = Object.freeze({
		critical: "Critical vulnerabilities were found. Review and address them before proceeding.",
		high: "High-severity vulnerabilities were found and should be addressed promptly.",
		medium: "Medium-severity vulnerabilities were found and should be reviewed.",
		low: "Low-severity vulnerabilities were found and should be reviewed.",
		info: "Informational findings were recorded for review.",
		scanner_error: "No vulnerabilities were reported, but some checks could not run.",
		safe: "The checks that ran found nothing."
	});

	function isValidUuid(value) {
		return typeof value === "string" && SCAN_ID_PATTERN.test(value);
	}

	function parseIdFromQuery(search, param = "id") {
		const value = new URLSearchParams(search || "").get(param);
		return value && SCAN_ID_PATTERN.test(value) ? value : null;
	}

	function parseScanId(search) {
		return parseIdFromQuery(search, "id");
	}

	function severityClass(severity) {
		const normalized = String(severity || "info").toLowerCase();
		return SEVERITY_ORDER.includes(normalized) ? `severity-${normalized}` : "severity-info";
	}

	function isSafeHttpUrl(value) {
		if (typeof value !== "string" || !/^https?:\/\//i.test(value)) return false;
		try {
			const parsed = new URL(value);
			return parsed.protocol === "http:" || parsed.protocol === "https:";
		} catch (error) {
			return false;
		}
	}

	function getVerdictKey(results) {
		const findings = Array.isArray(results?.findings) ? results.findings : [];
		const counts = results?.counts || {};
		const hasSeverity = (severity) =>
			Number(counts[severity] || 0) > 0 ||
			findings.some((finding) => String(finding?.severity || "").toLowerCase() === severity);
		if (hasSeverity("critical")) return "critical";
		if (hasSeverity("high")) return "high";
		if (hasSeverity("medium")) return "medium";
		if (hasSeverity("low")) return "low";
		if (hasSeverity("info")) return "info";
		if (Number(results?.scanner_error_count || 0) > 0) return "scanner_error";
		const verdict = String(results?.verdict || "safe").toLowerCase();
		return Object.hasOwn(VERDICT_MESSAGES, verdict) ? verdict : "safe";
	}

	function getVerdictMessage(verdict, passedCount = 0) {
		const key = Object.hasOwn(VERDICT_MESSAGES, verdict) ? verdict : "safe";
		const message = VERDICT_MESSAGES[key];
		return key === "safe" ? `${message} Passed checks: ${Math.max(0, Number(passedCount) || 0)}.` : message;
	}

	function getSeverityCount(results, severity) {
		const counts = results?.counts;
		if (counts && Object.hasOwn(counts, severity)) return Math.max(0, Number(counts[severity]) || 0);
		return (Array.isArray(results?.findings) ? results.findings : [])
			.filter((finding) => String(finding?.severity || "").toLowerCase() === severity).length;
	}

	function formatTimestamp(value) {
		if (!value) return "Not available";
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? "Not available" : date.toLocaleString();
	}

	const exported = Object.freeze({
		FINDING_STATUSES,
		SCAN_ID_PATTERN,
		SEVERITY_ORDER,
		VERDICT_MESSAGES,
		formatTimestamp,
		getSeverityCount,
		getVerdictKey,
		getVerdictMessage,
		isSafeHttpUrl,
		isValidUuid,
		parseIdFromQuery,
		parseScanId,
		severityClass
	});

	globalThis.ScanHelpers = exported;

	if (typeof module !== "undefined" && module.exports) {
		module.exports = exported;
	}
})();
