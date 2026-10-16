(() => {
	const sharedHelpers = typeof module !== "undefined" && module.exports
		? require("./report_helpers.js")
		: globalThis.ReportHelpers;
	const { SEVERITY_ORDER, getVerdictKey, getVerdictMessage, isSafeHttpUrl } = sharedHelpers;
	const FINDING_STATUSES = Object.freeze(["open", "confirmed", "false_positive", "resolved"]);
	const SCAN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

	function parseScanId(search) {
		const value = new URLSearchParams(search || "").get("id");
		return value && SCAN_ID_PATTERN.test(value) ? value : null;
	}

	function severityClass(severity) {
		const normalized = String(severity || "info").toLowerCase();
		return SEVERITY_ORDER.includes(normalized) ? `severity-${normalized}` : "severity-info";
	}

	function getSeverityCount(results, severity) {
		const counts = results?.counts;
		if (counts && Object.hasOwn(counts, severity)) return Math.max(0, Number(counts[severity]) || 0);
		return (Array.isArray(results?.findings) ? results.findings : [])
			.filter((finding) => String(finding?.severity || "").toLowerCase() === severity).length;
	}

	function filterFindings(findings, filters = {}) {
		const severity = filters.severity || "all";
		const moduleName = filters.module || "all";
		const status = filters.status || "all";
		const query = String(filters.query || "").trim().toLocaleLowerCase();
		return (Array.isArray(findings) ? findings : []).filter((finding) => {
			if (severity !== "all" && String(finding?.severity || "").toLowerCase() !== severity) return false;
			if (moduleName !== "all" && finding?.module !== moduleName) return false;
			if (status !== "all" && finding?.status !== status) return false;
			if (query && !`${finding?.title || ""} ${finding?.affected_url || ""}`.toLocaleLowerCase().includes(query)) return false;
			return true;
		});
	}

	function formatTimestamp(value) {
		if (!value) return "Not available";
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? "Not available" : date.toLocaleString();
	}

	if (typeof module !== "undefined" && module.exports) {
		module.exports = {
			FINDING_STATUSES,
			SEVERITY_ORDER,
			filterFindings,
			formatTimestamp,
			getSeverityCount,
			getVerdictKey,
			getVerdictMessage,
			isSafeHttpUrl,
			parseScanId,
			severityClass
		};
		return;
	}

	const scanId = parseScanId(globalThis.location.search);
	const pageError = document.getElementById("pageError");
	const pageLoading = document.getElementById("pageLoading");
	const summaryPanel = document.getElementById("summaryPanel");
	const resultTarget = document.getElementById("resultTarget");
	const findingList = document.getElementById("findingList");
	const severityFilter = document.getElementById("severityFilter");
	const moduleFilter = document.getElementById("moduleFilter");
	const statusFilter = document.getElementById("statusFilter");
	const findingSearch = document.getElementById("findingSearch");
	const runAnotherScan = document.getElementById("runAnotherScan");
	const liveScanLink = document.getElementById("liveScanLink");
	const scanStatusNote = document.getElementById("scanStatusNote");
	const createReportButton = document.getElementById("createReportButton");
	const savingFindings = new Set();
	const findingMessages = new Map();
	let scanResults = null;
	let scanDetails = null;
	let creatingReport = false;

	function setText(node, value) {
		node.textContent = value == null || value === "" ? "—" : String(value);
	}

	function showError(message) {
		setText(pageError, message);
		pageError.hidden = false;
	}

	function textElement(tagName, className, text) {
		const node = document.createElement(tagName);
		if (className) node.className = className;
		if (text !== undefined) node.textContent = text == null || text === "" ? "—" : String(text);
		return node;
	}

	function appendValue(parent, label, value) {
		const item = textElement("span", "finding-meta-item");
		item.append(textElement("strong", "", `${label}: `), document.createTextNode(value == null || value === "" ? "—" : String(value)));
		parent.append(item);
	}

	function appendAffectedUrl(parent, value) {
		const wrapper = textElement("span", "finding-meta-item finding-url");
		wrapper.append(textElement("strong", "", "Affected URL: "));
		if (isSafeHttpUrl(value)) {
			const link = textElement("a", "", value);
			link.href = value;
			link.target = "_blank";
			link.rel = "noopener noreferrer";
			wrapper.append(link);
		} else {
			wrapper.append(document.createTextNode(value == null || value === "" ? "—" : String(value)));
		}
		parent.append(wrapper);
	}

	function makeStatusSelect(finding) {
		const wrapper = textElement("label", "finding-status-control", "Finding status");
		const select = document.createElement("select");
		select.className = "finding-status-select";
		select.dataset.findingId = finding.id || "";
		select.disabled = !finding.id || savingFindings.has(finding.id);
		for (const value of FINDING_STATUSES) {
			const option = document.createElement("option");
			option.value = value;
			option.textContent = value.replaceAll("_", " ");
			select.append(option);
		}
		select.value = FINDING_STATUSES.includes(finding.status) ? finding.status : "open";
		wrapper.append(select);
		if (savingFindings.has(finding.id)) wrapper.append(textElement("span", "save-state", "Saving…"));
		const message = findingMessages.get(finding.id);
		if (message) wrapper.append(textElement("span", `finding-message${message.error ? " error" : ""}`, message.text));
		return wrapper;
	}

	function createFindingCard(finding) {
		const card = textElement("article", `finding-card ${severityClass(finding.severity)}`);
		const heading = textElement("div", "finding-card-heading");
		heading.append(textElement("span", `severity-badge ${severityClass(finding.severity)}`, finding.severity || "Info"));
		heading.append(textElement("h3", "finding-card-title", finding.title));
		heading.append(textElement("span", "finding-status-badge", String(finding.status || "open").replaceAll("_", " ")));
		const meta = textElement("div", "finding-meta");
		appendValue(meta, "Module", finding.module);
		appendAffectedUrl(meta, finding.affected_url);
		appendValue(meta, "Parameter", finding.parameter);
		appendValue(meta, "OWASP", finding.owasp_category);
		appendValue(meta, "CWE", finding.cwe_id);
		const details = document.createElement("details");
		details.className = "finding-details";
		const summary = textElement("summary", "", "Description, evidence and remediation");
		const body = textElement("div", "finding-detail-body");
		body.append(textElement("h4", "", "Description"), textElement("p", "", finding.description));
		body.append(textElement("h4", "", "Evidence"), textElement("pre", "finding-evidence", finding.evidence));
		body.append(textElement("h4", "", "Remediation"), textElement("p", "", finding.remediation));
		details.append(summary, body);
		card.append(heading, meta, details, makeStatusSelect(finding));
		return card;
	}

	function updateModuleFilter(findings) {
		const selected = moduleFilter.value;
		const modules = [...new Set(findings.map((finding) => finding.module).filter((value) => typeof value === "string" && value))].sort();
		const options = [textElement("option", "", "All modules")];
		options[0].value = "all";
		for (const name of modules) {
			const option = textElement("option", "", name);
			option.value = name;
			options.push(option);
		}
		moduleFilter.replaceChildren(...options);
		if (modules.includes(selected)) moduleFilter.value = selected;
	}

	function renderFindings() {
		const filtered = filterFindings(scanResults?.findings, {
			severity: severityFilter.value,
			module: moduleFilter.value,
			status: statusFilter.value,
			query: findingSearch.value
		});
		if (!filtered.length) {
			const hasFindings = scanResults?.findings?.length > 0;
			const emptyText = hasFindings
				? "No findings match the selected filters."
				: scanResults?.status === "completed"
					? `The checks that ran found nothing. Passed checks: ${Number(scanResults.passed_count) || 0}.`
					: "No findings are available for this scan yet.";
			findingList.replaceChildren(textElement("p", "empty-findings", emptyText));
			return;
		}
		findingList.replaceChildren(...filtered.map(createFindingCard));
	}

	function renderSummary(results, details) {
		const findings = Array.isArray(results.findings) ? results.findings : [];
		const verdictKey = getVerdictKey(results);
		const status = String(results.status || details.status || "unknown").toLowerCase();
		createReportButton.hidden = status !== "completed";
		const isCompleted = status === "completed";
		setText(document.getElementById("scoreValue"), results.score == null ? "—" : results.score);
		setText(document.getElementById("verdict"), !isCompleted ? `Scan ${status}` : verdictKey === "scanner_error" ? "Checks incomplete" : `${verdictKey.charAt(0).toUpperCase()}${verdictKey.slice(1)} verdict`);
		setText(document.getElementById("verdictNote"), isCompleted ? getVerdictMessage(verdictKey, results.passed_count) : "This scan has not completed. Results may be incomplete.");
		document.getElementById("scannerErrorNote").hidden = !(Number(results.scanner_error_count) > 0);
		for (const severity of SEVERITY_ORDER) setText(document.getElementById(`count${severity.charAt(0).toUpperCase()}${severity.slice(1)}`), getSeverityCount(results, severity));
		setText(document.getElementById("countPassed"), Number(results.passed_count) || 0);
		setText(document.getElementById("countErrors"), Number(results.scanner_error_count) || 0);
		setText(document.getElementById("scanIdLabel"), results.id || scanId);
		setText(document.getElementById("depthLabel"), details.depth || "Not available");
		setText(document.getElementById("startedLabel"), formatTimestamp(details.started_at || details.created_at));
		setText(document.getElementById("finishedLabel"), formatTimestamp(details.finished_at));
		setText(resultTarget, details.target_url || "Target URL not available");
		if (details.target_id) {
			runAnotherScan.href = `new_scan.html?target=${encodeURIComponent(details.target_id)}`;
			runAnotherScan.hidden = false;
		}
		if (status !== "completed") {
			setText(scanStatusNote, `This scan is ${status}. ${details.error_message || "Results may be incomplete."}`);
			scanStatusNote.hidden = false;
			if (status === "queued" || status === "running") {
				liveScanLink.href = `live_scan.html?id=${encodeURIComponent(scanId)}`;
				liveScanLink.hidden = false;
			}
		}
		summaryPanel.hidden = false;
		updateModuleFilter(findings);
		renderFindings();
	}

	async function updateFindingStatus(select) {
		const findingId = select.dataset.findingId;
		if (!findingId || savingFindings.has(findingId)) return;
		const finding = scanResults.findings.find((item) => item.id === findingId);
		if (!finding || finding.status === select.value) return;
		const nextStatus = select.value;
		const previousStatus = finding.status;
		savingFindings.add(findingId);
		findingMessages.set(findingId, { text: "", error: false });
		renderFindings();
		try {
			const updated = await Api.request(`/api/findings/${encodeURIComponent(findingId)}`, {
				method: "PATCH",
				body: { status: nextStatus }
			});
			finding.status = FINDING_STATUSES.includes(updated?.status) ? updated.status : nextStatus;
			findingMessages.set(findingId, { text: "Status updated.", error: false });
		} catch (error) {
			finding.status = previousStatus;
			findingMessages.set(findingId, { text: error.message || "Could not update finding status.", error: true });
		} finally {
			savingFindings.delete(findingId);
			renderFindings();
		}
	}

	async function loadResults() {
		pageLoading.hidden = false;
		try {
			const [results, details] = await Promise.all([
				Api.get(`/api/scans/${encodeURIComponent(scanId)}/results`),
				Api.get(`/api/scans/${encodeURIComponent(scanId)}`)
			]);
			scanResults = { ...results, status: results?.status || details?.status, findings: Array.isArray(results?.findings) ? results.findings : [] };
			scanDetails = details || {};
			renderSummary(scanResults, scanDetails);
		} catch (error) {
			showError(error?.status === 404 ? "Scan not found." : (error.message || "Could not load scan results."));
		} finally {
			pageLoading.hidden = true;
		}
	}

	async function createReport() {
		if (creatingReport || createReportButton.hidden) return;
		creatingReport = true;
		createReportButton.disabled = true;
		createReportButton.textContent = "Creating report…";
		setText(pageError, "");
		pageError.hidden = true;
		try {
			const report = await Api.post("/api/reports", { scan_id: scanId, report_format: "pdf" });
			if (!report?.id) throw new Error("The server did not return a report ID.");
			globalThis.location.assign(`reports.html?id=${encodeURIComponent(report.id)}`);
		} catch (error) {
			showError(error.message || "Could not create report.");
			createReportButton.disabled = false;
			createReportButton.textContent = "Create report";
			creatingReport = false;
		}
	}

	for (const filter of [severityFilter, moduleFilter, statusFilter]) filter.addEventListener("change", renderFindings);
	createReportButton.addEventListener("click", createReport);
	findingSearch.addEventListener("input", renderFindings);
	findingList.addEventListener("change", (event) => {
		if (event.target.matches(".finding-status-select")) updateFindingStatus(event.target);
	});
	document.getElementById("sidebarToggle").addEventListener("click", () => {
		document.getElementById("sidebar").classList.toggle("open");
		document.getElementById("sidebarOverlay").classList.toggle("show");
	});
	document.getElementById("sidebarOverlay").addEventListener("click", () => {
		document.getElementById("sidebar").classList.remove("open");
		document.getElementById("sidebarOverlay").classList.remove("show");
	});

	if (!scanId) {
		pageLoading.hidden = true;
		showError("A valid scan ID is required. Open scan history to choose a scan.");
	} else {
		Auth.requireAuth().then((user) => {
			if (user) loadResults();
		});
	}
})();