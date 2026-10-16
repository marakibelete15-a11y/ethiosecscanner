(() => {
	const PAGE_SIZE = 10;
	const { SEVERITY_ORDER, getVerdictKey, getVerdictMessage, isSafeHttpUrl } = globalThis.ReportHelpers;
	const REPORT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

	function parseReportId(search) {
		const value = new URLSearchParams(search || "").get("id");
		return value && REPORT_ID_PATTERN.test(value) ? value : null;
	}

	function getReportPageCount(total, pageSize = PAGE_SIZE) {
		return Math.ceil(Math.max(0, Number(total) || 0) / Math.max(1, Number(pageSize) || PAGE_SIZE));
	}

	function getReportPageState(total, page, pageSize = PAGE_SIZE) {
		const pageCount = getReportPageCount(total, pageSize);
		const currentPage = pageCount ? Math.min(Math.max(1, Number(page) || 1), pageCount) : 1;
		return { page: currentPage, pageCount, canPrevious: currentPage > 1, canNext: currentPage < pageCount };
	}

	function getReportSummaryValues(report) {
		const summary = report?.summary || {};
		const moduleSummary = summary.module_summary && typeof summary.module_summary === "object" ? summary.module_summary : {};
		const passedFromModules = Object.values(moduleSummary).reduce((total, item) => total + (Number(item?.checks_passed) || 0), 0);
		return {
			target: summary.target_url || "Target URL unavailable",
			depth: summary.depth || "Not available",
			score: summary.security_score ?? "Not scored",
			verdict: getVerdictKey({
				verdict: summary.verdict,
				counts: summary.counts,
				scanner_error_count: summary.scanner_error_count
			}),
			counts: Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, Math.max(0, Number(summary.counts?.[severity]) || 0)])),
			passedCount: summary.passed_count == null ? passedFromModules : Math.max(0, Number(summary.passed_count) || 0),
			scannerErrorCount: Math.max(0, Number(summary.scanner_error_count) || 0),
			moduleSummary
		};
	}

	function formatTimestamp(value) {
		if (!value) return "Not available";
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? "Not available" : date.toLocaleString();
	}

	if (typeof module !== "undefined" && module.exports) {
		module.exports = { PAGE_SIZE, formatTimestamp, getReportPageCount, getReportPageState, getReportSummaryValues, parseReportId };
		return;
	}

	const list = document.getElementById("reportList");
	const documentPanel = document.getElementById("reportDoc");
	const listLoading = document.getElementById("reportsLoading");
	const listError = document.getElementById("reportsError");
	const listLink = document.getElementById("reportsListLink");
	const listEmpty = document.getElementById("reportsEmpty");
	const countLabel = document.getElementById("reportCount");
	const previousButton = document.getElementById("reportsPrevious");
	const nextButton = document.getElementById("reportsNext");
	const pageInfo = document.getElementById("reportsPageInfo");
	let page = 1;
	let total = 0;
	let reports = [];
	let selectedReportId = null;
	let loadingList = false;

	function make(tag, className, text) {
		const node = document.createElement(tag);
		if (className) node.className = className;
		if (text !== undefined) node.textContent = text == null || text === "" ? "—" : String(text);
		return node;
	}

	function setListError(message) {
		listError.textContent = message || "";
		listError.hidden = !message;
	}

	function appendLabeled(parent, label, value) {
		const item = make("div", "report-meta-item");
		item.append(make("strong", "", `${label}: `), document.createTextNode(value == null || value === "" ? "—" : String(value)));
		parent.append(item);
	}

	function createReportItem(report) {
		const button = make("button", `report-item${report.id === selectedReportId ? " active" : ""}`);
		button.type = "button";
		button.dataset.reportId = report.id || "";
		const summary = report.summary || {};
		const main = make("span", "report-item-main");
		main.append(make("strong", "report-host", summary.target_url || "Target URL unavailable"));
		main.append(make("span", "report-when", formatTimestamp(summary.scan_dates?.started_at || report.created_at)));
		const score = make("span", "report-score", summary.security_score == null ? "—" : summary.security_score);
		const verdict = getVerdictKey({ verdict: summary.verdict, counts: summary.counts, scanner_error_count: summary.scanner_error_count });
		button.append(main, score, make("span", `report-verdict verdict-${verdict}`, verdict.replaceAll("_", " ")));
		return button;
	}

	function updatePagination() {
		const state = getReportPageState(total, page, PAGE_SIZE);
		page = state.page;
		pageInfo.textContent = `Page ${state.pageCount ? state.page : 0} of ${state.pageCount}`;
		countLabel.textContent = `${total} report${total === 1 ? "" : "s"}`;
		previousButton.disabled = loadingList || !state.canPrevious;
		nextButton.disabled = loadingList || !state.canNext;
	}

	async function loadReportList() {
		if (loadingList) return;
		loadingList = true;
		listLoading.hidden = false;
		listEmpty.hidden = true;
		setListError("");
		updatePagination();
		try {
			const response = await Api.get(`/api/reports?page=${page}&page_size=${PAGE_SIZE}`);
			total = Math.max(0, Number(response?.total) || 0);
			reports = Array.isArray(response?.reports) ? response.reports : [];
			const state = getReportPageState(total, page, PAGE_SIZE);
			if (total > 0 && state.page !== page) {
				page = state.page;
				loadingList = false;
				return loadReportList();
			}
			list.replaceChildren(...reports.map(createReportItem));
			listEmpty.hidden = total !== 0;
			if (selectedReportId && !reports.some((report) => report.id === selectedReportId) && !new URLSearchParams(globalThis.location.search).has("id")) {
				selectedReportId = null;
				documentPanel.replaceChildren(make("p", "empty-state", "Select a report on the left to open it."));
			}
		} catch (error) {
			reports = [];
			list.replaceChildren();
			setListError(error.message || "Could not load reports.");
		} finally {
			loadingList = false;
			listLoading.hidden = true;
			updatePagination();
		}
	}

	function safeUrlNode(value) {
		if (!isSafeHttpUrl(value)) return document.createTextNode(value == null || value === "" ? "—" : String(value));
		const link = make("a", "report-safe-url", value);
		link.href = value;
		link.target = "_blank";
		link.rel = "noopener noreferrer";
		return link;
	}

	function renderReport(report) {
		const values = getReportSummaryValues(report);
		const summary = report.summary || {};
		const root = make("div", "report-document-content");
		const head = make("header", "doc-head");
		const title = make("div", "report-title-block");
		title.append(make("h2", "", "Security assessment report"));
		title.append(make("p", "report-target-url", values.target));
		title.lastChild.replaceChildren(safeUrlNode(values.target));
		title.append(make("p", "", `Started ${formatTimestamp(summary.scan_dates?.started_at)} · Finished ${formatTimestamp(summary.scan_dates?.finished_at)}`));
		const actions = make("div", "doc-actions");
		const printButton = make("button", "primary-btn", "Export PDF");
		printButton.type = "button";
		printButton.addEventListener("click", () => globalThis.print());
		actions.append(printButton);
		head.append(title, actions);
		root.append(head);

		const verdictKey = values.verdict;
		const verdict = make("section", "doc-section report-verdict-block");
		verdict.append(make("h3", "", `${verdictKey.replaceAll("_", " ")} verdict`));
		verdict.append(make("p", "exec-summary", getVerdictMessage(verdictKey, values.passedCount)));
		if (values.scannerErrorCount > 0) verdict.append(make("p", "report-error-note", "Some checks could not run."));
		root.append(verdict);

		const summarySection = make("section", "doc-section");
		summarySection.append(make("h3", "", "Scan summary"));
		const tiles = make("div", "score-strip");
		for (const [label, value] of [["Score", values.score], ["Depth", values.depth], ["Passed", values.passedCount], ["Scanner errors", values.scannerErrorCount]]) {
			const tile = make("div", "score-tile");
			tile.append(make("b", "", value), make("span", "", label));
			tiles.append(tile);
		}
		summarySection.append(tiles);
		const counts = make("div", "score-strip report-severity-counts");
		for (const severity of SEVERITY_ORDER) {
			const tile = make("div", `score-tile severity-${severity}`);
			tile.append(make("b", "", values.counts[severity]), make("span", "", severity));
			counts.append(tile);
		}
		summarySection.append(counts);
		root.append(summarySection);

		const moduleSection = make("section", "doc-section");
		moduleSection.append(make("h3", "", "Module execution"));
		const table = make("table", "tech-table module-summary-table");
		const header = make("tr", "");
		for (const label of ["Module", "Status", "Checks run", "Checks passed", "Findings"]) header.append(make("th", "", label));
		const thead = make("thead", "");
		thead.append(header);
		const tbody = make("tbody", "");
		for (const [name, module] of Object.entries(values.moduleSummary)) {
			const row = make("tr", "");
			for (const value of [name.replaceAll("_", " "), module?.status || "pending", Number(module?.checks_run) || 0, Number(module?.checks_passed) || 0, Number(module?.findings_count) || 0]) row.append(make("td", "", value));
			tbody.append(row);
		}
		if (!tbody.childElementCount) {
			const row = make("tr", "");
			const cell = make("td", "", "Module details are unavailable.");
			cell.colSpan = 5;
			row.append(cell);
			tbody.append(row);
		}
		table.append(thead, tbody);
		moduleSection.append(table);
		root.append(moduleSection);

		const findingsSection = make("section", "doc-section report-findings");
		findingsSection.append(make("h3", "", `Findings (${Array.isArray(report.findings) ? report.findings.length : 0})`));
		const findings = Array.isArray(report.findings) ? report.findings : [];
		if (!findings.length) findingsSection.append(make("p", "empty-state", "This report contains no findings."));
		for (const finding of findings) {
			const item = make("article", `fix-item ${String(finding.severity || "info").toLowerCase()}`);
			const heading = make("div", "fix-head");
			heading.append(make("span", `sev-badge sev-${String(finding.severity || "info").toLowerCase()}`, finding.severity || "Info"));
			heading.append(make("strong", "", finding.title || "Untitled finding"));
			item.append(heading);
			const metadata = make("div", "report-finding-meta");
			metadata.append(safeUrlNode(finding.affected_url));
			appendLabeled(metadata, "OWASP", finding.owasp_category);
			appendLabeled(metadata, "CWE", finding.cwe_id);
			item.append(metadata);
			item.append(make("p", "", finding.description));
			item.append(make("h4", "", "Evidence"), make("pre", "report-evidence", finding.evidence));
			item.append(make("h4", "", "Remediation"), make("p", "", finding.remediation));
			findingsSection.append(item);
		}
		root.append(findingsSection);
		documentPanel.replaceChildren(root);
	}

	async function openReport(reportId) {
		selectedReportId = reportId;
		list.replaceChildren(...reports.map(createReportItem));
		documentPanel.replaceChildren(make("p", "reports-loading", "Loading report details…"));
		try {
			const report = await Api.get(`/api/reports/${encodeURIComponent(reportId)}`);
			if (report?.id !== selectedReportId) return;
			renderReport(report || {});
		} catch (error) {
			documentPanel.replaceChildren(make("p", "reports-error", error?.status === 404 ? "Report not found." : (error.message || "Could not load report details.")));
		}
	}

	list.addEventListener("click", (event) => {
		const button = event.target.closest("button[data-report-id]");
		if (button?.dataset.reportId) openReport(button.dataset.reportId);
	});
	previousButton.addEventListener("click", () => {
		if (loadingList || page <= 1) return;
		page -= 1;
		loadReportList();
	});
	nextButton.addEventListener("click", () => {
		if (loadingList || page >= getReportPageCount(total, PAGE_SIZE)) return;
		page += 1;
		loadReportList();
	});
	document.getElementById("sidebarToggle").addEventListener("click", () => {
		document.getElementById("sidebar").classList.toggle("open");
		document.getElementById("sidebarOverlay").classList.toggle("show");
	});
	document.getElementById("sidebarOverlay").addEventListener("click", () => {
		document.getElementById("sidebar").classList.remove("open");
		document.getElementById("sidebarOverlay").classList.remove("show");
	});

	const requestedId = parseReportId(globalThis.location.search);
	const hasIdParameter = new URLSearchParams(globalThis.location.search).has("id");
	Auth.requireAuth().then((user) => {
		if (!user) return;
		if (hasIdParameter && !requestedId) {
			setListError("A valid report ID is required. Select a report from the list.");
			listLink.hidden = false;
		}
		loadReportList().then(() => {
			if (requestedId) openReport(requestedId);
		});
	});
})();