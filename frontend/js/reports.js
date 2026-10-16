(() => {
	const helpers = typeof module !== "undefined" && typeof require !== "undefined"
		? require("./scan_helpers.js")
		: (globalThis.ScanHelpers || {});

	const {
		SEVERITY_ORDER,
		formatTimestamp,
		getSeverityCount,
		getVerdictKey,
		getVerdictMessage,
		isSafeHttpUrl,
		isValidUuid,
		parseIdFromQuery,
		severityClass
	} = helpers;

	const PAGE_SIZE = 10;

	function parseReportId(search) {
		return parseIdFromQuery(search, "id");
	}

	function hasReportIdParam(search) {
		return new URLSearchParams(search || "").has("id");
	}

	function getScoreClass(score) {
		const num = Number(score);
		if (Number.isNaN(num)) return "score-mid";
		if (num >= 80) return "score-good";
		if (num >= 50) return "score-mid";
		return "score-bad";
	}

	function getReportPageBounds(total, page, pageSize = PAGE_SIZE) {
		const totalItems = Math.max(0, Number(total) || 0);
		const size = Math.max(1, Number(pageSize) || 10);
		const pageCount = Math.max(1, Math.ceil(totalItems / size));
		const currentPage = Math.min(Math.max(1, Number(page) || 1), pageCount);
		const canPrevious = currentPage > 1;
		const canNext = currentPage < pageCount;
		return {
			page: currentPage,
			pageCount,
			total: totalItems,
			canPrevious,
			canNext
		};
	}

	function getModuleRows(report) {
		const summary = report?.summary || report || {};
		const raw = summary.modules || summary.module_progress || summary.per_module || summary.module_data || [];
		if (Array.isArray(raw)) {
			return raw.map((item) => ({
				module: item.module || item.name || "unknown",
				status: item.status || "completed",
				checksRun: Number(item.checks_run ?? item.checksRun ?? 0),
				checksPassed: Number(item.checks_passed ?? item.checksPassed ?? 0),
				findingsCount: Number(item.findings_count ?? item.findingsCount ?? item.count ?? 0)
			}));
		}
		if (raw && typeof raw === "object") {
			return Object.entries(raw).map(([key, item]) => ({
				module: key,
				status: item?.status || "completed",
				checksRun: Number(item?.checks_run ?? item?.checksRun ?? 0),
				checksPassed: Number(item?.checks_passed ?? item?.checksPassed ?? 0),
				findingsCount: Number(item?.findings_count ?? item?.findingsCount ?? item?.count ?? 0)
			}));
		}
		return [];
	}

	function formatFindingMeta(finding) {
		const parts = [];
		if (finding?.owasp_category) parts.push(`OWASP: ${finding.owasp_category}`);
		if (finding?.cwe_id) parts.push(`CWE: ${finding.cwe_id}`);
		return parts.join(" · ");
	}

	if (typeof module !== "undefined" && module.exports) {
		module.exports = {
			PAGE_SIZE,
			formatFindingMeta,
			getModuleRows,
			getReportPageBounds,
			getScoreClass,
			hasReportIdParam,
			parseReportId
		};
		return;
	}

	const reportList = document.getElementById("reportList");
	const reportListLoading = document.getElementById("reportListLoading");
	const reportListEmpty = document.getElementById("reportListEmpty");
	const reportCount = document.getElementById("reportCount");
	const reportPagination = document.getElementById("reportPagination");
	const prevBtn = document.getElementById("prevBtn");
	const nextBtn = document.getElementById("nextBtn");
	const pageInfo = document.getElementById("pageInfo");
	const reportDoc = document.getElementById("reportDoc");
	const pageError = document.getElementById("pageError");
	const pageLoading = document.getElementById("pageLoading");

	let currentPage = 1;
	let currentReportId = parseReportId(globalThis.location.search);

	function textElement(tag, className, text) {
		const node = document.createElement(tag);
		if (className) node.className = className;
		if (text !== undefined) node.textContent = text == null || text === "" ? "—" : String(text);
		return node;
	}

	function showError(message) {
		if (pageError) {
			pageError.textContent = message;
			pageError.hidden = false;
		}
	}

	function renderReportError(message) {
		reportDoc.replaceChildren();
		const box = textElement("div", "report-error-box");
		box.append(textElement("h3", "", "Report Error"));
		box.append(textElement("p", "", message));
		const link = textElement("a", "primary-btn", "Back to reports list");
		link.href = "reports.html";
		box.append(link);
		reportDoc.append(box);
	}

	function renderReportDocument(report) {
		reportDoc.replaceChildren();
		const summary = report?.summary || {};
		const findings = Array.isArray(report?.findings) ? report.findings : [];
		const targetUrl = summary.target_url || summary.target || "Target URL unavailable";
		const score = summary.score ?? summary.security_score ?? "—";
		const verdictKey = getVerdictKey(summary);
		const passedCount = Number(summary.passed_count ?? summary.checks_passed ?? 0);
		const scannerErrorCount = Number(summary.scanner_error_count ?? summary.scanner_errors ?? 0);

		// Header
		const head = textElement("div", "doc-head");
		const titleBlock = textElement("div", "doc-title-block");
		titleBlock.append(textElement("h2", "", "Security Assessment Report"));
		titleBlock.append(textElement("p", "", targetUrl));

		const actions = textElement("div", "doc-actions");
		const printBtn = textElement("button", "primary-btn", "Export PDF");
		printBtn.type = "button";
		printBtn.id = "exportPdfBtn";
		printBtn.addEventListener("click", () => globalThis.print());

		const allReportsLink = textElement("a", "ghost-btn", "← All reports");
		allReportsLink.href = "reports.html";

		actions.append(printBtn, allReportsLink);
		head.append(titleBlock, actions);
		reportDoc.append(head);

		// Executive Summary
		const execSection = textElement("div", "doc-section");
		execSection.append(textElement("h3", "", "Executive Summary"));
		const execSummary = textElement("div", "exec-summary");
		execSummary.append(
			textElement("h4", "", `${verdictKey.toUpperCase()} VERDICT`),
			textElement("p", "", getVerdictMessage(verdictKey, passedCount))
		);
		execSection.append(execSummary);
		reportDoc.append(execSection);

		// Score & Severity Strip
		const scoreSection = textElement("div", "doc-section");
		scoreSection.append(textElement("h3", "", "Score & Severity Breakdown"));
		const strip = textElement("div", "score-strip");

		function addTile(value, label, className = "") {
			const tile = textElement("div", `score-tile ${className}`.trim());
			tile.append(textElement("b", "", value));
			tile.append(textElement("span", "", label));
			strip.append(tile);
		}

		addTile(score, "Score", getScoreClass(score));
		for (const sev of SEVERITY_ORDER) {
			addTile(getSeverityCount(summary, sev), sev, severityClass(sev));
		}
		addTile(passedCount, "Passed");
		addTile(scannerErrorCount, "Errors");
		scoreSection.append(strip);
		reportDoc.append(scoreSection);

		// Assessment Details Table
		const metaSection = textElement("div", "doc-section");
		metaSection.append(textElement("h3", "", "Assessment Details"));
		const metaTable = textElement("table", "tech-table");
		const tbody = document.createElement("tbody");

		function addMetaRow(label, value) {
			const tr = document.createElement("tr");
			tr.append(textElement("td", "", label));
			tr.append(textElement("td", "", value));
			tbody.append(tr);
		}

		addMetaRow("Target URL", targetUrl);
		addMetaRow("Report ID", report.id);
		addMetaRow("Scan ID", report.scan_id || summary.scan_id || "—");
		addMetaRow("Scan Depth", summary.depth || "standard");
		addMetaRow("Scan Started", formatTimestamp(summary.started_at || summary.created_at));
		addMetaRow("Scan Finished", formatTimestamp(summary.finished_at));
		addMetaRow("Report Generated", formatTimestamp(report.created_at));
		metaTable.append(tbody);
		metaSection.append(metaTable);
		reportDoc.append(metaSection);

		// Module Execution Summary Table
		const moduleRows = getModuleRows(report);
		if (moduleRows.length > 0) {
			const moduleSection = textElement("div", "doc-section");
			moduleSection.append(textElement("h3", "", "Module Execution Summary"));
			const modTable = textElement("table", "module-table");
			const thead = document.createElement("thead");
			const htr = document.createElement("tr");
			htr.append(
				textElement("th", "", "Module"),
				textElement("th", "", "Status"),
				textElement("th", "", "Checks Run"),
				textElement("th", "", "Checks Passed"),
				textElement("th", "", "Findings")
			);
			thead.append(htr);
			const mtbody = document.createElement("tbody");
			for (const m of moduleRows) {
				const tr = document.createElement("tr");
				tr.append(
					textElement("td", "module-name", m.module),
					textElement("td", "module-status", m.status),
					textElement("td", "", m.checksRun),
					textElement("td", "", m.checksPassed),
					textElement("td", "", m.findingsCount)
				);
				mtbody.append(tr);
			}
			modTable.append(thead, mtbody);
			moduleSection.append(modTable);
			reportDoc.append(moduleSection);
		}

		// Vulnerability Findings (in API order)
		const findingsSection = textElement("div", "doc-section");
		findingsSection.append(textElement("h3", "", `Vulnerability Findings (${findings.length})`));
		if (findings.length === 0) {
			findingsSection.append(textElement("p", "empty-state", "No findings were reported for this assessment."));
		} else {
			for (const finding of findings) {
				const sev = String(finding.severity || "info").toLowerCase();
				const card = textElement("article", `fix-item ${sev}`);

				const fHead = textElement("div", "fix-head");
				const printSev = textElement("span", "print-severity", `[${sev.toUpperCase()}] `);
				const badge = textElement("span", `severity-badge ${severityClass(sev)}`, sev);
				const title = textElement("strong", "", finding.title);
				fHead.append(printSev, badge, title);
				card.append(fHead);

				const meta = textElement("div", "finding-meta");
				if (finding.owasp_category) meta.append(textElement("span", "", `OWASP: ${finding.owasp_category}`));
				if (finding.cwe_id) meta.append(textElement("span", "", `CWE: ${finding.cwe_id}`));
				if (finding.affected_url) {
					const urlSpan = textElement("span", "finding-url");
					urlSpan.append(document.createTextNode("URL: "));
					if (isSafeHttpUrl(finding.affected_url)) {
						const link = textElement("a", "", finding.affected_url);
						link.href = finding.affected_url;
						link.target = "_blank";
						link.rel = "noopener noreferrer";
						urlSpan.append(link);
					} else {
						urlSpan.append(document.createTextNode(finding.affected_url));
					}
					meta.append(urlSpan);
				}
				card.append(meta);

				if (finding.description) {
					card.append(textElement("h4", "", "Description"));
					card.append(textElement("p", "", finding.description));
				}
				if (finding.evidence) {
					card.append(textElement("h4", "", "Evidence"));
					card.append(textElement("pre", "finding-evidence", finding.evidence));
				}
				if (finding.remediation) {
					card.append(textElement("h4", "", "Remediation"));
					card.append(textElement("p", "", finding.remediation));
				}
				findingsSection.append(card);
			}
		}
		reportDoc.append(findingsSection);
	}

	async function loadSingleReport(id) {
		if (pageLoading) pageLoading.hidden = false;
		try {
			const report = await Api.get(`/api/reports/${encodeURIComponent(id)}`);
			renderReportDocument(report);
		} catch (error) {
			const message = error.status === 404 ? "Report not found." : (error.message || "Could not load report.");
			renderReportError(message);
		} finally {
			if (pageLoading) pageLoading.hidden = true;
		}
	}

	function renderReportsList(reports, total) {
		const items = Array.isArray(reports) ? reports : [];
		reportList.replaceChildren();

		if (!items.length) {
			if (reportListEmpty) reportListEmpty.hidden = false;
			if (reportPagination) reportPagination.hidden = true;
			if (reportCount) reportCount.textContent = "0 reports";
			return;
		}

		if (reportListEmpty) reportListEmpty.hidden = true;
		if (reportCount) reportCount.textContent = `${total} ${total === 1 ? "report" : "reports"}`;

		for (const report of items) {
			const summary = report.summary || {};
			const card = textElement("article", "report-item");
			if (report.id === currentReportId) card.classList.add("active");

			const main = textElement("div", "report-item-main");
			const host = textElement("div", "report-host", summary.target_url || summary.target || "Target URL unavailable");
			const date = formatTimestamp(summary.started_at || summary.created_at || report.created_at);
			const verdict = summary.verdict || getVerdictKey(summary);
			const when = textElement("div", "report-when", `${date} · ${verdict} verdict`);
			const link = textElement("a", "report-open-link", "Open report →");
			link.href = `reports.html?id=${encodeURIComponent(report.id)}`;
			main.append(host, when, link);

			const scoreValue = summary.score ?? summary.security_score ?? "—";
			const scoreBadge = textElement("div", `report-score ${getScoreClass(scoreValue)}`, scoreValue);

			card.append(main, scoreBadge);
			card.addEventListener("click", (event) => {
				if (event.target !== link) {
					globalThis.location.assign(`reports.html?id=${encodeURIComponent(report.id)}`);
				}
			});
			reportList.append(card);
		}

		const bounds = getReportPageBounds(total, currentPage, PAGE_SIZE);
		if (pageInfo) pageInfo.textContent = `Page ${bounds.page} of ${bounds.pageCount}`;
		if (prevBtn) prevBtn.disabled = !bounds.canPrevious;
		if (nextBtn) nextBtn.disabled = !bounds.canNext;
		if (reportPagination) reportPagination.hidden = bounds.pageCount <= 1;
	}

	async function loadReportsList(page = 1) {
		if (reportListLoading) reportListLoading.hidden = false;
		if (prevBtn) prevBtn.disabled = true;
		if (nextBtn) nextBtn.disabled = true;

		try {
			const response = await Api.get(`/api/reports?page=${page}&page_size=${PAGE_SIZE}`);
			currentPage = page;
			renderReportsList(response?.reports || [], response?.total || 0);
		} catch (error) {
			showError(error.message || "Could not load reports list.");
		} finally {
			if (reportListLoading) reportListLoading.hidden = true;
		}
	}

	prevBtn?.addEventListener("click", () => {
		if (currentPage > 1) loadReportsList(currentPage - 1);
	});

	nextBtn?.addEventListener("click", () => {
		loadReportsList(currentPage + 1);
	});

	document.getElementById("sidebarToggle")?.addEventListener("click", () => {
		document.getElementById("sidebar")?.classList.toggle("open");
		document.getElementById("sidebarOverlay")?.classList.toggle("show");
	});
	document.getElementById("sidebarOverlay")?.addEventListener("click", () => {
		document.getElementById("sidebar")?.classList.remove("open");
		document.getElementById("sidebarOverlay")?.classList.remove("show");
	});

	Auth.requireAuth().then((user) => {
		if (!user) return;
		loadReportsList(currentPage);
		if (hasReportIdParam(globalThis.location.search)) {
			if (!currentReportId) {
				renderReportError("Invalid report ID format. Choose a report from the list.");
			} else {
				loadSingleReport(currentReportId);
			}
		}
	});
})();
