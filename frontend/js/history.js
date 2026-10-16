(() => {
	const helpers = typeof module !== "undefined" && typeof require !== "undefined"
		? require("./scan_helpers.js")
		: (globalThis.ScanHelpers || {});

	const PAGE_SIZE = 10;
	const SEVERITIES = helpers.SEVERITY_ORDER || Object.freeze(["critical", "high", "medium", "low", "info"]);
	const formatDate = helpers.formatTimestamp || ((value) => {
		if (!value) return "Not available";
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? "Not available" : date.toLocaleString();
	});
	const VALID_STATUSES = new Set(["queued", "running", "completed", "failed", "cancelled"]);

	function getPageCount(total, pageSize = PAGE_SIZE) {
		const safeTotal = Math.max(0, Number(total) || 0);
		const safePageSize = Math.max(1, Number(pageSize) || PAGE_SIZE);
		return Math.ceil(safeTotal / safePageSize);
	}

	function getPageBounds(total, page, pageSize = PAGE_SIZE) {
		const pageCount = getPageCount(total, pageSize);
		const safePage = pageCount === 0 ? 1 : Math.min(Math.max(1, Number(page) || 1), pageCount);
		return {
			page: safePage,
			pageCount,
			canPrevious: safePage > 1,
			canNext: pageCount > 0 && safePage < pageCount,
			start: Number(total) > 0 ? ((safePage - 1) * pageSize) + 1 : 0,
			end: Math.min(safePage * pageSize, Math.max(0, Number(total) || 0))
		};
	}

	function buildScansQuery({ page = 1, status = "all", targetId = "all", pageSize = PAGE_SIZE } = {}) {
		const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
		if (VALID_STATUSES.has(status)) params.set("status", status);
		if (targetId !== "all" && targetId) params.set("target_id", targetId);
		return params.toString();
	}

	function getScanDestination(scanId, status) {
		const route = status === "queued" || status === "running" ? "live_scan.html" : "results.html";
		return `${route}?id=${encodeURIComponent(scanId)}`;
	}

	function getStatusClass(status) {
		const normalized = String(status || "unknown").toLowerCase();
		return ["queued", "running", "completed", "failed", "cancelled"].includes(normalized) ? `history-status-${normalized}` : "history-status-unknown";
	}

	if (typeof module !== "undefined" && module.exports) {
		module.exports = { PAGE_SIZE, SEVERITIES, buildScansQuery, getPageBounds, getPageCount, getScanDestination, getStatusClass };
		return;
	}

	const statusFilter = document.getElementById("statusFilter");
	const targetFilter = document.getElementById("targetFilter");
	const targetFilterError = document.getElementById("targetFilterError");
	const tableBody = document.getElementById("tableBody");
	const historyLoading = document.getElementById("historyLoading");
	const historyError = document.getElementById("historyError");
	const historyEmpty = document.getElementById("historyEmpty");
	const resultCount = document.getElementById("resultCount");
	const previousButton = document.getElementById("prevBtn");
	const nextButton = document.getElementById("nextBtn");
	const pageInfo = document.getElementById("pageInfo");
	let currentPage = 1;
	let total = 0;
	let targets = [];
	let scans = [];
	let isLoading = false;
	let targetsLoaded = false;
	const deletingScans = new Set();

	function makeElement(tag, className, value) {
		const element = document.createElement(tag);
		if (className) element.className = className;
		if (value !== undefined) element.textContent = value == null || value === "" ? "—" : String(value);
		return element;
	}

	function setError(message) {
		historyError.textContent = message || "";
		historyError.hidden = !message;
	}

	function createCell(label, value, className = "") {
		const cell = makeElement("td", className, value);
		cell.dataset.label = label;
		return cell;
	}

	function renderTargetOptions() {
		const currentValue = targetFilter.value || "all";
		const options = [makeElement("option", "", "All targets")];
		options[0].value = "all";
		for (const target of targets) {
			if (!target?.id) continue;
			const option = makeElement("option", "", target.url || "Unnamed target");
			option.value = target.id;
			options.push(option);
		}
		targetFilter.replaceChildren(...options);
		if (targets.some(({ id }) => id === currentValue)) targetFilter.value = currentValue;
	}

	function scanCounts(scan) {
		const counts = scan.finding_counts || {};
		return SEVERITIES.map((severity) => Number(counts[severity]) || 0);
	}

	function createScanRow(scan) {
		const row = makeElement("tr", "history-row");
		const target = targets.find((item) => item.id === scan.target_id);
		const url = scan.target_url || target?.url || "Target URL unavailable";
		const targetCell = createCell("Target", "");
		const link = makeElement("a", "url-link", url);
		link.href = getScanDestination(scan.id, scan.status);
		targetCell.append(link);
		row.append(targetCell);

		const status = String(scan.status || "unknown").toLowerCase();
		const statusCell = createCell("Status", "");
		statusCell.append(makeElement("span", `status-badge ${getStatusClass(status)}`, status));
		row.append(statusCell);
		row.append(createCell("Depth", scan.depth || "Not available"));
		row.append(createCell("Progress / score", status === "completed" ? (scan.security_score ?? "Not scored") : `${Math.max(0, Math.min(100, Number(scan.progress) || 0))}%`, "score-cell"));
		row.append(createCell("Started", formatDate(scan.started_at), "timestamp"));
		for (const count of scanCounts(scan)) row.append(createCell("Finding count", count, "issue-count"));
		const actions = createCell("Action", "", "history-actions");
		const remove = makeElement("button", "history-delete", deletingScans.has(scan.id) ? "Deleting…" : "Delete");
		remove.type = "button";
		remove.dataset.scanId = scan.id;
		remove.disabled = deletingScans.has(scan.id);
		actions.append(remove);
		row.append(actions);
		return row;
	}

	function updatePagination() {
		const bounds = getPageBounds(total, currentPage, PAGE_SIZE);
		currentPage = bounds.page;
		pageInfo.textContent = total ? `Page ${bounds.page} of ${bounds.pageCount}` : "Page 0 of 0";
		resultCount.textContent = total ? `${bounds.start}–${bounds.end} of ${total}` : "0 scans";
		previousButton.disabled = isLoading || !bounds.canPrevious;
		nextButton.disabled = isLoading || !bounds.canNext;
	}

	function renderRows() {
		tableBody.replaceChildren(...scans.map(createScanRow));
		const isFiltered = statusFilter.value !== "all" || targetFilter.value !== "all";
		historyEmpty.replaceChildren();
		if (isFiltered) {
			historyEmpty.textContent = "No scans match the selected filters.";
		} else {
			historyEmpty.append(document.createTextNode("No scans yet. "));
			const link = makeElement("a", "", "Start a new scan");
			link.href = "new_scan.html";
			historyEmpty.append(link, document.createTextNode("."));
		}
		historyEmpty.hidden = isLoading || scans.length > 0 || Boolean(historyError.textContent);
		updatePagination();
	}

	async function loadTargets() {
		try {
			const response = await Api.get("/api/targets");
			targets = Array.isArray(response) ? response : [];
			renderTargetOptions();
			targetFilterError.hidden = true;
		} catch (error) {
			targetFilterError.textContent = error.message || "Could not load target filters.";
			targetFilterError.hidden = false;
		} finally {
			targetsLoaded = true;
		}
	}

	async function loadScans() {
		if (isLoading) return;
		isLoading = true;
		historyLoading.hidden = false;
		statusFilter.disabled = true;
		targetFilter.disabled = true;
		setError("");
		previousButton.disabled = true;
		nextButton.disabled = true;
		historyEmpty.hidden = true;
		try {
			const query = buildScansQuery({
				page: currentPage,
				status: statusFilter.value,
				targetId: targetFilter.value,
				pageSize: PAGE_SIZE
			});
			const response = await Api.get(`/api/scans?${query}`);
			total = Number(response?.total) || 0;
			scans = Array.isArray(response?.scans) ? response.scans : [];
			const bounds = getPageBounds(total, currentPage, PAGE_SIZE);
			if (total > 0 && currentPage > bounds.page) {
				currentPage = bounds.page;
				isLoading = false;
				return loadScans();
			}
			renderRows();
		} catch (error) {
			scans = [];
			tableBody.replaceChildren();
			setError(error.message || "Could not load scan history.");
		} finally {
			isLoading = false;
			historyLoading.hidden = true;
			statusFilter.disabled = false;
			targetFilter.disabled = false;
			renderRows();
		}
	}

	async function deleteScan(scanId) {
		if (!scanId || deletingScans.has(scanId)) return;
		const confirmed = globalThis.confirm("Delete this scan? Its findings and reports will also be deleted.");
		if (!confirmed) return;
		deletingScans.add(scanId);
		renderRows();
		try {
			await Api.request(`/api/scans/${encodeURIComponent(scanId)}`, { method: "DELETE" });
			setError("");
			if (scans.length === 1 && currentPage > 1) currentPage -= 1;
			await loadScans();
		} catch (error) {
			const message = error?.status === 409
				? `${error.message} Cancel the scan first, then delete it.`
				: (error.message || "Could not delete this scan.");
			setError(message);
		} finally {
			deletingScans.delete(scanId);
			renderRows();
		}
	}

	previousButton.addEventListener("click", () => {
		if (isLoading || currentPage <= 1) return;
		currentPage -= 1;
		loadScans();
	});
	nextButton.addEventListener("click", () => {
		if (isLoading || currentPage >= getPageCount(total, PAGE_SIZE)) return;
		currentPage += 1;
		loadScans();
	});
	statusFilter.addEventListener("change", () => { currentPage = 1; loadScans(); });
	targetFilter.addEventListener("change", () => { currentPage = 1; loadScans(); });
	tableBody.addEventListener("click", (event) => {
		const button = event.target.closest("button[data-scan-id]");
		if (button) deleteScan(button.dataset.scanId);
	});
	document.getElementById("sidebarToggle").addEventListener("click", () => {
		document.getElementById("sidebar").classList.toggle("open");
		document.getElementById("sidebarOverlay").classList.toggle("show");
	});
	document.getElementById("sidebarOverlay").addEventListener("click", () => {
		document.getElementById("sidebar").classList.remove("open");
		document.getElementById("sidebarOverlay").classList.remove("show");
	});

	Auth.requireAuth().then(async (user) => {
		if (!user) return;
		await loadTargets();
		if (targetsLoaded) loadScans();
	});
})();