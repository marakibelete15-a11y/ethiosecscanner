(() => {
	const helpers = typeof module !== "undefined" && typeof require !== "undefined"
		? require("./scan_helpers.js")
		: (globalThis.ScanHelpers || {});

	const SCAN_ID_PATTERN = helpers.SCAN_ID_PATTERN || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	const parseScanId = helpers.parseScanId || ((search) => {
		const value = new URLSearchParams(search || "").get("id");
		return value && SCAN_ID_PATTERN.test(value) ? value : null;
	});
	const TERMINAL_STATES = new Set(["completed", "failed", "cancelled"]);
	const POLL_INTERVAL_MS = 2000;
	const HIDDEN_POLL_INTERVAL_MS = 10000;
	const MAX_NETWORK_RETRIES = 3;
	const MODULE_LABELS = Object.freeze({
		headers: "Security headers",
		https: "HTTPS and TLS",
		cookies: "Cookie security",
		cors: "Cross-origin policy",
		http_methods: "HTTP methods",
		info_disclosure: "Information disclosure",
		exposed_files: "Exposed files",
		sqli: "SQL injection",
		xss: "Cross-site scripting",
		access_control: "Access control",
		auth_checks: "Authentication checks"
	});

	function clampProgress(value) {
		const numericValue = Number(value);
		return Number.isFinite(numericValue) ? Math.max(0, Math.min(100, Math.round(numericValue))) : 0;
	}

	function getModuleRows(moduleProgress) {
		if (!moduleProgress || typeof moduleProgress !== "object" || Array.isArray(moduleProgress)) return [];
		return Object.entries(moduleProgress).map(([key, data]) => {
			const rawState = data && typeof data.status === "string" ? data.status.toLowerCase() : "pending";
			const state = ["pending", "running", "done", "error"].includes(rawState) ? rawState : "pending";
			return { key, label: MODULE_LABELS[key] || key.replaceAll("_", " "), state };
		});
	}

	function getStateLabel(state) {
		const normalizedState = typeof state === "string" ? state.toLowerCase() : "";
		const labels = { queued: "Queued", running: "Running", completed: "Completed", failed: "Failed", cancelled: "Cancelled" };
		return labels[normalizedState] || "Unknown";
	}

	function getModuleStateLabel(state) {
		const labels = { pending: "Pending", running: "Running", done: "Done", error: "Error" };
		return labels[state] || "Pending";
	}

	function getPollingInterval(isHidden) {
		return isHidden ? HIDDEN_POLL_INTERVAL_MS : POLL_INTERVAL_MS;
	}

	function isTerminalState(state) {
		return TERMINAL_STATES.has(String(state || "").toLowerCase());
	}

	function isNetworkError(error) {
		return error?.status === 0 || error?.code === "NETWORK_ERROR";
	}

	if (typeof module !== "undefined" && module.exports) {
		module.exports = {
			MAX_NETWORK_RETRIES,
			MODULE_LABELS,
			POLL_INTERVAL_MS,
			clampProgress,
			getModuleRows,
			getModuleStateLabel,
			getPollingInterval,
			getStateLabel,
			isNetworkError,
			isTerminalState,
			parseScanId
		};
		return;
	}

	const scanId = parseScanId(globalThis.location.search);
	const scanTarget = document.getElementById("scanTarget");
	const scanError = document.getElementById("scanError");
	const pollingStatus = document.getElementById("pollingStatus");
	const scanDetails = document.getElementById("scanDetails");
	const statusLabel = document.getElementById("statusLabel");
	const progressPercent = document.getElementById("progressPercent");
	const scanProgress = document.getElementById("scanProgress");
	const progressFill = document.getElementById("progressFill");
	const currentModule = document.getElementById("currentModule");
	const failureMessage = document.getElementById("scanFailureMessage");
	const moduleProgressList = document.getElementById("moduleProgressList");
	const cancelButton = document.getElementById("cancelScan");
	const retryButton = document.getElementById("retryPolling");
	const resultsLink = document.getElementById("viewResults");
	const anotherScanLink = document.getElementById("startAnotherScan");
	let pollingTimer = null;
	let pollingActive = false;
	let pollingInFlight = false;
	let networkRetries = 0;
	let cancelInFlight = false;

	function setText(node, value) {
		node.textContent = value;
	}

	function showError(message) {
		setText(scanError, message);
		scanError.hidden = false;
	}

	function stopPolling() {
		pollingActive = false;
		if (pollingTimer !== null) globalThis.clearTimeout(pollingTimer);
		pollingTimer = null;
	}

	function schedulePoll(delay = getPollingInterval(document.hidden)) {
		if (!pollingActive || pollingTimer !== null) return;
		pollingTimer = globalThis.setTimeout(() => {
			pollingTimer = null;
			pollStatus();
		}, delay);
	}

	function updateModules(moduleProgress) {
		const rows = getModuleRows(moduleProgress);
		moduleProgressList.replaceChildren();
		if (!rows.length) {
			const empty = document.createElement("li");
			empty.className = "module-progress-empty";
			empty.textContent = "Module details will appear when the worker reports progress.";
			moduleProgressList.append(empty);
			return;
		}
		for (const row of rows) {
			const item = document.createElement("li");
			item.className = `module-progress-item state-${row.state}`;
			const name = document.createElement("span");
			name.className = "module-progress-name";
			name.textContent = row.label;
			const state = document.createElement("span");
			state.className = "module-progress-state";
			state.textContent = getModuleStateLabel(row.state);
			item.append(name, state);
			moduleProgressList.append(item);
		}
	}

	function showTerminalState(scan) {
		stopPolling();
		cancelButton.hidden = true;
		if (scan.status === "completed") {
			setText(pollingStatus, "Scan completed. Your results are ready.");
			resultsLink.hidden = false;
			return;
		}
		setText(pollingStatus, scan.status === "cancelled" ? "Scan cancelled." : "Scan failed.");
		if (scan.error_message) {
			setText(failureMessage, scan.error_message);
			failureMessage.hidden = false;
		}
		resultsLink.hidden = false;
		anotherScanLink.hidden = false;
	}

	function renderScan(scan) {
		const progress = clampProgress(scan.progress);
		const status = String(scan.status || "unknown").toLowerCase();
		scanDetails.hidden = false;
		scanError.hidden = true;
		retryButton.hidden = true;
		setText(statusLabel, getStateLabel(status));
		statusLabel.className = `live-scan-status state-${status}`;
		setText(progressPercent, `${progress}%`);
		scanProgress.setAttribute("aria-valuenow", String(progress));
		progressFill.style.width = `${progress}%`;
		setText(currentModule, scan.current_module ? `Current module: ${MODULE_LABELS[scan.current_module] || scan.current_module.replaceAll("_", " ")}` : "Waiting for the scan worker…");
		updateModules(scan.module_progress);
		cancelButton.hidden = status !== "queued" && status !== "running";
		if (isTerminalState(status)) showTerminalState({ ...scan, status });
		else setText(pollingStatus, document.hidden ? "Scan status updates are checking in the background." : "Refreshing scan status every few seconds.");
	}

	function showPollFailure(error) {
		if (error?.status === 401) return;
		if (error?.status === 404) {
			stopPolling();
			showError("Scan not found.");
			retryButton.hidden = true;
			return;
		}
		if (isNetworkError(error)) {
			networkRetries += 1;
			if (networkRetries <= MAX_NETWORK_RETRIES) {
				setText(pollingStatus, `Connection lost. Retrying status check (${networkRetries}/${MAX_NETWORK_RETRIES})…`);
				schedulePoll(getPollingInterval(document.hidden));
				return;
			}
		}
		stopPolling();
		showError(isNetworkError(error)
			? "Could not reach the server after several attempts. Retry to resume status checks."
			: error?.message || "Could not load scan status.");
		retryButton.hidden = false;
	}

	async function pollStatus() {
		if (!pollingActive) return;
		if (pollingInFlight) {
			schedulePoll();
			return;
		}
		pollingInFlight = true;
		setText(pollingStatus, "Checking scan status…");
		try {
			const scan = await Api.get(`/api/scans/${encodeURIComponent(scanId)}/status`);
			networkRetries = 0;
			renderScan(scan || {});
			if (!isTerminalState(scan?.status)) schedulePoll();
		} catch (error) {
			showPollFailure(error);
		} finally {
			pollingInFlight = false;
		}
	}

	async function cancelScan() {
		if (cancelInFlight || cancelButton.hidden) return;
		if (!globalThis.confirm("Cancel this scan? Work completed so far will remain available in the results.")) return;
		cancelInFlight = true;
		cancelButton.disabled = true;
		setText(pollingStatus, "Sending cancellation request…");
		try {
			const result = await Api.post(`/api/scans/${encodeURIComponent(scanId)}/cancel`);
			setText(pollingStatus, result.message || "Cancellation requested. Checking final status…");
			schedulePoll(0);
		} catch (error) {
			if (error?.status === 409) {
				setText(pollingStatus, error.message || "This scan has already finished.");
				schedulePoll(0);
			} else if (error?.status !== 401) {
				showError(error?.message || "Could not cancel the scan.");
			}
		} finally {
			cancelInFlight = false;
			cancelButton.disabled = false;
		}
	}

	if (!scanId) {
		setText(scanTarget, "Scan ID is missing or invalid.");
		showError("Open a valid scan from the scan history.");
		anotherScanLink.href = "history.html";
		setText(anotherScanLink, "Open scan history");
		anotherScanLink.hidden = false;
		cancelButton.hidden = true;
	} else {
		setText(scanTarget, `Scan ID: ${scanId}`);
		cancelButton.hidden = true;
		resultsLink.href = `results.html?id=${encodeURIComponent(scanId)}`;
		resultsLink.hidden = true;
		anotherScanLink.hidden = true;
		retryButton.hidden = true;

	}

	Auth.requireAuth().then((user) => {
		if (!user || !scanId) return;
		pollingActive = true;
		pollStatus();
	});

	cancelButton.addEventListener("click", cancelScan);
	retryButton.addEventListener("click", () => {
		networkRetries = 0;
		scanError.hidden = true;
		pollingActive = true;
		pollStatus();
	});
	document.getElementById("sidebarToggle").addEventListener("click", () => {
		document.getElementById("sidebar").classList.toggle("open");
		document.getElementById("sidebarOverlay").classList.toggle("show");
	});
	document.getElementById("sidebarOverlay").addEventListener("click", () => {
		document.getElementById("sidebar").classList.remove("open");
		document.getElementById("sidebarOverlay").classList.remove("show");
	});
	document.addEventListener("visibilitychange", () => {
		if (!pollingActive || pollingInFlight) return;
		if (pollingTimer !== null) globalThis.clearTimeout(pollingTimer);
		pollingTimer = null;
		schedulePoll(getPollingInterval(document.hidden));
	});
	globalThis.addEventListener("pagehide", stopPolling, { once: true });
})();