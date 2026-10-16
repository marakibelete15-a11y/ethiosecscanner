(() => {
	const SEVERITIES = Object.freeze(["critical", "high", "medium", "low", "info"]);

	function getBarWidth(value, maximum) {
		const count = Math.max(0, Number(value) || 0);
		const max = Math.max(0, Number(maximum) || 0);
		if (count === 0 || max === 0) return 0;
		return Math.min(100, Math.max(6, (count / max) * 100));
	}

	function getDashboardText(summary) {
		const data = summary || {};
		return {
			totalTargets: Math.max(0, Number(data.total_targets) || 0),
			verifiedTargets: Math.max(0, Number(data.verified_targets) || 0),
			totalScans: Math.max(0, Number(data.total_scans) || 0),
			completedScans: Math.max(0, Number(data.completed_scans) || 0),
			latestScore: data.latest_security_score == null ? "—" : String(data.latest_security_score)
		};
	}

	function getScanLink(scan) {
		const status = String(scan?.status || "").toLowerCase();
		const route = status === "queued" || status === "running" ? "live_scan.html" : "results.html";
		return `${route}?id=${encodeURIComponent(scan?.id || "")}`;
	}

	function formatDate(value) {
		if (!value) return "Not available";
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? "Not available" : date.toLocaleString();
	}

	function formatStatus(status) {
		if (!status) return "Unknown";
		const str = String(status).toLowerCase();
		return str.charAt(0).toUpperCase() + str.slice(1);
	}

	function getStatusBadgeClass(status) {
		const normalized = String(status || "unknown").toLowerCase();
		return ["queued", "running", "completed", "failed", "cancelled"].includes(normalized)
			? `status-${normalized}`
			: "status-unknown";
	}

	if (typeof module !== "undefined" && module.exports) {
		module.exports = {
			SEVERITIES,
			formatDate,
			formatStatus,
			getBarWidth,
			getDashboardText,
			getScanLink,
			getStatusBadgeClass
		};
		return;
	}

	const loading = document.getElementById("dashboardLoading");
	const error = document.getElementById("dashboardError");
	const severityBars = document.getElementById("severityBars");
	const recentScans = document.getElementById("recentScans");
	const empty = document.getElementById("dashboardEmpty");

	function setText(id, value) {
		const node = document.getElementById(id);
		if (node) node.textContent = String(value);
	}

	function make(tag, className, text) {
		const node = document.createElement(tag);
		if (className) node.className = className;
		if (text !== undefined) node.textContent = text == null || text === "" ? "—" : String(text);
		return node;
	}

	function renderSeverity(distribution = {}) {
		const values = SEVERITIES.map((severity) => Math.max(0, Number(distribution[severity]) || 0));
		const maximum = Math.max(0, ...values);
		const rows = SEVERITIES.map((severity, index) => {
			const row = make("div", `severity-row severity-${severity}`);
			row.append(make("span", "severity-name", severity.charAt(0).toUpperCase() + severity.slice(1)));
			const track = make("div", "severity-track");
			track.setAttribute("role", "img");
			track.setAttribute("aria-label", `${severity}: ${values[index]}`);
			const bar = make("span", "severity-fill");
			bar.style.width = `${getBarWidth(values[index], maximum)}%`;
			track.append(bar);
			row.append(track, make("strong", "severity-value", values[index]));
			return row;
		});
		severityBars.replaceChildren(...rows);
	}

	function renderRecent(scans) {
		const validScans = Array.isArray(scans) ? scans.slice(0, 5) : [];
		empty.hidden = validScans.length > 0;
		if (!validScans.length) {
			recentScans.replaceChildren();
			return;
		}
		const rows = validScans.map((scan) => {
			const row = make("article", "recent-scan-row");
			const details = make("div", "recent-scan-details");
			details.append(make("strong", "recent-scan-target", scan.target_url || "Target URL unavailable"));
			const scoreText = scan.security_score == null ? "—" : scan.security_score;
			const timeAndScore = make(
				"span",
				"recent-scan-meta",
				`${formatDate(scan.started_at || scan.created_at)} · Score ${scoreText}`
			);
			details.append(timeAndScore);
			const normalizedStatus = String(scan.status || "unknown").toLowerCase();
			const status = make("span", `dashboard-status ${getStatusBadgeClass(scan.status)}`, formatStatus(scan.status));
			const isRunning = normalizedStatus === "queued" || normalizedStatus === "running";
			const link = make("a", "recent-scan-link", isRunning ? "Open live scan" : "View results");
			link.href = getScanLink(scan);
			row.append(details, status, link);
			return row;
		});
		recentScans.replaceChildren(...rows);
	}

	async function loadDashboard() {
		loading.hidden = false;
		error.hidden = true;
		try {
			const summary = await Api.get("/api/dashboard/summary");
			const values = getDashboardText(summary);
			setText("totalTargets", values.totalTargets);
			setText("verifiedTargets", values.verifiedTargets);
			setText("totalScans", values.totalScans);
			setText("completedScans", values.completedScans);
			setText("latestScore", values.latestScore);
			renderSeverity(summary.severity_distribution || {});
			renderRecent(summary.recent_scans || []);
		} catch (requestError) {
			error.textContent = requestError.message || "Could not load dashboard summary.";
			error.hidden = false;
		} finally {
			loading.hidden = true;
		}
	}

	document.getElementById("sidebarToggle").addEventListener("click", () => {
		document.getElementById("sidebar").classList.toggle("open");
		document.getElementById("sidebarOverlay").classList.toggle("show");
	});
	document.getElementById("sidebarOverlay").addEventListener("click", () => {
		document.getElementById("sidebar").classList.remove("open");
		document.getElementById("sidebarOverlay").classList.remove("show");
	});
	Auth.requireAuth().then((user) => {
		if (user) loadDashboard();
	});
})();