(() => {
	const DEPTHS = Object.freeze({
		quick: "Home page and well-known paths; passive checks only.",
		standard: "A limited crawl plus light parameter probes.",
		deep: "A larger crawl and more probes; takes longest."
	});
	const MODULES = Object.freeze([
		{ key: "headers", label: "Security headers", description: "Check browser security headers on site pages." },
		{ key: "https", label: "HTTPS and TLS", description: "Check encrypted transport, certificates, and HSTS." },
		{ key: "cookies", label: "Cookie security", description: "Check Secure, HttpOnly, and SameSite cookie flags." },
		{ key: "cors", label: "Cross-origin policy", description: "Check for permissive cross-origin response headers." },
		{ key: "http_methods", label: "HTTP methods", description: "Check advertised methods and safe TRACE behavior." },
		{ key: "info_disclosure", label: "Information disclosure", description: "Look for version headers and exposed error details." },
		{ key: "exposed_files", label: "Exposed files", description: "Check common sensitive paths for exposed content." },
		{ key: "sqli", label: "SQL injection", description: "Run limited, non-destructive SQL injection probes." },
		{ key: "xss", label: "Cross-site scripting", description: "Check for harmless reflected input in responses." },
		{ key: "access_control", label: "Access control", description: "Check common paths for publicly accessible areas." },
		{ key: "auth_checks", label: "Authentication checks", description: "Review login-form responses and basic throttling." }
	]);
	const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

	function getDefaultDepth(settings) {
		const value = settings?.default_scan_depth;
		return Object.hasOwn(DEPTHS, value) ? value : "standard";
	}

	function parseTargetId(search) {
		const value = new URLSearchParams(search || "").get("target");
		return value && UUID_PATTERN.test(value) ? value : null;
	}

	function selectedModuleKeys(checkedModules) {
		return MODULES.filter(({ key }) => checkedModules.includes(key)).map(({ key }) => key);
	}

	if (typeof module !== "undefined" && module.exports) {
		module.exports = { DEPTHS, MODULES, getDefaultDepth, parseTargetId, selectedModuleKeys };
		return;
	}

	const form = document.getElementById("scanForm");
	if (!form) return;
	const targetSelect = document.getElementById("targetSelect");
	const targetHelp = document.getElementById("targetHelp");
	const targetError = document.getElementById("targetError");
	const settingsLoading = document.getElementById("settingsLoading");
	const settingsError = document.getElementById("settingsError");
	const formError = document.getElementById("formError");
	const moduleError = document.getElementById("moduleError");
	const authorizationError = document.getElementById("authorizationError");
	const moduleChoices = document.getElementById("moduleChoices");
	const toggleModules = document.getElementById("toggleModules");
	const authorization = document.getElementById("authorized");
	const startButton = document.getElementById("startScanBtn");
	const startLoading = document.getElementById("startLoading");
	let isSubmitting = false;
	let hasVerifiedTargets = false;
	let settingsLoaded = false;

	function updateSubmitAvailability() {
		startButton.disabled = !hasVerifiedTargets || !settingsLoaded || isSubmitting;
	}

	function setMessage(node, message) {
		node.textContent = message;
		node.hidden = !message;
	}

	function makeModuleChoice({ key, label, description }) {
		const choice = document.createElement("label");
		choice.className = "module-choice";
		const input = document.createElement("input");
		input.type = "checkbox";
		input.name = "modules";
		input.value = key;
		input.checked = true;
		const text = document.createElement("span");
		const strong = document.createElement("strong");
		strong.textContent = label;
		const small = document.createElement("small");
		small.textContent = description;
		text.append(strong, small);
		choice.append(input, text);
		return choice;
	}

	function renderTargets(targets) {
		const safeTargets = targets.filter((target) => target && typeof target === "object");
		const verifiedTargets = safeTargets.filter((target) => target.is_verified === true && typeof target.id === "string");
		hasVerifiedTargets = verifiedTargets.length > 0;
		updateSubmitAvailability();
		targetSelect.replaceChildren();
		const prompt = document.createElement("option");
		prompt.value = "";
		prompt.textContent = verifiedTargets.length ? "Choose a verified target" : "No verified targets available";
		targetSelect.append(prompt);
		for (const target of safeTargets) {
			const option = document.createElement("option");
			option.value = typeof target.id === "string" ? target.id : "";
			option.textContent = target.is_verified === true ? (target.url || "Unnamed target") : `${target.url || "Unnamed target"} (not verified)`;
			option.disabled = target.is_verified !== true || !target.id;
			targetSelect.append(option);
		}
		targetSelect.disabled = verifiedTargets.length === 0;
		const requestedId = parseTargetId(globalThis.location.search);
		if (requestedId && verifiedTargets.some(({ id }) => id === requestedId)) targetSelect.value = requestedId;
		if (verifiedTargets.length === 0) {
			setMessage(targetHelp, "No verified targets are available. Verify a target before starting a scan.");
			const link = document.createElement("a");
			link.href = "target_verify.html";
			link.textContent = " Open target verification";
			targetHelp.append(link);
		} else {
			const unverifiedCount = safeTargets.length - verifiedTargets.length;
			setMessage(targetHelp, unverifiedCount ? `${unverifiedCount} unverified target(s) are disabled. Verify them before scanning.` : "Only verified targets can be scanned.");
			if (unverifiedCount) {
				const link = document.createElement("a");
				link.href = "target_verify.html";
				link.textContent = " Verify a target";
				targetHelp.append(link);
			}
		}
	}

	async function loadFormOptions() {
		moduleChoices.replaceChildren(...MODULES.map(makeModuleChoice));
		try {
			const targets = await Api.get("/api/targets");
			renderTargets(Array.isArray(targets) ? targets : []);
		} catch (error) {
			setMessage(targetError, error.message || "Could not load targets.");
			targetSelect.replaceChildren(new Option("Targets could not be loaded", ""));
			targetSelect.disabled = true;
			startButton.disabled = true;
		}
		try {
			const settings = await Api.get("/api/user/settings");
			document.querySelector(`input[name="depth"][value="${getDefaultDepth(settings)}"]`).checked = true;
			settingsLoading.hidden = true;
		} catch (error) {
			settingsLoading.hidden = true;
			setMessage(settingsError, `${error.message || "Could not load settings."} Using standard depth.`);
			document.querySelector('input[name="depth"][value="standard"]').checked = true;
		} finally {
			settingsLoaded = true;
			updateSubmitAvailability();
		}
	}

	function updateModuleToggleLabel() {
		const allSelected = [...moduleChoices.querySelectorAll('input[name="modules"]')].every((input) => input.checked);
		toggleModules.textContent = allSelected ? "Select none" : "Select all";
	}

	toggleModules.addEventListener("click", () => {
		const checkboxes = [...moduleChoices.querySelectorAll('input[name="modules"]')];
		const selectAll = checkboxes.some((input) => !input.checked);
		checkboxes.forEach((input) => { input.checked = selectAll; });
		updateModuleToggleLabel();
	});
	moduleChoices.addEventListener("change", updateModuleToggleLabel);

	form.addEventListener("submit", async (event) => {
		event.preventDefault();
		if (isSubmitting) return;
		for (const node of [formError, moduleError, authorizationError]) setMessage(node, "");
		if (!targetSelect.value) {
			setMessage(formError, "Select a verified target before starting a scan.");
			targetSelect.focus();
			return;
		}
		const checkedModules = [...moduleChoices.querySelectorAll('input[name="modules"]:checked')].map((input) => input.value);
		const modules = selectedModuleKeys(checkedModules);
		if (modules.length === 0) {
			setMessage(moduleError, "Select at least one security check.");
			return;
		}
		if (!authorization.checked) {
			setMessage(authorizationError, "Confirm that you own this website or have written permission to test it.");
			authorization.focus();
			return;
		}
		const depth = document.querySelector('input[name="depth"]:checked')?.value || "standard";
		isSubmitting = true;
		startButton.disabled = true;
		startLoading.hidden = false;
		try {
			const scan = await Api.post("/api/scans", { target_id: targetSelect.value, depth, modules });
			if (!scan?.id) throw new Error("The server did not return a scan ID.");
			globalThis.location.assign(`live_scan.html?id=${encodeURIComponent(scan.id)}`);
		} catch (error) {
			setMessage(formError, error.message || "Could not start the scan.");
		} finally {
			isSubmitting = false;
			updateSubmitAvailability();
			startLoading.hidden = true;
		}
	});

	document.getElementById("sidebarToggle").addEventListener("click", () => {
		document.getElementById("sidebar").classList.toggle("open");
		document.getElementById("sidebarOverlay").classList.toggle("show");
	});
	document.getElementById("sidebarOverlay").addEventListener("click", () => {
		document.getElementById("sidebar").classList.remove("open");
		document.getElementById("sidebarOverlay").classList.remove("show");
	});

	Auth.requireAuth().then((user) => {
		if (user) loadFormOptions();
	});
})();