(() => {
	const METHOD_LABELS = Object.freeze({
		meta_tag: "Meta tag",
		dns_txt: "DNS TXT record",
		http_file: "Verification file"
	});

	function formatTimestamp(value) {
		if (!value) return "Not checked";
		const date = new Date(value);
		return Number.isNaN(date.getTime()) ? "Not checked" : date.toLocaleString();
	}

	function getProofValues(target) {
		const instructions = target?.instructions || {};
		const values = [{ label: "Verification token", value: instructions.token || target?.verification_token || "" }];
		const method = target?.verification_method || instructions.method;
		const methodValues = {
			meta_tag: [["Meta tag", instructions.meta_tag]],
			http_file: [["File URL", instructions.file_url], ["File content", instructions.file_content]],
			dns_txt: [["DNS record name", instructions.dns_record_name], ["DNS record value", instructions.dns_record_value]]
		};
		for (const [label, value] of methodValues[method] || []) {
			if (value) values.push({ label, value });
		}
		return values.filter((entry) => entry.value);
	}

	function getErrorMessage(error) {
		return error?.message || "The request could not be completed. Please try again.";
	}

	if (typeof module !== "undefined" && module.exports) {
		module.exports = { formatTimestamp, getProofValues, getErrorMessage };
		return;
	}

	const addForm = document.getElementById("addTargetForm");
	if (!addForm) return;

	const targetUrlInput = document.getElementById("targetUrl");
	const methodInput = document.getElementById("verificationMethod");
	const addButton = document.getElementById("addTargetButton");
	const addFeedback = document.getElementById("addTargetFeedback");
	const addLoading = document.getElementById("addTargetLoading");
	const targetsLoading = document.getElementById("targetsLoading");
	const targetsFeedback = document.getElementById("targetsFeedback");
	const targetList = document.getElementById("targetList");
	const instructionsPanel = document.getElementById("instructionsPanel");
	const instructionsContainer = document.getElementById("targetVerifyContainer");
	const selectedTargetUrl = document.getElementById("selectedTargetUrl");
	const verifyFeedback = document.getElementById("verifyFeedback");
	const busyVerifications = new Set();
	const busyDeletes = new Set();
	let targets = [];
	let selectedTargetId = null;
	let isAdding = false;
	let isLoadingTargets = false;

	function setMessage(element, message) {
		element.textContent = message;
		element.hidden = !message;
	}

	function element(tagName, className, text) {
		const node = document.createElement(tagName);
		if (className) node.className = className;
		if (text !== undefined) node.textContent = text;
		return node;
	}

	function actionButton(label, action, targetId, className = "target-button target-button-quiet") {
		const button = element("button", className, label);
		button.type = "button";
		button.dataset.action = action;
		button.dataset.targetId = targetId;
		return button;
	}

	function methodLabel(method) {
		return METHOD_LABELS[method] || "Unknown method";
	}

	function createTargetItem(target) {
		const item = element("article", `target-item${target.id === selectedTargetId ? " is-selected" : ""}`);
		const main = element("div", "target-item-main");
		const select = actionButton(target.url, "select", target.id, "target-select");
		select.setAttribute("aria-label", `Show ownership proof for ${target.url}`);
		const metadata = element("div", "target-meta");
		metadata.append(element("span", "target-status" + (target.is_verified === true ? " verified" : ""), target.is_verified === true ? "Verified" : "Not verified"));
		metadata.append(element("span", "", methodLabel(target.verification_method)));
		const times = element("div", "target-times");
		times.append(element("span", "", `Verified: ${target.verified_at ? formatTimestamp(target.verified_at) : "Not verified"}`));
		times.append(element("span", "", `Last checked: ${formatTimestamp(target.last_checked_at)}`));
		main.append(select, metadata, times);

		const actions = element("div", "target-actions");
		if (target.is_verified !== true) {
			const verifyButton = actionButton(busyVerifications.has(target.id) ? "Verifying…" : "Verify now", "verify", target.id, "target-button target-button-primary");
			verifyButton.disabled = busyVerifications.has(target.id);
			actions.append(verifyButton);
		} else {
			const scanLink = element("a", "scan-target-link", "Scan this target");
			scanLink.href = `new_scan.html?target=${encodeURIComponent(target.id)}`;
			actions.append(scanLink);
		}
		const deleteButton = actionButton(busyDeletes.has(target.id) ? "Deleting…" : "Delete", "delete", target.id, "target-button target-button-quiet target-delete");
		deleteButton.disabled = busyDeletes.has(target.id);
		actions.append(deleteButton);
		item.append(main, actions);
		return item;
	}

	function renderTargets() {
		const items = targets.map(createTargetItem);
		if (targets.length === 0 && !isLoadingTargets) {
			items.push(element("p", "target-empty", "No targets yet. Add a website you own or are authorized to test to get started."));
		}
		targetList.replaceChildren(...items);
	}

	function createProofValue({ label, value }) {
		const row = element("div", "proof-value");
		const textGroup = element("div");
		textGroup.append(element("span", "proof-value-label", label));
		textGroup.append(element("code", "", value));
		const copyButton = element("button", "target-button target-button-quiet", "Copy");
		copyButton.type = "button";
		copyButton.dataset.action = "copy";
		copyButton.dataset.copyValue = value;
		row.append(textGroup, copyButton);
		return row;
	}

	function renderInstructions(target) {
		instructionsPanel.hidden = false;
		selectedTargetUrl.textContent = target.url;
		instructionsContainer.replaceChildren();
		const instructions = target.instructions || {};
		if (instructions.summary) instructionsContainer.append(element("p", "proof-summary", instructions.summary));
		const proofValues = getProofValues(target);
		if (proofValues.length) {
			const heading = element("h3", "proof-heading", "Publish these values");
			const values = element("div", "proof-values");
			values.append(...proofValues.map(createProofValue));
			instructionsContainer.append(heading, values);
		} else {
			instructionsContainer.append(element("p", "target-feedback", "The server did not return proof instructions for this method."));
		}
		const verifyResult = target.verifyResult;
		if (verifyResult) {
			const succeeded = verifyResult.is_verified === true;
			const result = element("p", `verify-result ${succeeded ? "success" : "failure"}`,
				succeeded ? "Ownership verified successfully." : (verifyResult.details || "Ownership verification failed."));
			instructionsContainer.append(result);
		}
		if (target.is_verified === true) {
			const scanLink = element("a", "scan-target-link", "Scan this target");
			scanLink.href = `new_scan.html?target=${encodeURIComponent(target.id)}`;
			instructionsContainer.append(scanLink);
		}
	}

	async function selectTarget(targetId) {
		selectedTargetId = targetId;
		verifyFeedback.hidden = true;
		instructionsPanel.hidden = false;
		selectedTargetUrl.textContent = "Loading ownership instructions…";
		instructionsContainer.replaceChildren();
		renderTargets();
		try {
			const target = await Api.get(`/api/targets/${encodeURIComponent(targetId)}`);
			selectedTargetId = target.id;
			targets = targets.map((item) => item.id === target.id ? { ...item, ...target } : item);
			renderTargets();
			renderInstructions(target);
		} catch (error) {
			setMessage(verifyFeedback, getErrorMessage(error));
			selectedTargetUrl.textContent = "Could not load target instructions.";
		}
	}

	async function loadTargets({ showLoading = true } = {}) {
		if (isLoadingTargets) return;
		isLoadingTargets = true;
		if (showLoading) targetsLoading.hidden = false;
		setMessage(targetsFeedback, "");
		renderTargets();
		try {
			targets = await Api.get("/api/targets");
			renderTargets();
			if (selectedTargetId && !targets.some((target) => target.id === selectedTargetId)) {
				selectedTargetId = null;
				instructionsPanel.hidden = true;
			}
		} catch (error) {
			setMessage(targetsFeedback, getErrorMessage(error));
		} finally {
			isLoadingTargets = false;
			targetsLoading.hidden = true;
			renderTargets();
		}
	}

	async function addTarget(event) {
		event.preventDefault();
		if (isAdding) return;
		setMessage(addFeedback, "");
		if (!targetUrlInput.value.trim()) {
			setMessage(addFeedback, "Enter a website URL.");
			targetUrlInput.focus();
			return;
		}
		isAdding = true;
		addButton.disabled = true;
		addLoading.hidden = false;
		try {
			const target = await Api.post("/api/targets", {
				url: targetUrlInput.value.trim(),
				verification_method: methodInput.value
			});
			targetUrlInput.value = "";
			targets = [target, ...targets.filter((item) => item.id !== target.id)];
			selectedTargetId = target.id;
			renderTargets();
			renderInstructions(target);
			await loadTargets({ showLoading: false });
			await selectTarget(target.id);
		} catch (error) {
			setMessage(addFeedback, getErrorMessage(error));
		} finally {
			isAdding = false;
			addButton.disabled = false;
			addLoading.hidden = true;
		}
	}

	async function verifyTarget(targetId) {
		if (busyVerifications.has(targetId)) return;
		busyVerifications.add(targetId);
		setMessage(verifyFeedback, "");
		renderTargets();
		try {
			const result = await Api.post(`/api/targets/${encodeURIComponent(targetId)}/verify`);
			targets = targets.map((target) => target.id === targetId ? { ...target, ...result, verifyResult: result } : target);
			renderTargets();
			if (selectedTargetId === targetId) renderInstructions(targets.find((target) => target.id === targetId));
		} catch (error) {
			setMessage(verifyFeedback, getErrorMessage(error));
		} finally {
			busyVerifications.delete(targetId);
			renderTargets();
		}
	}

	async function deleteTarget(targetId) {
		const target = targets.find((item) => item.id === targetId);
		if (!target || busyDeletes.has(targetId)) return;
		const confirmed = globalThis.confirm(`Delete ${target.url}? All associated scans and findings will also be deleted.`);
		if (!confirmed) return;
		busyDeletes.add(targetId);
		renderTargets();
		try {
			await Api.request(`/api/targets/${encodeURIComponent(targetId)}`, { method: "DELETE" });
			targets = targets.filter((item) => item.id !== targetId);
			if (selectedTargetId === targetId) {
				selectedTargetId = null;
				instructionsPanel.hidden = true;
			}
			await loadTargets({ showLoading: false });
		} catch (error) {
			setMessage(targetsFeedback, getErrorMessage(error));
		} finally {
			busyDeletes.delete(targetId);
			renderTargets();
		}
	}

	async function copyValue(button) {
		const value = button.dataset.copyValue || "";
		try {
			if (navigator.clipboard?.writeText) {
				await navigator.clipboard.writeText(value);
			} else {
				throw new Error("Clipboard API unavailable");
			}
			button.textContent = "Copied";
		} catch (error) {
			const temporaryInput = document.createElement("textarea");
			temporaryInput.value = value;
			temporaryInput.setAttribute("readonly", "");
			temporaryInput.style.position = "fixed";
			temporaryInput.style.opacity = "0";
			document.body.append(temporaryInput);
			temporaryInput.select();
			const copied = document.execCommand("copy");
			temporaryInput.remove();
			button.textContent = copied ? "Copied" : "Select and copy";
		}
		globalThis.setTimeout(() => { button.textContent = "Copy"; }, 1400);
	}

	addForm.addEventListener("submit", addTarget);
	document.getElementById("refreshTargetsButton").addEventListener("click", () => loadTargets());
	document.getElementById("sidebarToggle").addEventListener("click", () => {
		document.getElementById("sidebar").classList.toggle("open");
		document.getElementById("sidebarOverlay").classList.toggle("show");
	});
	document.getElementById("sidebarOverlay").addEventListener("click", () => {
		document.getElementById("sidebar").classList.remove("open");
		document.getElementById("sidebarOverlay").classList.remove("show");
	});
	targetList.addEventListener("click", (event) => {
		const button = event.target.closest("[data-action]");
		if (!button) return;
		const { action, targetId } = button.dataset;
		if (action === "select") selectTarget(targetId);
		if (action === "verify") verifyTarget(targetId);
		if (action === "delete") deleteTarget(targetId);
	});
	instructionsContainer.addEventListener("click", (event) => {
		const button = event.target.closest('[data-action="copy"]');
		if (button) copyValue(button);
	});

	Auth.requireAuth().then((user) => {
		if (user) loadTargets();
	});
})();// Target Ownership Verification Logic placeholder
