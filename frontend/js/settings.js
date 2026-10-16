(() => {
	function validateFullName(fullName) {
		if (typeof fullName !== "string") {
			return { valid: false, error: "Full name is required.", value: "" };
		}
		const trimmed = fullName.trim();
		if (trimmed.length < 1) {
			return { valid: false, error: "Full name is required.", value: "" };
		}
		if (trimmed.length > 150) {
			return { valid: false, error: "Full name cannot exceed 150 characters.", value: trimmed };
		}
		return { valid: true, error: "", value: trimmed };
	}

	function validatePasswordInputs({ currentPassword, newPassword, confirmPassword }) {
		if (!currentPassword || typeof currentPassword !== "string" || !currentPassword.trim()) {
			return { valid: false, error: "Current password is required." };
		}
		if (!newPassword || typeof newPassword !== "string") {
			return { valid: false, error: "New password is required." };
		}
		if (!confirmPassword || typeof confirmPassword !== "string") {
			return { valid: false, error: "Please confirm your new password." };
		}

		const byteLength = typeof TextEncoder !== "undefined"
			? new TextEncoder().encode(newPassword).length
			: Buffer.byteLength(newPassword, "utf8");

		if (byteLength > 72) {
			return { valid: false, error: "Password cannot exceed 72 bytes." };
		}
		if (Array.from(newPassword).length < 8) {
			return { valid: false, error: "Password must be at least 8 characters long." };
		}
		if (!/[A-Z]/.test(newPassword)) {
			return { valid: false, error: "Password must contain at least one uppercase letter." };
		}
		if (!/[a-z]/.test(newPassword)) {
			return { valid: false, error: "Password must contain at least one lowercase letter." };
		}
		if (!/[0-9]/.test(newPassword)) {
			return { valid: false, error: "Password must contain at least one digit." };
		}

		if (newPassword !== confirmPassword) {
			return { valid: false, error: "New passwords do not match." };
		}
		if (newPassword === currentPassword) {
			return { valid: false, error: "New password must be different from current password." };
		}

		return { valid: true, error: "" };
	}

	function getPasswordErrorMessage(error) {
		if (!error) return "Failed to update password.";
		if (error.code === "INVALID_CURRENT_PASSWORD" || (error.status === 400 && error.code === "INVALID_CURRENT_PASSWORD")) {
			return "The current password is incorrect.";
		}
		return error.message || "Failed to update password.";
	}

	function validateSettingsPayload(settings) {
		if (!settings || typeof settings !== "object") {
			return { valid: false, error: "Invalid settings payload." };
		}
		const allowedDepths = ["quick", "standard", "deep"];
		const rawDepth = (settings.default_scan_depth || "").toString().toLowerCase().trim();
		const default_scan_depth = allowedDepths.includes(rawDepth) ? rawDepth : "standard";

		return {
			valid: true,
			payload: {
				default_scan_depth,
				notify_scan_completed: Boolean(settings.notify_scan_completed),
				notify_scan_failed: Boolean(settings.notify_scan_failed),
				notify_critical_finding: Boolean(settings.notify_critical_finding)
			}
		};
	}

	function checkPasswordStrength(password) {
		if (!password || typeof password !== "string") {
			return { length: false, case: false, number: false, symbol: false, score: 0, label: "Not checked" };
		}
		const lengthMet = Array.from(password).length >= 8;
		const caseMet = /[A-Z]/.test(password) && /[a-z]/.test(password);
		const numberMet = /[0-9]/.test(password);
		const symbolMet = /[^A-Za-z0-9]/.test(password);

		let score = 0;
		if (lengthMet) score += 1;
		if (caseMet) score += 1;
		if (numberMet) score += 1;
		if (symbolMet) score += 1;

		let label = "Weak";
		if (score >= 4) label = "Strong";
		else if (score === 3) label = "Good";
		else if (score === 2) label = "Fair";

		return {
			length: lengthMet,
			case: caseMet,
			number: numberMet,
			symbol: symbolMet,
			score,
			label
		};
	}

	function showFeedback(element, message, type) {
		if (!element) return;
		element.textContent = message;
		element.className = `form-feedback ${type}`;
		element.hidden = false;
	}

	function clearFeedback(element) {
		if (!element) return;
		element.textContent = "";
		element.className = "form-feedback";
		element.hidden = true;
	}

	function setButtonLoading(button, isLoading, text) {
		if (!button) return;
		button.disabled = isLoading;
		if (text !== undefined) button.textContent = text;
	}

	let toastTimer = null;
	function showToast(title, message) {
		const toast = document.getElementById("toast");
		const titleEl = document.getElementById("toastTitle");
		const msgEl = document.getElementById("toastMsg");
		if (!toast) return;
		if (titleEl) titleEl.textContent = title;
		if (msgEl) msgEl.textContent = message;
		toast.classList.add("show");
		if (toastTimer) clearTimeout(toastTimer);
		toastTimer = setTimeout(() => {
			toast.classList.remove("show");
		}, 3000);
	}

	function updateProfileDisplay(user) {
		if (!user) return;
		const name = (user.full_name || user.email || "").trim();
		const email = user.email || "";
		const role = user.role || "User";

		const previewName = document.getElementById("previewName");
		const previewEmail = document.getElementById("previewEmail");
		const previewRole = document.getElementById("previewRole");
		const avatarLetter = document.getElementById("avatarLetter");
		const fullNameInput = document.getElementById("fullName");
		const emailInput = document.getElementById("email");
		const roleInput = document.getElementById("role");

		if (previewName) previewName.textContent = name || "Security Analyst";
		if (previewEmail) previewEmail.textContent = email;
		if (previewRole) previewRole.textContent = role;
		if (avatarLetter) avatarLetter.textContent = (name[0] || email[0] || "U").toUpperCase();
		if (fullNameInput && user.full_name !== undefined) fullNameInput.value = user.full_name || "";
		if (emailInput && email) emailInput.value = email;
		if (roleInput && role) roleInput.value = role;

		// Synchronize header / sidebar profile display if present
		const navName = document.querySelector(".user-name");
		const navEmail = document.getElementById("userEmailDisplay");
		const navAvatar = document.querySelector(".user-avatar");
		if (navName) navName.textContent = name || email;
		if (navEmail) navEmail.textContent = email;
		if (navAvatar) navAvatar.textContent = (name[0] || email[0] || "U").toUpperCase();
	}

	function updateStrengthIndicator(password) {
		const strength = checkPasswordStrength(password);
		const bar = document.getElementById("strengthBar");
		const text = document.getElementById("strengthText");
		const rulesList = document.getElementById("strengthRules");

		if (bar) bar.style.width = `${strength.score * 25}%`;
		if (text) text.textContent = strength.label;

		if (rulesList) {
			const ruleItems = rulesList.querySelectorAll("li[data-rule]");
			ruleItems.forEach((li) => {
				const rule = li.dataset.rule;
				if (rule && strength[rule]) {
					li.classList.add("met");
				} else {
					li.classList.remove("met");
				}
			});
		}
	}

	function switchTab(sectionName) {
		const tabButtons = document.querySelectorAll(".settings-tabs .tab-btn");
		const sections = document.querySelectorAll(".settings-section");
		tabButtons.forEach((btn) => {
			if (btn.dataset.section === sectionName) {
				btn.classList.add("active");
			} else {
				btn.classList.remove("active");
			}
		});
		sections.forEach((sec) => {
			if (sec.id === sectionName) {
				sec.classList.add("active");
			} else {
				sec.classList.remove("active");
			}
		});
	}

	function togglePasswordVisibility(button) {
		const container = button.closest(".password-input");
		if (!container) return;
		const input = container.querySelector("input");
		if (!input) return;
		if (input.type === "password") {
			input.type = "text";
			button.textContent = "🙈";
			button.setAttribute("aria-label", "Hide password");
		} else {
			input.type = "password";
			button.textContent = "👁";
			button.setAttribute("aria-label", "Show password");
		}
	}

	async function handleProfileSubmit(event) {
		if (event) event.preventDefault();
		const nameInput = document.getElementById("fullName");
		const saveBtn = document.getElementById("saveProfileBtn");
		const msgEl = document.getElementById("profileMessage");

		const validation = validateFullName(nameInput ? nameInput.value : "");
		if (!validation.valid) {
			showFeedback(msgEl, validation.error, "error");
			return;
		}

		setButtonLoading(saveBtn, true, "Saving profile…");
		clearFeedback(msgEl);
		try {
			const updated = await Api.request("/api/user/profile", {
				method: "PUT",
				body: { full_name: validation.value }
			});
			updateProfileDisplay(updated);
			showFeedback(msgEl, "Profile updated successfully.", "success");
			showToast("Profile updated", "Your profile details have been saved.");
		} catch (error) {
			showFeedback(msgEl, error.message || "Failed to update profile.", "error");
		} finally {
			setButtonLoading(saveBtn, false, "Save Profile");
		}
	}

	async function handlePasswordSubmit(event) {
		if (event) event.preventDefault();
		const currentInput = document.getElementById("currentPassword");
		const newInput = document.getElementById("newPassword");
		const confirmInput = document.getElementById("confirmPassword");
		const saveBtn = document.getElementById("savePasswordBtn");
		const msgEl = document.getElementById("passwordMessage");

		const currentPassword = currentInput ? currentInput.value : "";
		const newPassword = newInput ? newInput.value : "";
		const confirmPassword = confirmInput ? confirmInput.value : "";

		const validation = validatePasswordInputs({ currentPassword, newPassword, confirmPassword });
		if (!validation.valid) {
			showFeedback(msgEl, validation.error, "error");
			return;
		}

		setButtonLoading(saveBtn, true, "Updating password…");
		clearFeedback(msgEl);
		try {
			const result = await Api.request("/api/user/password", {
				method: "PUT",
				body: { current_password: currentPassword, new_password: newPassword }
			});
			if (currentInput) currentInput.value = "";
			if (newInput) newInput.value = "";
			if (confirmInput) confirmInput.value = "";
			updateStrengthIndicator("");
			showFeedback(msgEl, result && result.message ? result.message : "Password updated successfully.", "success");
			showToast("Password updated", "Your password has been changed successfully.");
		} catch (error) {
			const errorMsg = getPasswordErrorMessage(error);
			showFeedback(msgEl, errorMsg, "error");
		} finally {
			setButtonLoading(saveBtn, false, "Update Password");
		}
	}

	async function handleSettingsSubmit(event, source = "scanning") {
		if (event) event.preventDefault();
		const depthEl = document.getElementById("defDepth");
		const completeEl = document.getElementById("notifComplete");
		const failedEl = document.getElementById("notifFailed");
		const criticalEl = document.getElementById("notifCritical");

		const scanBtn = document.getElementById("saveScanningBtn");
		const notifBtn = document.getElementById("saveNotificationsBtn");
		const prefBtn = document.getElementById("savePreferencesBtn");
		const bottomBtn = document.getElementById("saveChanges");
		const saveStatus = document.getElementById("saveStatus");

		let msgEl = document.getElementById("scanningMessage");
		if (source === "notifications") {
			msgEl = document.getElementById("notificationsMessage");
		} else if (source === "preferences") {
			msgEl = document.getElementById("preferencesMessage");
		}

		const payloadCheck = validateSettingsPayload({
			default_scan_depth: depthEl ? depthEl.value : "standard",
			notify_scan_completed: completeEl ? completeEl.checked : false,
			notify_scan_failed: failedEl ? failedEl.checked : false,
			notify_critical_finding: criticalEl ? criticalEl.checked : false
		});

		if (!payloadCheck.valid) {
			if (msgEl) showFeedback(msgEl, payloadCheck.error, "error");
			return;
		}

		if (scanBtn) setButtonLoading(scanBtn, true, "Saving…");
		if (notifBtn) setButtonLoading(notifBtn, true, "Saving…");
		if (prefBtn) setButtonLoading(prefBtn, true, "Saving…");
		if (bottomBtn) setButtonLoading(bottomBtn, true, "Saving…");
		if (msgEl) clearFeedback(msgEl);
		if (saveStatus) saveStatus.textContent = "Saving preferences…";

		try {
			const updated = await Api.request("/api/user/settings", {
				method: "PUT",
				body: payloadCheck.payload
			});
			if (msgEl) showFeedback(msgEl, "Preferences saved successfully.", "success");
			showToast("Preferences saved", "Your scan and notification settings have been updated.");
			if (saveStatus) {
				saveStatus.replaceChildren();
				const dot = document.createElement("span");
				dot.className = "save-status-dot";
				saveStatus.append(dot, document.createTextNode(" All changes saved"));
			}
		} catch (error) {
			if (msgEl) showFeedback(msgEl, error.message || "Failed to save preferences.", "error");
			if (saveStatus) saveStatus.textContent = "Failed to save changes.";
		} finally {
			if (scanBtn) setButtonLoading(scanBtn, false, "Save Scan Defaults");
			if (notifBtn) setButtonLoading(notifBtn, false, "Save Notifications");
			if (prefBtn) setButtonLoading(prefBtn, false, "Save Preferences");
			if (bottomBtn) setButtonLoading(bottomBtn, false, "Save changes");
		}
	}

	function handleResetDefaults() {
		const depthEl = document.getElementById("defDepth");
		const completeEl = document.getElementById("notifComplete");
		const failedEl = document.getElementById("notifFailed");
		const criticalEl = document.getElementById("notifCritical");
		if (depthEl) depthEl.value = "standard";
		if (completeEl) completeEl.checked = true;
		if (failedEl) failedEl.checked = true;
		if (criticalEl) criticalEl.checked = true;
		handleSettingsSubmit(null, "scanning");
	}

	function handleResetStorage() {
		const token = localStorage.getItem("token");
		const email = localStorage.getItem("email");
		localStorage.clear();
		if (token) localStorage.setItem("token", token);
		if (email) localStorage.setItem("email", email);
		showToast("Storage reset", "Cached local data cleared.");
	}

	function toggleTheme() {
		const current = document.documentElement.getAttribute("data-theme") || "dark";
		const next = current === "light" ? "dark" : "light";
		document.documentElement.setAttribute("data-theme", next);
		const icon = document.getElementById("themeIcon");
		if (icon) icon.textContent = next === "light" ? "☀️" : "🌙";
	}

	async function initSettings() {
		if (globalThis.Auth && typeof globalThis.Auth.requireAuth === "function") {
			const authUser = await globalThis.Auth.requireAuth();
			if (!authUser) return;
		}

		// Load user profile and settings concurrently
		try {
			const profilePromise = Api.get("/api/user/profile");
			const settingsPromise = Api.get("/api/user/settings");
			const [profileResult, settingsResult] = await Promise.allSettled([profilePromise, settingsPromise]);

			if (profileResult.status === "fulfilled" && profileResult.value) {
				updateProfileDisplay(profileResult.value);
			}

			if (settingsResult.status === "fulfilled" && settingsResult.value) {
				const settings = settingsResult.value;
				const depthEl = document.getElementById("defDepth");
				const completeEl = document.getElementById("notifComplete");
				const failedEl = document.getElementById("notifFailed");
				const criticalEl = document.getElementById("notifCritical");

				if (depthEl && settings.default_scan_depth) {
					depthEl.value = settings.default_scan_depth;
				}
				if (completeEl && settings.notify_scan_completed !== undefined) {
					completeEl.checked = Boolean(settings.notify_scan_completed);
				}
				if (failedEl && settings.notify_scan_failed !== undefined) {
					failedEl.checked = Boolean(settings.notify_scan_failed);
				}
				if (criticalEl && settings.notify_critical_finding !== undefined) {
					criticalEl.checked = Boolean(settings.notify_critical_finding);
				}
			}
		} catch (error) {
			console.error("Failed to load initial settings:", error);
		}

		// Event listeners
		const profileForm = document.getElementById("profileForm");
		if (profileForm) {
			profileForm.addEventListener("submit", handleProfileSubmit);
		}

		const passwordForm = document.getElementById("passwordForm");
		if (passwordForm) {
			passwordForm.addEventListener("submit", handlePasswordSubmit);
		}

		const newPasswordInput = document.getElementById("newPassword");
		if (newPasswordInput) {
			newPasswordInput.addEventListener("input", (e) => {
				updateStrengthIndicator(e.target.value);
			});
		}

		const saveScanningBtn = document.getElementById("saveScanningBtn");
		if (saveScanningBtn) {
			saveScanningBtn.addEventListener("click", (e) => handleSettingsSubmit(e, "scanning"));
		}

		const savePreferencesBtn = document.getElementById("savePreferencesBtn");
		if (savePreferencesBtn) {
			savePreferencesBtn.addEventListener("click", (e) => handleSettingsSubmit(e, "preferences"));
		}

		const saveNotificationsBtn = document.getElementById("saveNotificationsBtn");
		if (saveNotificationsBtn) {
			saveNotificationsBtn.addEventListener("click", (e) => handleSettingsSubmit(e, "notifications"));
		}

		const saveChangesBtn = document.getElementById("saveChanges");
		if (saveChangesBtn) {
			saveChangesBtn.addEventListener("click", (e) => {
				const activeSection = document.querySelector(".settings-section.active");
				const activeId = activeSection ? activeSection.id : "scanning";
				if (activeId === "profile") {
					handleProfileSubmit(e);
				} else if (activeId === "security") {
					handlePasswordSubmit(e);
				} else if (activeId === "notifications") {
					handleSettingsSubmit(e, "notifications");
				} else if (activeId === "preferences") {
					handleSettingsSubmit(e, "preferences");
				} else {
					handleSettingsSubmit(e, "scanning");
				}
			});
		}

		const resetDefaultsBtn = document.getElementById("resetDefaults");
		if (resetDefaultsBtn) {
			resetDefaultsBtn.addEventListener("click", handleResetDefaults);
		}

		const deleteAccountBtn = document.getElementById("deleteAccount");
		if (deleteAccountBtn) {
			deleteAccountBtn.addEventListener("click", handleResetStorage);
		}

		const themeToggle = document.getElementById("themeToggle");
		if (themeToggle) {
			themeToggle.addEventListener("click", toggleTheme);
		}

		document.addEventListener("click", (event) => {
			const actionBtn = event.target.closest("[data-action]");
			if (!actionBtn) return;
			const action = actionBtn.dataset.action;
			if (action === "switch-tab") {
				const section = actionBtn.dataset.section;
				if (section) switchTab(section);
			} else if (action === "toggle-password") {
				togglePasswordVisibility(actionBtn);
			} else if (action === "toggle-theme") {
				toggleTheme();
			}
		});
	}

	if (typeof document !== "undefined") {
		document.addEventListener("DOMContentLoaded", initSettings);
	}

	const exported = {
		validateFullName,
		validatePasswordInputs,
		getPasswordErrorMessage,
		validateSettingsPayload,
		checkPasswordStrength
	};

	if (typeof module !== "undefined" && module.exports) {
		module.exports = exported;
	}

	globalThis.Settings = Object.freeze(exported);
})();
