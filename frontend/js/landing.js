(() => {
	function validateContactForm({ name, email, message }) {
		const trimmedName = typeof name === "string" ? name.trim() : "";
		const trimmedEmail = typeof email === "string" ? email.trim() : "";
		const trimmedMessage = typeof message === "string" ? message.trim() : "";

		if (!trimmedName) {
			return { valid: false, error: "Please enter your name." };
		}
		if (!trimmedEmail) {
			return { valid: false, error: "Please enter your email address." };
		}
		const emailPattern = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
		if (!emailPattern.test(trimmedEmail)) {
			return { valid: false, error: "Please enter a valid email address." };
		}
		if (!trimmedMessage) {
			return { valid: false, error: "Please enter a message." };
		}
		if (trimmedMessage.length < 10) {
			return { valid: false, error: "Message must be at least 10 characters long." };
		}
		if (trimmedMessage.length > 1000) {
			return { valid: false, error: "Message cannot exceed 1000 characters." };
		}

		return { valid: true, error: "" };
	}

	function getDemoConfirmationMessage() {
		return "This contact form is a demo; no message was sent.";
	}

	function getLegalNoticeText() {
		return "Only scan websites you own or have written permission to test. Scanning systems without permission may be illegal.";
	}

	async function syncPublicNavigation() {
		const dashboardLink = document.getElementById("openDashboard");
		const loginLink = document.getElementById("openLogin");
		const footerLogin = document.getElementById("footerLogin");

		// If no token exists, show logged-out version
		if (!localStorage.getItem("token")) {
			if (dashboardLink) dashboardLink.hidden = true;
			if (loginLink) {
				loginLink.hidden = false;
				loginLink.textContent = "LOGIN / REGISTER";
				loginLink.href = "login.html";
			}
			if (footerLogin) {
				footerLogin.textContent = "Login";
				footerLogin.href = "login.html";
			}
			return false;
		}

		// Must validate session with the API (/api/auth/me) via Auth.validatedSession
		if (globalThis.Auth && typeof globalThis.Auth.validatedSession === "function") {
			try {
				const user = await globalThis.Auth.validatedSession();
				if (user) {
					if (dashboardLink) dashboardLink.hidden = false;
					if (loginLink) loginLink.hidden = true;
					if (footerLogin) {
						footerLogin.textContent = "Dashboard";
						footerLogin.href = "dashboard.html";
					}
					return true;
				} else {
					if (globalThis.Auth.clearCredentials) globalThis.Auth.clearCredentials();
					if (dashboardLink) dashboardLink.hidden = true;
					if (loginLink) {
						loginLink.hidden = false;
						loginLink.textContent = "LOGIN / REGISTER";
						loginLink.href = "login.html";
					}
					if (footerLogin) {
						footerLogin.textContent = "Login";
						footerLogin.href = "login.html";
					}
					return false;
				}
			} catch (error) {
				if (globalThis.Auth.clearCredentials) globalThis.Auth.clearCredentials();
				if (dashboardLink) dashboardLink.hidden = true;
				if (loginLink) {
					loginLink.hidden = false;
					loginLink.textContent = "LOGIN / REGISTER";
					loginLink.href = "login.html";
				}
				if (footerLogin) {
					footerLogin.textContent = "Login";
					footerLogin.href = "login.html";
				}
				return false;
			}
		}
		return false;
	}

	function initMenuToggle() {
		const menuBtn = document.getElementById("menuBtn");
		const navLinks = document.getElementById("navLinks");
		if (!menuBtn || !navLinks) return;

		menuBtn.addEventListener("click", () => {
			menuBtn.classList.toggle("active");
			navLinks.classList.toggle("active");
		});

		document.addEventListener("click", (event) => {
			if (!menuBtn.contains(event.target) && !navLinks.contains(event.target)) {
				menuBtn.classList.remove("active");
				navLinks.classList.remove("active");
			}
		});
	}

	function initContactForm() {
		const contactForm = document.getElementById("contactForm");
		if (!contactForm) return;

		const nameInput = document.getElementById("contactName");
		const emailInput = document.getElementById("contactEmail");
		const subjectInput = document.getElementById("contactSubject");
		const messageInput = document.getElementById("contactMessage");
		const submitBtn = contactForm.querySelector("button[type='submit']");
		const statusEl = document.getElementById("contactStatus");

		contactForm.addEventListener("submit", (event) => {
			event.preventDefault();

			const name = nameInput ? nameInput.value : "";
			const email = emailInput ? emailInput.value : "";
			const message = messageInput ? messageInput.value : "";

			if (submitBtn) {
				submitBtn.disabled = true;
				submitBtn.textContent = "SENDING…";
			}

			const validation = validateContactForm({ name, email, message });
			if (!validation.valid) {
				if (statusEl) {
					statusEl.textContent = validation.error;
					statusEl.className = "form-status error";
					statusEl.hidden = false;
				}
				if (submitBtn) {
					submitBtn.disabled = false;
					submitBtn.textContent = "SEND MESSAGE →";
				}
				return;
			}

			// Valid: Show confirmation message (using textContent)
			// Nothing is sent anywhere and nothing is stored
			if (statusEl) {
				statusEl.textContent = getDemoConfirmationMessage();
				statusEl.className = "form-status success";
				statusEl.hidden = false;
			}

			// Clear form fields
			if (nameInput) nameInput.value = "";
			if (emailInput) emailInput.value = "";
			if (subjectInput) subjectInput.value = "";
			if (messageInput) messageInput.value = "";

			if (submitBtn) {
				submitBtn.disabled = false;
				submitBtn.textContent = "SEND MESSAGE →";
			}
		});
	}

	function initLandingScanner() {
		const scanForm = document.getElementById("scanForm");
		if (!scanForm) return;

		scanForm.addEventListener("submit", (event) => {
			event.preventDefault();
			const urlInput = document.getElementById("urlInput");
			const rawUrl = urlInput ? urlInput.value.trim() : "";
			if (localStorage.getItem("token")) {
				globalThis.location.assign("new_scan.html");
			} else {
				if (rawUrl) {
					try {
						sessionStorage.setItem("pendingScanUrl", rawUrl);
					} catch {}
				}
				globalThis.location.assign("signup.html");
			}
		});
	}

	function initLanding() {
		syncPublicNavigation();
		initMenuToggle();
		initContactForm();
		initLandingScanner();
	}

	if (typeof document !== "undefined") {
		document.addEventListener("DOMContentLoaded", initLanding);
	}

	const exported = {
		validateContactForm,
		getDemoConfirmationMessage,
		getLegalNoticeText,
		syncPublicNavigation
	};

	if (typeof module !== "undefined" && module.exports) {
		module.exports = exported;
	}

	globalThis.Landing = Object.freeze(exported);
})();
