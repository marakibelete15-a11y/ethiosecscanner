(() => {
	const LOGIN_URL = "login.html";
	const DASHBOARD_URL = "dashboard.html";
	const protectedNavigation = [
		["dashboard.html", "Dashboard", "📊"],
		["new_scan.html", "New Scan", "⚡"],
		["history.html", "History", "🕒"],
		["results.html", "Results", "📈"],
		["reports.html", "Reports", "📄"],
		["ai_assistant.html", "AI Assistant", "🤖"],
		["settings.html", "Settings", "⚙️"]
	];

	function validateEmail(email) {
		return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());
	}

	function passwordError(password) {
		if (new TextEncoder().encode(password).length > 72) return "Password cannot exceed 72 bytes.";
		if (Array.from(password).length < 8) return "Password must be at least 8 characters long.";
		if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter.";
		if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter.";
		if (!/[0-9]/.test(password)) return "Password must contain at least one digit.";
		return "";
	}

	function clearCredentials() {
		localStorage.clear();
	}

	function redirectToLogin() {
		const current = globalThis.location.pathname;
		if (!current.endsWith("/login.html")) {
			globalThis.location.replace(LOGIN_URL);
		}
	}

	function handleUnauthorized() {
		clearCredentials();
		redirectToLogin();
	}

	function handleTransportFailure() {
		clearCredentials();
		redirectToLogin();
	}

	function logout() {
		clearCredentials();
		globalThis.location.replace(LOGIN_URL);
	}

	function makeLink([href, label, icon], currentPage) {
		const link = document.createElement("a");
		link.href = href;
		link.className = "side-link";
		if (href === currentPage) link.classList.add("active");
		const iconElement = document.createElement("span");
		iconElement.className = "side-icon";
		iconElement.textContent = icon;
		link.append(iconElement, document.createTextNode(label));
		return link;
	}

	function renderNavigation() {
		const nav = document.querySelector(".sidebar-nav");
		if (!nav) return;
		const currentPage = globalThis.location.pathname.split("/").pop();
		nav.replaceChildren(...protectedNavigation.map((item) => makeLink(item, currentPage)));
		const divider = document.createElement("div");
		divider.className = "nav-divider";
		nav.append(divider);
		const logoutLink = document.createElement("a");
		logoutLink.href = "#";
		logoutLink.className = "side-link";
		logoutLink.dataset.action = "logout";
		const icon = document.createElement("span");
		icon.className = "side-icon";
		icon.textContent = "🚪";
		logoutLink.append(icon, document.createTextNode("Logout"));
		nav.append(logoutLink);
	}

	function renderUser(user) {
		const name = user.full_name || user.email;
		const nameElement = document.querySelector(".user-name");
		const emailElement = document.getElementById("userEmailDisplay");
		const avatarElement = document.querySelector(".user-avatar");
		if (nameElement) nameElement.textContent = name;
		if (emailElement) emailElement.textContent = user.email;
		if (avatarElement) avatarElement.textContent = (name.trim()[0] || "U").toUpperCase();
		const loading = document.getElementById("authLoading");
		if (loading) loading.textContent = `Welcome, ${name}.`;
	}

	async function requireAuth() {
		const loading = document.getElementById("authLoading");
		if (loading) loading.textContent = "Checking your session…";
		try {
			const user = await Api.get("/api/auth/me");
			renderUser(user);
			renderNavigation();
			return user;
		} catch (error) {
			handleUnauthorized();
			return null;
		}
	}

	async function validatedSession() {
		if (!localStorage.getItem("token")) return null;
		try {
			return await Api.get("/api/auth/me");
		} catch (error) {
			handleUnauthorized();
			return null;
		}
	}

	async function prepareLoginPage() {
		const user = await validatedSession();
		if (user) globalThis.location.replace(DASHBOARD_URL);
		const query = new URLSearchParams(globalThis.location.search);
		if (query.get("registered") === "1") {
			const notice = document.getElementById("formSuccess");
			if (notice) {
				notice.textContent = "Your account was created. Please sign in.";
				notice.hidden = false;
			}
		}
	}

	async function login(email, password) {
		const result = await Api.post("/api/auth/login", { email: email.trim(), password });
		localStorage.setItem("token", result.access_token);
		localStorage.setItem("email", email.trim().toLowerCase());
		const user = await Api.get("/api/auth/me");
		localStorage.setItem("email", user.email);
		globalThis.location.assign(DASHBOARD_URL);
		return user;
	}

	async function register({ email, password, fullName }) {
		return Api.post("/api/auth/register", {
			email: email.trim(),
			password,
			full_name: fullName.trim() || null
		});
	}

	function updatePublicNavigation() {
		const dashboardLink = document.getElementById("openDashboard");
		const loginLink = document.getElementById("openLogin");
		if (!dashboardLink && !loginLink) return;
		if (!localStorage.getItem("token")) {
			if (dashboardLink) dashboardLink.hidden = true;
			if (loginLink) loginLink.hidden = false;
			return;
		}
		validatedSession().then((user) => {
			if (!user) return;
			if (dashboardLink) dashboardLink.hidden = false;
			if (loginLink) loginLink.hidden = true;
		});
	}

	document.addEventListener("click", (event) => {
		const action = event.target.closest("[data-action]")?.dataset.action;
		if (action === "logout") {
			event.preventDefault();
			logout();
		}
	});

	document.querySelectorAll(".sidebar-nav").forEach(() => requireAuth());
	updatePublicNavigation();

	globalThis.Auth = Object.freeze({
		validateEmail,
		passwordError,
		clearCredentials,
		handleUnauthorized,
		handleTransportFailure,
		requireAuth,
		validatedSession,
		prepareLoginPage,
		login,
		register,
		logout
	});

	if (typeof module !== "undefined" && module.exports) {
		module.exports = { validateEmail, passwordError };
	}
})();
