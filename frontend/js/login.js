(() => {
	const form = document.getElementById("loginForm");
	if (!form) return;

	const emailInput = document.getElementById("email");
	const passwordInput = document.getElementById("password");
	const errorElement = document.getElementById("formError");
	const statusElement = document.getElementById("formStatus");
	const submitButton = document.getElementById("loginBtn");
	let isSubmitting = false;

	function showError(message) {
		errorElement.textContent = message;
		errorElement.hidden = false;
	}

	function setLoading(loading) {
		submitButton.disabled = loading;
		statusElement.textContent = loading ? "Signing in…" : "";
		statusElement.hidden = !loading;
	}

	document.getElementById("togglePasswordBtn").addEventListener("click", () => {
		passwordInput.type = passwordInput.type === "password" ? "text" : "password";
	});

	document.querySelectorAll('[data-action^="oauth-"]').forEach((button) => {
		button.addEventListener("click", () => showError("Social sign-in is not available yet. Please use your email and password."));
	});

	form.addEventListener("submit", async (event) => {
		event.preventDefault();
		if (isSubmitting) return;
		errorElement.hidden = true;
		statusElement.hidden = true;
		if (!Auth.validateEmail(emailInput.value)) {
			showError("Enter a valid email address.");
			emailInput.focus();
			return;
		}
		if (!passwordInput.value) {
			showError("Enter your password.");
			passwordInput.focus();
			return;
		}

		isSubmitting = true;
		setLoading(true);
		try {
			await Auth.login(emailInput.value, passwordInput.value);
		} catch (error) {
			showError(error.message);
		} finally {
			isSubmitting = false;
			setLoading(false);
		}
	});

	Auth.prepareLoginPage();
})();
