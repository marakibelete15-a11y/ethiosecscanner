(() => {
	const form = document.getElementById("signupForm");
	if (!form) return;

	const nameInput = document.getElementById("fullname");
	const emailInput = document.getElementById("email");
	const passwordInput = document.getElementById("password");
	const confirmInput = document.getElementById("confirm-password");
	const errorElement = document.getElementById("formError");
	const statusElement = document.getElementById("formStatus");
	const submitButton = document.getElementById("signupBtn");

	function showError(message) {
		errorElement.textContent = message;
		errorElement.hidden = false;
	}

	function setLoading(loading) {
		submitButton.disabled = loading;
		statusElement.textContent = loading ? "Creating your account…" : "";
		statusElement.hidden = !loading;
	}

	document.getElementById("togglePasswordBtn").addEventListener("click", () => {
		passwordInput.type = passwordInput.type === "password" ? "text" : "password";
	});
	document.getElementById("toggleConfirmPasswordBtn").addEventListener("click", () => {
		confirmInput.type = confirmInput.type === "password" ? "text" : "password";
	});
	document.querySelectorAll('[data-action^="oauth-"]').forEach((button) => {
		button.addEventListener("click", () => showError("Social sign-up is not available yet. Please register with your email."));
	});

	form.addEventListener("submit", async (event) => {
		event.preventDefault();
		errorElement.hidden = true;
		statusElement.hidden = true;
		if (!Auth.validateEmail(emailInput.value)) {
			showError("Enter a valid email address.");
			emailInput.focus();
			return;
		}
		const passwordMessage = Auth.passwordError(passwordInput.value);
		if (passwordMessage) {
			showError(passwordMessage);
			passwordInput.focus();
			return;
		}
		if (confirmInput.value !== passwordInput.value) {
			showError("The passwords do not match.");
			confirmInput.focus();
			return;
		}
		if (!document.getElementById("terms").checked) {
			showError("Accept the Terms of Service and Privacy Policy to continue.");
			return;
		}

		setLoading(true);
		try {
			await Auth.register({
				email: emailInput.value,
				password: passwordInput.value,
				fullName: nameInput.value
			});
			globalThis.location.assign("login.html?registered=1");
		} catch (error) {
			showError(error.message);
		} finally {
			setLoading(false);
		}
	});
})();
