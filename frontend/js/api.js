(() => {
	class ApiError extends Error {
		constructor(message, status, code) {
			super(message);
			this.name = "ApiError";
			this.status = status;
			this.code = code;
		}
	}

	async function request(path, options = {}) {
		const headers = new Headers(options.headers || {});
		const token = localStorage.getItem("token");
		if (token) headers.set("Authorization", `Bearer ${token}`);
		if (options.body !== undefined) headers.set("Content-Type", "application/json");

		let response;
		try {
			response = await fetch(`${EthioSecConfig.apiBaseUrl}${path}`, {
				...options,
				headers,
				body: options.body === undefined ? undefined : JSON.stringify(options.body)
			});
		} catch (error) {
			const apiError = new ApiError("Unable to reach the server. Check your connection and try again.", 0, "NETWORK_ERROR");
			if (globalThis.Auth) globalThis.Auth.handleTransportFailure();
			throw apiError;
		}

		let data = null;
		try {
			data = await response.json();
		} catch (error) {
			data = null;
		}

		if (!response.ok) {
			const errorData = data && data.error ? data.error : {};
			const apiError = new ApiError(
				errorData.message || "The request could not be completed.",
				response.status,
				errorData.code || "REQUEST_FAILED"
			);
			if (response.status === 401 && globalThis.Auth) {
				globalThis.Auth.handleUnauthorized();
			}
			throw apiError;
		}
		return data;
	}

	globalThis.Api = Object.freeze({
		request,
		get: (path, options) => request(path, { ...options, method: "GET" }),
		post: (path, body, options) => request(path, { ...options, method: "POST", body }),
		ApiError
	});
})();
