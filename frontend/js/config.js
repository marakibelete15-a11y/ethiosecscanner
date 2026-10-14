(() => {
	const configuredBase = globalThis.ETHIOSEC_API_BASE_URL;
	globalThis.EthioSecConfig = Object.freeze({
		apiBaseUrl: (configuredBase || globalThis.location.origin).replace(/\/$/, "")
	});
})();
