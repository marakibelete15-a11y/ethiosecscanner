(() => {
	async function initAiAssistant() {
		if (globalThis.Auth && typeof globalThis.Auth.requireAuth === "function") {
			const user = await globalThis.Auth.requireAuth();
			if (!user) return;
		}
	}

	if (typeof document !== "undefined") {
		document.addEventListener("DOMContentLoaded", initAiAssistant);
	}
})();
