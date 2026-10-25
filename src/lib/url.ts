const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function isIpHost(hostname: string): boolean {
	return hostname.startsWith("[") || IPV4_PATTERN.test(hostname);
}

function hasDotSegment(value: string): boolean {
	const path =
		value.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, "").split(/[?#]/)[0] ?? "";

	return path.split("/").some((segment) => segment === "." || segment === "..");
}

function isLoopback(hostname: string): boolean {
	return (
		hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]"
	);
}

export function canonicalizeUrl(input: string): string {
	const value = input.trim();
	if (!value) {
		throw new TypeError("URL must not be empty");
	}

	const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(value);
	let url: URL;
	try {
		url = new URL(hasScheme ? value : `https://${value}`);
	} catch {
		throw new TypeError(`Invalid URL: ${input}`);
	}

	return url.href;
}

export function isHttpUrl(value: string): boolean {
	try {
		const url = new URL(value);
		return url.protocol === "http:" || url.protocol === "https:";
	} catch {
		return false;
	}
}

export function isValidProfileUrl(value: string): boolean {
	try {
		const url = new URL(value);
		if (url.protocol !== "http:" && url.protocol !== "https:") {
			return false;
		}
		if (url.username || url.password || url.port || url.hash) {
			return false;
		}
		if (hasDotSegment(value) || isIpHost(url.hostname)) {
			return false;
		}
		return url.hostname.includes(".");
	} catch {
		return false;
	}
}

export function isValidClientId(value: string): boolean {
	try {
		const url = new URL(value);
		if (url.protocol !== "https:" || url.hash || url.username || url.password) {
			return false;
		}
		if (hasDotSegment(value)) {
			return false;
		}
		if (isIpHost(url.hostname) && !isLoopback(url.hostname)) {
			return false;
		}
		return isLoopback(url.hostname) || url.hostname.includes(".");
	} catch {
		return false;
	}
}

export function isValidIssuer(issuer: string, metadataUrl: string): boolean {
	try {
		const url = new URL(issuer);
		if (url.protocol !== "https:" || url.search || url.hash) {
			return false;
		}
		return metadataUrl.startsWith(issuer);
	} catch {
		return false;
	}
}
