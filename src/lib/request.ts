import { IndieAuthError, toIndieAuthError } from "./errors.js";

export interface FetchResult {
	response: Response;
	finalUrl: string;
	canonicalUrl: string;
	redirects: string[];
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 10;

export async function fetchDocument(
	url: string,
	init: RequestInit = {},
): Promise<FetchResult> {
	let currentUrl = url;
	let canonicalUrl = url;
	const redirects = [url];

	for (let attempt = 0; attempt <= MAX_REDIRECTS; attempt += 1) {
		const response = await fetch(currentUrl, {
			...init,
			redirect: "manual",
		});

		if (!REDIRECT_STATUSES.has(response.status)) {
			return {
				response,
				finalUrl: currentUrl,
				canonicalUrl,
				redirects,
			};
		}

		const location = response.headers.get("location");
		if (!location) {
			throw new IndieAuthError(
				`Redirect response from ${currentUrl} did not include a Location header`,
				response.status,
			);
		}

		await response.body?.cancel();

		if (response.status === 301 || response.status === 308) {
			canonicalUrl = new URL(location, currentUrl).href;
		}

		currentUrl = new URL(location, currentUrl).href;
		redirects.push(currentUrl);
	}

	throw new IndieAuthError(`Too many redirects while fetching ${url}`);
}

export async function readResponse(
	response: Response,
): Promise<Record<string, unknown>> {
	const text = await response.text();
	if (!text.trim()) {
		return {};
	}

	const contentType = response.headers.get("content-type") ?? "";
	const trimmed = text.trim();
	const looksLikeJson =
		contentType.includes("json") ||
		trimmed.startsWith("{") ||
		trimmed.startsWith("[");

	if (looksLikeJson) {
		let data: unknown;
		try {
			data = JSON.parse(trimmed);
		} catch {
			throw new IndieAuthError("Invalid JSON response", response.status);
		}

		if (typeof data !== "object" || data === null || Array.isArray(data)) {
			throw new IndieAuthError("Unexpected JSON response", response.status);
		}

		return data as Record<string, unknown>;
	}

	return Object.fromEntries(new URLSearchParams(trimmed));
}

export function throwForResponse(
	response: Response,
	data: Record<string, unknown>,
	context: string,
): void {
	const error = typeof data.error === "string" ? data.error : null;
	if (response.ok && !error) {
		return;
	}

	const description =
		typeof data.error_description === "string"
			? data.error_description
			: (error ?? `${context} (HTTP ${response.status})`);

	throw new IndieAuthError(description, response.status, data);
}

export async function requestForm(
	url: string,
	body: URLSearchParams,
	context: string,
): Promise<Record<string, unknown>> {
	let response: Response;
	try {
		response = await fetch(url, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded;charset=UTF-8",
				accept: "application/json, application/x-www-form-urlencoded",
			},
			body: body.toString(),
		});
	} catch (err) {
		throw toIndieAuthError(err, context);
	}

	const data = await readResponse(response);
	throwForResponse(response, data, context);
	return data;
}

export async function requestJson(
	url: string,
	init: RequestInit,
	context: string,
): Promise<Record<string, unknown>> {
	let response: Response;
	try {
		response = await fetch(url, init);
	} catch (err) {
		throw toIndieAuthError(err, context);
	}

	const data = await readResponse(response);
	throwForResponse(response, data, context);
	return data;
}
