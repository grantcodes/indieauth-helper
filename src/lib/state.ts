import { base64UrlDecode, base64UrlEncode } from "./base64url.js";

export interface StatePayload {
	date: number;
	me: string;
	clientId: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const buffer = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(buffer).set(bytes);
	return buffer;
}

function timingSafeEqual(first: string, second: string): boolean {
	if (first.length !== second.length) {
		return false;
	}

	let difference = 0;
	for (let index = 0; index < first.length; index += 1) {
		difference |= first.charCodeAt(index) ^ second.charCodeAt(index);
	}
	return difference === 0;
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
	return crypto.subtle.importKey(
		"raw",
		toArrayBuffer(encoder.encode(secret)),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
}

async function sign(encodedPayload: string, secret: string): Promise<string> {
	const key = await importHmacKey(secret);
	const signature = await crypto.subtle.sign(
		"HMAC",
		key,
		toArrayBuffer(encoder.encode(encodedPayload)),
	);
	return base64UrlEncode(new Uint8Array(signature));
}

export async function signState(
	payload: StatePayload,
	secret: string,
): Promise<string> {
	const encodedPayload = base64UrlEncode(
		encoder.encode(JSON.stringify(payload)),
	);
	return `${encodedPayload}.${await sign(encodedPayload, secret)}`;
}

export async function verifyState(
	state: string,
	secret: string,
): Promise<StatePayload | null> {
	const [encodedPayload, encodedSignature] = state.split(".");
	if (!encodedPayload || !encodedSignature) {
		return null;
	}

	try {
		const expectedSignature = await sign(encodedPayload, secret);
		if (!timingSafeEqual(expectedSignature, encodedSignature)) {
			return null;
		}

		const payload: unknown = JSON.parse(
			decoder.decode(base64UrlDecode(encodedPayload)),
		);
		if (
			typeof payload !== "object" ||
			payload === null ||
			!(
				"date" in payload &&
				typeof payload.date === "number" &&
				"me" in payload &&
				typeof payload.me === "string" &&
				"clientId" in payload &&
				typeof payload.clientId === "string"
			)
		) {
			return null;
		}

		return payload as StatePayload;
	} catch {
		return null;
	}
}
