import { base64UrlEncode } from "./base64url.js";
import { randomString } from "./random.js";

export interface PkceParameters {
	codeVerifier: string;
	codeChallenge: string;
	codeChallengeMethod: "S256";
}

const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

export function isValidCodeVerifier(codeVerifier: string): boolean {
	return CODE_VERIFIER_PATTERN.test(codeVerifier);
}

export async function createCodeChallenge(
	codeVerifier: string,
): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(codeVerifier),
	);
	return base64UrlEncode(new Uint8Array(digest));
}

export async function generatePkceParameters(): Promise<PkceParameters> {
	const codeVerifier = randomString(64);
	const codeChallenge = await createCodeChallenge(codeVerifier);

	return {
		codeVerifier,
		codeChallenge,
		codeChallengeMethod: "S256",
	};
}
