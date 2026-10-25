import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { base64UrlEncode } from "../../lib/base64url.js";
import {
	createCodeChallenge,
	generatePkceParameters,
	isValidCodeVerifier,
} from "../../lib/pkce.js";

const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("PKCE", () => {
	it("matches the RFC 7636 example challenge", async () => {
		assert.equal(await createCodeChallenge(RFC_VERIFIER), RFC_CHALLENGE);
	});

	it("generates a verifier within the spec length range", async () => {
		const params = await generatePkceParameters();
		assert.ok(params.codeVerifier.length >= 43);
		assert.ok(params.codeVerifier.length <= 128);
		assert.match(params.codeVerifier, /^[A-Za-z0-9\-._~]+$/);
		assert.equal(params.codeChallengeMethod, "S256");
	});

	it("derives the challenge from the verifier", async () => {
		const params = await generatePkceParameters();
		const digest = await crypto.subtle.digest(
			"SHA-256",
			new Uint8Array(new TextEncoder().encode(params.codeVerifier)),
		);
		assert.equal(params.codeChallenge, base64UrlEncode(new Uint8Array(digest)));
		assert.equal(params.codeChallenge.length, 43);
	});

	it("generates unique parameters", async () => {
		const first = await generatePkceParameters();
		const second = await generatePkceParameters();
		assert.notEqual(first.codeVerifier, second.codeVerifier);
		assert.notEqual(first.codeChallenge, second.codeChallenge);
	});

	it("validates verifier length and characters", () => {
		assert.equal(isValidCodeVerifier(RFC_VERIFIER), true);
		assert.equal(isValidCodeVerifier("a".repeat(42)), false);
		assert.equal(isValidCodeVerifier("a".repeat(129)), false);
		assert.equal(isValidCodeVerifier(`${"a".repeat(43)}!`), false);
	});
});
