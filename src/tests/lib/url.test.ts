import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	canonicalizeUrl,
	isValidClientId,
	isValidIssuer,
	isValidProfileUrl,
} from "../../lib/url.js";

describe("canonicalizeUrl", () => {
	it("adds a trailing slash when the path is missing", () => {
		assert.equal(
			canonicalizeUrl("https://example.com"),
			"https://example.com/",
		);
	});

	it("adds an https scheme when the scheme is missing", () => {
		assert.equal(canonicalizeUrl("example.com"), "https://example.com/");
	});

	it("lowercases the host and keeps the path and query", () => {
		assert.equal(
			canonicalizeUrl("https://EXAMPLE.com/Users?Id=100"),
			"https://example.com/Users?Id=100",
		);
	});

	it("rejects empty input", () => {
		assert.throws(() => canonicalizeUrl("  "), /URL must not be empty/);
	});

	it("rejects malformed input", () => {
		assert.throws(() => canonicalizeUrl("https://"), /Invalid URL/);
	});
});

describe("isValidProfileUrl", () => {
	const valid = [
		"https://example.com/",
		"https://example.com/username",
		"https://example.com/users?id=100",
		"http://example.com/",
	];

	for (const url of valid) {
		it(`accepts ${url}`, () => {
			assert.equal(isValidProfileUrl(url), true);
		});
	}

	const invalid = [
		"example.com",
		"mailto:user@example.com",
		"https://example.com/foo/../bar",
		"https://example.com/#me",
		"https://user:pass@example.com/",
		"https://example.com:8443/",
		"https://172.28.92.51/",
		"https://[::1]/",
		"https://localhost/",
	];

	for (const url of invalid) {
		it(`rejects ${url}`, () => {
			assert.equal(isValidProfileUrl(url), false);
		});
	}
});

describe("isValidClientId", () => {
	const valid = [
		"https://app.example.com/",
		"https://app.example.com/callback",
		"https://app.example.com:8443/",
		"https://127.0.0.1:8080/",
		"https://[::1]/",
	];

	for (const url of valid) {
		it(`accepts ${url}`, () => {
			assert.equal(isValidClientId(url), true);
		});
	}

	const invalid = [
		"http://app.example.com/",
		"https://app.example.com/#fragment",
		"https://user:pass@app.example.com/",
		"https://app.example.com/foo/../bar",
		"https://192.168.0.1/",
	];

	for (const url of invalid) {
		it(`rejects ${url}`, () => {
			assert.equal(isValidClientId(url), false);
		});
	}
});

describe("isValidIssuer", () => {
	it("accepts an issuer that prefixes the metadata URL", () => {
		assert.equal(
			isValidIssuer(
				"https://example.com/",
				"https://example.com/.well-known/oauth-authorization-server",
			),
			true,
		);
	});

	it("accepts a path issuer", () => {
		assert.equal(
			isValidIssuer(
				"https://example.com/wp-json/indieauth/1.0",
				"https://example.com/wp-json/indieauth/1.0/metadata",
			),
			true,
		);
	});

	it("rejects a non-https issuer", () => {
		assert.equal(
			isValidIssuer("http://example.com/", "http://example.com/metadata"),
			false,
		);
	});

	it("rejects issuers with a query or fragment", () => {
		assert.equal(
			isValidIssuer(
				"https://example.com/?a=1",
				"https://example.com/?a=1/metadata",
			),
			false,
		);
	});

	it("rejects an issuer that does not prefix the metadata URL", () => {
		assert.equal(
			isValidIssuer("https://other.example/", "https://example.com/metadata"),
			false,
		);
	});
});
