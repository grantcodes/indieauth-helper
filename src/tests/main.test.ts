import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { base64UrlEncode } from "../lib/base64url.js";
import type { IndieAuthOptions } from "../main.js";
import { IndieAuth, IndieAuthError } from "../main.js";
import type { ServerHandler } from "./_helpers/server.js";
import { readBody, startServer, type TestServer } from "./_helpers/server.js";

const clientId = "https://client.example/";
const redirectUri = "https://client.example/callback";
const me = "https://user.example/";

const servers: TestServer[] = [];

async function server(handler: ServerHandler): Promise<TestServer> {
	const started = await startServer(handler);
	servers.push(started);
	return started;
}

afterEach(async () => {
	mock.restoreAll();
	await Promise.all(servers.splice(0).map((item) => item.close()));
});

function makeAuth(overrides: Record<string, string | number> = {}): IndieAuth {
	return new IndieAuth({
		me,
		clientId,
		redirectUri,
		...overrides,
	});
}

function jsonResponse(
	response: import("node:http").ServerResponse,
	body: unknown,
	status = 200,
): void {
	response.writeHead(status, { "content-type": "application/json" });
	response.end(JSON.stringify(body));
}

describe("discovery", () => {
	it("discovers legacy endpoints from a Link header", async () => {
		const site = await server((_request, response) => {
			response.writeHead(200, {
				"content-type": "text/html",
				link: '<https://auth.example/auth>; rel="authorization_endpoint", <https://auth.example/token>; rel="token_endpoint"',
			});
			response.end("<html></html>");
		});

		const auth = new IndieAuth({ me: site.url });
		const result = await auth.discover();

		assert.equal(result.authorization_endpoint, "https://auth.example/auth");
		assert.equal(result.token_endpoint, "https://auth.example/token");
		assert.equal(auth.options.authEndpoint, "https://auth.example/auth");
		assert.equal(auth.options.me, `${site.url}/`);
	});

	it("discovers endpoints from HTML link elements and resolves relative URLs", async () => {
		const site = await server((_request, response) => {
			response.writeHead(200, { "content-type": "text/html" });
			response.end(
				'<html><head><link rel="authorization_endpoint" href="https://html.example/auth"><link rel="token_endpoint" href="/token"></head></html>',
			);
		});

		const auth = new IndieAuth({ me: site.url });
		const result = await auth.discover();

		assert.equal(result.authorization_endpoint, "https://html.example/auth");
		assert.equal(result.token_endpoint, `${site.url}/token`);
	});

	it("prefers the HTTP Link header over HTML link elements", async () => {
		const site = await server((_request, response) => {
			response.writeHead(200, {
				"content-type": "text/html",
				link: '<https://header.example/auth>; rel="authorization_endpoint"',
			});
			response.end(
				'<html><head><link rel="authorization_endpoint" href="https://html.example/auth"></head></html>',
			);
		});

		const auth = new IndieAuth({ me: site.url });
		const result = await auth.discover();

		assert.equal(result.authorization_endpoint, "https://header.example/auth");
	});

	it("uses a permanent redirect as the canonical me URL", async () => {
		const site = await server((request, response) => {
			if (request.url === "/") {
				response.writeHead(301, { location: "/final" });
				response.end();
				return;
			}
			response.writeHead(200, {
				link: '<https://auth.example/auth>; rel="authorization_endpoint"',
			});
			response.end();
		});

		const auth = new IndieAuth({ me: site.url });
		await auth.discover();

		assert.equal(auth.options.me, `${site.url}/final`);
	});

	it("keeps the original me URL after a temporary redirect", async () => {
		const site = await server((request, response) => {
			if (request.url === "/") {
				response.writeHead(302, { location: "/final" });
				response.end();
				return;
			}
			response.writeHead(200, {
				link: '<https://auth.example/auth>; rel="authorization_endpoint"',
			});
			response.end();
		});

		const auth = new IndieAuth({ me: site.url });
		await auth.discover();

		assert.equal(auth.options.me, `${site.url}/`);
	});

	it("rejects a site without an authorization endpoint", async () => {
		const site = await server((_request, response) => {
			response.writeHead(200, { "content-type": "text/html" });
			response.end("<html></html>");
		});

		const auth = new IndieAuth({ me: site.url });
		await assert.rejects(() => auth.discover(), /No authorization endpoint/);
	});

	it("reports the HTTP status for a failed discovery request", async () => {
		const site = await server((_request, response) => {
			response.writeHead(404);
			response.end();
		});

		const auth = new IndieAuth({ me: site.url });
		try {
			await auth.discover();
			assert.fail("Expected discovery to fail");
		} catch (err: unknown) {
			assert.ok(err instanceof IndieAuthError);
			assert.equal(err.status, 404);
		}
	});

	it("discovers IndieAuth server metadata", async () => {
		const metadataUrl =
			"https://server.example/.well-known/oauth-authorization-server";

		mock.method(
			globalThis,
			"fetch",
			async (input: string | URL | Request): Promise<Response> => {
				const url = input instanceof Request ? input.url : String(input);
				if (url === "https://user.example/") {
					return new Response(
						`<html><head><link rel="indieauth-metadata" href="${metadataUrl}"></head></html>`,
						{ headers: { "content-type": "text/html" } },
					);
				}
				if (url === metadataUrl) {
					return new Response(
						JSON.stringify({
							issuer: "https://server.example/",
							authorization_endpoint: "/auth",
							token_endpoint: "/token",
							introspection_endpoint: "/introspect",
							revocation_endpoint: "/revoke",
							userinfo_endpoint: "/userinfo",
							code_challenge_methods_supported: ["S256"],
						}),
						{ headers: { "content-type": "application/json" } },
					);
				}
				return new Response("Not found", { status: 404 });
			},
		);

		const auth = new IndieAuth({ me });
		const result = await auth.discover();

		assert.equal(result.metadata?.issuer, "https://server.example/");
		assert.equal(result.authorization_endpoint, "https://server.example/auth");
		assert.equal(result.token_endpoint, "https://server.example/token");
		assert.equal(
			auth.options.introspectionEndpoint,
			"https://server.example/introspect",
		);
		assert.equal(
			auth.options.revocationEndpoint,
			"https://server.example/revoke",
		);
		assert.equal(
			auth.options.userinfoEndpoint,
			"https://server.example/userinfo",
		);
		assert.equal(auth.options.issuer, "https://server.example/");
	});

	it("rejects metadata whose issuer does not prefix the metadata URL", async () => {
		const metadataUrl = "https://server.example/metadata";

		mock.method(
			globalThis,
			"fetch",
			async (input: string | URL | Request): Promise<Response> => {
				const url = input instanceof Request ? input.url : String(input);
				if (url === "https://user.example/") {
					return new Response(
						'<link rel="indieauth-metadata" href="https://server.example/metadata">',
						{ headers: { "content-type": "text/html" } },
					);
				}
				if (url === metadataUrl) {
					return new Response(
						JSON.stringify({
							issuer: "https://other.example/",
							authorization_endpoint: "https://server.example/auth",
						}),
						{ headers: { "content-type": "application/json" } },
					);
				}
				return new Response("Not found", { status: 404 });
			},
		);

		const auth = new IndieAuth({ me });
		await assert.rejects(() => auth.discover(), /invalid issuer/);
	});
});

describe("authorization URL", () => {
	it("builds a spec-compliant authorization request", async () => {
		const auth = makeAuth({
			authEndpoint: "https://auth.example/auth",
		});

		const url = new URL(
			await auth.getAuthUrl({ scopes: ["profile", "create"] }),
		);

		assert.equal(url.origin, "https://auth.example");
		assert.equal(url.pathname, "/auth");
		assert.equal(url.searchParams.get("response_type"), "code");
		assert.equal(url.searchParams.get("client_id"), clientId);
		assert.equal(url.searchParams.get("redirect_uri"), redirectUri);
		assert.equal(url.searchParams.get("me"), me);
		assert.equal(url.searchParams.get("scope"), "profile create");
		assert.equal(url.searchParams.get("code_challenge_method"), "S256");
		assert.match(url.searchParams.get("state") ?? "", /^.+$/);
		assert.match(
			url.searchParams.get("code_challenge") ?? "",
			/^[A-Za-z0-9_-]{43}$/,
		);

		const verifier = auth.options.codeVerifier;
		assert.ok(verifier);
		assert.match(verifier, /^[A-Za-z0-9\-._~]{43,128}$/);

		const digest = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(verifier),
		);
		assert.equal(
			url.searchParams.get("code_challenge"),
			base64UrlEncode(new Uint8Array(digest)),
		);
	});

	it("does not send a scope when none are requested", async () => {
		const auth = makeAuth({
			authEndpoint: "https://auth.example/auth",
		});

		const url = new URL(await auth.getAuthUrl());
		assert.equal(url.searchParams.has("scope"), false);
	});

	it("uses a fresh state and PKCE verifier for each request", async () => {
		const auth = makeAuth({
			authEndpoint: "https://auth.example/auth",
		});

		const first = new URL(await auth.getAuthUrl());
		const firstState = first.searchParams.get("state");
		const firstVerifier = auth.options.codeVerifier;

		const second = new URL(await auth.getAuthUrl());
		const secondState = second.searchParams.get("state");
		const secondVerifier = auth.options.codeVerifier;

		assert.notEqual(firstState, secondState);
		assert.notEqual(firstVerifier, secondVerifier);
	});

	it("uses a signed state when a secret is configured", async () => {
		const auth = makeAuth({
			authEndpoint: "https://auth.example/auth",
			secret: "test-secret",
		});

		const url = new URL(await auth.getAuthUrl());
		const state = url.searchParams.get("state");
		assert.ok(state);
		assert.match(state, /\./);

		const payload = await auth.validateState(state);
		assert.equal(payload.clientId, clientId);
		assert.equal(payload.me, me);
	});

	it("rejects a server that does not advertise S256 PKCE", async () => {
		const metadataUrl = "https://server.example/metadata";

		mock.method(
			globalThis,
			"fetch",
			async (input: string | URL | Request): Promise<Response> => {
				const url = input instanceof Request ? input.url : String(input);
				if (url === "https://user.example/") {
					return new Response(
						'<link rel="indieauth-metadata" href="https://server.example/metadata">',
						{ headers: { "content-type": "text/html" } },
					);
				}
				if (url === metadataUrl) {
					return new Response(
						JSON.stringify({
							issuer: "https://server.example/",
							authorization_endpoint: "https://server.example/auth",
							token_endpoint: "https://server.example/token",
							code_challenge_methods_supported: ["plain"],
						}),
						{ headers: { "content-type": "application/json" } },
					);
				}
				return new Response("Not found", { status: 404 });
			},
		);

		const auth = new IndieAuth({ me, clientId, redirectUri });
		await assert.rejects(() => auth.getAuthUrl(), /S256/);
	});
});

describe("token exchange", () => {
	it("exchanges a code for a token", async () => {
		let body = "";
		let contentType = "";
		let accept = "";

		const tokenServer = await server((request, response) => {
			contentType = String(request.headers["content-type"]);
			accept = String(request.headers.accept);
			void readBody(request).then((value) => {
				body = value;
				jsonResponse(response, {
					access_token: "access-token",
					token_type: "Bearer",
					me,
					scope: "profile create",
					profile: { name: "Test User" },
					expires_in: 3600,
					refresh_token: "refresh-token",
				});
			});
		});

		const pkce = await makeAuth().generatePkce();
		const auth = makeAuth({
			authEndpoint: "https://auth.example/auth",
			tokenEndpoint: `${tokenServer.url}/token`,
			codeVerifier: pkce.codeVerifier,
		});

		const token = await auth.getToken("auth-code");
		const params = new URLSearchParams(body);

		assert.match(contentType, /x-www-form-urlencoded/);
		assert.match(accept, /application\/json/);
		assert.equal(params.get("grant_type"), "authorization_code");
		assert.equal(params.get("code"), "auth-code");
		assert.equal(params.get("client_id"), clientId);
		assert.equal(params.get("redirect_uri"), redirectUri);
		assert.equal(params.get("code_verifier"), pkce.codeVerifier);
		assert.equal(params.get("me"), null);

		assert.equal(token.access_token, "access-token");
		assert.equal(token.token_type, "Bearer");
		assert.equal(token.me, me);
		assert.equal(token.scope, "profile create");
		assert.equal(token.expires_in, 3600);
		assert.equal(token.refresh_token, "refresh-token");
		assert.equal(token.profile?.name, "Test User");
	});

	it("parses a form-encoded token response", async () => {
		const tokenServer = await server((_request, response) => {
			response.writeHead(200, {
				"content-type": "application/x-www-form-urlencoded",
			});
			response.end(
				`access_token=access-token&token_type=Bearer&me=${encodeURIComponent(me)}&scope=profile&expires_in=3600`,
			);
		});

		const pkce = await makeAuth().generatePkce();
		const auth = makeAuth({
			tokenEndpoint: `${tokenServer.url}/token`,
			codeVerifier: pkce.codeVerifier,
		});

		const token = await auth.getToken("auth-code");
		assert.equal(token.access_token, "access-token");
		assert.equal(token.me, me);
		assert.equal(token.scope, "profile");
		assert.equal(token.expires_in, 3600);
	});

	it("throws the error returned by the token endpoint", async () => {
		const tokenServer = await server((_request, response) => {
			jsonResponse(
				response,
				{
					error: "invalid_grant",
					error_description: "The authorization code has expired",
				},
				400,
			);
		});

		const pkce = await makeAuth().generatePkce();
		const auth = makeAuth({
			tokenEndpoint: `${tokenServer.url}/token`,
			codeVerifier: pkce.codeVerifier,
		});

		try {
			await auth.getToken("auth-code");
			assert.fail("Expected the token request to fail");
		} catch (err: unknown) {
			assert.ok(err instanceof IndieAuthError);
			assert.equal(err.status, 400);
			assert.equal(err.message, "The authorization code has expired");
		}
	});

	it("requires a Bearer token type and a me value", async () => {
		const tokenServer = await server((_request, response) => {
			jsonResponse(response, {
				access_token: "access-token",
				token_type: "mac",
				me,
			});
		});

		const pkce = await makeAuth().generatePkce();
		const auth = makeAuth({
			tokenEndpoint: `${tokenServer.url}/token`,
			codeVerifier: pkce.codeVerifier,
		});

		await assert.rejects(() => auth.getToken("auth-code"), /Bearer/);
	});

	it("requires a code verifier", async () => {
		const auth = makeAuth({
			tokenEndpoint: "https://auth.example/token",
		});

		await assert.rejects(
			() => auth.getToken("auth-code"),
			/Missing required options: codeVerifier/,
		);
	});
});

describe("code verification", () => {
	it("redeems a code at the authorization endpoint", async () => {
		let body = "";
		const authServer = await server((request, response) => {
			void readBody(request).then((value) => {
				body = value;
				jsonResponse(response, { me, profile: { name: "Test User" } });
			});
		});

		const pkce = await makeAuth().generatePkce();
		const auth = makeAuth({
			authEndpoint: `${authServer.url}/auth`,
			codeVerifier: pkce.codeVerifier,
		});

		const result = await auth.verifyCode("auth-code");
		const params = new URLSearchParams(body);

		assert.equal(result.me, me);
		assert.equal(result.profile?.name, "Test User");
		assert.equal(params.get("grant_type"), "authorization_code");
		assert.equal(params.get("code"), "auth-code");
		assert.equal(params.get("code_verifier"), pkce.codeVerifier);
		assert.equal(params.get("client_id"), clientId);
		assert.equal(params.get("redirect_uri"), redirectUri);
	});
});

describe("profile URL confirmation", () => {
	it("accepts a differing profile URL that declares the same authorization server", async () => {
		const profileServer = await server((_request, response) => {
			response.writeHead(200, {
				link: '<https://auth.example/auth>; rel="authorization_endpoint"',
			});
			response.end("<html></html>");
		});

		const tokenServer = await server((_request, response) => {
			jsonResponse(response, {
				access_token: "access-token",
				token_type: "Bearer",
				me: `${profileServer.url}/`,
			});
		});

		const pkce = await makeAuth().generatePkce();
		const auth = new IndieAuth({
			me: "https://initial.example/",
			clientId,
			redirectUri,
			authEndpoint: "https://auth.example/auth",
			tokenEndpoint: `${tokenServer.url}/token`,
			codeVerifier: pkce.codeVerifier,
		});

		const token = await auth.getToken("auth-code");
		assert.equal(token.me, `${profileServer.url}/`);
		assert.equal(auth.options.me, `${profileServer.url}/`);
	});

	it("rejects a profile URL that declares a different authorization server", async () => {
		const profileServer = await server((_request, response) => {
			response.writeHead(200, {
				link: '<https://other.example/auth>; rel="authorization_endpoint"',
			});
			response.end("<html></html>");
		});

		const tokenServer = await server((_request, response) => {
			jsonResponse(response, {
				access_token: "access-token",
				token_type: "Bearer",
				me: `${profileServer.url}/`,
			});
		});

		const pkce = await makeAuth().generatePkce();
		const auth = new IndieAuth({
			me: "https://initial.example/",
			clientId,
			redirectUri,
			authEndpoint: "https://auth.example/auth",
			tokenEndpoint: `${tokenServer.url}/token`,
			codeVerifier: pkce.codeVerifier,
		});

		await assert.rejects(
			() => auth.getToken("auth-code"),
			/same authorization server/,
		);
	});
});

describe("refresh, revoke, introspect, and user info", () => {
	it("refreshes a token", async () => {
		let body = "";
		const tokenServer = await server((request, response) => {
			void readBody(request).then((value) => {
				body = value;
				jsonResponse(response, {
					access_token: "new-token",
					token_type: "Bearer",
					me,
					scope: "profile",
				});
			});
		});

		const auth = makeAuth({
			tokenEndpoint: `${tokenServer.url}/token`,
		});

		const token = await auth.refreshToken("refresh-token", ["profile"]);
		const params = new URLSearchParams(body);

		assert.equal(token.access_token, "new-token");
		assert.equal(params.get("grant_type"), "refresh_token");
		assert.equal(params.get("refresh_token"), "refresh-token");
		assert.equal(params.get("client_id"), clientId);
		assert.equal(params.get("scope"), "profile");
		assert.equal(params.get("code_verifier"), null);
	});

	it("revokes a token at the revocation endpoint", async () => {
		let body = "";
		const revocationServer = await server((request, response) => {
			void readBody(request).then((value) => {
				body = value;
				response.writeHead(200);
				response.end();
			});
		});

		const auth = makeAuth({
			revocationEndpoint: `${revocationServer.url}/revoke`,
		});

		await auth.revokeToken("access-token");
		const params = new URLSearchParams(body);
		assert.equal(params.get("token"), "access-token");
		assert.equal(params.get("action"), null);
	});

	it("falls back to the token endpoint for revocation", async () => {
		let body = "";
		const tokenServer = await server((request, response) => {
			void readBody(request).then((value) => {
				body = value;
				response.writeHead(200);
				response.end();
			});
		});

		const auth = makeAuth({
			tokenEndpoint: `${tokenServer.url}/token`,
		});

		await auth.revokeToken("access-token");
		const params = new URLSearchParams(body);
		assert.equal(params.get("token"), "access-token");
		assert.equal(params.get("action"), "revoke");
	});

	it("introspects a token", async () => {
		let body = "";
		let authorization = "";
		const introspectionServer = await server((request, response) => {
			authorization = String(request.headers.authorization);
			void readBody(request).then((value) => {
				body = value;
				jsonResponse(response, {
					active: true,
					me,
					client_id: clientId,
					scope: "profile",
				});
			});
		});

		const auth = makeAuth({
			introspectionEndpoint: `${introspectionServer.url}/introspect`,
		});

		const result = await auth.introspectToken("access-token");
		const params = new URLSearchParams(body);

		assert.equal(result.active, true);
		assert.equal(result.me, me);
		assert.equal(params.get("token"), "access-token");
		assert.equal(authorization, "Bearer access-token");
	});

	it("returns false for an inactive token", async () => {
		const introspectionServer = await server((_request, response) => {
			jsonResponse(response, { active: false });
		});

		const auth = makeAuth({
			introspectionEndpoint: `${introspectionServer.url}/introspect`,
		});

		assert.equal(await auth.verifyToken("access-token"), false);
	});

	it("accepts the string values used in the spec introspection example", async () => {
		const introspectionServer = await server((_request, response) => {
			jsonResponse(response, {
				active: "true",
				me,
				client_id: clientId,
				scope: "create update delete",
				exp: "1632443647",
				iat: "1632443147",
			});
		});

		const auth = makeAuth({
			introspectionEndpoint: `${introspectionServer.url}/introspect`,
		});

		const result = await auth.introspectToken("access-token");
		assert.equal(result.active, true);
		assert.equal(result.me, me);
	});

	it("rejects an introspection response without active", async () => {
		const introspectionServer = await server((_request, response) => {
			jsonResponse(response, { me });
		});

		const auth = makeAuth({
			introspectionEndpoint: `${introspectionServer.url}/introspect`,
		});

		await assert.rejects(
			() => auth.introspectToken("access-token"),
			/active property/,
		);
	});

	it("gets user info", async () => {
		let authorization = "";
		const userinfoServer = await server((request, response) => {
			authorization = String(request.headers.authorization);
			jsonResponse(response, {
				name: "Test User",
				url: me,
				photo: "https://user.example/photo.jpg",
			});
		});

		const auth = makeAuth({
			userinfoEndpoint: `${userinfoServer.url}/userinfo`,
		});

		const profile = await auth.getUserInfo("access-token");
		assert.equal(profile.name, "Test User");
		assert.equal(profile.url, me);
		assert.equal(authorization, "Bearer access-token");
	});
});

describe("options", () => {
	it("rejects unknown options", () => {
		const auth = makeAuth();
		const unknown: Record<string, unknown> = { foo: "bar" };
		assert.throws(() => {
			// SAFETY: the runtime option validator is the behaviour under test.
			auth.options = unknown as Partial<IndieAuthOptions>;
		}, /Unknown option: foo/);
	});

	it("validates client identifiers", () => {
		assert.throws(
			() => makeAuth({ clientId: "http://client.example/" }),
			/invalid client identifier/,
		);
	});

	it("canonicalizes me", () => {
		const auth = makeAuth({ me: "example.com" });
		assert.equal(auth.options.me, "https://example.com/");
	});

	it("rejects invalid me URLs", () => {
		assert.throws(
			() => makeAuth({ me: "mailto:user@example.com" }),
			/invalid URL/,
		);
	});

	it("rejects a negative stateMaxAge", () => {
		assert.throws(() => makeAuth({ stateMaxAge: -1 }), /non-negative/);
	});

	it("reports missing required options", () => {
		const auth = new IndieAuth();
		assert.throws(
			() => auth.checkRequiredOptions(["me", "clientId"]),
			/Missing required options: me, clientId/,
		);
	});

	it("exposes URL validators", () => {
		const auth = makeAuth();
		assert.equal(auth.isValidProfileUrl(me), true);
		assert.equal(auth.isValidClientId(clientId), true);
		assert.equal(auth.getCanonicalUrl("example.com"), "https://example.com/");
	});
});
