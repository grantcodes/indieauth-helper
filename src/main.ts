import { relParser } from "rel-parser";
import { IndieAuthError, toIndieAuthError } from "./lib/errors.js";
import {
	createCodeChallenge,
	generatePkceParameters,
	isValidCodeVerifier,
	type PkceParameters,
} from "./lib/pkce.js";
import { randomString } from "./lib/random.js";
import {
	fetchDocument,
	readResponse,
	requestForm,
	requestJson,
} from "./lib/request.js";
import { type StatePayload, signState, verifyState } from "./lib/state.js";
import {
	canonicalizeUrl,
	isHttpUrl,
	isValidClientId,
	isValidIssuer,
	isValidProfileUrl,
} from "./lib/url.js";

const DEFAULT_STATE_MAX_AGE = 10 * 60 * 1000;

const OPTION_KEYS = [
	"me",
	"clientId",
	"redirectUri",
	"authEndpoint",
	"tokenEndpoint",
	"metadataEndpoint",
	"issuer",
	"introspectionEndpoint",
	"revocationEndpoint",
	"userinfoEndpoint",
	"introspectionToken",
	"state",
	"secret",
	"codeVerifier",
	"codeChallenge",
	"stateMaxAge",
] as const;

export type IndieAuthOptionKey = (typeof OPTION_KEYS)[number];
type UrlOptionKey =
	| "me"
	| "clientId"
	| "redirectUri"
	| "authEndpoint"
	| "tokenEndpoint"
	| "metadataEndpoint"
	| "issuer"
	| "introspectionEndpoint"
	| "revocationEndpoint"
	| "userinfoEndpoint";

const URL_OPTION_KEYS: readonly UrlOptionKey[] = [
	"me",
	"clientId",
	"redirectUri",
	"authEndpoint",
	"tokenEndpoint",
	"metadataEndpoint",
	"issuer",
	"introspectionEndpoint",
	"revocationEndpoint",
	"userinfoEndpoint",
];

export interface IndieAuthOptions {
	me: string;
	clientId: string;
	redirectUri: string;
	authEndpoint: string;
	tokenEndpoint: string;
	metadataEndpoint: string;
	issuer: string;
	introspectionEndpoint: string;
	revocationEndpoint: string;
	userinfoEndpoint: string;
	introspectionToken: string;
	state: string;
	secret: string;
	codeVerifier: string;
	codeChallenge: string;
	stateMaxAge: number;
}

export interface IndieAuthMetadata {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint?: string;
	introspection_endpoint?: string;
	revocation_endpoint?: string;
	userinfo_endpoint?: string;
	code_challenge_methods_supported?: string[];
	scopes_supported?: string[];
	[key: string]: unknown;
}

export interface DiscoveryResult {
	me: string;
	finalUrl: string;
	redirects: string[];
	metadataEndpoint: string | null;
	metadata: IndieAuthMetadata | null;
	authorization_endpoint: string;
	token_endpoint: string | null;
	introspection_endpoint: string | null;
	revocation_endpoint: string | null;
	userinfo_endpoint: string | null;
	rels: Record<string, string | null>;
}

export interface UserProfile {
	name?: string;
	url?: string;
	photo?: string;
	email?: string;
	[key: string]: unknown;
}

export interface TokenResponse {
	access_token: string;
	token_type: string;
	me: string;
	scope?: string;
	profile?: UserProfile;
	expires_in?: number;
	refresh_token?: string;
}

export interface ProfileResponse {
	me: string;
	profile?: UserProfile;
}

export interface TokenIntrospection {
	active: boolean;
	me?: string;
	client_id?: string;
	scope?: string;
	exp?: number;
	iat?: number;
	[key: string]: unknown;
}

export interface AuthUrlOptions {
	scopes?: string[];
	state?: string;
	codeVerifier?: string;
	codeChallenge?: string;
	responseType?: "code";
	me?: string;
}

export interface AuthorizationResponse {
	code: string;
	state: string;
	iss?: string;
}

export type AuthorizationResponseInput =
	| URLSearchParams
	| string
	| Record<string, string | null | undefined>;

const DEFAULT_OPTIONS: IndieAuthOptions = {
	me: "",
	clientId: "",
	redirectUri: "",
	authEndpoint: "",
	tokenEndpoint: "",
	metadataEndpoint: "",
	issuer: "",
	introspectionEndpoint: "",
	revocationEndpoint: "",
	userinfoEndpoint: "",
	introspectionToken: "",
	state: "",
	secret: "",
	codeVerifier: "",
	codeChallenge: "",
	stateMaxAge: DEFAULT_STATE_MAX_AGE,
};

function toSearchParams(input: AuthorizationResponseInput): URLSearchParams {
	if (input instanceof URLSearchParams) {
		return input;
	}

	if (typeof input === "string") {
		return new URLSearchParams(input.startsWith("?") ? input.slice(1) : input);
	}

	const params = new URLSearchParams();
	for (const [key, value] of Object.entries(input)) {
		if (value !== null && value !== undefined) {
			params.set(key, value);
		}
	}
	return params;
}

function readProfile(data: Record<string, unknown>): UserProfile | undefined {
	if (data.profile === undefined) {
		return undefined;
	}

	if (
		typeof data.profile !== "object" ||
		data.profile === null ||
		Array.isArray(data.profile)
	) {
		throw new IndieAuthError("The response contained an invalid profile");
	}

	return data.profile as UserProfile;
}

/**
 * IndieAuth client implementing the IndieAuth Living Standard (11 July 2024).
 * https://indieauth.spec.indieweb.org/
 */
export class IndieAuth {
	#options: IndieAuthOptions = { ...DEFAULT_OPTIONS };
	#metadata: IndieAuthMetadata | null = null;
	#discoveredUrls = new Set<string>();
	#stateUsed = false;
	#pkceUsed = false;

	constructor(userSettings: Partial<IndieAuthOptions> = {}) {
		this.options = userSettings;
	}

	get options(): Readonly<IndieAuthOptions> {
		return { ...this.#options };
	}

	set options(settings: Partial<IndieAuthOptions>) {
		for (const key of Object.keys(settings)) {
			if (!OPTION_KEYS.includes(key as IndieAuthOptionKey)) {
				throw new IndieAuthError(`Unknown option: ${key}`);
			}
		}

		const normalized: Partial<IndieAuthOptions> = { ...settings };
		for (const key of URL_OPTION_KEYS) {
			const value = settings[key];
			if (typeof value !== "string" || value === "") {
				continue;
			}

			if (key === "me") {
				try {
					normalized.me = canonicalizeUrl(value);
				} catch {
					throw new IndieAuthError(
						`Attempted to set ${key} option with an invalid URL`,
					);
				}
				continue;
			}

			if (!isHttpUrl(value)) {
				throw new IndieAuthError(
					`Attempted to set ${key} option with an invalid URL`,
				);
			}
		}

		if (normalized.me && !isHttpUrl(normalized.me)) {
			throw new IndieAuthError(
				"Attempted to set me option with an invalid URL",
			);
		}

		if (normalized.clientId && !isValidClientId(normalized.clientId)) {
			throw new IndieAuthError(
				"Attempted to set clientId option with an invalid client identifier",
			);
		}

		if (
			normalized.stateMaxAge !== undefined &&
			(!Number.isFinite(normalized.stateMaxAge) || normalized.stateMaxAge < 0)
		) {
			throw new IndieAuthError("stateMaxAge must be a non-negative number");
		}

		this.#options = { ...this.#options, ...normalized };

		if (settings.state !== undefined) {
			this.#stateUsed = false;
		}
		if (
			settings.codeVerifier !== undefined ||
			settings.codeChallenge !== undefined
		) {
			this.#pkceUsed = false;
		}
	}

	checkRequiredOptions(requirements: IndieAuthOptionKey[]): true {
		const missing = requirements.filter((key) => !this.#options[key]);
		if (missing.length > 0) {
			throw new IndieAuthError(
				`Missing required options: ${missing.join(", ")}`,
			);
		}

		return true;
	}

	getCanonicalUrl(url: string): string {
		return canonicalizeUrl(url);
	}

	isValidProfileUrl(url: string): boolean {
		return isValidProfileUrl(url);
	}

	isValidClientId(url: string): boolean {
		return isValidClientId(url);
	}

	/** Client and authorization server discovery: https://indieauth.spec.indieweb.org/#x4-discovery */
	async discover(
		me = this.#options.me,
		extraRels: string[] = [],
	): Promise<DiscoveryResult> {
		const result = await this.#resolveDiscovery(me, extraRels);
		this.#applyDiscovery(result);
		return result;
	}

	/** Authorization request: https://indieauth.spec.indieweb.org/#x5-2-authorization-request */
	async getAuthUrl(options: AuthUrlOptions = {}): Promise<string> {
		if (options.responseType && options.responseType !== "code") {
			throw new IndieAuthError('Only response_type "code" is supported');
		}

		this.checkRequiredOptions(["me", "clientId", "redirectUri"]);

		if (!this.#options.authEndpoint) {
			await this.discover(this.#options.me);
		}

		this.checkRequiredOptions([
			"me",
			"clientId",
			"redirectUri",
			"authEndpoint",
		]);

		const methods = this.#metadata?.code_challenge_methods_supported;
		if (Array.isArray(methods) && !methods.includes("S256")) {
			throw new IndieAuthError(
				"The authorization server does not support S256 PKCE",
			);
		}

		if (options.state !== undefined) {
			this.#options.state = options.state;
			this.#stateUsed = true;
		} else if (!this.#options.state || this.#stateUsed) {
			this.#options.state = this.#options.secret
				? await this.generateState()
				: randomString(32);
			this.#stateUsed = true;
		}

		if (options.codeVerifier) {
			this.#options.codeVerifier = options.codeVerifier;
			this.#pkceUsed = true;
		} else if (!this.#options.codeVerifier || this.#pkceUsed) {
			const pkce = await generatePkceParameters();
			this.#options.codeVerifier = pkce.codeVerifier;
			this.#options.codeChallenge = pkce.codeChallenge;
			this.#pkceUsed = true;
		} else if (!isValidCodeVerifier(this.#options.codeVerifier)) {
			throw new IndieAuthError("The codeVerifier is not valid for PKCE");
		}

		if (options.codeChallenge) {
			if (!this.#options.codeVerifier) {
				throw new IndieAuthError(
					"A codeVerifier is required when providing a codeChallenge",
				);
			}
			this.#options.codeChallenge = options.codeChallenge;
			this.#pkceUsed = true;
		} else if (this.#options.codeVerifier && !this.#options.codeChallenge) {
			this.#options.codeChallenge = await createCodeChallenge(
				this.#options.codeVerifier,
			);
			this.#pkceUsed = true;
		}

		const authUrl = (() => {
			try {
				return new URL(this.#options.authEndpoint);
			} catch {
				throw new IndieAuthError(
					"The authorization endpoint is not a valid URL",
				);
			}
		})();
		authUrl.searchParams.set("response_type", "code");
		authUrl.searchParams.set("client_id", this.#options.clientId);
		authUrl.searchParams.set("redirect_uri", this.#options.redirectUri);
		authUrl.searchParams.set("state", this.#options.state);
		authUrl.searchParams.set("code_challenge", this.#options.codeChallenge);
		authUrl.searchParams.set("code_challenge_method", "S256");
		authUrl.searchParams.set("me", options.me ?? this.#options.me);

		if (options.scopes && options.scopes.length > 0) {
			authUrl.searchParams.set("scope", options.scopes.join(" "));
		}

		return authUrl.toString();
	}

	/** Redeeming the authorization code: https://indieauth.spec.indieweb.org/#x5-3-redeeming-the-authorization-code */
	async getToken(code: string): Promise<TokenResponse> {
		if (!this.#options.tokenEndpoint && this.#options.me) {
			await this.discover(this.#options.me);
		}

		this.checkRequiredOptions([
			"clientId",
			"redirectUri",
			"tokenEndpoint",
			"codeVerifier",
		]);

		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			client_id: this.#options.clientId,
			redirect_uri: this.#options.redirectUri,
			code_verifier: this.#options.codeVerifier,
		});

		const data = await requestForm(
			this.#options.tokenEndpoint,
			body,
			"Error requesting token endpoint",
		);
		const token = this.#parseTokenResponse(data);
		await this.#confirmProfileUrl(token.me);
		token.me = this.#options.me;
		return token;
	}

	/** Authorization code verification (legacy IndieAuth profile flow): https://indieauth.spec.indieweb.org/#x5-3-redeeming-the-authorization-code */
	async verifyCode(code: string): Promise<ProfileResponse> {
		if (!this.#options.authEndpoint && this.#options.me) {
			await this.discover(this.#options.me);
		}

		this.checkRequiredOptions([
			"clientId",
			"redirectUri",
			"authEndpoint",
			"codeVerifier",
		]);

		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			client_id: this.#options.clientId,
			redirect_uri: this.#options.redirectUri,
			code_verifier: this.#options.codeVerifier,
		});

		const data = await requestForm(
			this.#options.authEndpoint,
			body,
			"Error verifying authorization code",
		);

		if (typeof data.me !== "string" || !isHttpUrl(data.me)) {
			throw new IndieAuthError(
				"The auth endpoint did not return a valid me parameter",
			);
		}

		const profile = readProfile(data);
		await this.#confirmProfileUrl(data.me);

		return {
			me: this.#options.me,
			...(profile ? { profile } : {}),
		};
	}

	/** Refresh tokens: https://indieauth.spec.indieweb.org/#x5-5-refresh-tokens */
	async refreshToken(
		refreshToken: string,
		scopes?: string[],
	): Promise<TokenResponse> {
		if (!this.#options.tokenEndpoint && this.#options.me) {
			await this.discover(this.#options.me);
		}

		this.checkRequiredOptions(["clientId", "tokenEndpoint"]);

		const body = new URLSearchParams({
			grant_type: "refresh_token",
			refresh_token: refreshToken,
			client_id: this.#options.clientId,
		});

		if (scopes && scopes.length > 0) {
			body.set("scope", scopes.join(" "));
		}

		const data = await requestForm(
			this.#options.tokenEndpoint,
			body,
			"Error refreshing access token",
		);
		const token = this.#parseTokenResponse(data);
		await this.#confirmProfileUrl(token.me);
		token.me = this.#options.me;
		return token;
	}

	/** Token revocation: https://indieauth.spec.indieweb.org/#x7-token-revocation */
	async revokeToken(token: string): Promise<void> {
		if (
			!this.#options.revocationEndpoint &&
			!this.#options.tokenEndpoint &&
			this.#options.me
		) {
			await this.discover(this.#options.me);
		}

		const endpoint =
			this.#options.revocationEndpoint || this.#options.tokenEndpoint;
		if (!endpoint) {
			throw new IndieAuthError(
				"Missing required options: revocationEndpoint or tokenEndpoint",
			);
		}

		const body = new URLSearchParams({ token });
		if (!this.#options.revocationEndpoint) {
			body.set("action", "revoke");
		}

		await requestForm(endpoint, body, "Error revoking token");
	}

	/** Access token verification request: https://indieauth.spec.indieweb.org/#x6-1-access-token-verification-request */
	async introspectToken(token: string): Promise<TokenIntrospection> {
		if (
			!this.#options.introspectionEndpoint &&
			!this.#options.tokenEndpoint &&
			this.#options.me
		) {
			await this.discover(this.#options.me);
		}

		const endpoint =
			this.#options.introspectionEndpoint || this.#options.tokenEndpoint;
		if (!endpoint) {
			throw new IndieAuthError(
				"Missing required options: introspectionEndpoint or tokenEndpoint",
			);
		}

		const body = new URLSearchParams({ token });
		const authorizationToken = this.#options.introspectionToken || token;
		const data = await requestJson(
			endpoint,
			{
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded;charset=UTF-8",
					accept: "application/json",
					authorization: `Bearer ${authorizationToken}`,
				},
				body: body.toString(),
			},
			"Error verifying token",
		);

		const active =
			data.active === true || data.active === "true"
				? true
				: data.active === false || data.active === "false"
					? false
					: null;

		if (active === null) {
			throw new IndieAuthError(
				"The introspection endpoint did not return an active property",
			);
		}

		if (active && (typeof data.me !== "string" || !isHttpUrl(data.me))) {
			throw new IndieAuthError(
				"The introspection response did not contain a valid me property",
			);
		}

		return { ...data, active } as TokenIntrospection;
	}

	/** Access token verification: https://indieauth.spec.indieweb.org/#x6-access-token-verification */
	async verifyToken(token: string): Promise<boolean> {
		const result = await this.introspectToken(token);
		return result.active;
	}

	/** User information: https://indieauth.spec.indieweb.org/#x9-user-information */
	async getUserInfo(token: string): Promise<UserProfile> {
		if (!this.#options.userinfoEndpoint && this.#options.me) {
			await this.discover(this.#options.me);
		}

		this.checkRequiredOptions(["userinfoEndpoint"]);

		const data = await requestJson(
			this.#options.userinfoEndpoint,
			{
				headers: {
					accept: "application/json",
					authorization: `Bearer ${token}`,
				},
			},
			"Error getting user info",
		);

		return data as UserProfile;
	}

	/** Authorization server confirmation (state and iss): https://indieauth.spec.indieweb.org/#x5-4-authorization-server-confirmation */
	async validateAuthorizationResponse(
		input: AuthorizationResponseInput,
	): Promise<AuthorizationResponse> {
		const params = toSearchParams(input);
		const state = params.get("state");
		const code = params.get("code");
		const iss = params.get("iss");
		const error = params.get("error");
		const errorDescription = params.get("error_description");

		if (!state) {
			throw new IndieAuthError(
				"Missing state parameter in authorization response",
			);
		}

		let validState =
			this.#options.state !== "" && state === this.#options.state;

		if (!validState && this.#options.secret) {
			try {
				await this.validateState(state);
				validState = true;
			} catch {
				validState = false;
			}
		}

		if (!validState) {
			throw new IndieAuthError("The authorization response state is not valid");
		}

		if (error) {
			throw new IndieAuthError(
				errorDescription ?? error,
				null,
				errorDescription
					? { error, error_description: errorDescription }
					: error,
			);
		}

		if (!code) {
			throw new IndieAuthError(
				"Missing code parameter in authorization response",
			);
		}

		if (this.#options.issuer) {
			if (!iss) {
				throw new IndieAuthError(
					"Missing iss parameter in authorization response",
				);
			}
			if (iss !== this.#options.issuer) {
				throw new IndieAuthError(
					"The iss parameter does not match the authorization server issuer",
				);
			}
		} else if (iss && !isHttpUrl(iss)) {
			throw new IndieAuthError("The iss parameter is not a valid URL");
		}

		return { code, state, ...(iss ? { iss } : {}) };
	}

	async generateState(): Promise<string> {
		this.checkRequiredOptions(["secret", "me", "clientId"]);

		return signState(
			{
				date: Date.now(),
				me: this.#options.me,
				clientId: this.#options.clientId,
			},
			this.#options.secret,
		);
	}

	async validateState(state: string): Promise<StatePayload> {
		this.checkRequiredOptions(["secret", "clientId"]);

		const payload = await verifyState(state, this.#options.secret);
		if (!payload) {
			throw new IndieAuthError("The state is not valid");
		}

		if (payload.clientId !== this.#options.clientId) {
			throw new IndieAuthError("The state was issued for a different client");
		}

		const age = Date.now() - payload.date;
		if (
			!Number.isFinite(age) ||
			age > this.#options.stateMaxAge ||
			age < -60_000
		) {
			throw new IndieAuthError("The state has expired");
		}

		if (!payload.me) {
			throw new IndieAuthError("The state does not contain a me value");
		}

		if (!this.#options.me) {
			this.#options.me = canonicalizeUrl(payload.me);
		}

		return payload;
	}

	async generatePkce(): Promise<PkceParameters> {
		return generatePkceParameters();
	}

	generateRandomString(length = 64, charset?: string): string {
		return randomString(length, charset);
	}

	async #resolveDiscovery(
		me: string,
		extraRels: string[],
	): Promise<DiscoveryResult> {
		if (!me) {
			throw new IndieAuthError("Missing required options: me");
		}

		const requestedUrl = canonicalizeUrl(me);
		let fetched: Awaited<ReturnType<typeof fetchDocument>>;
		try {
			fetched = await fetchDocument(requestedUrl, {
				method: "GET",
				headers: {
					accept: "text/html,application/xhtml+xml",
				},
			});
		} catch (err) {
			throw toIndieAuthError(err, `Error getting ${requestedUrl}`);
		}

		const { response, finalUrl, canonicalUrl, redirects } = fetched;
		if (!response.ok) {
			throw new IndieAuthError(
				`Error getting ${requestedUrl}`,
				response.status,
				response.statusText || null,
			);
		}

		const contentType = response.headers.get("content-type") ?? "";
		const html =
			contentType === "" || contentType.includes("html")
				? await response.text()
				: "";
		const headers = Object.fromEntries(response.headers.entries());
		const parsedRels = await relParser(finalUrl, html, headers);

		const rels: Record<string, string | null> = {};
		for (const [key, values] of Object.entries(parsedRels)) {
			rels[key.toLowerCase()] = values[0] ?? null;
		}

		for (const rel of [
			"authorization_endpoint",
			"token_endpoint",
			...extraRels,
		]) {
			const name = rel.toLowerCase();
			if (!(name in rels)) {
				rels[name] = null;
			}
		}

		const metadataEndpoint = rels["indieauth-metadata"] ?? null;
		const metadata = metadataEndpoint
			? await this.#fetchMetadata(metadataEndpoint)
			: null;

		const authorizationEndpoint =
			metadata?.authorization_endpoint ?? rels.authorization_endpoint ?? null;

		if (!authorizationEndpoint) {
			throw new IndieAuthError("No authorization endpoint found");
		}

		const tokenEndpoint =
			metadata?.token_endpoint ?? rels.token_endpoint ?? null;

		return {
			me: canonicalUrl,
			finalUrl,
			redirects,
			metadataEndpoint,
			metadata,
			authorization_endpoint: authorizationEndpoint,
			token_endpoint: tokenEndpoint,
			introspection_endpoint: metadata?.introspection_endpoint ?? null,
			revocation_endpoint: metadata?.revocation_endpoint ?? null,
			userinfo_endpoint: metadata?.userinfo_endpoint ?? null,
			rels,
		};
	}

	#applyDiscovery(result: DiscoveryResult): void {
		this.#options = {
			...this.#options,
			me: result.me,
			authEndpoint: result.authorization_endpoint,
			tokenEndpoint: result.token_endpoint ?? "",
			metadataEndpoint: result.metadataEndpoint ?? "",
			issuer: result.metadata?.issuer ?? "",
			introspectionEndpoint: result.introspection_endpoint ?? "",
			revocationEndpoint: result.revocation_endpoint ?? "",
			userinfoEndpoint: result.userinfo_endpoint ?? "",
		};
		this.#metadata = result.metadata;

		for (const url of [
			...result.redirects,
			result.finalUrl,
			result.me,
			result.metadataEndpoint,
		]) {
			if (url) {
				this.#discoveredUrls.add(url);
			}
		}
	}

	async #fetchMetadata(metadataUrl: string): Promise<IndieAuthMetadata> {
		let response: Response;
		try {
			response = await fetch(metadataUrl, {
				headers: {
					accept: "application/json",
				},
			});
		} catch (err) {
			throw toIndieAuthError(
				err,
				`Error getting IndieAuth metadata from ${metadataUrl}`,
			);
		}

		if (!response.ok) {
			throw new IndieAuthError(
				`Error getting IndieAuth metadata from ${metadataUrl}`,
				response.status,
			);
		}

		const data = await readResponse(response);
		const metadataBase = response.url || metadataUrl;
		const issuer = data.issuer;
		const authorizationEndpoint = data.authorization_endpoint;

		if (typeof issuer !== "string" || !isValidIssuer(issuer, metadataBase)) {
			throw new IndieAuthError(
				"The IndieAuth metadata contains an invalid issuer",
			);
		}

		const resolveEndpoint = (key: string, value: unknown): string => {
			if (typeof value !== "string") {
				throw new IndieAuthError(
					`The IndieAuth metadata contains an invalid ${key}`,
				);
			}

			let url: URL;
			try {
				url = new URL(value, metadataBase);
			} catch {
				throw new IndieAuthError(
					`The IndieAuth metadata contains an invalid ${key}`,
				);
			}

			if (url.protocol !== "http:" && url.protocol !== "https:") {
				throw new IndieAuthError(
					`The IndieAuth metadata contains an invalid ${key}`,
				);
			}

			return url.href;
		};

		const metadata: IndieAuthMetadata = {
			...data,
			issuer,
			authorization_endpoint: resolveEndpoint(
				"authorization_endpoint",
				authorizationEndpoint,
			),
		};

		for (const key of [
			"token_endpoint",
			"introspection_endpoint",
			"revocation_endpoint",
			"userinfo_endpoint",
		]) {
			const value = data[key];
			if (value !== undefined) {
				metadata[key] = resolveEndpoint(key, value);
			}
		}

		for (const key of [
			"code_challenge_methods_supported",
			"scopes_supported",
		]) {
			const value = data[key];
			if (
				value !== undefined &&
				(!Array.isArray(value) ||
					!value.every((item) => typeof item === "string"))
			) {
				throw new IndieAuthError(
					`The IndieAuth metadata contains an invalid ${key}`,
				);
			}
		}

		return metadata;
	}

	#parseTokenResponse(data: Record<string, unknown>): TokenResponse {
		if (typeof data.access_token !== "string" || data.access_token === "") {
			throw new IndieAuthError(
				"The token endpoint did not return an access_token",
			);
		}

		if (
			typeof data.token_type !== "string" ||
			data.token_type.toLowerCase() !== "bearer"
		) {
			throw new IndieAuthError(
				"The token endpoint did not return a Bearer token type",
			);
		}

		if (typeof data.me !== "string" || !isHttpUrl(data.me)) {
			throw new IndieAuthError(
				"The token endpoint did not return a valid me parameter",
			);
		}

		const token: TokenResponse = {
			access_token: data.access_token,
			token_type: data.token_type,
			me: data.me,
		};

		if (data.scope !== undefined) {
			if (typeof data.scope !== "string") {
				throw new IndieAuthError(
					"The token endpoint returned an invalid scope",
				);
			}
			token.scope = data.scope;
		}

		if (data.expires_in !== undefined) {
			const expiresIn =
				typeof data.expires_in === "number"
					? data.expires_in
					: typeof data.expires_in === "string" && /^\d+$/.test(data.expires_in)
						? Number(data.expires_in)
						: Number.NaN;

			if (!Number.isFinite(expiresIn)) {
				throw new IndieAuthError(
					"The token endpoint returned an invalid expires_in",
				);
			}
			token.expires_in = expiresIn;
		}

		if (data.refresh_token !== undefined) {
			if (typeof data.refresh_token !== "string") {
				throw new IndieAuthError(
					"The token endpoint returned an invalid refresh_token",
				);
			}
			token.refresh_token = data.refresh_token;
		}

		const profile = readProfile(data);
		if (profile) {
			token.profile = profile;
		}

		return token;
	}

	async #confirmProfileUrl(me: string): Promise<void> {
		const canonical = canonicalizeUrl(me);
		const current = this.#options.me;

		if (current && canonicalizeUrl(current) === canonical) {
			return;
		}

		if (this.#discoveredUrls.has(canonical)) {
			this.#options.me = canonical;
			return;
		}

		const authEndpoint = this.#options.authEndpoint;
		if (!authEndpoint) {
			throw new IndieAuthError(
				"Cannot verify the returned profile URL without an authorization endpoint",
			);
		}

		const result = await this.#resolveDiscovery(canonical, []);
		if (result.authorization_endpoint !== authEndpoint) {
			throw new IndieAuthError(
				"The returned profile URL does not declare the same authorization server",
			);
		}

		if (
			this.#metadata?.issuer &&
			result.metadata?.issuer &&
			this.#metadata.issuer !== result.metadata.issuer
		) {
			throw new IndieAuthError(
				"The returned profile URL declares a different issuer",
			);
		}

		this.#options.me = canonical;
	}
}

export { IndieAuthError };
export default IndieAuth;
