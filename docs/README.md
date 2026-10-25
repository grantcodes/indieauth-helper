# IndieAuth Helper

A [IndieAuth](https://indieauth.spec.indieweb.org/) helper library for JavaScript and TypeScript.

This version implements the IndieAuth Living Standard (11 July 2024): metadata discovery, the authorization code flow, mandatory PKCE, `iss` validation, refresh tokens, revocation, introspection, and user info.

## Installation

```bash
npm install indieauth-helper
```

CommonJS consumers can use the named export:

```js
const { IndieAuth } = require("indieauth-helper");
```

Requires Node.js 22.20 or later, or a browser with native `fetch`, `URL`, and `crypto.subtle`.

## Quick start

```ts
import IndieAuth from "indieauth-helper";

const auth = new IndieAuth({
  me: "https://user.example/",
  clientId: "https://app.example/",
  redirectUri: "https://app.example/callback",
  secret: "a long random string",
});

await auth.discover();
const authUrl = await auth.getAuthUrl({
  scopes: ["profile", "create", "update"],
});

// Store these in the user's session before redirecting.
const codeVerifier = auth.options.codeVerifier;
const state = auth.options.state;
```

Redirect the browser to `authUrl`. On the callback:

```ts
const auth = new IndieAuth({
  me: "https://user.example/",
  clientId: "https://app.example/",
  redirectUri: "https://app.example/callback",
  secret: "a long random string",
});

auth.options = { state, codeVerifier };

const { code } = await auth.validateAuthorizationResponse(location.search);
const token = await auth.getToken(code);

console.log(token.access_token, token.me, token.scope);
```

`getToken` returns the complete token response, including `access_token`, `token_type`, `me`, and optional `scope`, `profile`, `expires_in`, and `refresh_token`.

## Discovery

`discover` fetches the user's URL, follows redirects, and looks for `rel="indieauth-metadata"` in HTTP `Link` headers or HTML `<link>` elements. It then fetches the IndieAuth server metadata document and stores the discovered endpoints and issuer.

```ts
const discovery = await auth.discover("https://user.example/");

console.log(discovery.metadataEndpoint);
console.log(discovery.authorization_endpoint);
console.log(discovery.token_endpoint);
```

If no metadata endpoint is advertised, it falls back to the legacy `authorization_endpoint` and `token_endpoint` link relations.

HTTP `Link` headers take precedence over HTML `<link>` elements. Relative URLs are resolved against the current document. `301` and `308` redirects update the canonical `me` URL; temporary redirects do not.

## Authorization URL

```ts
const url = await auth.getAuthUrl({
  scopes: ["profile", "email", "create"],
  state: "optional-custom-state",
  codeVerifier: "optional-custom-verifier",
});
```

The authorization request always uses `response_type=code` and PKCE with `S256`.

Unless supplied per call, a fresh state and code verifier are generated for every authorization request and stored on `auth.options`. Persist `auth.options.state` and `auth.options.codeVerifier` between the redirect and the callback.

If a `secret` is set, the generated state is HMAC-signed and validated with `validateState`. Without a `secret`, the state is an opaque random string and `validateAuthorizationResponse` compares it exactly.

## Validating the callback

```ts
const { code, state, iss } = await auth.validateAuthorizationResponse(
  location.search,
);
```

This validates the state, rejects `error` responses, requires a `code`, and verifies the `iss` parameter against the discovered issuer. If an issuer is known, `iss` is required and must match exactly.

## Token responses

`getToken` exchanges an authorization code at the token endpoint.

`verifyCode` exchanges the code at the authorization endpoint when you only need the user's profile URL and do not need an access token.

```ts
const token = await auth.getToken(code);
const profile = await auth.verifyCode(code);
```

Both methods confirm that a returned `me` URL that differs from the discovered URL declares the same authorization server, as required by the spec.

## Refresh, revoke, introspect, and user info

```ts
const refreshed = await auth.refreshToken(token.refresh_token, ["profile"]);

await auth.revokeToken(token.access_token);

const introspection = await auth.introspectToken(token.access_token);
if (introspection.active) {
  console.log(introspection.me, introspection.scope);
}

const user = await auth.getUserInfo(token.access_token);
```

`verifyToken` is a convenience wrapper that returns `introspection.active`.

If an endpoint was not supplied, these methods discover it from `me` when possible.

## Options

| Option | Description |
| --- | --- |
| `me` | The user's profile URL. A bare host is upgraded to `https://`. |
| `clientId` | The client identifier URL. Must be `https`. |
| `redirectUri` | The redirect URL registered with the client. |
| `authEndpoint` | Authorization endpoint. Discovered when omitted. |
| `tokenEndpoint` | Token endpoint. Discovered when omitted. |
| `metadataEndpoint` | IndieAuth metadata endpoint. Discovered when omitted. |
| `issuer` | Authorization server issuer identifier. Discovered when omitted. |
| `introspectionEndpoint` | Token introspection endpoint. |
| `introspectionToken` | Optional bearer token used to authenticate introspection requests. Defaults to the token being inspected. |
| `revocationEndpoint` | Token revocation endpoint. Falls back to `tokenEndpoint` with `action=revoke`. |
| `userinfoEndpoint` | User info endpoint. |
| `state` | State value for the current authorization request. |
| `secret` | Secret used to sign generated state values. |
| `codeVerifier` | PKCE code verifier for the current authorization request. |
| `codeChallenge` | PKCE code challenge. Derived from `codeVerifier` when omitted. |
| `stateMaxAge` | Maximum state age in milliseconds. Defaults to 10 minutes. |

Options can be read from `auth.options` and updated with the setter:

```ts
auth.options = { state: "new-state" };
```

Unknown options and invalid URLs are rejected with an `IndieAuthError`.

## Other methods

```ts
const pkce = await auth.generatePkce();
const state = await auth.generateState();
const payload = await auth.validateState(state);
const random = auth.generateRandomString(64);

auth.isValidProfileUrl("https://user.example/");
auth.isValidClientId("https://app.example/");
auth.getCanonicalUrl("example.com");
```

`generateRandomString` uses `crypto.getRandomValues` and the PKCE character set by default.

## Errors

Methods reject with `IndieAuthError`, which extends `Error`:

```ts
try {
  await auth.getToken(code);
} catch (error) {
  if (error instanceof IndieAuthError) {
    console.error(error.message, error.status, error.error);
  }
}
```

`status` is the HTTP status when the error came from a server response. `error` contains the parsed response body when available.

## Migrating from v1

- `response_type=id` is no longer supported. The default and only response type is `code`.
- `getToken` returns the full token response instead of only the access token string.
- `getRelsFromUrl` is replaced by `discover`.
- `generateState`, `validateState`, `getAuthUrl`, and `generatePkce` are asynchronous.
- Errors are `IndieAuthError` instances instead of plain objects.
- `axios`, `qs`, and `crypto-js` were replaced with native `fetch`, `URLSearchParams`, and WebCrypto.

## Thanks

- [martymcguire](https://github.com/martymcguire) - For the idea and building a lot of the functionality
- [sknebel](https://github.com/sknebel) - For helping with the rel scraping function
- [Zegnat](https://github.com/Zegnat) - For helping with the rel scraping function
- [myfreeweb](https://github.com/myfreeweb) - For fixing Link header handling and help with Accept headers
- [00dani](https://github.com/00dani) - For fixing base tag support in the rel scraper
- [cweiske](https://github.com/cweiske) - For fixing the 'me' domain check

## Links

- [Source code](https://github.com/grantcodes/indieauth-helper/)
- [Bug tracker](https://github.com/grantcodes/indieauth-helper/issues/)
