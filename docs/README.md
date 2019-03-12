# IndieAuth Helper

A [IndieAuth](https://indieweb.org/IndieAuth) helper library for JavaScript.

## Usage

### Client side usage

Although this library is intended to be usable client side you will likely run into [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) issues and so be careful about that.

### Installation

```bash
npm install indieauth-helper
```

or

```bash
yarn add indieauth-helper
```

### Setup

The library is setup as an es6 class, and is initialized by passing an object of options.

```js
import IndieAuth from 'indieauth-helper'
const auth = new IndieAuth({
  clientId: 'https://myindieauthclientapp.com',
  redirectUri: 'https://myindieauthclientapp.com/auth',
  me: 'https://userindiewebsite.com',
  secret: 'topSecretString',
})

// If you are able to store a variable between sending the user to the auth url
// and requesting the auth token you should also set a `codeVerifier`
const codeVerifier = auth.generateRandomString()
auth.options.codeVerifier = codeVerifier
```

If you already have other information stored such as the auth endpoint you want to use you can also pass those in. The available options are:

- `me` - The url of the user you are authenticating with
- `clientId` - The url of your IndieAuth client app
- `redirectUri` - The redirect url of your IndieAuth client from the auth endpoint. This is the page where you will get the code to exchange for an access token.
- `state` - A custom identifier to validate a response from the auth endpoint. If a state is not set and a secret is set then the state will be automatically generated and must be checked with the `validateState` method.
- `secret` -A string that is used to encrypt and decrypt generated states
- `codeVerifier` - A random string to use as a PKCE code verifier. It must be stored between sending the user to the auth url and requesting the auth token
- `authEndpoint` - The authorization endpoint
- `tokenEndpoint` - The token endpoint to receive the access toke from

You can directly retrieve and modify the options on an instantiated class with the `options` property:

```js
// Get the user domain
const me = auth.options.me

// Change the me url
auth.options.me = 'https://example.com'
```

### Getting site endpoints

You can get the various endpoints for a website - either from headers or `link` tags.

By default returns an object with `authorization_endpoint` and `token_endpoint` properties with the urls of the endpoints.

This method will also automatically set the endpoint options in the current instance so you can read `auth.options.authEndpoint` and `auth.options.tokenEndpoint`.

```js
auth
  .getRelsFromUrl('http://example.com')
  .then(rels => {
    const { authorization_endpoint, token_endpoint } = rels
  })
  .catch(err => console.log(err))
```

Note: This is also run by the `getAuthUrl` method so chances are you will not need to use this method.

The same method can also be used to attempt to find any other rel value from the given url by passing in an array of rels you want.

By default the `authorization_endpoint` and `token_endpoint` are always requested and rels are normalized to lowercase. If a rel is not found it will have a `null` value.

```js
auth
  .getRelsFromUrl('http://example.com', ['micropub', 'microsub'])
  .then(rels => {
    const { authorization_endpoint, token_endpoint, micropub, microsub } = rels
  })
  .catch(err => console.log(err))
```

### Getting authorization url

The first step is likely to be getting the authorization url to direct the user to.

By default this method requests `response_type=id`.

```js
auth
  .getAuthUrl()
  .then(url => {
    // Handle directing user to this url to authenticate
  })
  .catch(err => console.log(err))
```

If you want to request `response_type=code` with some scopes you can pass the `response_type` string in the first param and an array of scopes in the second:

```js
auth
  .getAuthUrl('code', ['create', 'update'])
  .then(url => {
    // When doing `response_type=code` you will probably want to store the `auth.options.tokenEndpoint` value to talk to the token endpoint in the next step.
    // Then handle directing user to this url to authenticate
  })
  .catch(err => console.log(err))
```

Because this method also calls the `getRelsFromUrl` method the instance will also hold the found auth and token endpoints.

### State generation and validation

State values should always be unique and verified when requesting an access code from the authorization endpoint.

To help with this this library has a couple of methods to generate and validate state strings without the need for caching them between requests.

To use these methods you first need to have a `secret` option set as well as the `clientId` option.

If you do not explicitly set a state value one will automatically be generated with the `generateState` method.

The `generateState` method also required the `me` option to be set.

```js
auth.options.secret = 'privateSecretValue'
const state = auth.generateState()
```

Then the state string can be validated to return a object:

```js
const { date, me, clientId } = auth.validateState(state)
```

### Verify the auth code

Once you have an auth code you may want to check that it is valid against the auth endpoint.
You first need to initialize the library with the details you used to get the auth code and then pass the code to the `verifyCode` method:

```js
auth
  .verifyCode('auth_code_goes_here')
  .then(me => {
    // Returns the me value on success
  })
  .catch(err => console.log(err))
```

### Exchange your code for an access token

If you requested `response_type=code` the next step would be to exchange your code for an access token.
You first need to initialize the library with the details you used to get the auth code and then pass the code to the auth token method:

```js
auth
  .getToken('auth_code_goes_here')
  .then(token => {
    // Here you will probably want to save the token for future use
  })
  .catch(err => console.log(err))
```

### Error handling

If there are any errors then the methods will reject with an object:

```js
{
  message: 'Human readable string',
  status: null or the http status code,
  error: null or further error information,
}
```

Generally if there is a `status` code that means that a requested url returned an unexpected http error.
This might not be 100% accurate as there are a lot of potential errors.

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
