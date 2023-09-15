import relScraper from 'rel-parser'
import CryptoJS from 'crypto-js'
import { parse as qsParse, stringify as qsStringify } from 'qs'
import { IndieAuthError } from './lib/indieauth-error'
import { validateUrl } from './lib/validate-url'
import { generateState, validateState } from './lib/state'
import type { IndieAuthOptions } from './types'

const defaultSettings: IndieAuthOptions = {
  me: '',
  clientId: '',
  redirectUri: '',
  authEndpoint: '',
  tokenEndpoint: '',
  state: '',
  secret: '',
  codeVerifier: ''
}

/**
 * A indieAuth helper class
 */
class IndieAuth {
  _me: string = ''
  _clientId: string = ''
  _redirectUri: string = ''
  _state: string = ''
  _secret: string = ''
  _codeVerifier: string = ''
  _authEndpoint: string = ''
  _tokenEndpoint: string = ''

  get me (): string {
    return this._me
  }

  set me (value: string) {
    validateUrl(value)
    this._me = value
  }

  get clientId (): string {
    return this._clientId
  }

  set clientId (value: string) {
    validateUrl(value)
    this._clientId = value
  }

  get redirectUri (): string {
    return this._redirectUri
  }

  set redirectUri (value: string) {
    validateUrl(value)
    this._redirectUri = value
  }

  get tokenEndpoint (): string {
    return this._tokenEndpoint
  }

  set tokenEndpoint (value: string) {
    validateUrl(value)
    this._tokenEndpoint = value
  }

  get authEndpoint (): string {
    return this._authEndpoint
  }

  set authEndpoint (value: string) {
    validateUrl(value)
    this._authEndpoint = value
  }

  get secret (): string {
    return this._secret
  }

  set secret (value: string) {
    this._secret = value
  }

  get state (): string {
    return this._state
  }

  set state (value: string) {
    this._state = value
  }

  get codeVerifier (): string {
    return this._codeVerifier
  }

  set codeVerifier (value: string) {
    this._codeVerifier = value
  }

  /**
   * Micropub class constructor
   * @param {object} userSettings Settings supplied for this indieAuth client
   */
  constructor (userSettings: Partial<IndieAuthOptions>) {
    const initialOptions = { ...defaultSettings, ...userSettings }

    this.me = initialOptions.me
    this.clientId = initialOptions.clientId
    this.redirectUri = initialOptions.redirectUri
    this.state = initialOptions.state
    this.secret = initialOptions.secret
    this.codeVerifier = initialOptions.codeVerifier
    this.authEndpoint = initialOptions.authEndpoint
    this.tokenEndpoint = initialOptions.tokenEndpoint
  }

  /**
   * Checks to see if the given options are set
   * @param  {array} requirements An array of option keys to check
   * @return {object}             An object with boolean pass property and array missing property listing missing options
   */
  checkRequiredOptions (requirements: Array<keyof IndieAuthOptions>): true {
    const missing = []
    let pass = true
    for (const optionName of requirements) {
      const option = this?.[optionName]
      if (typeof option === 'undefined' || option === '' || option === null) {
        pass = false
        missing.push(optionName)
      }
    }

    if (!pass) {
      throw new IndieAuthError(
        'Missing required options: ' + missing.join(', ')
      )
    }

    return true
  }

  /**
   * Canonicalize the given url according to the rules at
   * https://indieauth.spec.indieweb.org/#url-canonicalization
   * @param  {string} url The url to canonicalize
   * @return {string}     The canonicalized url.
   */
  getCanonicalUrl (url: string): string {
    return new URL(url).href
  }

  /**
   * Fetch a URL, keeping track of 301 redirects to update
   * https://indieauth.spec.indieweb.org/#redirect-examples
   * @param  {string} url The url to scrape
   * @return {Promise}    Passes the fetch response object and the "final" url.
   */
  async getUrlWithRedirects (url: string): Promise<any> {
    const getRedirectUrl = (to: string, from: string): string => {
      if (!to.startsWith('http')) {
        return new URL(to, from).toString()
      } else {
        return to
      }
    }

    try {
      const res = await fetch(url, {
        method: 'GET',
        redirect: 'error',
        headers: {
          accept: 'text/html,application/xhtml+xml'
        }
      })

      const resText = await res.text()

      return { url, response: resText }
    } catch (err: any) {
      console.warn('Error getting url with redirects', err)

      // TODO: This won't work.
      if (err?.response !== null) {
        const res = err.response
        if (res.status === 301 || res.status === 308) {
          // Permanent redirect means we use this new url as canonical so, recurse on the new url!
          const redirectUrl = getRedirectUrl(res.headers.location, url)
          const { response: redirectRes, url: followUrl } =
            await this.getUrlWithRedirects(redirectUrl)
          return { url: followUrl, response: redirectRes }
        } else if (res.status === 302 || res.status === 307) {
          // Temporary redirect means we use the new url for discovery, but don't treat it as canonical
          const redirectUrl = getRedirectUrl(res.headers.location, url)
          const tmp = await this.getUrlWithRedirects(redirectUrl)
          if (tmp.response.status > 199 && tmp.response.status < 300) {
            return { response: tmp.response, url }
          }

          // TODO: Pass more error data
          throw new IndieAuthError(
            'Error following redirects for ' + url,
            tmp?.response?.status
            // tmp.response
          )
        }
      }
      // TODO: Pass more error data
      throw new IndieAuthError(
        'Error getting ' + url,
        err?.response?.status
        // err
      )
    }
  }

  /**
   * Get the various endpoints needed from the given url
   * @param  {string} url The url to scrape
   * @param  {array}  extraRels An array of extra rels to try and parse from the url. Everything is normalized to lowercase
   * @return {Promise}    Passes an object of endpoints on success: `authorization_endpoint`, `token_endpoint` and any extras.
   *                      If a requested rel was not found it will have a null value.
   *                      Note: Will only pass the first value of any rel if there are multiple results.
   * TODO: should return a better type
   */
  async getRelsFromUrl (url: string, extraRels: string[] = []): Promise<any> {
    url = this.getCanonicalUrl(url)
    try {
      const toFind = ['authorization_endpoint', 'token_endpoint', ...extraRels]

      const { response: res, url: finalUrl } = await this.getUrlWithRedirects(
        url
      )
      this.me = finalUrl
      // Get rel links
      const rels = await relScraper(finalUrl, res.data, res.headers)

      const foundRels: any = {}

      for (const key of toFind) {
        foundRels[key] = rels?.[key]?.[0] ?? null
      }

      if (typeof foundRels.authorization_endpoint === 'undefined') {
        throw new IndieAuthError('No authorization endpoint found')
      }

      this.authEndpoint = foundRels.authorization_endpoint

      if (typeof foundRels.token_endpoint !== 'undefined') {
        this.tokenEndpoint = foundRels.token_endpoint
      }

      return foundRels
    } catch (err: any) {
      throw new IndieAuthError(
        'Error getting rels from url',
        err?.response?.status
        // err
      )
    }
  }

  /**
   * Exchanges a code for an access token
   * @param {string} code A code received from the auth endpoint
   * @return {Promise} Promise which resolves with the access token on success
   */
  async getToken (code: string): Promise<string> {
    this.checkRequiredOptions([
      'me',
      'clientId',
      'redirectUri',
      'tokenEndpoint'
    ])

    try {
      const data: any = {
        grant_type: 'authorization_code',
        me: this.me,
        code,
        client_id: this.clientId,
        redirect_uri: this.redirectUri
      }

      // Add PKCE code verifier if it is set
      if (typeof this.codeVerifier !== 'undefined') {
        data.code_verifier = this.codeVerifier
      }

      const res = await fetch(this.tokenEndpoint, {
        method: 'POST',
        body: qsStringify(data),
        headers: {
          'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
          accept: 'application/json, application/x-www-form-urlencoded'
        }
      })

      // Figure out the type of the response.
      let result: any = null
      const headers = res.headers.get('content-type')
      if (headers?.includes('application/json') === true) {
        result = await res.json()
      } else {
        result = await res.text()
      }

      // Parse the response from the indieauth server
      if (typeof result === 'string') {
        result = qsParse(result)
      }
      if (
        typeof result.error_description !== 'undefined' &&
        result.error_description !== ''
      ) {
        throw new IndieAuthError(result.error_description)
      } else if (result?.error !== 'undefined' && result.error !== '') {
        throw new IndieAuthError(result.error)
      }
      if (
        result?.me === 'undefined' ||
        result?.scope === 'undefined' ||
        result?.access_token === 'undefined'
      ) {
        throw new IndieAuthError(
          'The token endpoint did not return the expected parameters'
        )
      }
      // Check "me" values have the same hostname
      const urlResult = new URL(result.me)
      const urlOptions = new URL(this.me)
      if (urlResult.hostname !== urlOptions.hostname) {
        throw new IndieAuthError('The me values do not share the same hostname')
      }
      // Successfully got the token
      return result.access_token
    } catch (err: any) {
      throw new IndieAuthError(
        'Error requesting token endpoint',
        err?.response?.status
        // err
      )
    }
  }

  /**
   * Get the authentication url based on the set options
   * @param {string} responseType The response type expected from the auth endpoint. Usually `code` or `id`. Defaults to `id`
   * @param {array} scopes An array of scopes to send to the auth endpoint.
   * @return {Promise} Passes the authentication url on success
   */
  async getAuthUrl (
    responseType: string = 'id',
    scopes: string[] = []
  ): Promise<string> {
    this.autoGenerateState()
    this.checkRequiredOptions(['me', 'state'])
    if (responseType === 'code' && scopes.length === 0) {
      // If doing code auth you also need scopes.
      throw new IndieAuthError(
        'You need to provide some scopes when using response type "code"'
      )
    }
    try {
      if (
        typeof this.authEndpoint === 'undefined' ||
        this.authEndpoint === ''
      ) {
        await this.getRelsFromUrl(this.me)
      }

      this.checkRequiredOptions([
        'me',
        'state',
        'clientId',
        'redirectUri',
        'authEndpoint'
      ])

      const authUrl = new URL(this.authEndpoint)
      authUrl.searchParams.append('me', this.me)
      authUrl.searchParams.append('client_id', this.clientId)
      authUrl.searchParams.append('redirect_uri', this.redirectUri)
      authUrl.searchParams.append('response_type', responseType)
      authUrl.searchParams.append('state', this.state)

      if (scopes.length > 0) {
        authUrl.searchParams.append('scope', scopes.join(' '))
      }

      // Add a PKCE code challenge if a code verifier is set.
      if (
        responseType === 'code' &&
        typeof this.codeVerifier !== 'undefined' &&
        this.codeVerifier !== ''
      ) {
        const hashedVerifier = CryptoJS.SHA256(this.codeVerifier).toString()
        const codeChallenge = encodeURIComponent(hashedVerifier)
        authUrl.searchParams.append('code_challenge_method', 'S256')
        authUrl.searchParams.append('code_challenge', codeChallenge)
      }

      return authUrl.toString()
    } catch (err) {
      throw new IndieAuthError('Error getting auth url', undefined /*, err */)
    }
  }

  /**
   * Verify that a code is valid with the auth endpoint.
   * @param {string} code The code to verify
   * @returns {Promise} If the code is valid then the promise is resolved with the `me` value
   */
  async verifyCode (code: string): Promise<string> {
    this.checkRequiredOptions(['me', 'clientId', 'redirectUri', 'authEndpoint'])

    try {
      const postData = {
        code,
        client_id: this.clientId,
        redirect_uri: this.redirectUri
      }

      const res = await fetch(this.authEndpoint, {
        method: 'POST',
        body: qsStringify(postData),
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          Accept: 'application/json, application/x-www-form-urlencoded'
        }
      })

      if (res.status < 200 || res.status > 299) {
        throw new IndieAuthError('Error verifying code', res.status /* res */)
      }

      let data: any = null
      const headers = res.headers.get('content-type')
      if (headers?.includes('application/json') === true) {
        data = await res.json()
      } else {
        data = await res.text()
      }

      if (typeof data === 'string') {
        data = qsParse(data)
      }
      if (data?.error_description !== 'undefined') {
        throw new IndieAuthError(data.error_description)
      } else if (data?.error !== 'undefined') {
        throw new IndieAuthError(data.error)
      }
      if (data?.me === 'undefined') {
        throw new IndieAuthError(
          'The auth endpoint did not return the "me" parameter while verifying the code'
        )
      }
      // Check me is the same (removing any trailing slashes)
      if (
        data.me !== 'undefined' &&
        data.me.replace(/\/+$/, '') !== this.me.replace(/\/+$/, '')
      ) {
        throw new IndieAuthError('The me values did not match')
      }

      if (this.me === '') {
        this.me = data.me
      }

      return data.me
    } catch (err) {
      throw new IndieAuthError('Error verifying authorization code')
    }
  }

  /**
   * Verify the stored access token
   * @param {string} The token to verify
   * @return {Promise} A promise that resolves true or rejects
   */
  async verifyToken (token: string): Promise<boolean> {
    this.checkRequiredOptions(['authEndpoint'])

    try {
      const res = await fetch(this.authEndpoint, {
        method: 'GET',
        headers: {
          Authorization: 'Bearer ' + token
        }
      })

      if (res.status === 200) {
        return true
      }

      throw new Error()
    } catch (err: any) {
      throw new IndieAuthError(
        'Error verifying token',
        err?.response?.status
        // err
      )
    }
  }

  /**
   * Generates a unique, encrypted state value that doesn't need to be cached
   * @returns {string} A state string
   */
  generateState (): string {
    this.checkRequiredOptions(['secret', 'me', 'clientId'])

    const state = generateState(this.me, this.clientId, this.secret)

    return state
  }

  /**
   * Uses `generateState` to set the `this.state` property if required
   */
  autoGenerateState (): void {
    try {
      if (this.state === '') {
        this.state = this.generateState()
      }
    } catch (err) {
      // Something is missing to generate the state, but no need to throw an error.
    }
  }

  /**
   * Validates a state string that was generated with the `generateState` method
   * @param {string} state The state string
   * @returns {object|false} If successful it will return the validated state option. Which has `date`, `me` and `clientId` properties. Returns false on failure.
   */
  validateState (state: string): object | false {
    this.checkRequiredOptions(['secret', 'clientId'])
    try {
      const stateObj = validateState(state, this.me, this.clientId, this.secret)
      if (this.me === '') {
        this.me = stateObj.me
      }
      return stateObj
    } catch (err) {
      return false
    }
  }

  /**
   * Generates a cryptographically random string
   * @param {int} length The character count of the random string. Defaults to 100. (NOTE: Will round up to an even number)
   * @returns {string} The random string
   */
  generateRandomString (length: number = 100): string {
    // Create a random word array and convert it to a string
    // 1 word = 2 characters
    const wordArray = CryptoJS.lib.WordArray.random(Math.round(length / 2))
    return wordArray.toString()
  }
}

export { IndieAuth }
export default IndieAuth
