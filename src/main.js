const axios = require('axios')
const relScraper = require('rel-parser')
const CryptoJS = require('crypto-js')
const { parse: qsParse, stringify: qsStringify } = require('qs')

const defaultSettings = {
  me: '',
  token: '',
  authEndpoint: '',
  tokenEndpoint: '',
}

/**
 * Creates an error object
 * @param {string} message A human readable error message
 * @param {int} status A http response status from the indieAuth endpoint
 * @param {object} error A full error object if available
 * @return {object} A consistently formatted error object
 */
const indieAuthError = (message, status = null, error = null) => {
  if (error.message && error.error) {
    // Don't want to have nested errors.
    error = error.error
    message = error.message
  }
  return { message, status, error }
}

/**
 * A indieAuth helper class
 */
class IndieAuth {
  /**
   * Micropub class constructor
   * @param {object} userSettings Settings supplied for this indieAuth client
   */
  constructor(userSettings = {}) {
    this.options = Object.assign({}, defaultSettings, userSettings)

    // Bind all the things
    this.checkRequiredOptions = this.checkRequiredOptions.bind(this)
    this.getAuthUrl = this.getAuthUrl.bind(this)
    this.getRelsFromUrl = this.getRelsFromUrl.bind(this)
    this.verifyCode = this.verifyCode.bind(this)
    this.getToken = this.getToken.bind(this)
    this.generateState = this.generateState.bind(this)
    this.autoGenerateState = this.autoGenerateState.bind(this)
    this.validateState = this.validateState.bind(this)
  }

  /**
   * Checks to see if the given options are set
   * @param  {array} requirements An array of option keys to check
   * @return {object}             An object with boolean pass property and array missing property listing missing options
   */
  checkRequiredOptions(requirements) {
    let missing = []
    let pass = true
    for (const optionName of requirements) {
      const option = this.options[optionName]
      if (!option) {
        pass = false
        missing.push(optionName)
      }
    }

    if (!pass) {
      throw indieAuthError('Missing required options: ' + missing.join(', '))
    }

    return true
  }

  /**
   * Canonicalize the given url according to the rules at
   * https://indieauth.spec.indieweb.org/#url-canonicalization
   * @param  {string} url The url to canonicalize
   * @return {string}     The canonicalized url.
   */
  getCanonicalUrl(url) {
    return new URL(url).href
  }

  /**
   * Fetch a URL, keeping track of 301 redirects to update
   * https://indieauth.spec.indieweb.org/#redirect-examples
   * @param  {string} url The url to scrape
   * @return {Promise}    Passes the axios response object and the "final" url.
   */
  async getUrlWithRedirects(url) {
    const request = {
      url,
      method: 'GET',
      responseType: 'text',
      maxRedirects: 0,
    }

    const getRedirectUrl = (to, from) => {
      if (!to.startsWith('http')) {
        return new URL(to, from).toString()
      } else {
        return to
      }
    }

    try {
      const res = await axios(request)
      return { url, response: res }
    } catch (err) {
      if (err.response) {
        const res = err.response
        if (res.status === 301 || res.status === 308) {
          // Permanent redirect means we use this new url as canonical so, recurse on the new url!
          const redirectUrl = getRedirectUrl(res.headers.location, url)
          const {
            response: redirectRes,
            url: followUrl,
          } = await this.getUrlWithRedirects(redirectUrl)
          return { url: followUrl, response: redirectRes }
        } else if (res.status === 302 || res.status === 307) {
          // Temporary redirect means we use the new url for discovery, but don't treat it as canonical
          const redirectUrl = getRedirectUrl(res.headers.location, url)
          const tmp = await this.getUrlWithRedirects(redirectUrl)
          if (tmp.response.status > 199 && tmp.response.status < 300) {
            return { response: tmp.response, url }
          }
          throw indieAuthError(
            'Error following redirects for ' + url,
            tmp && tmp.response && tmp.response.status
              ? tmp.response.status
              : null,
            tmp.response
          )
        }
      }
      throw indieAuthError(
        'Error getting ' + url,
        err && err.response ? err.response.status : null,
        err
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
   */
  async getRelsFromUrl(url, extraRels = []) {
    url = this.getCanonicalUrl(url)
    try {
      const toFind = ['authorization_endpoint', 'token_endpoint', ...extraRels]

      const { response: res, url: finalUrl } = await this.getUrlWithRedirects(
        url
      )
      this.options.me = finalUrl
      // Get rel links
      const rels = await relScraper(finalUrl, res.data, res.headers)

      const foundRels = {}

      if (rels) {
        for (const key of toFind) {
          foundRels[key] = rels[key] && rels[key][0] ? rels[key][0] : null
        }
      }

      if (!foundRels.authorization_endpoint) {
        throw indieAuthError('No authorization endpoint found')
      }

      this.options.authEndpoint = foundRels.authorization_endpoint

      if (foundRels.token_endpoint) {
        this.options.tokenEndpoint = foundRels.token_endpoint
      }

      return foundRels
    } catch (err) {
      throw indieAuthError(
        'Error getting rels from url',
        err && err.response ? err.response.status : null,
        err
      )
    }
  }

  /**
   * Exchanges a code for an access token
   * @param {string} code A code received from the auth endpoint
   * @return {Promise} Promise which resolves with the access token on success
   */
  async getToken(code) {
    this.checkRequiredOptions([
      'me',
      'clientId',
      'redirectUri',
      'tokenEndpoint',
    ])

    try {
      const data = {
        grant_type: 'authorization_code', // TODO: Should this be customizable somehow?
        me: this.options.me,
        code: code,
        client_id: this.options.clientId,
        redirect_uri: this.options.redirectUri,
      }

      const request = {
        url: this.options.tokenEndpoint,
        method: 'POST',
        data: qsStringify(data),
        headers: {
          'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
          accept: 'application/json, application/x-www-form-urlencoded',
        },
      }
      // This could maybe use the postMicropub method
      const res = await axios(request)
      let result = res.data
      // Parse the response from the indieauth server
      if (typeof result === 'string') {
        result = qsParse(result)
      }
      if (result.error_description) {
        throw indieAuthError(result.error_description)
      } else if (result.error) {
        throw indieAuthError(result.error)
      }
      if (!result.me || !result.scope || !result.access_token) {
        throw indieAuthError(
          'The token endpoint did not return the expected parameters'
        )
      }
      // Check "me" values have the same hostname
      let urlResult = new URL(result.me)
      let urlOptions = new URL(this.options.me)
      if (urlResult.hostname != urlOptions.hostname) {
        throw indieAuthError('The me values do not share the same hostname')
      }
      // Successfully got the token
      this.options.token = result.access_token
      return result.access_token
    } catch (err) {
      throw indieAuthError(
        'Error requesting token endpoint',
        err.response.status,
        err
      )
    }
  }

  /**
   * Get the authentication url based on the set options
   * @param {string} responseType The response type expected from the auth endpoint. Usually `code` or `id`. Defaults to `id`
   * @param {array} scopes An array of scopes to send to the auth endpoint.
   * @return {Promise} Passes the authentication url on success
   */
  async getAuthUrl(responseType = 'id', scopes = []) {
    this.autoGenerateState()
    this.checkRequiredOptions(['me', 'state'])
    if (responseType === 'code' && scopes.length === 0) {
      // If doing code auth you also need scopes.
      throw indieAuthError(
        'You need to provide some scopes when using response type "code"'
      )
    }
    try {
      if (!this.options.authEndpoint) {
        await this.getRelsFromUrl(this.options.me)
      }

      this.checkRequiredOptions([
        'me',
        'state',
        'clientId',
        'redirectUri',
        'authEndpoint',
      ])

      const authUrl = new URL(this.options.authEndpoint)
      authUrl.searchParams.append('me', this.options.me)
      authUrl.searchParams.append('client_id', this.options.clientId)
      authUrl.searchParams.append('redirect_uri', this.options.redirectUri)
      authUrl.searchParams.append('response_type', responseType)
      authUrl.searchParams.append('state', this.options.state)

      if (scopes.length) {
        authUrl.searchParams.append('scope', scopes.join(' '))
      }

      return authUrl.toString()
    } catch (err) {
      throw indieAuthError('Error getting auth url', null, err)
    }
  }

  /**
   * Verify that a code is valid with the auth endpoint.
   * @param {string} code The code to verify
   * @returns {Promise} If the code is valid then the promise is resolved with the `me` value
   */
  async verifyCode(code) {
    this.checkRequiredOptions(['me', 'clientId', 'redirectUri', 'authEndpoint'])

    const data = {
      code,
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
    }

    const request = {
      url: this.options.authEndpoint,
      method: 'POST',
      data: qsStringify(data),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        Accept: 'application/json, application/x-www-form-urlencoded',
      },
    }

    try {
      const res = await axios(request)
      if (res.status < 200 || res.status > 299) {
        throw new Error('Error verifying code', res.status, res)
      }
      let { data } = res
      if (typeof data === 'string') {
        data = qsParse(data)
      }
      if (data.error_description) {
        throw indieAuthError(data.error_description)
      } else if (data.error) {
        throw indieAuthError(data.error)
      }
      if (!data.me) {
        throw indieAuthError(
          'The auth endpoint did not return the "me" parameter while verifying the code'
        )
      }
      // Check me is the same (removing any trailing slashes)
      if (
        data.me &&
        data.me.replace(/\/+$/, '') !== this.options.me.replace(/\/+$/, '')
      ) {
        throw indieAuthError('The me values did not match')
      }

      if (!this.options.me) {
        this.options.me = data.me
      }

      return data.me
    } catch (err) {
      throw indieAuthError('Error verifying authorization code')
    }
  }

  /**
   * Verify the stored access token
   * @return {Promise} A promise that resolves true or rejects
   */
  async verifyToken() {
    this.checkRequiredOptions(['token', 'indieAuthEndpoint'])

    try {
      const request = {
        url: this.options.indieAuthEndpoint,
        method: 'GET',
        headers: {
          Authorization: 'Bearer ' + this.options.token,
        },
      }

      const res = await axios(request)
      if (res.status === 200) {
        return true
      }
      throw res
    } catch (err) {
      throw indieAuthError(
        'Error verifying token',
        err && err.response ? err.response.status : null,
        err
      )
    }
  }

  /**
   * Generates a unique, encrypted state value that doesn't need to be cached
   * @returns {string} A state string
   */
  generateState() {
    this.checkRequiredOptions(['secret', 'me', 'clientId'])
    let state = {
      date: Date.now(),
      me: this.options.me,
      clientId: this.options.clientId,
    }
    state = CryptoJS.AES.encrypt(
      JSON.stringify(state),
      this.options.secret
    ).toString()
    return state
  }

  /**
   * Uses `generateState` to set the `this.options.state` property if required
   */
  autoGenerateState() {
    try {
      if (!this.options.state) {
        this.checkRequiredOptions(['secret', 'me', 'clientId'])
        this.options.state = this.generateState()
      }
      return
    } catch (err) {
      // Something is missing to generate the state, but no need to throw an error.
      return
    }
  }

  /**
   * Validates a state string that was generated with the `generateState` method
   * @param {string} state The state string
   * @returns {object|false} If successful it will return the validated state option. Which has `date`, `me` and `clientId` properties. Returns false on failure.
   */
  validateState(state) {
    this.checkRequiredOptions(['secret', 'clientId'])
    try {
      state = JSON.parse(
        CryptoJS.AES.decrypt(state, this.options.secret).toString(
          CryptoJS.enc.Utf8
        )
      )
      if (
        state.clientId === this.options.clientId &&
        state.date > Date.now() - 1000 * 60 * 10 &&
        state.me
      ) {
        if (!this.options.me) {
          this.options.me = state.me
        }
        return state
      } else {
        throw 'State is invalid'
      }
    } catch (err) {
      return false
    }
  }
}

module.exports = IndieAuth
