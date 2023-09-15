interface IndieAuthOptions {
  me: string
  clientId: string
  redirectUri: string
  state: string
  secret: string
  codeVerifier: string
  authEndpoint: string
  tokenEndpoint: string
}

export type { IndieAuthOptions }
