import test from 'ava'
import { IndieAuth } from '../main'
import { IndieAuthOptions } from '../types'
import { IndieAuthError } from '../lib/indieauth-error'

const TEST_OPTIONS: IndieAuthOptions = {
  me: 'https://example.com',
  clientId: 'https://client.example.com',
  redirectUri: 'https://client.example.com/redirect',
  state: '1234',
  codeVerifier: '1234',
  secret: '1234',
  authEndpoint: 'https://example.com/auth',
  tokenEndpoint: 'https://example.com/token'
}

test('getters and setters', t => {
  const indieAuth = new IndieAuth(TEST_OPTIONS)

  // Test everything is set correctly from the constructor
  t.is(indieAuth.me, TEST_OPTIONS.me)
  t.is(indieAuth.clientId, TEST_OPTIONS.clientId)
  t.is(indieAuth.redirectUri, TEST_OPTIONS.redirectUri)
  t.is(indieAuth.state, TEST_OPTIONS.state)
  t.is(indieAuth.codeVerifier, TEST_OPTIONS.codeVerifier)
  t.is(indieAuth.secret, TEST_OPTIONS.secret)
  t.is(indieAuth.authEndpoint, TEST_OPTIONS.authEndpoint)
  t.is(indieAuth.tokenEndpoint, TEST_OPTIONS.tokenEndpoint)

  // Test that setters work individually
  indieAuth.me = 'https://example2.com'
  t.is(indieAuth.me, 'https://example2.com')
  indieAuth.clientId = 'https://client2.example.com'
  t.is(indieAuth.clientId, 'https://client2.example.com')
  indieAuth.redirectUri = 'https://client2.example.com/redirect'
  t.is(indieAuth.redirectUri, 'https://client2.example.com/redirect')
  indieAuth.state = '5678'
  t.is(indieAuth.state, '5678')
  indieAuth.codeVerifier = '5678'
  t.is(indieAuth.codeVerifier, '5678')
  indieAuth.secret = '5678'
  t.is(indieAuth.secret, '5678')
  indieAuth.authEndpoint = 'https://example2.com/auth'
  t.is(indieAuth.authEndpoint, 'https://example2.com/auth')
  indieAuth.tokenEndpoint = 'https://example2.com/token'
  t.is(indieAuth.tokenEndpoint, 'https://example2.com/token')

  // Test that setters reject invalid values
  t.throws(() => (indieAuth.me = 'example.com'))
  t.throws(() => (indieAuth.clientId = 'example.com'))
  t.throws(() => (indieAuth.redirectUri = 'example.com'))
  t.throws(() => (indieAuth.authEndpoint = 'example.com'))
})

test('checkRequiredOptions', t => {
  const indieAuth = new IndieAuth(TEST_OPTIONS)

  // Should be fine if everything is set
  t.notThrows(() =>
    indieAuth.checkRequiredOptions([
      'me',
      'clientId',
      'redirectUri',
      'state',
      'codeVerifier',
      'secret',
      'authEndpoint',
      'tokenEndpoint'
    ])
  )

  indieAuth.state = ''
  t.throws(() => indieAuth.checkRequiredOptions(['state']), {
    instanceOf: IndieAuthError,
    message: 'Missing required options: state'
  })
})
