import test from 'ava'
import { mock } from 'node:test'
import { generateState, validateState } from '../../lib/state'

const CLIENT = 'https://client.example.com'
const ME = 'https://example.com'
const SECRET = 'secret'

test('generate and validate state', (t) => {
  const state = generateState(CLIENT, SECRET, ME)
  const validated = validateState(state, CLIENT, SECRET, ME)
  t.true(typeof state === 'string')
  t.is(validated.clientId, CLIENT)
  t.is(validated.me, ME)
  t.is(typeof validated.date, 'number')
  t.true(validated.date <= Date.now())
})

test('expired state', (t) => {
  const state = generateState(CLIENT, SECRET, ME)
  const startTime = Date.now()
  mock.method(Date, 'now', () => startTime + 1100 * 60 * 60 * 24 * 7)
  t.throws(() => validateState(state, CLIENT, SECRET, ME), {
    instanceOf: Error,
    message: 'State has expired'
  })
})

test('mismatched client', (t) => {
  const state = generateState(CLIENT, SECRET, ME)
  t.throws(
    () => validateState(state, 'https://client2.example.com', SECRET, ME),
    {
      instanceOf: Error,
      message: 'State clientId does not match'
    }
  )
})

test('mismatched me', (t) => {
  const state = generateState(CLIENT, SECRET, ME)
  t.throws(
    () => validateState(state, CLIENT, SECRET, 'https://not-example.com'),
    {
      instanceOf: Error,
      message: 'State me does not match'
    }
  )
})

test('mismatched secret', (t) => {
  const state = generateState(CLIENT, SECRET, ME)
  t.throws(() => validateState(state, CLIENT, 'bassectret', ME), {
    instanceOf: Error
  })
})

test('invalid state', (t) => {
  t.throws(() => validateState('invalid', CLIENT, SECRET, ME))
})
