import test from 'ava'
import { IndieAuthError } from '../../lib/indieauth-error'

test('no status code', (t) => {
  const err = new IndieAuthError('test')
  t.is(err.message, 'test')
  t.is(err.statusCode, null)
})

test('with status code', (t) => {
  const err = new IndieAuthError('test', 500)
  t.is(err.message, 'test')
  t.is(err.statusCode, 500)
})
