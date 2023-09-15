import test from 'ava'
import { validateUrl } from '../../lib/validate-url'

test('valid url', t => {
  t.true(validateUrl('https://example.com'))
})

test('invalid url', t => {
  t.throws(() => validateUrl('example.com'))
  t.throws(() => validateUrl('ftp://user:pass@example.com'))
  t.throws(() => validateUrl('htt://example.com'))
  t.throws(() => validateUrl('http://[::1'))
  t.throws(() => validateUrl('http://ex ample.com'))
  t.throws(() => validateUrl('http://example.com^'))
  t.throws(() => validateUrl('/example'))
})
