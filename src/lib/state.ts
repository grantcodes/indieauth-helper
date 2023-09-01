import CryptoJS from 'crypto-js'

interface IndieAuthState {
  date: number
  me: string
  clientId: string
}

const TIMEOUT = 1000 * 60 * 10 // 10 minutes

/**
 * Generates a unique, encrypted state value that doesn't need to be cached
 */
const generateState = (
  clientId: string,
  secret: string,
  me: string
): string => {
  const state: IndieAuthState = {
    date: Date.now(),
    me,
    clientId
  }

  const stateJson = JSON.stringify(state)

  return CryptoJS.AES.encrypt(stateJson, secret).toString()
}

const validateState = (
  state: string,
  clientId: string,
  secret: string,
  me?: string
): IndieAuthState => {
  const stateJson = CryptoJS.AES.decrypt(state, secret).toString(
    CryptoJS.enc.Utf8
  )
  const stateObj = JSON.parse(stateJson)
  const keys = Object.keys(stateObj)

  if (
    !keys.includes('date') ||
    !keys.includes('me') ||
    !keys.includes('clientId')
  ) {
    throw new Error('State is missing required properties')
  }

  if (
    typeof stateObj.date !== 'number' ||
    typeof stateObj.me !== 'string' ||
    typeof stateObj.clientId !== 'string'
  ) {
    throw new Error('State has invalid property types')
  }

  if (stateObj.date < Date.now() - TIMEOUT) {
    throw new Error('State has expired')
  }

  if (typeof me !== 'undefined' && stateObj.me !== me) {
    throw new Error('State me does not match')
  }

  if (stateObj.clientId !== clientId) {
    throw new Error('State clientId does not match')
  }

  return stateObj
}

export { generateState, validateState }
