const validateUrl = (url: string): true => {
  try {
    const res = new URL(url) // eslint-disable-line

    // Only allow http and https protocols.
    if (res.protocol !== 'http:' && res.protocol !== 'https:') {
      throw new Error('Invalid protocol')
    }
    return true
  } catch (err) {
    throw new TypeError('Invalid URL')
  }
}

export { validateUrl }
