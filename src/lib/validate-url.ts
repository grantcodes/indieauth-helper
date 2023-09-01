const validateUrl = (url: string): true => {
  try {
    // TODO: Ignore this.
    new URL(url)
    return true
  } catch (err) {
    throw new TypeError('Invalid URL')
  }
}

export { validateUrl }
