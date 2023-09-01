class IndieAuthError extends Error {
  statusCode: number | null = null

  constructor (message: string, statusCode?: number) {
    super(message)
    this.name = 'IndieAuthError'
    this.statusCode = statusCode ?? null
  }
}

export { IndieAuthError }
