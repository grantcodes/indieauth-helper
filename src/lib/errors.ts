export class IndieAuthError extends Error {
	readonly status: number | null;
	readonly error: unknown;

	constructor(
		message: string,
		status: number | null = null,
		error: unknown = null,
	) {
		super(message);
		this.name = "IndieAuthError";
		this.status = status;
		this.error = error;
	}
}

export function toIndieAuthError(
	err: unknown,
	fallback: string,
): IndieAuthError {
	if (err instanceof IndieAuthError) {
		return err;
	}

	if (err instanceof Error) {
		return new IndieAuthError(err.message, null, err);
	}

	return new IndieAuthError(fallback, null, err);
}
