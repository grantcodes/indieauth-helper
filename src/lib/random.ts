const PKCE_CHARSET =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

export function randomString(length = 64, charset = PKCE_CHARSET): string {
	if (!Number.isInteger(length) || length < 1) {
		throw new TypeError("Length must be a positive integer");
	}

	if (charset.length < 2 || charset.length > 256) {
		throw new TypeError("Charset must contain between 2 and 256 characters");
	}

	const result: string[] = [];
	const limit = 256 - (256 % charset.length);

	while (result.length < length) {
		const bytes = crypto.getRandomValues(
			new Uint8Array(length - result.length),
		);
		for (const byte of bytes) {
			if (byte >= limit) {
				continue;
			}

			result.push(charset[byte % charset.length]);
			if (result.length === length) {
				break;
			}
		}
	}

	return result.join("");
}
