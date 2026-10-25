import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { signState, verifyState } from "../../lib/state.js";
import { IndieAuth, IndieAuthError } from "../../main.js";

const me = "https://user.example/";
const clientId = "https://client.example/";
const secret = "test-secret";

describe("signed state", () => {
	it("round-trips a payload", async () => {
		const payload = { date: Date.now(), me, clientId };
		const state = await signState(payload, secret);
		assert.deepEqual(await verifyState(state, secret), payload);
	});

	it("rejects a tampered state", async () => {
		const state = await signState({ date: Date.now(), me, clientId }, secret);
		const replacement = state.endsWith("a") ? "b" : "a";
		assert.equal(
			await verifyState(`${state.slice(0, -1)}${replacement}`, secret),
			null,
		);
	});

	it("rejects a state signed with a different secret", async () => {
		const state = await signState({ date: Date.now(), me, clientId }, secret);
		assert.equal(await verifyState(state, "other-secret"), null);
	});

	it("rejects malformed states", async () => {
		assert.equal(await verifyState("not-a-state", secret), null);
		assert.equal(await verifyState("a.b", secret), null);
	});
});

describe("IndieAuth state", () => {
	it("generates and validates a state", async () => {
		const auth = new IndieAuth({ me, clientId, secret });
		const state = await auth.generateState();
		const payload = await auth.validateState(state);

		assert.equal(payload.clientId, clientId);
		assert.equal(payload.me, me);
		assert.ok(payload.date <= Date.now());
	});

	it("rejects a state issued for a different client", async () => {
		const issuer = new IndieAuth({ me, clientId, secret });
		const state = await issuer.generateState();
		const other = new IndieAuth({
			me,
			clientId: "https://other.example/",
			secret,
		});

		await assert.rejects(() => other.validateState(state), /different client/);
	});

	it("rejects an expired state", async () => {
		const auth = new IndieAuth({ me, clientId, secret });
		const state = await signState(
			{ date: Date.now() - 20 * 60 * 1000, me, clientId },
			secret,
		);

		await assert.rejects(() => auth.validateState(state), /expired/);
	});

	it("rejects a state from the future", async () => {
		const auth = new IndieAuth({ me, clientId, secret });
		const state = await signState(
			{ date: Date.now() + 2 * 60 * 1000, me, clientId },
			secret,
		);

		await assert.rejects(() => auth.validateState(state), /expired/);
	});

	it("rejects a state signed with the wrong secret", async () => {
		const auth = new IndieAuth({ me, clientId, secret });
		const state = await signState({ date: Date.now(), me, clientId }, "wrong");

		await assert.rejects(() => auth.validateState(state), /not valid/);
	});
});

describe("validateAuthorizationResponse", () => {
	it("accepts matching state and issuer", async () => {
		const auth = new IndieAuth({
			me,
			clientId,
			state: "custom-state",
			issuer: "https://issuer.example/",
		});

		const result = await auth.validateAuthorizationResponse({
			code: "auth-code",
			state: "custom-state",
			iss: "https://issuer.example/",
		});

		assert.deepEqual(result, {
			code: "auth-code",
			state: "custom-state",
			iss: "https://issuer.example/",
		});
	});

	it("accepts a generated signed state", async () => {
		const auth = new IndieAuth({ me, clientId, secret });
		const state = await auth.generateState();

		const result = await auth.validateAuthorizationResponse({
			code: "auth-code",
			state,
		});

		assert.equal(result.code, "auth-code");
	});

	it("rejects a mismatched state", async () => {
		const auth = new IndieAuth({
			me,
			clientId,
			state: "custom-state",
		});

		await assert.rejects(
			() =>
				auth.validateAuthorizationResponse({
					code: "auth-code",
					state: "other-state",
				}),
			/state is not valid/,
		);
	});

	it("requires state", async () => {
		const auth = new IndieAuth({ me, clientId });
		await assert.rejects(
			() =>
				auth.validateAuthorizationResponse({
					code: "auth-code",
				}),
			/Missing state/,
		);
	});

	it("requires the issuer when one is known", async () => {
		const auth = new IndieAuth({
			me,
			clientId,
			state: "custom-state",
			issuer: "https://issuer.example/",
		});

		await assert.rejects(
			() =>
				auth.validateAuthorizationResponse({
					code: "auth-code",
					state: "custom-state",
				}),
			/Missing iss/,
		);
	});

	it("rejects a mismatched issuer", async () => {
		const auth = new IndieAuth({
			me,
			clientId,
			state: "custom-state",
			issuer: "https://issuer.example/",
		});

		await assert.rejects(
			() =>
				auth.validateAuthorizationResponse({
					code: "auth-code",
					state: "custom-state",
					iss: "https://other.example/",
				}),
			/does not match/,
		);
	});

	it("throws the error returned by the authorization server", async () => {
		const auth = new IndieAuth({
			me,
			clientId,
			state: "custom-state",
		});

		try {
			await auth.validateAuthorizationResponse({
				state: "custom-state",
				error: "access_denied",
				error_description: "The user denied the request",
			});
			assert.fail("Expected the response to be rejected");
		} catch (err: unknown) {
			assert.ok(err instanceof IndieAuthError);
			assert.equal(err.message, "The user denied the request");
		}
	});

	it("requires a code on success", async () => {
		const auth = new IndieAuth({
			me,
			clientId,
			state: "custom-state",
		});

		await assert.rejects(
			() =>
				auth.validateAuthorizationResponse({
					state: "custom-state",
				}),
			/Missing code/,
		);
	});
});
