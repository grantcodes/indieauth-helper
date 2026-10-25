import {
	createServer,
	type IncomingMessage,
	type ServerResponse,
} from "node:http";

export type ServerHandler = (
	request: IncomingMessage,
	response: ServerResponse,
) => void;

export interface TestServer {
	url: string;
	close: () => Promise<void>;
}

export async function startServer(handler: ServerHandler): Promise<TestServer> {
	const server = createServer(handler);

	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});

	const address = server.address();
	if (!address || typeof address === "string") {
		throw new Error("Test server did not expose a TCP address");
	}

	return {
		url: `http://127.0.0.1:${address.port}`,
		close: () =>
			new Promise<void>((resolve, reject) => {
				server.close((err) => {
					if (err) {
						reject(err);
						return;
					}
					resolve();
				});
			}),
	};
}

export async function readBody(request: IncomingMessage): Promise<string> {
	const chunks: Buffer[] = [];
	for await (const chunk of request) {
		chunks.push(Buffer.from(chunk));
	}
	return Buffer.concat(chunks).toString("utf8");
}
