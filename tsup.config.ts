import { defineConfig } from "tsup";

export default defineConfig((options) => {
	if (options.env?.TEST === "yes") {
		return {
			entry: ["src"],
			outDir: "tmp/tests",
			format: ["esm"],
			clean: true,
			minify: false,
			sourcemap: "inline",
			removeNodeProtocol: false,
		};
	}

	return {
		entry: ["src/main.ts"],
		format: ["esm", "cjs"],
		dts: true,
		clean: true,
		target: "es2022",
		minify: options.watch !== true,
		sourcemap: options.watch === true,
	};
});
