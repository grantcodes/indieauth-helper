import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

let packageJson;
try {
	packageJson = JSON.parse(readFileSync("package.json", "utf8"));
} catch (err) {
	throw new Error(`Could not read package.json: ${err.message}`);
}

function collectPaths(value, paths = []) {
	if (typeof value === "string") {
		paths.push(value);
	} else if (value && typeof value === "object") {
		for (const nested of Object.values(value)) {
			collectPaths(nested, paths);
		}
	}
	return paths;
}

const entryPoints = new Set(
	[
		packageJson.main,
		packageJson.module,
		packageJson.types,
		...collectPaths(packageJson.exports),
	]
		.filter((value) => typeof value === "string")
		.map((value) => value.replace(/^\.\//, "")),
);

for (const entryPoint of entryPoints) {
	if (!existsSync(entryPoint)) {
		throw new Error(
			`Package entry point "${entryPoint}" does not exist. Run npm run build first.`,
		);
	}
}

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const output = execFileSync(
	npm,
	["pack", "--dry-run", "--json", "--ignore-scripts"],
	{
		encoding: "utf8",
	},
);
let packed;
try {
	const parsed = JSON.parse(output.trim());
	packed = Array.isArray(parsed)
		? parsed[0]
		: (parsed[packageJson.name] ?? Object.values(parsed)[0]);
} catch (err) {
	throw new Error(`Could not parse npm pack output: ${err.message}`);
}

if (!packed || !Array.isArray(packed.files)) {
	throw new Error("npm pack did not return a file list");
}

const packedFiles = new Set(packed.files.map((file) => file.path));

for (const entryPoint of entryPoints) {
	if (!packedFiles.has(entryPoint)) {
		throw new Error(
			`Package tarball is missing the entry point "${entryPoint}".`,
		);
	}
}

const developmentFiles = [...packedFiles].filter(
	(file) =>
		file.startsWith("src/") ||
		file.startsWith("tmp/") ||
		file.includes(".test."),
);

if (developmentFiles.length > 0) {
	throw new Error(
		`Package tarball includes development files: ${developmentFiles.join(", ")}`,
	);
}

console.log(
	`Package tarball contains all ${entryPoints.size} entry points (${packedFiles.size} files).`,
);
