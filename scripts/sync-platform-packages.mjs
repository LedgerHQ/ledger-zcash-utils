#!/usr/bin/env node
// Align npm/*/package.json versions with the root package version.
// --optional-dependencies also pins them in the root manifest (publish time only).
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const writeJson = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);

const rootManifestPath = join(root, "package.json");
const rootManifest = readJson(rootManifestPath);
const { version } = rootManifest;

const optionalDependencies = {};
const dirs = readdirSync(join(root, "npm"), { withFileTypes: true }).filter((entry) => entry.isDirectory());
for (const { name: dir } of dirs.sort((a, b) => a.name.localeCompare(b.name))) {
  const manifestPath = join(root, "npm", dir, "package.json");
  const manifest = readJson(manifestPath);
  manifest.version = version;
  writeJson(manifestPath, manifest);
  optionalDependencies[manifest.name] = version;
  console.log(`${manifest.name}@${version}`);
}

if (process.argv.includes("--optional-dependencies")) {
  rootManifest.optionalDependencies = optionalDependencies;
  writeJson(rootManifestPath, rootManifest);
  console.log(`${rootManifest.name}: optionalDependencies pinned to ${version}`);
}
