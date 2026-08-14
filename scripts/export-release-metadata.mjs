#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const EXPORTED_FILES = [
  "editors/vscode/package.json",
  "plugins/bifrost-agent/bifrost-release.json",
];

const options = parseArgs(process.argv.slice(2));
const tag = required(options.tag, "tag");
const version = required(options.version, "version");
const publicCommit = required(options.publicCommit, "public-commit");
const outputDir = path.resolve(required(options.outputDir, "output-dir"));
const sourceRoot = path.resolve(
  options.sourceRoot
    ?? fileURLToPath(new URL("..", import.meta.url)),
);

if (tag !== `v${version}`) {
  throw new Error(`Release tag ${tag} does not match version ${version}.`);
}
if (!/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(publicCommit)) {
  throw new Error(`Invalid public release commit: ${publicCommit}`);
}

// Refuse an existing directory so a retry cannot accidentally include stale
// files in the uploaded artifact.
fs.mkdirSync(outputDir);

const files = [];
for (const relativePath of EXPORTED_FILES) {
  const sourcePath = path.join(sourceRoot, relativePath);
  const contents = fs.readFileSync(sourcePath);
  const destinationPath = path.join(outputDir, relativePath);
  fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
  fs.writeFileSync(destinationPath, contents);
  files.push({
    path: relativePath,
    sha256: sha256(contents),
  });
}

const manifest = {
  schemaVersion: 1,
  release: {
    tag,
    version,
    publicCommit,
  },
  files,
};
fs.writeFileSync(
  path.join(outputDir, "release-metadata-export.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
);

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function parseArgs(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(
        "Usage: export-release-metadata.mjs --tag <vX.Y.Z> --version <X.Y.Z> --public-commit <sha> --output-dir <dir> [--source-root <dir>]",
      );
    }
    parsed[toCamelCase(key.slice(2))] = value;
  }
  return parsed;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
}

function required(value, name) {
  if (!value) {
    throw new Error(`Missing required --${name}`);
  }
  return value;
}
