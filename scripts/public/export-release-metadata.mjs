#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseCamelCaseArgs, required } from "./cli-argument-helpers.mjs";
import { sha256Hex } from "../lib/sha256.mjs";

const EXPORTED_FILES = [
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
  return sha256Hex(contents);
}

function parseArgs(args) {
  return parseCamelCaseArgs(
    args,
    "Usage: export-release-metadata.mjs --tag <vX.Y.Z> --version <X.Y.Z> --public-commit <sha> --output-dir <dir> [--source-root <dir>]",
  );
}
