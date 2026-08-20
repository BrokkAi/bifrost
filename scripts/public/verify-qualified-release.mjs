#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyManifest } from "./release-qualification.mjs";

const SHA256 = /^sha256:[0-9a-f]{64}$/u;

export function verifyQualifiedRelease({
  bundleDir,
  manifestPath,
  repository,
  commit,
  version,
  runId,
  runAttempt,
  privateCommit,
  expectedManifestSha256,
}) {
  const resolvedBundle = path.resolve(requiredString(bundleDir, "Bundle directory"));
  const resolvedManifest = path.resolve(requiredString(manifestPath, "Manifest path"));
  const manifestBytes = fs.readFileSync(resolvedManifest);
  const manifestSha256 = createHash("sha256").update(manifestBytes).digest("hex");
  if (expectedManifestSha256 !== undefined && manifestSha256 !== expectedManifestSha256) {
    throw new Error(
      `Qualification manifest checksum mismatch: expected ${expectedManifestSha256}, got ${manifestSha256}.`,
    );
  }

  const manifest = verifyManifest({
    bundleDir: resolvedBundle,
    manifestPath: resolvedManifest,
    expected: {
      release: { version },
      source: {
        repository,
        publicCommit: commit,
        ...(privateCommit === undefined ? {} : { privateCommit }),
      },
      qualification: {
        ...(runId === undefined ? {} : { runId }),
        ...(runAttempt === undefined ? {} : { runAttempt }),
      },
    },
  });

  return {
    bundleDir: resolvedBundle,
    manifestPath: resolvedManifest,
    manifestSha256,
    identity: {
      release: manifest.release,
      source: manifest.source,
      qualification: manifest.qualification,
    },
    files: manifest.files.map((entry) => ({
      ...entry,
      absolutePath: path.join(resolvedBundle, ...entry.path.split("/")),
    })),
  };
}

export function qualifiedFile(verified, relativePath) {
  const match = verified.files.find((entry) => entry.path === relativePath);
  if (!match) throw new Error(`Qualified file is not in the verified manifest: ${relativePath}`);
  return match.absolutePath;
}

export function qualifiedFiles(verified, predicate) {
  if (typeof predicate !== "function") throw new TypeError("Qualified file predicate must be a function.");
  return verified.files.filter(predicate).map((entry) => entry.absolutePath);
}

export function qualifiedManifestFiles(verified, predicate) {
  if (typeof predicate !== "function") throw new TypeError("Qualified file predicate must be a function.");
  return verified.files.filter(predicate).map((entry) => entry.path);
}

function requiredString(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is required.`);
  return value;
}

function parsePositiveInteger(value, label) {
  if (!/^[1-9][0-9]*$/u.test(value)) throw new Error(`${label} must be a positive integer.`);
  return Number(value);
}

function parseArgs(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (!option?.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error("Usage: node scripts/public/verify-qualified-release.mjs verify --bundle DIR --manifest FILE --repository OWNER/REPO --commit SHA --version VERSION [options]");
    }
    if (options[option] !== undefined) throw new Error(`${option} may only be provided once.`);
    options[option] = value;
  }
  return options;
}

function requiredOption(options, name) {
  return requiredString(options[name], name);
}

export function main(args = process.argv.slice(2)) {
  const command = args.shift();
  if (command !== "verify") throw new Error("Usage: node scripts/public/verify-qualified-release.mjs verify ...");
  const options = parseArgs(args);
  const expectedManifestSha256 = options["--manifest-sha256"];
  if (expectedManifestSha256 !== undefined && !/^[0-9a-f]{64}$/u.test(expectedManifestSha256)) {
    throw new Error("--manifest-sha256 must be 64 lowercase hexadecimal characters.");
  }
  const verified = verifyQualifiedRelease({
    bundleDir: requiredOption(options, "--bundle"),
    manifestPath: requiredOption(options, "--manifest"),
    repository: requiredOption(options, "--repository"),
    commit: requiredOption(options, "--commit"),
    version: requiredOption(options, "--version"),
    ...(options["--run-id"] === undefined ? {} : { runId: parsePositiveInteger(options["--run-id"], "--run-id") }),
    ...(options["--run-attempt"] === undefined ? {} : { runAttempt: parsePositiveInteger(options["--run-attempt"], "--run-attempt") }),
    ...(options["--private-commit"] === undefined ? {} : { privateCommit: options["--private-commit"] }),
    expectedManifestSha256,
  });
  if (options["--output"] === undefined) {
    process.stdout.write(`${JSON.stringify(verified, null, 2)}\n`);
  } else {
    fs.writeFileSync(options["--output"], `${JSON.stringify(verified, null, 2)}\n`, { flag: "wx" });
  }
  return verified;
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === currentFile) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`verify-qualified-release: ${error.message}\n`);
    process.exitCode = 1;
  }
}
