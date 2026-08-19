#!/usr/bin/env node

// Post-qualification checksum sync for the committed marketplace launcher
// metadata (issue #2400).
//
// The release packaging jobs regenerate launcher metadata inside disposable
// checkouts, so the archive hashes that ship in the release assets never reach
// tracked source. Marketplace installs read the tracked source, so a release
// with new binary hashes leaves every launcher refusing the published binary
// with checksum_mismatch until the source metadata is corrected.
//
// This module performs that correction from the promoted release sidecars. It
// writes exactly one file, plugins/bifrost-agent/bifrost-release.json, and then
// lets the existing release-version sync project the derived copies. Keeping a
// single writer for each projection is what makes the result verifiable: the
// derived files are not independently authored here, they are re-derived by the
// same code path that CI already validates.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SUPPORTED_TARGETS, parseSha256 } from "../plugins/bifrost-agent/bin/bifrost-launcher.mjs";
import { readCargoVersion, syncReleaseVersion } from "./release-version.mjs";

export { SUPPORTED_TARGETS };

export const CANONICAL_RELEASE_METADATA = "plugins/bifrost-agent/bifrost-release.json";

// Files the release-version sync is permitted to rewrite as a consequence of new
// archive hashes. Anything else in its update set means the tree was not
// release-clean, which must abort before either repository is written.
export const DERIVED_CHECKSUM_PROJECTIONS = [
  "editors/vscode/package.json",
  "plugins/bifrost-dsh/bifrost-release.json",
];

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

export function archiveNameFor(target, version) {
  const suffix = target.includes("windows") ? "zip" : "tar.gz";
  return `bifrost-v${version}-${target}.${suffix}`;
}

// Sidecars are parsed with the launcher's own parseSha256 rather than a local
// reimplementation. The launcher is the consumer that will accept or reject
// these hashes at install time, so parsing them any differently here would
// reintroduce exactly the class of disagreement this workflow exists to close.
export function readSidecarDigest(contents, expectedArchiveName) {
  return parseSha256(contents, expectedArchiveName);
}

export function collectSidecarChecksums(assetDir, version) {
  const checksums = {};
  for (const target of SUPPORTED_TARGETS) {
    const archiveName = archiveNameFor(target, version);
    const sidecarPath = path.join(assetDir, `${archiveName}.sha256`);
    if (!fs.existsSync(sidecarPath)) {
      throw new Error(`Missing promoted sidecar ${archiveName}.sha256 in ${assetDir}`);
    }
    checksums[target] = readSidecarDigest(
      fs.readFileSync(sidecarPath, "utf8"),
      archiveName,
    );
  }
  return checksums;
}

function readCanonicalMetadata(repoRoot) {
  const absolutePath = path.join(repoRoot, CANONICAL_RELEASE_METADATA);
  return {
    absolutePath,
    contents: fs.readFileSync(absolutePath, "utf8"),
    json: JSON.parse(fs.readFileSync(absolutePath, "utf8")),
  };
}

// canCopyReleaseChecksums in release-version.mjs gates the VS Code hash copy on
// binaryVersion === cargoVersion. If that does not hold, sync silently leaves
// the VS Code hashes alone and we would commit a half-synced tree. Assert it
// rather than depending on the release commit happening to be well-formed.
function assertChecksumProjectionEnabled(repoRoot, metadata, version) {
  const cargoVersion = readCargoVersion(
    fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8"),
  );
  if (cargoVersion !== version) {
    throw new Error(
      `Refusing to sync: Cargo.toml is ${cargoVersion} but the release is ${version}. This workflow corrects hashes only, never versions.`,
    );
  }
  if (metadata.json.binaryVersion !== version) {
    throw new Error(
      `Refusing to sync: ${CANONICAL_RELEASE_METADATA} declares binaryVersion ${metadata.json.binaryVersion} but the release is ${version}. Derived checksum projections would be skipped.`,
    );
  }
}

function assertExactTargetSet(actual, source) {
  const found = Object.keys(actual).sort();
  const expected = [...SUPPORTED_TARGETS].sort();
  if (found.length !== expected.length || found.some((key, index) => key !== expected[index])) {
    throw new Error(
      `${source} covers targets ${JSON.stringify(found)}, expected exactly ${JSON.stringify(expected)}`,
    );
  }
}

/**
 * Whether the tracked metadata already carries the promoted hashes.
 *
 * This is the whole idempotency decision, and it is deliberately anchored to the
 * sidecars rather than to the repository's internal consistency. release-version
 * never reads or writes archiveSha256 on the canonical file, so its update set
 * is empty for a tree whose versions agree even when every hash is stale. At
 * aad49ea03^ that was literally true: Cargo, the agent metadata and the VS Code
 * manifest all read 0.10.3 and all carried the same superseded darwin hash.
 */
export function checksumsAlreadyMatch(metadataJson, checksums) {
  const tracked = metadataJson.archiveSha256 ?? {};
  return SUPPORTED_TARGETS.every((target) => tracked[target] === checksums[target]);
}

/**
 * Guard the fan-out. release-version syncs far more than checksums, so a tree
 * that was not already release-clean would smuggle unrelated version edits into
 * a commit that claims to be checksum-only.
 */
export function assertAllowedUpdates(updates) {
  const unexpected = updates.filter(
    (relativePath) => !DERIVED_CHECKSUM_PROJECTIONS.includes(relativePath),
  );
  if (unexpected.length > 0) {
    throw new Error(
      `Refusing to commit: release metadata sync rewrote paths outside the checksum projection allowlist: ${JSON.stringify(unexpected)}`,
    );
  }
}

/**
 * Correct the tracked launcher checksums from the promoted release sidecars.
 *
 * Idempotency is decided against the sidecars, never against the repository's
 * internal consistency. A tree whose version projections all agree can still
 * carry hashes for binaries that were never published -- that is exactly the
 * v0.10.3 failure -- so "already synced" has to mean "matches the promoted
 * artifacts", and the sync seam is used only to verify the fan-out afterwards.
 */
export function syncReleaseChecksums({ repoRoot = process.cwd(), version, checksums } = {}) {
  assertExactTargetSet(checksums, "The promoted sidecar set");
  for (const target of SUPPORTED_TARGETS) {
    if (!SHA256_PATTERN.test(checksums[target] ?? "")) {
      throw new Error(`Promoted checksum for ${target} is not a SHA-256: ${checksums[target]}`);
    }
  }

  const metadata = readCanonicalMetadata(repoRoot);
  assertChecksumProjectionEnabled(repoRoot, metadata, version);
  assertExactTargetSet(metadata.json.archiveSha256 ?? {}, CANONICAL_RELEASE_METADATA);

  const alreadyCorrect = checksumsAlreadyMatch(metadata.json, checksums);
  if (!alreadyCorrect) {
    metadata.json.archiveSha256 = Object.fromEntries(
      [...SUPPORTED_TARGETS].sort().map((target) => [target, checksums[target]]),
    );
    fs.writeFileSync(
      metadata.absolutePath,
      `${JSON.stringify(metadata.json, undefined, 2)}\n`,
      "utf8",
    );
  }

  // Run the sync in both cases. When the hashes were already correct this
  // proves the derived copies had not drifted on their own; when they were not,
  // it is what projects the new hashes outward.
  const { updates } = syncReleaseVersion({ repoRoot });
  assertAllowedUpdates(updates);

  const changed = alreadyCorrect ? [...updates] : [CANONICAL_RELEASE_METADATA, ...updates];
  return { changed, alreadyCorrect: changed.length === 0, version };
}

function parseArgs(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option !== "--asset-dir" && option !== "--version" && option !== "--github-output") {
      throw new Error(`Unknown option ${option}.`);
    }
    const value = args[index + 1];
    if (value === undefined) {
      throw new Error(`${option} requires a value.`);
    }
    const key = option === "--asset-dir" ? "assetDir" : option === "--version" ? "version" : "githubOutput";
    if (options[key] !== undefined) {
      throw new Error(`${option} may only be provided once.`);
    }
    options[key] = value;
    index += 1;
  }
  if (!options.assetDir || !options.version) {
    throw new Error("Both --asset-dir and --version are required.");
  }
  return options;
}

function main(args) {
  const { assetDir, version, githubOutput } = parseArgs(args);
  const checksums = collectSidecarChecksums(assetDir, version);
  const result = syncReleaseChecksums({ version, checksums });

  if (result.alreadyCorrect) {
    console.log(`Tracked launcher checksums already match the promoted v${version} sidecars.`);
  } else {
    console.log(`Synced launcher checksums to the promoted v${version} sidecars:`);
    for (const relativePath of result.changed) {
      console.log(`- ${relativePath}`);
    }
  }
  if (githubOutput) {
    fs.appendFileSync(
      githubOutput,
      `changed=${result.alreadyCorrect ? "false" : "true"}\nchanged_paths=${result.changed.join(",")}\n`,
      "utf8",
    );
  }
}

const thisFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === thisFile) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
