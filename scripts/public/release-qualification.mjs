#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = 1;
const READINESS_WORKFLOW_PATH = ".github/workflows/release-readiness.yml";
const WORKFLOW_NAME = "release-readiness.yml";
const COMMIT = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const REPOSITORY = /^[^/\\\s]+\/[^/\\\s]+$/u;
const VERSION =
  /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const KIND = /^[a-z][a-z0-9._-]*$/u;

export function validateIdentity(identity) {
  exactKeys(identity, ["release", "source", "qualification"], "identity");
  exactKeys(identity.release, ["version", "tag"], "release identity");
  exactKeys(identity.source, ["repository", "publicCommit", "privateCommit"], "source identity");
  // The re-qualification path re-labels an existing bundle for a corrected
  // commit and records where its artifacts were actually built. Those two
  // fields travel together or not at all, the same invariant the writer
  // enforces; see scripts/public/write-qualification-identity.mjs.
  exactKeys(
    identity.qualification,
    ["workflow", "runId", "runAttempt", "builtByRunId", "builtFromCommit"],
    "qualification identity",
  );

  const version = string(identity.release.version, "release.version");
  if (!VERSION.test(version)) throw new Error(`Invalid release version: ${version}`);
  const tag = string(identity.release.tag, "release.tag");
  if (tag !== `v${version}`) {
    throw new Error(`Release tag ${tag} does not match version ${version}.`);
  }
  const repository = string(identity.source.repository, "source.repository");
  if (!REPOSITORY.test(repository)) throw new Error(`Invalid source repository: ${repository}`);
  const publicCommit = commit(identity.source.publicCommit, "source.publicCommit");
  const privateCommit = identity.source.privateCommit === undefined
    ? undefined
    : commit(identity.source.privateCommit, "source.privateCommit");

  const workflow = string(identity.qualification.workflow, "qualification.workflow");
  if (workflow !== WORKFLOW_NAME) {
    throw new Error(`Qualification workflow must be ${WORKFLOW_NAME}, got ${workflow}.`);
  }
  const runId = positiveInteger(identity.qualification.runId, "qualification.runId");
  const runAttempt = positiveInteger(identity.qualification.runAttempt, "qualification.runAttempt");
  const reused = identity.qualification.builtByRunId !== undefined;
  if (reused !== (identity.qualification.builtFromCommit !== undefined)) {
    throw new Error("qualification.builtByRunId and qualification.builtFromCommit must be set together.");
  }
  const builtByRunId = reused
    ? positiveInteger(identity.qualification.builtByRunId, "qualification.builtByRunId")
    : undefined;
  const builtFromCommit = reused
    ? commit(identity.qualification.builtFromCommit, "qualification.builtFromCommit")
    : undefined;

  return {
    release: { version, tag },
    source: {
      repository,
      publicCommit,
      ...(privateCommit === undefined ? {} : { privateCommit }),
    },
    qualification: {
      workflow,
      runId,
      runAttempt,
      ...(reused ? { builtByRunId, builtFromCommit } : {}),
    },
  };
}

export function normalizeManifestPath(relativePath) {
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    throw new Error("Manifest paths must be non-empty strings.");
  }
  const normalized = relativePath.replaceAll("\\", "/");
  const segments = normalized.split("/");
  if (
    normalized.includes("\0") ||
    path.posix.isAbsolute(normalized) ||
    path.win32.isAbsolute(relativePath) ||
    /^[A-Za-z]:/u.test(normalized) ||
    segments.some((segment) => segment.length === 0 || segment === "." || segment === "..") ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw new Error(`Unsafe manifest path: ${JSON.stringify(relativePath)}`);
  }
  return normalized;
}

export function classifyArtifact(relativePath) {
  const normalized = normalizeManifestPath(relativePath).toLowerCase();
  if (normalized.endsWith(".crate")) return "crate";
  if (normalized.endsWith(".whl")) return "wheel";
  if (normalized.endsWith(".vsix")) return "vsix";
  if (normalized.endsWith(".sha256")) return "checksum";
  if (normalized.includes("semantic-pack")) return "semantic-pack";
  if (normalized.startsWith("agent-plugin/")) return "agent-plugin";
  if (normalized.startsWith("pi/")) return "pi";
  if (normalized.endsWith(".tgz")) return "npm";
  if (normalized.endsWith(".tar.gz") || normalized.endsWith(".zip")) return "cli";
  return "release";
}

export function generateManifest({ bundleDir, identity, outputPath }) {
  const root = path.resolve(bundleDir);
  const output = path.resolve(outputPath ?? path.join(root, "release-qualification.json"));
  assertBundleDirectory(root);
  if (fs.existsSync(output)) throw new Error(`Manifest output already exists: ${output}`);
  const excludedPath = pathInside(root, output)
    ? normalizeManifestPath(path.relative(root, output))
    : undefined;
  const manifest = makeManifest(validateIdentity(identity), inventoryBundle(root, excludedPath));
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
  return manifest;
}

export function verifyManifest({ bundleDir, manifest, manifestPath, expected = {} }) {
  const supplied = manifest ?? JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const canonical = canonicalManifest(supplied);
  assertExpectedIdentity(canonical, expected);

  const root = path.resolve(bundleDir);
  const manifestFile = manifestPath ?? path.join(root, "release-qualification.json");
  const excludedPath = pathInside(root, path.resolve(manifestFile))
    ? normalizeManifestPath(path.relative(root, path.resolve(manifestFile)))
    : undefined;
  const actual = validateFiles(inventoryBundle(root, excludedPath));
  const expectedByPath = new Map(canonical.files.map((entry) => [entry.path, entry]));
  const actualByPath = new Map(actual.map((entry) => [entry.path, entry]));
  const missing = canonical.files.filter((entry) => !actualByPath.has(entry.path)).map((entry) => entry.path);
  const extra = actual.filter((entry) => !expectedByPath.has(entry.path)).map((entry) => entry.path);
  if (missing.length || extra.length) {
    throw new Error(
      `Qualification bundle inventory mismatch; missing=${JSON.stringify(missing)}, extra=${JSON.stringify(extra)}`,
    );
  }

  const tampered = canonical.files.filter((entry) => {
    const actualEntry = actualByPath.get(entry.path);
    return actualEntry.bytes !== entry.bytes || actualEntry.sha256 !== entry.sha256;
  });
  if (tampered.length) {
    throw new Error(`Tampered qualification files: ${tampered.map((entry) => entry.path).join(", ")}`);
  }
  return canonical;
}

export function qualificationArtifactName(publicCommit, version) {
  const commitValue = commit(publicCommit, "public commit");
  const versionValue = string(version, "release version");
  if (!VERSION.test(versionValue)) throw new Error(`Invalid release version: ${versionValue}`);
  return `release-qualification-${commitValue}-v${versionValue}`;
}

export function selectQualificationRun({ runs, artifacts, repository, commit: publicCommit, version, runId, now = Date.now() }) {
  const requestedCommit = commit(publicCommit, "release commit");
  const requestedVersion = string(version, "release version");
  const requestedRepository = string(repository, "release repository");
  if (!REPOSITORY.test(requestedRepository)) throw new Error(`Invalid release repository: ${requestedRepository}`);
  if (!VERSION.test(requestedVersion)) throw new Error(`Invalid release version: ${requestedVersion}`);
  exactKeys(runs, ["workflow_runs"], "workflow-run evidence");
  exactKeys(artifacts, ["artifacts"], "artifact evidence");
  if (!Array.isArray(runs.workflow_runs) || !Array.isArray(artifacts.artifacts)) {
    throw new Error("Workflow-run and artifact evidence must contain arrays.");
  }
  const requestedRunId = runId === undefined ? undefined : positiveInteger(runId, "run ID");
  const qualificationName = qualificationArtifactName(requestedCommit, requestedVersion);
  const candidates = [];
  for (const artifact of artifacts.artifacts) validateArtifactEvidence(artifact);

  for (const run of runs.workflow_runs) {
    validateRunEvidence(run);
    if (requestedRunId !== undefined && run.id !== requestedRunId) continue;
    if (
      run.path !== READINESS_WORKFLOW_PATH ||
      run.status !== "completed" ||
      run.conclusion !== "success" ||
      run.head_sha !== requestedCommit ||
      (run.inputs !== undefined && run.inputs.version !== requestedVersion) ||
      run.repository.full_name !== requestedRepository
    ) continue;

    for (const artifact of artifacts.artifacts) {
      if (
        artifact.name !== qualificationName ||
        artifact.workflow_run.id !== run.id ||
        artifact.expired ||
        Date.parse(artifact.expires_at) <= Number(now)
      ) continue;
      candidates.push({
        run,
        artifact,
        runId: run.id,
        runAttempt: run.run_attempt,
        artifactId: artifact.id,
        commit: requestedCommit,
        version: requestedVersion,
        repository: run.repository.full_name,
      });
    }
  }

  if (candidates.length === 0) {
    throw new Error(
      requestedRunId === undefined
        ? "No successful, unexpired release qualification run matches the requested commit and version."
        : `No successful, unexpired release qualification run matches run ID ${requestedRunId}.`,
    );
  }
  if (candidates.length !== 1) {
    throw new Error(`Ambiguous release qualification runs: ${candidates.map((candidate) => candidate.runId).join(", ")}`);
  }
  return candidates[0];
}

function makeManifest(identity, files) {
  return { schemaVersion: SCHEMA_VERSION, ...identity, files: validateFiles(files) };
}

function canonicalManifest(manifest) {
  exactKeys(manifest, ["schemaVersion", "release", "source", "qualification", "files"], "qualification manifest");
  if (manifest.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`Unsupported qualification manifest schema: ${manifest.schemaVersion}`);
  }
  return makeManifest(validateIdentity({
    release: manifest.release,
    source: manifest.source,
    qualification: manifest.qualification,
  }), manifest.files);
}

function validateFiles(files) {
  if (!Array.isArray(files)) throw new Error("Manifest files must be an array.");
  const seen = new Set();
  const canonical = files.map((entry) => {
    exactKeys(entry, ["path", "kind", "bytes", "sha256"], "manifest file entry");
    const filePath = normalizeManifestPath(entry.path);
    if (seen.has(filePath)) throw new Error(`Duplicate manifest path: ${filePath}`);
    seen.add(filePath);
    const kind = string(entry.kind, `file kind for ${filePath}`);
    if (!KIND.test(kind)) throw new Error(`Invalid file kind for ${filePath}: ${kind}`);
    if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0) {
      throw new Error(`File bytes for ${filePath} must be a non-negative integer.`);
    }
    const digest = string(entry.sha256, `file sha256 for ${filePath}`);
    if (!SHA256.test(digest)) throw new Error(`Invalid SHA-256 for ${filePath}: ${digest}`);
    return { path: filePath, kind, bytes: entry.bytes, sha256: digest };
  });
  canonical.sort((left, right) => codePointCompare(left.path, right.path));
  return canonical;
}

function inventoryBundle(root, excludedPath) {
  const files = [];
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop();
    const entries = fs.readdirSync(directory, { withFileTypes: true });
    entries.sort((left, right) => codePointCompare(left.name, right.name));
    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);
      const relativePath = normalizeManifestPath(path.relative(root, absolutePath));
      if (relativePath === excludedPath) continue;
      if (entry.isSymbolicLink()) {
        throw new Error(`Symbolic links are not allowed in qualification bundles: ${relativePath}`);
      }
      if (entry.isDirectory()) {
        pending.push(absolutePath);
        continue;
      }
      if (!entry.isFile()) throw new Error(`Qualification bundle entry is not a regular file: ${relativePath}`);
      const contents = fs.readFileSync(absolutePath);
      files.push({
        path: relativePath,
        kind: classifyArtifact(relativePath),
        bytes: contents.byteLength,
        sha256: createHash("sha256").update(contents).digest("hex"),
      });
    }
  }
  return files;
}

function assertBundleDirectory(root) {
  const stat = fs.lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Bundle must be a real directory: ${root}`);
  }
}

function assertExpectedIdentity(manifest, expected) {
  for (const [actual, wanted, label] of [
    [manifest.release.version, expected.release?.version, "version"],
    [manifest.release.tag, expected.release?.tag, "tag"],
    [manifest.source.repository, expected.source?.repository, "repository"],
    [manifest.source.publicCommit, expected.source?.publicCommit, "commit"],
    [manifest.source.privateCommit, expected.source?.privateCommit, "private commit"],
    [manifest.qualification.workflow, expected.qualification?.workflow, "workflow"],
    [manifest.qualification.runId, expected.qualification?.runId, "run ID"],
    [manifest.qualification.runAttempt, expected.qualification?.runAttempt, "run attempt"],
  ]) {
    if (wanted !== undefined && String(actual) !== String(wanted)) {
      throw new Error(`Qualification manifest ${label} mismatch: expected ${wanted}, got ${actual}.`);
    }
  }
}

function validateRunEvidence(run) {
  exactKeys(run, ["id", "path", "status", "conclusion", "head_sha", "run_attempt", "repository", "inputs"], "workflow run");
  positiveInteger(run.id, "workflow run id");
  string(run.path, "workflow run path");
  string(run.status, "workflow run status");
  string(run.conclusion, "workflow run conclusion");
  commit(run.head_sha, "workflow run head_sha");
  positiveInteger(run.run_attempt, "workflow run run_attempt");
  exactKeys(run.repository, ["full_name"], "workflow run repository");
  if (!REPOSITORY.test(string(run.repository.full_name, "workflow run repository.full_name"))) {
    throw new Error(`Invalid workflow run repository: ${run.repository.full_name}`);
  }
  if (run.inputs !== undefined) {
    exactKeys(run.inputs, ["version"], "workflow run inputs");
    string(run.inputs.version, "workflow run inputs.version");
  }
}

function validateArtifactEvidence(artifact) {
  exactKeys(artifact, ["id", "name", "expired", "expires_at", "workflow_run"], "artifact");
  positiveInteger(artifact.id, "artifact id");
  string(artifact.name, "artifact name");
  if (typeof artifact.expired !== "boolean") throw new Error("Artifact expired must be a boolean.");
  string(artifact.expires_at, "artifact expires_at");
  if (!Number.isFinite(Date.parse(artifact.expires_at))) {
    throw new Error(`Invalid artifact expires_at: ${artifact.expires_at}`);
  }
  exactKeys(artifact.workflow_run, ["id"], "artifact workflow_run");
  positiveInteger(artifact.workflow_run.id, "artifact workflow_run.id");
}

function exactKeys(value, allowed, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length) throw new Error(`${label} has unexpected fields: ${unexpected.join(", ")}`);
}

function string(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string.`);
  return value;
}

function commit(value, label) {
  const candidate = string(value, label);
  if (!COMMIT.test(candidate)) throw new Error(`${label} must be 40 lowercase hexadecimal characters.`);
  return candidate;
}

function positiveInteger(value, label) {
  const candidate = typeof value === "string" && /^[1-9][0-9]*$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(candidate) || candidate <= 0) throw new Error(`${label} must be a positive integer.`);
  return candidate;
}

function codePointCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function pathInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function readJsonFile(filePath, label) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`Unable to read ${label}: ${error.message}`);
  }
}

function parseArgs(args, usage) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (!option?.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error(`Usage: ${usage}`);
    }
    if (options[option] !== undefined) throw new Error(`${option} may only be provided once.`);
    options[option] = value;
  }
  return options;
}

function required(options, option) {
  if (!options[option]) throw new Error(`Missing required ${option}.`);
  return options[option];
}

function main(args) {
  const command = args.shift();
  if (command === "manifest") {
    const options = parseArgs(args, "node scripts/public/release-qualification.mjs manifest --bundle DIR --identity FILE --output FILE");
    const manifest = generateManifest({
      bundleDir: required(options, "--bundle"),
      identity: readJsonFile(required(options, "--identity"), "--identity"),
      outputPath: required(options, "--output"),
    });
    console.log(JSON.stringify(manifest, null, 2));
    return;
  }
  if (command === "verify") {
    const options = parseArgs(args, "node scripts/public/release-qualification.mjs verify --bundle DIR --manifest FILE --repository OWNER/REPO --commit SHA --version VERSION [--run-id ID]");
    const version = required(options, "--version");
    const verified = verifyManifest({
      bundleDir: required(options, "--bundle"),
      manifestPath: required(options, "--manifest"),
      expected: {
        release: { version, tag: `v${version}` },
        source: { repository: required(options, "--repository"), publicCommit: required(options, "--commit") },
        qualification: options["--run-id"] === undefined
          ? {}
          : { runId: positiveInteger(options["--run-id"], "--run-id") },
      },
    });
    console.log(JSON.stringify(verified, null, 2));
    return;
  }
  if (command === "select-run") {
    const options = parseArgs(args, "node scripts/public/release-qualification.mjs select-run --runs FILE --artifacts FILE --repository OWNER/REPO --commit SHA --version VERSION [--run-id ID]");
    const selected = selectQualificationRun({
      runs: readJsonFile(required(options, "--runs"), "--runs"),
      artifacts: readJsonFile(required(options, "--artifacts"), "--artifacts"),
      repository: required(options, "--repository"),
      commit: required(options, "--commit"),
      version: required(options, "--version"),
      ...(options["--run-id"] === undefined ? {} : { runId: positiveInteger(options["--run-id"], "--run-id") }),
    });
    console.log(JSON.stringify(selected, null, 2));
    return;
  }
  throw new Error("Usage: node scripts/public/release-qualification.mjs <manifest|verify|select-run> ...");
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
