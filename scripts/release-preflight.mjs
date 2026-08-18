#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FULL_COMMIT = /^[0-9a-f]{40}$/u;
const SEMVER =
  /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const ACTION_PATH = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const TOP_LEVEL_FIELDS = [
  "publicCommit",
  "expectedPublicHead",
  "observedPublicHead",
  "tag",
  "version",
  "refs",
  "versionCheck",
  "workflows",
  "actionRevisions",
  "releaseInventory",
  "trustedPublishers",
];
const VERSION_CHECK_FIELDS = ["command", "exitCode", "version", "tag"];
const WORKFLOW_FIELDS = ["path", "contents"];
const ACTION_REVISION_FIELDS = ["repository", "revision", "status"];
const PUBLISHER_FIELDS = ["package", "registry", "repository", "workflow", "environment"];
const USAGE = "Usage: node scripts/release-preflight.mjs --input FILE";

function error(errors, message) {
  errors.push(message);
}

function validCommit(value) {
  return typeof value === "string" && FULL_COMMIT.test(value);
}

function validateExactKeys(value, allowed, label, errors) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      error(errors, `${label} has unexpected key '${key}'.`);
    }
  }
}

function validateIdentity(input, errors) {
  if (!validCommit(input.publicCommit)) {
    error(errors, "Invalid public commit: expected exactly 40 lowercase hexadecimal characters.");
  }
  for (const field of ["expectedPublicHead", "observedPublicHead"]) {
    if (!validCommit(input[field])) {
      error(errors, `Invalid ${field}: expected exactly 40 lowercase hexadecimal characters.`);
    }
  }
  if (validCommit(input.expectedPublicHead) && validCommit(input.observedPublicHead)) {
    if (input.expectedPublicHead !== input.observedPublicHead) {
      error(
        errors,
        `Public head changed: expected independently supplied head ${input.expectedPublicHead}, but observed current public head is ${input.observedPublicHead}.`,
      );
    }
  }

  const validTag =
    typeof input.tag === "string" && input.tag.startsWith("v") && SEMVER.test(input.tag.slice(1));
  if (!validTag) {
    error(errors, "Invalid release tag: expected a v-prefixed semantic version such as v0.10.3.");
  }
  const validVersion = typeof input.version === "string" && SEMVER.test(input.version);
  if (!validVersion) {
    error(errors, "Invalid release version: expected a semantic version such as 0.10.3.");
  }
  if (validTag && validVersion && input.tag.slice(1) !== input.version) {
    error(errors, `Release version mismatch: tag ${input.tag} does not agree with version ${input.version}.`);
  }
  return validTag;
}

function validateRefs(input, errors, validTag) {
  if (!Array.isArray(input.refs)) {
    error(errors, "Git refs evidence must be an array of full ref strings.");
    return;
  }
  for (const [index, ref] of input.refs.entries()) {
    if (typeof ref !== "string" || !ref.startsWith("refs/")) {
      error(errors, `Git refs evidence entry ${index + 1} must be a full refs/... string.`);
    }
  }
  if (validTag) {
    const tagRef = `refs/tags/${input.tag}`;
    if (input.refs.includes(tagRef) || input.refs.includes(`${tagRef}^{}`)) {
      error(errors, `Release tag ${input.tag} is already present in supplied git refs evidence.`);
    }
  }
}

function validateVersionCheck(input, errors, validTag) {
  const check = input.versionCheck;
  if (!check || typeof check !== "object" || Array.isArray(check)) {
    error(errors, "Version check evidence must be an object.");
    return;
  }
  validateExactKeys(check, VERSION_CHECK_FIELDS, "Version check evidence", errors);
  if (!Array.isArray(check.command) || !check.command.every((part) => typeof part === "string")) {
    error(errors, "Version check command must be an array of strings.");
  }
  if (!Number.isInteger(check.exitCode) || check.exitCode !== 0) {
    error(errors, `Version check command did not succeed (exit code ${check.exitCode ?? "missing"}).`);
  }
  if (typeof check.version !== "string" || check.version !== input.version) {
    error(errors, `Version check evidence reports ${check.version ?? "no version"}, expected ${input.version ?? "no version"}.`);
  }
  if (typeof check.tag !== "string" || check.tag !== input.tag) {
    error(errors, `Version check evidence tag ${check.tag ?? "no tag"} does not match ${input.tag ?? "no tag"}.`);
  }
  if (validTag && Array.isArray(check.command)) {
    const expected = ["node", "scripts/release-version.mjs", "check", "--tag", input.tag];
    if (check.command.length !== expected.length || check.command.some((part, index) => part !== expected[index])) {
      error(errors, "Version check command must exactly be node scripts/release-version.mjs check --tag <tag>.");
    }
  }
}

function workflowActionTargets(workflows, errors) {
  if (!Array.isArray(workflows)) {
    error(errors, "Workflow evidence must be an array of {path, contents} objects.");
    return [];
  }
  const identities = new Set();
  for (const [index, workflow] of workflows.entries()) {
    const label = workflow?.path ?? `workflow ${index + 1}`;
    if (!workflow || typeof workflow !== "object" || Array.isArray(workflow)) {
      error(errors, `${label} must be a workflow object.`);
      continue;
    }
    validateExactKeys(workflow, WORKFLOW_FIELDS, label, errors);
    if (typeof workflow.path !== "string" || workflow.path.length === 0) {
      error(errors, `Workflow ${index + 1} must have a path string.`);
    }
    if (typeof workflow.contents !== "string") {
      error(errors, `${label} must have contents as a string.`);
      continue;
    }
    for (const [lineIndex, line] of workflow.contents.split(/\r?\n/u).entries()) {
      const match = /^\s*(?:-\s*)?uses:\s*(.*?)\s*$/u.exec(line);
      if (!match) {
        continue;
      }
      let target = match[1].replace(/\s+#.*$/u, "").trim();
      if ((target.startsWith("\"") && target.endsWith("\"")) || (target.startsWith("'") && target.endsWith("'"))) {
        target = target.slice(1, -1);
      }
      if (target.startsWith("./")) {
        continue;
      }
      const separator = target.lastIndexOf("@");
      const actionPath = separator === -1 ? target : target.slice(0, separator);
      const revision = separator === -1 ? "" : target.slice(separator + 1);
      const location = `${label}:${lineIndex + 1}`;
      if (!ACTION_PATH.test(actionPath)) {
        error(errors, `${location}: external workflow action '${target}' must be owner/repo[/subpath]@revision.`);
        continue;
      }
      if (!FULL_COMMIT.test(revision)) {
        error(errors, `${location}: external workflow action ${actionPath} must use a full lowercase 40-hex revision, got '${revision || "missing"}'.`);
        continue;
      }
      identities.add(`${actionPath.split("/").slice(0, 2).join("/").toLowerCase()}@${revision}`);
    }
  }
  return [...identities].sort();
}

function validateActionRevisions(input, errors, identities) {
  if (!Array.isArray(input.actionRevisions)) {
    error(errors, "Action revision evidence must be an array of {repository, revision, status} objects.");
    return;
  }
  const evidence = new Map();
  for (const [index, revision] of input.actionRevisions.entries()) {
    if (!revision || typeof revision !== "object" || Array.isArray(revision)) {
      error(errors, `Action revision evidence entry ${index + 1} must be an object.`);
      continue;
    }
    validateExactKeys(revision, ACTION_REVISION_FIELDS, `Action revision evidence entry ${index + 1}`, errors);
    if (!REPOSITORY.test(revision.repository ?? "")) {
      error(errors, `Action revision evidence entry ${index + 1} must name an owner/repository.`);
    }
    if (!FULL_COMMIT.test(revision.revision ?? "")) {
      error(errors, `Action revision evidence entry ${index + 1} must contain a full lowercase 40-hex revision.`);
    }
    if (!Number.isInteger(revision.status)) {
      error(errors, `Action revision evidence entry ${index + 1} must contain an HTTP status number.`);
    }
    if (REPOSITORY.test(revision.repository ?? "") && FULL_COMMIT.test(revision.revision ?? "")) {
      const identity = `${revision.repository.toLowerCase()}@${revision.revision}`;
      if (evidence.has(identity)) {
        error(errors, `Duplicate action revision identity ${identity}.`);
      } else {
        evidence.set(identity, revision.status);
      }
    }
  }
  for (const identity of identities) {
    if (!evidence.has(identity)) {
      error(errors, `Action revision reachability evidence is missing for ${identity}.`);
    } else if (evidence.get(identity) !== 200) {
      error(errors, `Action revision ${identity} is unreachable: supplied evidence status is ${evidence.get(identity)}; expected 200.`);
    }
  }
}

function validPublisherRecord(record) {
  return (
    record &&
    typeof record === "object" &&
    !Array.isArray(record) &&
    PUBLISHER_FIELDS.every((field) => typeof record[field] === "string" && record[field].length > 0)
  );
}

function validatePublisherKeys(records, label, errors) {
  for (const [index, record] of records.entries()) {
    if (record && typeof record === "object" && !Array.isArray(record)) {
      validateExactKeys(record, PUBLISHER_FIELDS, `${label} entry ${index + 1}`, errors);
    }
  }
}

function publisherKey(record) {
  return PUBLISHER_FIELDS.map((field) => record[field]).join("\u0000");
}

function validatePublishers(input, errors) {
  if (!Array.isArray(input.releaseInventory) || input.releaseInventory.length === 0) {
    error(errors, "Release inventory must be a non-empty array of publisher records.");
    return;
  }
  if (!Array.isArray(input.trustedPublishers)) {
    error(errors, "Trusted-publisher evidence must be an array of publisher records.");
    return;
  }
  validatePublisherKeys(input.releaseInventory, "Release inventory", errors);
  validatePublisherKeys(input.trustedPublishers, "Trusted-publisher evidence", errors);
  for (const [index, record] of input.releaseInventory.entries()) {
    if (!validPublisherRecord(record)) {
      error(errors, `Release inventory entry ${index + 1} must contain package, registry, repository, workflow, and environment strings.`);
    }
  }
  for (const [index, record] of input.trustedPublishers.entries()) {
    if (!validPublisherRecord(record)) {
      error(errors, `Trusted-publisher evidence entry ${index + 1} must contain package, registry, repository, workflow, and environment strings.`);
    }
  }
  const expected = new Set(input.releaseInventory.filter(validPublisherRecord).map(publisherKey));
  const actual = new Set(input.trustedPublishers.filter(validPublisherRecord).map(publisherKey));
  const duplicateInventory = input.releaseInventory.filter(validPublisherRecord).map(publisherKey);
  const duplicatePublishers = input.trustedPublishers.filter(validPublisherRecord).map(publisherKey);
  if (new Set(duplicateInventory).size !== duplicateInventory.length) {
    error(errors, "Release inventory contains duplicate publisher record keys.");
  }
  if (new Set(duplicatePublishers).size !== duplicatePublishers.length) {
    error(errors, "Trusted-publisher evidence contains duplicate publisher record keys.");
  }
  for (const record of input.releaseInventory.filter(validPublisherRecord)) {
    if (!actual.has(publisherKey(record))) {
      error(errors, `Trusted publisher for ${record.package} does not exactly match the release inventory.`);
    }
  }
  for (const record of input.trustedPublishers.filter(validPublisherRecord)) {
    if (!expected.has(publisherKey(record))) {
      error(errors, `Trusted publisher evidence for ${record.package} does not exactly match the release inventory.`);
    }
  }
}

export function validatePreflight(input) {
  const errors = [];
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return ["Preflight input must be a JSON object."];
  }
  validateExactKeys(input, TOP_LEVEL_FIELDS, "Preflight input", errors);
  const validTag = validateIdentity(input, errors);
  validateRefs(input, errors, validTag);
  validateVersionCheck(input, errors, validTag);
  const identities = workflowActionTargets(input.workflows, errors);
  validateActionRevisions(input, errors, identities);
  validatePublishers(input, errors);
  return errors;
}

function main(args = process.argv.slice(2)) {
  if (args.length !== 2 || args[0] !== "--input" || !args[1] || args[1].startsWith("--")) {
    throw new Error(USAGE);
  }
  const input = JSON.parse(fs.readFileSync(path.resolve(args[1]), "utf8"));
  const errors = validatePreflight(input);
  if (errors.length > 0) {
    console.error(`Release preflight failed with ${errors.length} error(s):`);
    for (const message of errors) {
      console.error(`- ${message}`);
    }
    return 1;
  }
  console.log("Release preflight passed.");
  return 0;
}

const thisFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === thisFile) {
  try {
    process.exitCode = main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
