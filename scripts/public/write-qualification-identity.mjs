#!/usr/bin/env node

// Write the identity record that scripts/public/release-qualification.mjs binds a
// qualification bundle to.
//
// Both readiness paths produce one: the aggregate qualification job after a
// full build, and the metadata-only re-qualification that re-labels an existing
// bundle. They carried separate inline copies of this object, so the field that
// records reuse existed in one shape only, and a change to the record had to be
// made twice to stay true.
//
// Environment:
//   RELEASE_VERSION    release version without the v prefix
//   RELEASE_TAG        release tag
//   PUBLIC_REPOSITORY  owner/name of the repository being qualified
//   PUBLIC_COMMIT      commit the bundle is qualified for
//   PRIVATE_COMMIT     optional private source commit from the projection ledger
//   RUN_ID             this readiness run
//   RUN_ATTEMPT        this readiness run's attempt
//   SOURCE_RUN_ID      set only when reusing artifacts: the run that built them
//   SOURCE_COMMIT      set only when reusing artifacts: the commit they were built from

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

export function buildIdentity(env) {
  const reused = Boolean(env.SOURCE_RUN_ID);
  if (reused !== Boolean(env.SOURCE_COMMIT)) {
    throw new Error("SOURCE_RUN_ID and SOURCE_COMMIT describe one reuse and must be set together.");
  }
  return {
    release: { version: env.RELEASE_VERSION, tag: env.RELEASE_TAG },
    source: {
      repository: env.PUBLIC_REPOSITORY,
      publicCommit: env.PUBLIC_COMMIT,
      ...(env.PRIVATE_COMMIT ? { privateCommit: env.PRIVATE_COMMIT } : {}),
    },
    qualification: {
      workflow: "release-readiness.yml",
      runId: Number(env.RUN_ID),
      runAttempt: Number(env.RUN_ATTEMPT),
      // The artifacts were built elsewhere and reused unchanged; this records
      // where, so the provenance is not silently rewritten.
      ...(reused
        ? { builtByRunId: Number(env.SOURCE_RUN_ID), builtFromCommit: env.SOURCE_COMMIT }
        : {}),
    },
  };
}

function main(args) {
  if (args.length !== 2 || args[0] !== "--output") {
    throw new Error("Usage: write-qualification-identity.mjs --output <file>");
  }
  for (const name of ["RELEASE_VERSION", "RELEASE_TAG", "PUBLIC_REPOSITORY", "PUBLIC_COMMIT", "RUN_ID", "RUN_ATTEMPT"]) {
    required(name);
  }
  const identity = buildIdentity(process.env);
  fs.writeFileSync(args[1], `${JSON.stringify(identity)}\n`, "utf8");
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
