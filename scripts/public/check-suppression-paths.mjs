#!/usr/bin/env node

// Prove every policy suppression record names a file that still exists.
//
// A suppression record is an accepted decision anchored to a path. When a file
// moves the record keeps pointing at the old location, the run reports
// `path_not_analyzed` instead of resolving it, and the acceptance silently
// stops applying. Two reorganizations did this at scale without anyone
// noticing: the `scripts/` split that moved eight scripts under
// `scripts/public/`, and the flow/RQL crate split that moved four analysis
// modules into `bifrost-core`, `bifrost-flow`, and `bifrost-rql`.
//
// The expensive way to learn this is the release: `report_exit_status` gates on
// a record that no longer resolves, so a stale document fails the staged-binary
// policy smoke -- after the readiness matrix has built every binary, wheel, and
// package for seven targets. Deciding it needs no binary and no analysis, only
// the tracked file list, so it belongs anywhere that runs in seconds (#2334).
//
// This checks paths only. Whether a record still resolves to a finding is a
// question for the policy run, which is the one thing that genuinely needs the
// engine.
//
// A stale path is not benign. It reports as `path_not_analyzed`, which does not
// gate, so it sits dormant -- but the record is already dead, because a finding
// identity is derived from where the code is. Repointing it at the moved file
// makes the path analyzable and the mismatch provable, turning it into
// `orphaned`, which does gate. That is what made this a release blocker rather
// than a cleanup task.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const SUPPRESSION_DOCUMENTS = [
  ".bifrost/suppressions.json",
  ".bifrost/suppressions.private.json",
];

/** Records whose `path` is absent from `trackedPaths`, in document order. */
export function staleSuppressionPaths(documents, trackedPaths) {
  const tracked = new Set(trackedPaths);
  const stale = [];
  for (const [document, contents] of documents) {
    const parsed = JSON.parse(contents);
    // Defaulting a missing key to an empty list would read a malformed or
    // renamed document as "nothing to check", which is the failure mode this
    // whole check exists to prevent. An empty array is legitimate; an absent
    // key is not.
    const records = parsed.suppressions ?? parsed.records;
    if (records === undefined || !Array.isArray(records)) {
      throw new Error(`${document} has no suppressions or records array`);
    }
    for (const record of records) {
      // A record without a path cannot be checked here. The engine reports it
      // as `path_unrecorded`, which is a different defect with its own remedy.
      if (typeof record.path !== "string" || record.path.length === 0) continue;
      if (!tracked.has(record.path)) {
        stale.push({
          document,
          path: record.path,
          policyId: record.policy_id ?? record.policyId ?? "<unknown policy>",
        });
      }
    }
  }
  return stale;
}

function main() {
  const repoRoot = process.cwd();
  const trackedPaths = execFileSync("git", ["ls-files"], {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  })
    .split("\n")
    .filter(Boolean);

  const documents = [];
  for (const relativePath of SUPPRESSION_DOCUMENTS) {
    const absolute = path.join(repoRoot, relativePath);
    // Absence is legitimate: the private document exists only in this
    // repository, and the public projection carries neither in some trees.
    if (!fs.existsSync(absolute)) continue;
    documents.push([relativePath, fs.readFileSync(absolute, "utf8")]);
  }
  if (documents.length === 0) {
    console.log("No suppression documents present; nothing to check.");
    return;
  }

  const stale = staleSuppressionPaths(documents, trackedPaths);
  if (stale.length > 0) {
    for (const entry of stale) {
      console.error(`::error::${entry.document}: ${entry.policyId} names ${entry.path}, which is not a tracked file`);
    }
    console.error(
      `${stale.length} suppression record(s) name a path that no longer exists. `
        + "Delete them. Repointing at the file's new location does not work: a "
        + "finding identity is derived from where the code is, so moving the "
        + "file moved the identity too, and the repointed record resolves to "
        + "nothing. It then reports as `orphaned` rather than "
        + "`path_not_analyzed`, which is the state that fails the gate -- so "
        + "repointing converts a dormant record into a blocking one. Re-accept "
        + "the finding at its new location if it still needs a suppression.",
    );
    process.exitCode = 1;
    return;
  }
  const checked = documents.map(([name]) => name).join(", ");
  console.log(`Every suppression record in ${checked} names a tracked file.`);
}

const thisFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === thisFile) {
  main();
}
