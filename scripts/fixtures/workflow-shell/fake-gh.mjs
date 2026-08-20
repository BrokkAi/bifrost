// Wiring for the `gh` double in this directory, shared by the release-readiness
// and metadata-sync script suites.
//
// The whole route table travels as one JSON document rather than a file per
// endpoint. That keeps the double's lookup a plain jq query, and keeps this
// side free of the per-route encode loop an earlier version had.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURE_BIN = fileURLToPath(new URL(".", import.meta.url));

/**
 * Put the `gh` double on PATH, answering `routes` (an endpoint-keyed object of
 * response bodies) and exiting `workflowRun` / `runWatch` for the two
 * non-`api` subcommands.
 *
 * Returns the environment to merge into the child, and a `calls()` reader over
 * what the double was asked.
 */
export function fakeGhEnv(dir, { routes = {}, workflowRun = 0, runWatch = 0 } = {}) {
  const routeFile = path.join(dir, "gh-routes.json");
  fs.writeFileSync(routeFile, JSON.stringify(routes), "utf8");
  const callLog = path.join(dir, "gh-calls.log");
  fs.writeFileSync(callLog, "");
  return {
    env: {
      PATH: `${FIXTURE_BIN}${path.delimiter}${process.env.PATH}`,
      FAKE_GH_ROUTES: routeFile,
      FAKE_GH_CALLS: callLog,
      FAKE_GH_WORKFLOW_RUN_EXIT: String(workflowRun),
      FAKE_GH_RUN_WATCH_EXIT: String(runWatch),
    },
    calls: () =>
      fs
        .readFileSync(callLog, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => line.split("\0").filter(Boolean)),
  };
}

/** Serve `files` (name -> contents) to the `curl` double in this directory. */
export function fakeCurlEnv(dir, files) {
  const served = path.join(dir, "served");
  fs.mkdirSync(served, { recursive: true });
  for (const [name, contents] of Object.entries(files)) {
    fs.writeFileSync(path.join(served, name), contents);
  }
  return { FAKE_CURL_ASSETS: served };
}
