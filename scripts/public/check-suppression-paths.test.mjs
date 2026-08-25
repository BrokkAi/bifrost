import assert from "node:assert/strict";
import test from "node:test";

import { staleSuppressionPaths } from "./check-suppression-paths.mjs";

const tracked = [
  "scripts/public/release-qualification.mjs",
  "crates/bifrost-flow/src/value_flow/client.rs",
];

function document(records) {
  return [[".bifrost/suppressions.json", JSON.stringify({ suppressions: records })]];
}

test("a record naming a tracked file is accepted", () => {
  const stale = staleSuppressionPaths(
    document([{ policy_id: "p", path: "scripts/public/release-qualification.mjs" }]),
    tracked,
  );
  assert.deepEqual(stale, []);
});

// The exact shape of the v0.10.6 blocker: `scripts/` split moved the file and
// the record kept the old path, so the acceptance stopped applying silently.
test("a record left behind by a file move is reported with its policy", () => {
  const stale = staleSuppressionPaths(
    document([{ policy_id: "bifrost.performance.file-read-in-loop", path: "scripts/release-qualification.mjs" }]),
    tracked,
  );
  assert.equal(stale.length, 1);
  assert.equal(stale[0].path, "scripts/release-qualification.mjs");
  assert.equal(stale[0].policyId, "bifrost.performance.file-read-in-loop");
  assert.equal(stale[0].document, ".bifrost/suppressions.json");
});

// `path_unrecorded` is a different defect with a different remedy, and the
// engine already reports it. Failing here would attribute it to the wrong cause.
test("a record without a path is not treated as stale", () => {
  assert.deepEqual(staleSuppressionPaths(document([{ policy_id: "p" }]), tracked), []);
  assert.deepEqual(staleSuppressionPaths(document([{ policy_id: "p", path: "" }]), tracked), []);
});

test("every stale record is reported, not just the first", () => {
  const stale = staleSuppressionPaths(
    document([
      { policy_id: "a", path: "gone/one.rs" },
      { policy_id: "b", path: "crates/bifrost-flow/src/value_flow/client.rs" },
      { policy_id: "c", path: "gone/two.rs" },
    ]),
    tracked,
  );
  assert.deepEqual(stale.map((entry) => entry.path), ["gone/one.rs", "gone/two.rs"]);
});

test("the legacy records key is accepted alongside suppressions", () => {
  const stale = staleSuppressionPaths(
    [[".bifrost/suppressions.private.json", JSON.stringify({ records: [{ policy_id: "p", path: "gone.rs" }] })]],
    tracked,
  );
  assert.equal(stale.length, 1);
  assert.equal(stale[0].document, ".bifrost/suppressions.private.json");
});

test("a document with neither key is a malformed document, not an empty one", () => {
  assert.throws(
    () => staleSuppressionPaths([[".bifrost/suppressions.json", JSON.stringify({})]], tracked),
    /no suppressions or records array/u,
  );
});
