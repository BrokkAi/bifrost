import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  qualifiedFile,
  qualifiedFiles,
  verifyQualifiedRelease,
} from "./verify-qualified-release.mjs";
import { generateManifest } from "./release-qualification.mjs";

const commit = "a".repeat(40);
const identity = {
  release: { version: "0.10.3", tag: "v0.10.3" },
  source: { repository: "BrokkAi/bifrost", publicCommit: commit },
  qualification: { workflow: "release-readiness.yml", runId: 123, runAttempt: 2 },
};

test("verifies a bundle and exposes only manifest-backed absolute paths", async () => {
  const fixture = await fixtureBundle();
  const verified = verifyQualifiedRelease({
    ...fixture,
    repository: "BrokkAi/bifrost",
    commit,
    version: "0.10.3",
    runId: 123,
    runAttempt: 2,
  });

  assert.equal(verified.identity.release.tag, "v0.10.3");
  assert.equal(qualifiedFile(verified, "bifrost-v0.10.3-linux.tar.gz"), fixture.binaryPath);
  assert.deepEqual(
    qualifiedFiles(verified, (entry) => entry.kind === "wheel").map((file) => path.basename(file)),
    ["brokk_bifrost_searchtools-0.10.3-py3-none-any.whl"],
  );
});

test("rejects a manifest digest mismatch before accepting paths", async () => {
  const fixture = await fixtureBundle();
  assert.throws(
    () => verifyQualifiedRelease({
      ...fixture,
      repository: "BrokkAi/bifrost",
      commit,
      version: "0.10.3",
      expectedManifestSha256: "0".repeat(64),
    }),
    /manifest checksum mismatch/u,
  );
});

test("rejects paths that are absent from the verified manifest", async () => {
  const fixture = await fixtureBundle();
  const verified = verifyQualifiedRelease({
    ...fixture,
    repository: "BrokkAi/bifrost",
    commit,
    version: "0.10.3",
  });
  assert.throws(() => qualifiedFile(verified, "not-qualified.tgz"), /not in the verified manifest/u);
});

async function fixtureBundle() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-qualified-release-"));
  const bundleDir = path.join(root, "bundle");
  await fs.mkdir(bundleDir);
  const binaryPath = path.join(bundleDir, "bifrost-v0.10.3-linux.tar.gz");
  await fs.writeFile(binaryPath, "binary");
  await fs.writeFile(path.join(bundleDir, "brokk_bifrost_searchtools-0.10.3-py3-none-any.whl"), "wheel");
  const manifestPath = path.join(bundleDir, "release-qualification.json");
  generateManifest({ bundleDir, identity, outputPath: manifestPath });
  return { bundleDir, manifestPath, binaryPath };
}
