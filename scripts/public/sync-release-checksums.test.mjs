import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import { SUPPORTED_TARGETS } from "../../plugins/bifrost-agent/bin/bifrost-launcher.mjs";
import {
  CANONICAL_RELEASE_METADATA,
  DERIVED_CHECKSUM_PROJECTIONS,
  archiveNameFor,
  assertAllowedUpdates,
  checksumsAlreadyMatch,
  collectSidecarChecksums,
  readSidecarDigest,
} from "./sync-release-checksums.mjs";

const digestFor = (seed) => seed.repeat(64).slice(0, 64);

function checksumMap(seed) {
  return Object.fromEntries(
    SUPPORTED_TARGETS.map((target, index) => [target, digestFor(String(index + 1) + seed)]),
  );
}

async function stageSidecars(version, checksums) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-sidecar-test-"));
  for (const target of SUPPORTED_TARGETS) {
    const archive = archiveNameFor(target, version);
    await fs.writeFile(path.join(dir, `${archive}.sha256`), `${checksums[target]}  ${archive}\n`);
  }
  return dir;
}

test("stale metadata that is internally consistent is not treated as synced", () => {
  // The exact v0.10.3 failure. Every version projection agreed, so the
  // release-version update set was empty, while the tracked darwin hash was the
  // superseded e5a2fdd5 rather than the qualified 4ebd001b. Anchoring
  // idempotency to the sidecars is what catches this.
  const stale = {
    binaryVersion: "0.10.3",
    archiveSha256: {
      "aarch64-pc-windows-msvc": "35d03fd4a041366f95b9b0f5f6b72ddf73e1ef671c6c932fb75fd49dda1113bb",
      "aarch64-unknown-linux-gnu": "5578286a4c82a4f757f24d478bbea135bb68c8c17d2a423885ac5df7c9250ad2",
      "universal-apple-darwin": "e5a2fdd5c11dd3d4fce6b06f580cadca56439178345402bf565fb3551d86ee85",
      "x86_64-pc-windows-msvc": "96b7b7769207ff8f5307298fc66d68f0f11b1e672f9cb20e737ef14595926b07",
      "x86_64-unknown-linux-gnu": "6d1c09bc9c8a40cfce5c347c61ec23e362a5d705fb309eeb45fa1c809a568025",
    },
  };
  const promoted = {
    ...stale.archiveSha256,
    "universal-apple-darwin": "4ebd001b2f4f3f6a5a1e4d0e5f6c7b8a9d0c1b2a3e4f5061728394a5b6c7d8e9",
  };

  assert.equal(checksumsAlreadyMatch(stale, promoted), false);
  assert.equal(checksumsAlreadyMatch(stale, stale.archiveSha256), true);
});

test("a target missing from tracked metadata is never reported as matching", () => {
  const promoted = checksumMap("a");
  const partial = { archiveSha256: { ...promoted } };
  delete partial.archiveSha256["universal-apple-darwin"];
  assert.equal(checksumsAlreadyMatch(partial, promoted), false);
});

test("the canonical file is written directly, never through the derived allowlist", () => {
  // Single-writer invariant: release-version projects the derived copies from
  // the canonical file's bytes, so listing it here would let sync overwrite the
  // hashes this workflow just committed.
  assert.ok(!DERIVED_CHECKSUM_PROJECTIONS.includes(CANONICAL_RELEASE_METADATA));
});

test("sync output confined to the derived projections is accepted", () => {
  assert.doesNotThrow(() => assertAllowedUpdates([]));
  assert.doesNotThrow(() => assertAllowedUpdates(["editors/vscode/package.json"]));
  assert.doesNotThrow(() => assertAllowedUpdates([...DERIVED_CHECKSUM_PROJECTIONS]));
});

test("a version edit smuggled into the sync aborts before any commit", () => {
  assert.throws(
    () => assertAllowedUpdates(["editors/vscode/package.json", "CITATION.cff"]),
    /outside the checksum projection allowlist.*CITATION\.cff/su,
  );
  assert.throws(
    () => assertAllowedUpdates(["Cargo.toml"]),
    /outside the checksum projection allowlist/u,
  );
});

test("windows targets carry zip archives and the rest tarballs", () => {
  assert.equal(archiveNameFor("x86_64-pc-windows-msvc", "0.10.4"), "bifrost-v0.10.4-x86_64-pc-windows-msvc.zip");
  assert.equal(
    archiveNameFor("universal-apple-darwin", "0.10.4"),
    "bifrost-v0.10.4-universal-apple-darwin.tar.gz",
  );
});

test("promoted sidecars are read for every supported target", async () => {
  const expected = checksumMap("b");
  const dir = await stageSidecars("0.10.4", expected);
  assert.deepEqual(collectSidecarChecksums(dir, "0.10.4"), expected);
});

test("a missing sidecar fails closed rather than syncing a partial matrix", async () => {
  const expected = checksumMap("c");
  const dir = await stageSidecars("0.10.4", expected);
  await fs.rm(path.join(dir, `${archiveNameFor("universal-apple-darwin", "0.10.4")}.sha256`));
  assert.throws(
    () => collectSidecarChecksums(dir, "0.10.4"),
    /Missing promoted sidecar bifrost-v0\.10\.4-universal-apple-darwin\.tar\.gz\.sha256/u,
  );
});

test("a sidecar naming a different archive is rejected", () => {
  // The launcher's parseSha256 owns this contract, so the App refuses exactly
  // what an install would refuse, with the same checksum_mismatch code.
  assert.throws(
    () => readSidecarDigest(`${digestFor("d")}  bifrost-v0.10.4-x86_64-unknown-linux-gnu.tar.gz\n`, "bifrost-v0.10.4-universal-apple-darwin.tar.gz"),
    (error) => error.code === "checksum_mismatch" && /No SHA-256 checksum found/u.test(error.message),
  );
});

test("binary-mode sidecars from coreutils are accepted", () => {
  const digest = digestFor("e");
  assert.equal(
    readSidecarDigest(`${digest} *bifrost-v0.10.4-universal-apple-darwin.tar.gz\n`, "bifrost-v0.10.4-universal-apple-darwin.tar.gz"),
    digest,
  );
});

test("a malformed sidecar digest is rejected", () => {
  assert.throws(
    () => readSidecarDigest("notahash  bifrost-v0.10.4-universal-apple-darwin.tar.gz\n", "bifrost-v0.10.4-universal-apple-darwin.tar.gz"),
    (error) => error.code === "checksum_mismatch",
  );
});
