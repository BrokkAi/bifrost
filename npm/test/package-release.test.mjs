import assert from "node:assert/strict";
import test from "node:test";

import {
  PLATFORMS,
  ROOT_PACKAGE,
  platformManifest,
  rootManifest,
  tarballBasename,
  versionFromTag,
} from "../scripts/package-release.mjs";

test("declares each Bifrost release target", () => {
  assert.deepEqual(
    PLATFORMS.map((platform) => platform.target),
    [
      "universal-apple-darwin",
      "x86_64-unknown-linux-gnu",
      "x86_64-unknown-linux-musl",
      "aarch64-unknown-linux-gnu",
      "aarch64-linux-android",
      "x86_64-pc-windows-msvc",
      "aarch64-pc-windows-msvc",
    ],
  );
  assert.equal(new Set(PLATFORMS.map((platform) => platform.packageName)).size, PLATFORMS.length);
});

test("derives the package version from a release tag", () => {
  assert.equal(versionFromTag("v0.8.22"), "0.8.22");
  assert.throws(() => versionFromTag("0.8.22"), /vX.Y.Z/);
});

test("pins all platform packages in the root package", () => {
  const manifest = rootManifest("0.8.22");
  assert.equal(manifest.name, ROOT_PACKAGE);
  assert.deepEqual(
    Object.values(manifest.optionalDependencies),
    PLATFORMS.map(() => "0.8.22"),
  );
  assert.deepEqual(manifest.bin, { bifrost: "bin/bifrost.js" });
});

test("sets npm platform constraints", () => {
  const platform = PLATFORMS.find((entry) => entry.target === "x86_64-unknown-linux-musl");
  const manifest = platformManifest(platform, "0.8.22");
  assert.deepEqual(manifest.os, ["linux"]);
  assert.deepEqual(manifest.cpu, ["x64"]);
  assert.deepEqual(manifest.libc, ["musl"]);
  assert.equal(manifest.preferUnplugged, true);
});

test("uses npm tarball names for scoped packages", () => {
  assert.equal(tarballBasename(ROOT_PACKAGE, "0.8.22"), "brokkai-bifrost-0.8.22.tgz");
});
