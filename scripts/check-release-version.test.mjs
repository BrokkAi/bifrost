import assert from "node:assert/strict";
import test from "node:test";

import {
  confirmReleaseVersion,
  readCargoVersion,
} from "./check-release-version.mjs";

test("reads the package version from Cargo.toml", () => {
  assert.equal(readCargoVersion('[package]\nname = "brokk-bifrost"\nversion = "0.8.7"\n'), "0.8.7");
});

test("accepts the released Cargo version", () => {
  assert.equal(confirmReleaseVersion("0.8.7", 'version = "0.8.7"\n'), "0.8.7");
});

test("rejects a different master Cargo version", () => {
  assert.throws(
    () => confirmReleaseVersion("0.8.7", 'version = "0.8.8"\n'),
    /Refusing to sync release metadata for 0\.8\.7 onto master at Cargo version 0\.8\.8/,
  );
});

test("rejects Cargo.toml without a package version", () => {
  assert.throws(() => readCargoVersion('[package]\nname = "brokk-bifrost"\n'), /Could not read package version/);
});
