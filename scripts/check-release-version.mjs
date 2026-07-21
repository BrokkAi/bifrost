#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function readCargoVersion(contents) {
  const match = contents.match(/^version\s*=\s*"([^"]+)"$/m);
  if (!match) {
    throw new Error("Could not read package version from Cargo.toml");
  }
  return match[1];
}

export function confirmReleaseVersion(expectedVersion, cargoTomlContents) {
  if (!expectedVersion) {
    throw new Error("Expected release version is required");
  }
  const cargoVersion = readCargoVersion(cargoTomlContents);
  if (cargoVersion !== expectedVersion) {
    throw new Error(
      `Refusing to sync release metadata for ${expectedVersion} onto master at Cargo version ${cargoVersion}.`,
    );
  }
  return cargoVersion;
}

const thisFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === thisFile) {
  const expectedVersion = process.argv[2];
  if (!expectedVersion || process.argv.length !== 3) {
    throw new Error("Usage: check-release-version.mjs <expected-version>");
  }
  const cargoToml = fs.readFileSync("Cargo.toml", "utf8");
  const cargoVersion = confirmReleaseVersion(expectedVersion, cargoToml);
  console.log(`Master Cargo version ${cargoVersion} matches the released version.`);
}
