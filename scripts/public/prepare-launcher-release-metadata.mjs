#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { SUPPORTED_TARGETS } from "../../plugins/bifrost-agent/bin/bifrost-launcher.mjs";

const supportedTargetSet = new Set(SUPPORTED_TARGETS);

const options = parseArgs(process.argv.slice(2));
const version = required(options.version, "version");
const distDir = path.resolve(required(options.dist, "dist"));
const pluginReleasePath = path.resolve(required(options.pluginRelease, "plugin-release"));
const archiveSha256 = readArchiveHashes(distDir, version);
const pluginRelease = JSON.parse(fs.readFileSync(pluginReleasePath, "utf8"));
const minimumBinaryVersion = sameMinorSeries(pluginRelease.binaryVersion, version)
  ? (pluginRelease.minimumBinaryVersion ?? version)
  : version;

pluginRelease.binaryVersion = version;
pluginRelease.minimumBinaryVersion = minimumBinaryVersion;
pluginRelease.allowPrerelease = pluginRelease.allowPrerelease ?? false;
pluginRelease.archiveSha256 = archiveSha256;
fs.writeFileSync(pluginReleasePath, `${JSON.stringify(pluginRelease, null, 2)}\n`);

function readArchiveHashes(distDir, version) {
  const hashes = {};

  for (const entry of fs.readdirSync(distDir)) {
    if (!entry.endsWith(".sha256")) {
      continue;
    }

    let target = entry.slice(0, -".sha256".length);
    target = target.replace(new RegExp(`^bifrost-v${escapeRegExp(version)}-`), "");
    target = target.replace(/\.tar\.gz$|\.zip$/, "");
    if (!supportedTargetSet.has(target)) {
      continue;
    }

    const checksumText = fs.readFileSync(path.join(distDir, entry), "utf8").trim();
    const hash = checksumText.split(/\s+/)[0];
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      throw new Error(`Invalid SHA-256 in ${entry}: ${hash}`);
    }
    hashes[target] = hash;
  }

  for (const target of SUPPORTED_TARGETS) {
    if (!hashes[target]) {
      throw new Error(`Missing release checksum for ${target}`);
    }
  }

  return hashes;
}

function parseArgs(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("Usage: prepare-launcher-release-metadata.mjs --version <version> --dist <dist-dir> --plugin-release <bifrost-release.json>");
    }
    options[toCamelCase(key.slice(2))] = value;
  }
  return options;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
}

function required(value, name) {
  if (!value) {
    throw new Error(`Missing required --${name}`);
  }
  return value;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sameMinorSeries(left, right) {
  const leftParts = String(left ?? "").split(".");
  const rightParts = String(right ?? "").split(".");
  return leftParts.length >= 2
    && rightParts.length >= 2
    && leftParts[0] === rightParts[0]
    && leftParts[1] === rightParts[1];
}
