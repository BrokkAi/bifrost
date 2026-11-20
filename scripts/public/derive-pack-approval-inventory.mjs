#!/usr/bin/env node
// Re-derives the engine's compiled-in first-party pack approval inventory from
// the pinned official packs archive and compares it, byte for byte, with the
// committed generated file. The inventory bytes ship in the binary; the
// archive never does.
//
//   derive-pack-approval-inventory.mjs check  --bifrost BIN [--archive PATH]
//   derive-pack-approval-inventory.mjs derive --bifrost BIN --output PATH [--archive PATH]
//   derive-pack-approval-inventory.mjs update-pin --tag TAG
//
// The pin (scripts/public/pack-approval-release.json) names the release tag,
// asset and archive digest. Without --archive the asset is downloaded from the
// pinned repository's release into a fresh temporary directory and verified
// against the pin before the producer sees it. The producer runs with a
// minimal environment and a scratch working directory: no repository
// content, network or inherited PACK_* settings reach it.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const defaultPinPath = path.join(here, "pack-approval-release.json");
const SHA256 = /^[0-9a-f]{64}$/u;
const TAG = /^packs\/v\d+\.\d+\.\d+$/u;
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;

export function readPin(pinPath = defaultPinPath) {
  const pin = JSON.parse(fs.readFileSync(pinPath, "utf8"));
  for (const key of ["channel", "repository", "releaseTag", "assetName", "archiveSha256", "inventoryPath"]) {
    if (typeof pin[key] !== "string" || pin[key] === "") {
      throw new Error(`${pinPath}: missing ${key}`);
    }
  }
  if (!SHA256.test(pin.archiveSha256)) throw new Error(`${pinPath}: archiveSha256 must be 64 lowercase hex digits`);
  if (!TAG.test(pin.releaseTag)) throw new Error(`${pinPath}: releaseTag must look like packs/vX.Y.Z`);
  if (pin.assetName.includes("/") || pin.assetName.includes("..")) throw new Error(`${pinPath}: bad assetName`);
  return pin;
}

export function assetUrl(pin) {
  return `https://github.com/${pin.repository}/releases/download/${pin.releaseTag}/${pin.assetName}`;
}

export function sha256File(file) {
  return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

async function download(url, destination) {
  const response = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(300_000) });
  if (!response.ok) throw new Error(`download failed: ${url}: ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_ARCHIVE_BYTES) throw new Error(`download too large: ${url}`);
  fs.writeFileSync(destination, bytes);
  return bytes;
}

/** Fetch (or accept) the archive and refuse unless it matches the pin. */
export async function obtainArchive(pin, scratch, archiveOverride) {
  const archive = path.join(scratch, pin.assetName);
  if (archiveOverride) {
    fs.copyFileSync(archiveOverride, archive);
  } else {
    await download(assetUrl(pin), archive);
  }
  const actual = sha256File(archive);
  if (actual !== pin.archiveSha256) {
    throw new Error(`archive ${pin.assetName} digest ${actual} does not match the pinned ${pin.archiveSha256}`);
  }
  return archive;
}

/** Run the engine producer once; return the inventory bytes it wrote. */
export async function deriveInventory({ bifrost, pin, archivePath, scratch, output }) {
  const out = output ?? path.join(scratch, "inventory.json");
  const { stdout } = await execFileAsync(
    bifrost,
    [
      "prepare-pack-approval-inventory",
      "--archive", archivePath,
      "--archive-sha256", pin.archiveSha256,
      "--channel", pin.channel,
      "--release-tag", pin.releaseTag,
      "--output", out,
    ],
    { cwd: scratch, env: minimalEnv(), maxBuffer: 1024 * 1024, timeout: 600_000 },
  );
  const bytes = fs.readFileSync(out);
  let report;
  try {
    report = JSON.parse(stdout);
  } catch {
    throw new Error("producer stdout was not JSON");
  }
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (report.inventory_sha256 !== actual) {
    throw new Error(`producer reported inventory_sha256 ${report.inventory_sha256}, file hashes to ${actual}`);
  }
  return bytes;
}

function minimalEnv() {
  const env = { PATH: process.env.PATH ?? "", HOME: os.tmpdir(), BIFROST_OPEN_PACKS_DISABLE: "1" };
  if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
  return env;
}

export async function checkInventory({ bifrost, pinPath, archiveOverride, root = repoRoot }) {
  const pin = readPin(pinPath);
  const committedPath = path.resolve(root, pin.inventoryPath);
  if (!fs.existsSync(committedPath)) {
    throw new Error(`committed inventory ${pin.inventoryPath} does not exist`);
  }
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-pack-approval-"));
  try {
    const archive = await obtainArchive(pin, scratch, archiveOverride);
    const derived = await deriveInventory({ bifrost, pin, archivePath: archive, scratch });
    const committed = fs.readFileSync(committedPath);
    if (!derived.equals(committed)) {
      throw new Error(
        `${pin.inventoryPath} drifted from ${pin.releaseTag}: committed ${sha(committed)}, re-derived ${sha(derived)}. ` +
          "Regenerate it with derive-pack-approval-inventory.mjs derive.",
      );
    }
    return { releaseTag: pin.releaseTag, inventorySha256: sha(derived) };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function sha(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export async function updatePin({ tag, pinPath = defaultPinPath, fetchText, fetchBytes }) {
  if (!TAG.test(tag)) throw new Error("--tag must look like packs/vX.Y.Z");
  const old = readPin(pinPath);
  const version = tag.slice("packs/v".length);
  const assetName = old.assetName.replace(/-\d+\.\d+\.\d+-native/u, `-${version}-native`);
  const pin = { ...old, releaseTag: tag, assetName };
  const sidecar = (await fetchText(`${assetUrl(pin)}.sha256`)).trim().split(/\s+/u)[0];
  if (!SHA256.test(sidecar)) throw new Error(`published checksum for ${assetName} is malformed`);
  const bytes = await fetchBytes(assetUrl(pin));
  if (sha(bytes) !== sidecar) throw new Error(`downloaded ${assetName} does not match its published checksum`);
  pin.archiveSha256 = sidecar;
  fs.writeFileSync(pinPath, `${JSON.stringify(pin, null, 2)}\n`);
  return pin;
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    if (!rest[i]?.startsWith("--") || rest[i + 1] === undefined) throw new Error(usage());
    options[rest[i].slice(2)] = rest[i + 1];
  }
  return { command, options };
}

function usage() {
  return "usage: derive-pack-approval-inventory.mjs (check --bifrost BIN [--archive PATH] | derive --bifrost BIN --output PATH [--archive PATH] | update-pin --tag TAG)";
}

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));
  const pinPath = options.pin ? path.resolve(options.pin) : defaultPinPath;
  if (command === "check") {
    if (!options.bifrost) throw new Error(usage());
    const result = await checkInventory({
      bifrost: path.resolve(options.bifrost),
      pinPath,
      archiveOverride: options.archive && path.resolve(options.archive),
    });
    console.log(`pack approval inventory matches ${result.releaseTag} (${result.inventorySha256})`);
  } else if (command === "derive") {
    if (!options.bifrost || !options.output) throw new Error(usage());
    const pin = readPin(pinPath);
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-pack-approval-"));
    try {
      const archive = await obtainArchive(pin, scratch, options.archive && path.resolve(options.archive));
      const bytes = await deriveInventory({ bifrost: path.resolve(options.bifrost), pin, archivePath: archive, scratch });
      fs.writeFileSync(path.resolve(options.output), bytes);
      console.log(`wrote ${options.output} (${sha(bytes)})`);
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  } else if (command === "update-pin") {
    if (!options.tag) throw new Error(usage());
    const pin = await updatePin({
      tag: options.tag,
      pinPath,
      fetchText: async (url) => (await fetch(url)).text(),
      fetchBytes: async (url) => Buffer.from(await (await fetch(url)).arrayBuffer()),
    });
    console.log(`pinned ${pin.releaseTag} ${pin.archiveSha256}`);
  } else {
    throw new Error(usage());
  }
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
