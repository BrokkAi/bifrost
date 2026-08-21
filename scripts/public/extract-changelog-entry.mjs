#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { normalizeReleaseTag } from "./release-version.mjs";

const scriptPath = fileURLToPath(import.meta.url);

export function extractChangelogEntry(
  contents,
  version,
  { requireDate = false } = {},
) {
  try {
    normalizeReleaseTag(`v${version}`);
  } catch {
    throw new Error(`Invalid release version: ${version}`);
  }

  const lines = contents.replaceAll("\r\n", "\n").split("\n");
  const headingPrefix = `## [${version}] - `;
  const entryStarts = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].startsWith(headingPrefix)) {
      entryStarts.push(index);
    }
  }

  if (entryStarts.length === 0) {
    throw new Error(`CHANGELOG.md has no entry for ${version}.`);
  }
  if (entryStarts.length !== 1) {
    throw new Error(`CHANGELOG.md has multiple entries for ${version}.`);
  }

  const start = entryStarts[0];
  const releaseDate = lines[start].slice(headingPrefix.length);
  if (releaseDate !== "Unreleased" && !/^\d{4}-\d{2}-\d{2}$/u.test(releaseDate)) {
    throw new Error(
      `CHANGELOG.md entry ${version} must use YYYY-MM-DD or Unreleased.`,
    );
  }
  if (requireDate && releaseDate === "Unreleased") {
    throw new Error(`CHANGELOG.md entry ${version} must have a release date.`);
  }

  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (lines[index].startsWith("## ")) {
      end = index;
      break;
    }
  }

  const body = lines.slice(start + 1, end).join("\n").trim();
  if (body.length === 0) {
    throw new Error(`CHANGELOG.md entry ${version} is empty.`);
  }
  return `${body}\n`;
}

export function main(args) {
  const options = parseArgs(args);
  const version = required(options.version, "version");
  const changelogPath = path.resolve(
    options.changelog
      ?? fileURLToPath(new URL("../../CHANGELOG.md", import.meta.url)),
  );
  const body = extractChangelogEntry(
    fs.readFileSync(changelogPath, "utf8"),
    version,
    { requireDate: options.requireDate === true },
  );

  if (options.output === undefined) {
    process.stdout.write(body);
    return;
  }
  fs.writeFileSync(path.resolve(options.output), body, { flag: "wx" });
}

function parseArgs(args) {
  const parsed = {};
  for (let index = 0; index < args.length;) {
    const key = args[index];
    if (key === "--require-date") {
      if (parsed.requireDate !== undefined) {
        throw new Error(`Unknown or repeated option: ${key}`);
      }
      parsed.requireDate = true;
      index += 1;
      continue;
    }
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(
        "Usage: extract-changelog-entry.mjs --version X.Y.Z [--changelog PATH] [--output PATH] [--require-date]",
      );
    }
    const name = key.slice(2);
    if (
      !["version", "changelog", "output"].includes(name)
      || parsed[name] !== undefined
    ) {
      throw new Error(`Unknown or repeated option: ${key}`);
    }
    parsed[name] = value;
    index += 2;
  }
  return parsed;
}

function required(value, name) {
  if (!value) {
    throw new Error(`Missing required --${name}`);
  }
  return value;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === scriptPath) {
  main(process.argv.slice(2));
}
