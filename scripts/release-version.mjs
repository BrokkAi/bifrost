#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SEMVER_PATTERN =
  /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;

export function normalizeReleaseTag(input) {
  const supplied = input?.trim() ?? "";
  const tag = supplied.replace(/^refs\/tags\//u, "");
  if (!tag.startsWith("v")) {
    throw new Error(`Release tag must start with v, got '${tag}'.`);
  }

  const version = tag.slice(1);
  if (!SEMVER_PATTERN.test(version)) {
    throw new Error(`Release tag '${tag}' does not contain a valid semver version.`);
  }
  return { tag, version };
}

export function readCargoVersion(contents) {
  const packageSection = readTomlSection(contents, "package", "Cargo.toml");
  const matches = [
    ...packageSection.matchAll(/^\s*version\s*=\s*"([^"]+)"\s*(?:#.*)?$/gmu),
  ];
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one package version in Cargo.toml, found ${matches.length}.`,
    );
  }
  return matches[0][1];
}

export function validatePyprojectVersionInheritance(contents) {
  const projectSection = readTomlSection(contents, "project", "pyproject.toml");
  if (/^\s*version\s*=/mu.test(projectSection)) {
    throw new Error(
      'pyproject.toml declares project.version; it must inherit Cargo.toml via dynamic = ["version"].',
    );
  }

  const dynamic = projectSection.match(/^\s*dynamic\s*=\s*\[([\s\S]*?)\]/mu);
  if (!dynamic) {
    throw new Error(
      'pyproject.toml must declare project.dynamic with "version" inherited from Cargo.toml.',
    );
  }
  const values = [...dynamic[1].matchAll(/["']([^"']+)["']/gu)].map((match) => match[1]);
  if (!values.includes("version")) {
    throw new Error('pyproject.toml project.dynamic must include "version".');
  }
}

export function confirmReleaseVersion(tagInput, cargoTomlContents) {
  const release = normalizeReleaseTag(tagInput);
  const cargoVersion = readCargoVersion(cargoTomlContents);
  if (release.version !== cargoVersion) {
    throw new Error(
      `Release tag version ${release.version} does not match Cargo.toml package version ${cargoVersion}.`,
    );
  }
  return release;
}

export function checkReleaseVersion({ repoRoot = process.cwd(), tag, githubOutput } = {}) {
  const cargoVersion = readCargoVersion(readFile(repoRoot, "Cargo.toml"));
  validatePyprojectVersionInheritance(readFile(repoRoot, "pyproject.toml"));

  let release;
  if (tag !== undefined) {
    release = confirmReleaseVersion(tag, readFile(repoRoot, "Cargo.toml"));
  }
  if (githubOutput && !release) {
    throw new Error("--github-output requires --tag");
  }

  const { updates } = collectProjectionUpdates(repoRoot, cargoVersion);
  if (updates.length > 0) {
    throw new Error(
      `Release metadata is not synced to Cargo.toml version ${cargoVersion}:\n${updates.map(({ relativePath }) => `- ${relativePath}`).join("\n")}`,
    );
  }

  if (githubOutput) {
    fs.appendFileSync(
      githubOutput,
      `tag=${release.tag}\nversion=${release.version}\n`,
      "utf8",
    );
  }

  const tagSummary = release ? ` against release tag ${release.tag}` : "";
  console.log(
    `Validated Cargo version ${cargoVersion}${tagSummary}; pyproject inheritance and all release metadata projections match.`,
  );
  return { tag: release?.tag, version: cargoVersion };
}

export function syncReleaseVersion({ repoRoot = process.cwd() } = {}) {
  const version = readCargoVersion(readFile(repoRoot, "Cargo.toml"));
  validatePyprojectVersionInheritance(readFile(repoRoot, "pyproject.toml"));
  const { updates, canCopyReleaseChecksums } = collectProjectionUpdates(repoRoot, version);
  for (const update of updates) {
    fs.writeFileSync(update.absolutePath, update.contents);
  }
  if (updates.length === 0) {
    console.log(`Release metadata is already synced to ${version}.`);
  } else {
    console.log(`Synced release metadata to ${version}:`);
    for (const update of updates) {
      console.log(`- ${update.relativePath}`);
    }
    if (!canCopyReleaseChecksums) {
      console.log(
        "Note: editors/vscode/package.json archiveSha256 was left unchanged because plugins/bifrost-agent/bifrost-release.json does not yet match this version.",
      );
    }
  }
  return { updates: updates.map(({ relativePath }) => relativePath), version };
}

function collectProjectionUpdates(repoRoot, version) {
  const existingReleaseMetadata = readJson(repoRoot, "plugins/bifrost-agent/bifrost-release.json");
  const canCopyReleaseChecksums = existingReleaseMetadata.binaryVersion === version;

  const updates = [
    updateJson(repoRoot, "plugins/bifrost-agent/.codex-plugin/plugin.json", (json) => {
      json.version = version;
    }),
    updateJson(repoRoot, "plugins/bifrost-agent/.claude-plugin/plugin.json", (json) => {
      json.version = version;
    }),
    updateJson(repoRoot, "plugins/bifrost-agent/.cursor-plugin/plugin.json", (json) => {
      json.version = version;
    }),
    updateJson(repoRoot, ".cursor-plugin/marketplace.json", (json) => {
      json.metadata ??= {};
      json.metadata.version = version;
      for (const plugin of json.plugins ?? []) {
        if (plugin.version !== undefined) {
          plugin.version = version;
        }
      }
    }),
    updateJson(repoRoot, "plugins/bifrost-agent/bifrost-release.json", (json) => {
      json.binaryVersion = version;
    }),
    updateJson(repoRoot, "plugins/bifrost-agent/package.json", (json) => {
      json.version = version;
    }),
    updateJson(repoRoot, "plugins/bifrost-agent/package-lock.json", (json) => {
      json.version = version;
      json.packages ??= {};
      json.packages[""] ??= {};
      json.packages[""].version = version;
    }),
    updateText(repoRoot, "plugins/bifrost-agent/README.md", (source) => {
      const pattern = /pi install npm:@brokk\/bifrost-agent@[^\s]+/gu;
      const matches = source.match(pattern) ?? [];
      if (matches.length !== 1) {
        throw new Error(
          `Expected exactly one Pi package install command, found ${matches.length}.`,
        );
      }
      return source.replace(pattern, `pi install npm:@brokk/bifrost-agent@${version}`);
    }),
    updateJson(
      repoRoot,
      "plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/bifrost-release.json",
      (json) => {
        json.binaryVersion = version;
      },
    ),
    updateJson(repoRoot, "editors/vscode/package.json", (json) => {
      json.version = version;
      json.bifrost ??= {};
      json.bifrost.binaryVersion = version;
      if (canCopyReleaseChecksums) {
        json.bifrost.archiveSha256 = existingReleaseMetadata.archiveSha256;
      }
    }),
    updateJson(repoRoot, "editors/vscode/package-lock.json", (json) => {
      json.version = version;
      json.packages ??= {};
      json.packages[""] ??= {};
      json.packages[""].version = version;
    }),
    updateText(repoRoot, "docs/src/content/docs/rust-library.md", (contents) => {
      const pattern = /^brokk-bifrost = "[^"]+"$/gmu;
      const matches = contents.match(pattern) ?? [];
      if (matches.length !== 1) {
        throw new Error(
          `Expected exactly one brokk-bifrost dependency example, found ${matches.length}.`,
        );
      }
      return contents.replace(pattern, `brokk-bifrost = "${version}"`);
    }),
  ].filter(Boolean);

  return { updates, canCopyReleaseChecksums };
}

function readTomlSection(contents, section, sourceName) {
  const lines = contents.split(/\r?\n/u);
  const heading = new RegExp(`^\\s*\\[${escapeRegExp(section)}\\]\\s*(?:#.*)?$`, "u");
  const start = lines.findIndex((line) => heading.test(line));
  if (start === -1) {
    throw new Error(`${sourceName} does not contain [${section}].`);
  }
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^\s*\[/.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start + 1, end).join("\n");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function readFile(repoRoot, relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function readJson(repoRoot, relativePath) {
  return JSON.parse(readFile(repoRoot, relativePath));
}

function updateJson(repoRoot, relativePath, mutate) {
  const original = readFile(repoRoot, relativePath);
  const json = JSON.parse(original);
  mutate(json);
  const lineEnding = original.includes("\r\n") ? "\r\n" : "\n";
  const serialized = `${JSON.stringify(json, null, 2).replaceAll("\n", lineEnding)}${lineEnding}`;
  return updateText(repoRoot, relativePath, () => serialized, original);
}

function updateText(repoRoot, relativePath, mutate, original = undefined) {
  const absolutePath = path.join(repoRoot, relativePath);
  const current = original ?? fs.readFileSync(absolutePath, "utf8");
  const next = mutate(current);
  if (next === current) {
    return null;
  }
  return { absolutePath, contents: next, relativePath };
}

function parseCheckArgs(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option !== "--tag" && option !== "--github-output") {
      throw new Error(
        "Usage: node scripts/release-version.mjs check [--tag TAG] [--github-output PATH]",
      );
    }
    const value = args[index + 1];
    if (!value) {
      throw new Error(`${option} requires a value.`);
    }
    const key = option === "--tag" ? "tag" : "githubOutput";
    if (options[key] !== undefined) {
      throw new Error(`${option} may only be provided once.`);
    }
    options[key] = value;
    index += 1;
  }
  return options;
}

function main(args) {
  const [command, ...rest] = args;
  if (command === "check") {
    checkReleaseVersion(parseCheckArgs(rest));
    return;
  }
  if (command === "sync" && rest.length === 0) {
    syncReleaseVersion();
    return;
  }
  throw new Error(
    "Usage: node scripts/release-version.mjs check [--tag TAG] [--github-output PATH]\n       node scripts/release-version.mjs sync",
  );
}

const thisFile = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === thisFile) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
