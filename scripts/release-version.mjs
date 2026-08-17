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
  const packageSection = readTomlSection(contents, "workspace.package", "Cargo.toml");
  const matches = [
    ...packageSection.matchAll(/^\s*version\s*=\s*"([^"]+)"\s*(?:#.*)?$/gmu),
  ];
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one workspace package version in Cargo.toml, found ${matches.length}.`,
    );
  }
  return matches[0][1];
}

export function validateWorkspaceVersionInheritance(repoRoot) {
  for (const relativePath of RELEASED_CARGO_MANIFESTS) {
    const packageSection = readTomlSection(readFile(repoRoot, relativePath), "package", relativePath);
    if (!/^\s*version\.workspace\s*=\s*true\s*(?:#.*)?$/mu.test(packageSection)) {
      throw new Error(`${relativePath} must inherit version.workspace = true.`);
    }
    if (/^\s*version\s*=\s*"/mu.test(packageSection)) {
      throw new Error(`${relativePath} must not declare an independent package version.`);
    }
  }
}

export const RELEASED_CARGO_MANIFESTS = [
  "Cargo.toml",
  "crates/bifrost-core/Cargo.toml",
  "crates/bifrost-cpp/Cargo.toml",
  "crates/bifrost-csharp/Cargo.toml",
  "crates/bifrost-go/Cargo.toml",
  "crates/bifrost-js-ts/Cargo.toml",
  "crates/bifrost-jvm/Cargo.toml",
  "crates/bifrost-php/Cargo.toml",
  "crates/bifrost-python/Cargo.toml",
  "crates/bifrost-ruby/Cargo.toml",
  "crates/bifrost-rust/Cargo.toml",
  "crates/bifrost-rql/Cargo.toml",
  "crates/bifrost-analysis/Cargo.toml",
  "crates/bifrost-nlp/Cargo.toml",
  "crates/bifrost-policy/Cargo.toml",
  "crates/bifrost-runtime/Cargo.toml",
  "crates/bifrost-mcp/Cargo.toml",
  "crates/bifrost-lsp/Cargo.toml",
  "crates/bifrost-semantic-packs/Cargo.toml",
];

export const THIRD_PARTY_SEMANTIC_PACK_SPECS = [
  "semantic-packs/jvm/temurin-jdk-21.0.8+9.json",
  "semantic-packs/jvm/kotlin-stdlib-2.2.20.json",
  "semantic-packs/jvm/scala-library-2.13.16.json",
  "semantic-packs/python/typeshed-stdlib-2026.8.8.json",
];

export const BIFROST_OWNED_SEMANTIC_PACK_SPECS = [
  "semantic-packs/framework-decls/bifrost.jdk-framework-decls.json",
  "semantic-packs/framework-decls/staged/bifrost.javax.servlet-api-framework-decls.json",
  "semantic-packs/golden-core/bifrost.jdk-golden-summaries.json",
  "semantic-packs/sanitizers/bifrost.esapi-sanitizers.json",
  "semantic-packs/sanitizers/bifrost.java-sanitizers.json",
  "semantic-packs/sanitizers/staged/bifrost.commons-text-sanitizers.json",
  "semantic-packs/sanitizers/staged/bifrost.encoder-sanitizers.json",
  "semantic-packs/sanitizers/staged/bifrost.esapi-sanitizers.json",
  "semantic-packs/sanitizers/staged/bifrost.guava-sanitizers.json",
  "semantic-packs/sanitizers/staged/bifrost.spring-web-sanitizers.json",
];

export const BIFROST_OWNED_SEMANTIC_PACK_REQUIREMENT_SOURCES = [
  "crates/bifrost-semantic-packs/src/summary_foundry/framework_pack.rs",
  "crates/bifrost-semantic-packs/src/summary_foundry/golden_pack.rs",
  "crates/bifrost-semantic-packs/src/summary_foundry/sanitizer_pack.rs",
];

export const RELEASE_BUNDLE_SPECS = [
  ...THIRD_PARTY_SEMANTIC_PACK_SPECS,
  ...BIFROST_OWNED_SEMANTIC_PACK_SPECS,
];

export function syncBifrostDependencyVersions(contents, version) {
  return contents.replace(
    /^(\s*brokk-bifrost-[a-z-]+\s*=\s*\{[^\n]*\bversion\s*=\s*")=[^"]+("[^\n]*\}\s*(?:#.*)?)$/gmu,
    `$1=${version}$2`,
  );
}

export function syncCitationVersion(contents, version) {
  const pattern = /^(version:[ \t]*)"[^"\r\n]*"([ \t]*(?:#[^\r\n]*)?)(\r?)$/gmu;
  const matches = [...contents.matchAll(pattern)];
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one top-level double-quoted version in CITATION.cff, found ${matches.length}.`,
    );
  }
  return contents.replace(pattern, (_match, prefix, suffix, carriageReturn) =>
    `${prefix}"${version}"${suffix}${carriageReturn}`,
  );
}

export function syncBifrostCompatibilityRequirementSource(contents, version, sourceName) {
  const pattern = /^(const BIFROST_REQUIREMENT: &str = ")([^"\r\n]+)(";[ \t]*)(\r?)$/gmu;
  const matches = [...contents.matchAll(pattern)];
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one BIFROST_REQUIREMENT constant in ${sourceName}, found ${matches.length}.`,
    );
  }
  return contents.replace(
    pattern,
    (_match, prefix, requirement, suffix, carriageReturn) =>
      `${prefix}${syncCompatibilityRequirement(requirement, version, sourceName)}${suffix}${carriageReturn}`,
  );
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
      `Release tag version ${release.version} does not match Cargo.toml workspace package version ${cargoVersion}.`,
    );
  }
  return release;
}

export function checkReleaseVersion({ repoRoot = process.cwd(), tag, githubOutput } = {}) {
  const cargoVersion = readCargoVersion(readFile(repoRoot, "Cargo.toml"));
  validateWorkspaceVersionInheritance(repoRoot);
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
  validateWorkspaceVersionInheritance(repoRoot);
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
    updateText(repoRoot, "CITATION.cff", (contents) =>
      syncCitationVersion(contents, version),
    ),
    ...RELEASED_CARGO_MANIFESTS.map((relativePath) =>
      updateText(repoRoot, relativePath, (contents) =>
        syncBifrostDependencyVersions(contents, version),
      ),
    ),
    ...BIFROST_OWNED_SEMANTIC_PACK_REQUIREMENT_SOURCES.map((relativePath) =>
      updateText(repoRoot, relativePath, (contents) =>
        syncBifrostCompatibilityRequirementSource(contents, version, relativePath),
      ),
    ),
    ...RELEASE_BUNDLE_SPECS.map((relativePath) =>
      updateJson(repoRoot, relativePath, (json) => {
        json.compatibility ??= {};
        json.compatibility.bifrost = syncCompatibilityRequirement(
          json.compatibility.bifrost,
          version,
          relativePath,
        );
      }),
    ),
    updateJson(repoRoot, "plugins/bifrost-agent/.claude-plugin/plugin.json", (json) => {
      json.version = version;
    }),
    updateJson(repoRoot, "plugins/bifrost-agent/.codex-plugin/plugin.json", (json) => {
      json.version = version;
    }),
    updateJson(repoRoot, "plugins/bifrost-agent/.cursor-plugin/plugin.json", (json) => {
      json.version = version;
    }),
    updateJson(repoRoot, "plugins/bifrost-agent/plugin.json", (json) => {
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
      const previousPreferred = json.binaryVersion;
      json.binaryVersion = version;
      if (!sameMinorSeries(previousPreferred, version)) {
        json.minimumBinaryVersion = version;
      } else {
        json.minimumBinaryVersion ??= version;
      }
      json.allowPrerelease ??= false;
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
    updateJson(repoRoot, "editors/vscode/package.json", (json) => {
      json.version = version;
      json.bifrost ??= {};
      json.bifrost.binaryVersion = version;
      json.bifrost.minimumBinaryVersion = sameMinorSeries(
        existingReleaseMetadata.binaryVersion,
        version,
      )
        ? (existingReleaseMetadata.minimumBinaryVersion ?? version)
        : version;
      json.bifrost.allowPrerelease = existingReleaseMetadata.allowPrerelease ?? false;
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

function sameMinorSeries(left, right) {
  const leftParts = String(left ?? "").split(".");
  const rightParts = String(right ?? "").split(".");
  return leftParts.length >= 2
    && rightParts.length >= 2
    && leftParts[0] === rightParts[0]
    && leftParts[1] === rightParts[1];
}

function syncCompatibilityRequirement(requirement, version, sourceName) {
  if (typeof requirement !== "string") {
    throw new Error(`${sourceName} does not declare compatibility.bifrost.`);
  }
  const versionMatch = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version);
  if (!versionMatch) {
    throw new Error(`Cargo version is not semantic: ${version}`);
  }
  const major = Number(versionMatch[1]);
  const minor = Number(versionMatch[2]);
  const upper = major === 0 ? `0.${minor + 1}.0` : `${major + 1}.0.0`;
  const upperPattern = /,\s*<\d+\.\d+\.\d+$/u;
  if (!upperPattern.test(requirement)) {
    throw new Error(`${sourceName} compatibility.bifrost has no exclusive upper bound.`);
  }
  return requirement.replace(upperPattern, `, <${upper}`);
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
  if (command === "print" && rest.length === 0) {
    console.log(readCargoVersion(readFile(process.cwd(), "Cargo.toml")));
    return;
  }
  throw new Error(
    "Usage: node scripts/release-version.mjs check [--tag TAG] [--github-output PATH]\n       node scripts/release-version.mjs sync\n       node scripts/release-version.mjs print",
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
