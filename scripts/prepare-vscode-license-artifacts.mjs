#!/usr/bin/env node

import { createHash } from "node:crypto";
import { copyFile, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const extensionRoot = path.join(repositoryRoot, "editors", "vscode");
const lockPath = path.join(extensionRoot, "package-lock.json");
const outputPath = path.join(extensionRoot, "THIRD_PARTY_LICENSES.txt");
const legalFilePattern = /^(licen[cs]e|copying|copyright|notice)(\..*)?$/i;

function declaredLicense(packageJson, lockEntry) {
  const value = packageJson.license ?? lockEntry.license;
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  if (value && typeof value.type === "string" && value.type.trim()) {
    return value.type.trim();
  }
  throw new Error(
    `${packageJson.name}@${packageJson.version} has no declared license`,
  );
}

function repositoryUrl(packageJson, lockEntry) {
  const repository = packageJson.repository;
  const raw =
    (typeof repository === "string" ? repository : repository?.url) ??
    packageJson.homepage ??
    lockEntry.resolved;
  if (typeof raw !== "string") {
    return "not declared";
  }
  return raw
    .replace(/^git\+/, "")
    .replace(/^git:\/\//, "https://")
    .replace(/\.git$/, "");
}

async function packageNotice(packagePath, lockEntry) {
  const packageJson = JSON.parse(
    await readFile(path.join(packagePath, "package.json"), "utf8"),
  );
  const names = (await readdir(packagePath))
    .filter((name) => legalFilePattern.test(name))
    .sort((left, right) => left.localeCompare(right));

  if (names.length === 0) {
    throw new Error(
      `${packageJson.name}@${packageJson.version} has no top-level license or notice file`,
    );
  }

  const sections = [];
  for (const name of names) {
    const text = (
      await readFile(path.join(packagePath, name), "utf8")
    ).trimEnd();
    if (text) {
      sections.push(`--- ${name} ---\n${text}`);
    }
  }
  if (sections.length === 0) {
    throw new Error(
      `${packageJson.name}@${packageJson.version} has only empty legal files`,
    );
  }

  return {
    name: packageJson.name,
    version: packageJson.version,
    license: declaredLicense(packageJson, lockEntry),
    repository: repositoryUrl(packageJson, lockEntry),
    text: sections.join("\n\n"),
  };
}

function render(packages) {
  const groups = new Map();
  for (const packageInfo of packages) {
    const digest = createHash("sha256").update(packageInfo.text).digest("hex");
    const group = groups.get(digest) ?? {
      text: packageInfo.text,
      packages: [],
    };
    group.packages.push(packageInfo);
    groups.set(digest, group);
  }

  const lines = [
    "BIFROST VS CODE EXTENSION THIRD-PARTY SOFTWARE NOTICES",
    "",
    "This report covers production npm packages bundled into out/extension.js.",
    "Development-only packages and the separately downloaded Bifrost executable are",
    "outside this report. Bifrost's own terms are in LICENSE.md; SOURCE.md explains",
    "how to obtain the corresponding source for the extension and executable.",
    "",
    `Packages: ${packages.length}`,
    "",
    "PACKAGE INVENTORY",
    "",
  ];

  for (const packageInfo of packages) {
    lines.push(
      `${packageInfo.name}@${packageInfo.version} | ${packageInfo.license} | ${packageInfo.repository}`,
    );
  }

  lines.push("", "LICENSE AND NOTICE TEXTS");
  const sortedGroups = [...groups.values()].sort((left, right) => {
    const leftName = left.packages[0].name;
    const rightName = right.packages[0].name;
    return leftName.localeCompare(rightName);
  });
  for (const group of sortedGroups) {
    group.packages.sort((left, right) => left.name.localeCompare(right.name));
    lines.push(
      "",
      "=".repeat(80),
      group.packages
        .map(({ name, version }) => `${name}@${version}`)
        .join(", "),
      "=".repeat(80),
      "",
      group.text,
    );
  }

  return `${lines.join("\n")}\n`;
}

async function main() {
  const lock = JSON.parse(await readFile(lockPath, "utf8"));
  const packageEntries = Object.entries(lock.packages ?? {})
    .filter(
      ([packagePath, entry]) =>
        packagePath && packagePath.includes("node_modules/") && !entry.dev,
    )
    .sort(([left], [right]) => left.localeCompare(right));

  const packages = [];
  for (const [packagePath, lockEntry] of packageEntries) {
    packages.push(
      await packageNotice(path.join(extensionRoot, packagePath), lockEntry),
    );
  }
  packages.sort((left, right) =>
    `${left.name}@${left.version}`.localeCompare(
      `${right.name}@${right.version}`,
    ),
  );

  await copyFile(
    path.join(repositoryRoot, "LICENSE.md"),
    path.join(extensionRoot, "LICENSE.md"),
  );
  await copyFile(
    path.join(repositoryRoot, "SOURCE.md"),
    path.join(extensionRoot, "SOURCE.md"),
  );
  await writeFile(outputPath, render(packages), "utf8");
  process.stdout.write(
    `Prepared VSIX license artifacts for ${packages.length} packages.\n`,
  );
}

await main();
