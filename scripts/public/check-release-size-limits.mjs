#!/usr/bin/env node
// Refuse a release whose artifacts exceed a registry's upload limit.
//
// v0.14.3 was tagged with a searchtools wheel over PyPI's 100 MiB file limit
// and an npm tarball over npm's payload limit, so publication failed after
// some wheels and crates were already out. This compares every artifact under
// the given directories with the limits in release-size-limits.json, without
// network access, so Release readiness fails before any tag exists. An
// artifact above warn_fraction of its limit is reported as a warning, so the
// growth is visible a release before it fails.
//
// Each file takes the first rule whose pattern matches its basename; files no
// rule matches (checksum sidecars, metadata) are not uploaded on their own.
//
// Usage: scripts/public/check-release-size-limits.mjs <directory>...

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const { warn_fraction: warnFraction, rules } = JSON.parse(
  fs.readFileSync(new URL("./release-size-limits.json", import.meta.url), "utf8"),
);
const matchers = rules.map((rule) => ({ ...rule, regex: new RegExp(rule.pattern, "u") }));

const directories = process.argv.slice(2);
if (directories.length === 0) {
  console.error("usage: check-release-size-limits.mjs <directory>...");
  process.exit(2);
}

const mebibytes = (bytes) => `${(bytes / 1048576).toFixed(1)} MiB`;
let checked = 0;
let exceeded = 0;
for (const directory of directories) {
  for (const entry of fs.readdirSync(directory, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const rule = matchers.find((candidate) => candidate.regex.test(entry.name));
    if (!rule) continue;
    const file = path.join(entry.parentPath, entry.name);
    const { size } = fs.statSync(file);
    const fraction = size / rule.limit_bytes;
    const line = `${file}: ${size} bytes (${mebibytes(size)}), ${(fraction * 100).toFixed(2)}% of the ${rule.registry} limit of ${rule.limit_bytes} bytes (${mebibytes(rule.limit_bytes)})`;
    checked += 1;
    if (size > rule.limit_bytes) {
      exceeded += 1;
      console.log(`::error::${line}`);
    } else if (fraction > warnFraction) {
      console.log(`::warning::${line}`);
    } else {
      console.log(line);
    }
  }
}

if (checked === 0) {
  console.error(`::error::no release artifact under ${directories.join(", ")} matches a rule in release-size-limits.json`);
  process.exit(1);
}
if (exceeded > 0) {
  console.error(`::error::${exceeded} of ${checked} release artifacts exceed their registry's upload limit`);
  process.exit(1);
}
console.log(`${checked} release artifacts are within their registry upload limits`);
