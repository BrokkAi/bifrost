#!/usr/bin/env node
// Preflight for the npm trusted-publishing client contract (issue #2334).
//
// npm publishes through GitHub OIDC trusted publishing. Two failure modes
// observed during the v0.10.3 recovery produce misleading E404 responses at
// publication time: an npm client older than 11.19 and a classic-token
// .npmrc entry written by setup-node's registry-url option. This check
// validates the effective client configuration statically, so Release
// readiness can fail minutes into a release attempt instead of after the
// tag exists.

import fs from "node:fs";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const MINIMUM_NPM_CLIENT = [11, 19, 0];

function parseVersion(text) {
  const parts = text.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 3 || parts.some((part) => !Number.isInteger(part) || part < 0)) {
    return null;
  }
  return parts;
}

function versionAtLeast(actual, minimum) {
  for (let index = 0; index < 3; index += 1) {
    if (actual[index] !== minimum[index]) {
      return actual[index] > minimum[index];
    }
  }
  return true;
}

// Returns an array of violated clauses; empty when the contract holds.
export function checkNpmTrustedPublishing({ publishNpm, release }) {
  const violations = [];

  const pin = publishNpm.match(/npm install --global npm@([0-9]+\.[0-9]+\.[0-9]+)\b/u);
  if (!pin) {
    violations.push(
      "publish-npm.yml must pin the trusted-publishing client with 'npm install --global npm@<exact semver>'.",
    );
  } else {
    const pinned = parseVersion(pin[1]);
    if (!pinned || !versionAtLeast(pinned, MINIMUM_NPM_CLIENT)) {
      violations.push(
        `publish-npm.yml pins npm@${pin[1]}, but OIDC trusted publishing requires at least npm@${MINIMUM_NPM_CLIENT.join(".")}.`,
      );
    }
  }

  if (/registry-url\s*:/u.test(publishNpm)) {
    violations.push(
      "publish-npm.yml must not configure setup-node registry-url: it writes a classic-token .npmrc that breaks OIDC publishes with a misleading E404.",
    );
  }

  if (!/NODE_AUTH_TOKEN:\s*""/u.test(publishNpm) || !publishNpm.includes("unset NODE_AUTH_TOKEN")) {
    violations.push(
      "publish-npm.yml must define NODE_AUTH_TOKEN: \"\" and unset NODE_AUTH_TOKEN before publishing so no classic token shadows the OIDC exchange.",
    );
  }

  if (!/NPM_CONFIG_PROVENANCE:\s*"true"/u.test(publishNpm)) {
    violations.push('publish-npm.yml must publish with explicit NPM_CONFIG_PROVENANCE: "true".');
  }

  if (!/environment:\s*npm-publish\b/u.test(publishNpm)) {
    violations.push("publish-npm.yml must publish from the protected npm-publish environment.");
  }

  if (!/id-token:\s*write\b/u.test(publishNpm)) {
    violations.push("publish-npm.yml must request id-token: write for the OIDC exchange.");
  }

  if (!/gh workflow run publish-npm\.yml[\s\S]{0,200}?--ref master\b/u.test(release)) {
    violations.push(
      "release.yml must dispatch publish-npm.yml on --ref master so a workflow-only recovery takes effect without re-qualifying the release source.",
    );
  }

  return violations;
}

function main() {
  const root = new URL("../../", import.meta.url);
  const publishNpm = fs.readFileSync(new URL(".github/workflows/publish-npm.yml", root), "utf8");
  const release = fs.readFileSync(new URL(".github/workflows/release.yml", root), "utf8");
  const violations = checkNpmTrustedPublishing({ publishNpm, release });
  if (violations.length > 0) {
    for (const violation of violations) {
      console.error(`npm trusted-publishing preflight: ${violation}`);
    }
    process.exit(1);
  }
  console.log(
    `npm trusted-publishing preflight: client contract holds (npm >= ${MINIMUM_NPM_CLIENT.join(".")}, OIDC-only, provenance on, master-ref dispatch).`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main();
}
