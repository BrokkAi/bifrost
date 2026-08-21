import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { extractChangelogEntry, main } from "./extract-changelog-entry.mjs";

const changelog = `# Changelog

## [0.10.6] - Unreleased

### Added

- Curated release notes.

### Fixed

- A useful fix.

## [0.10.5] - 2026-08-21

### Added

- An older feature.
`;

test("extracts only the requested entry body", () => {
  assert.equal(
    extractChangelogEntry(changelog, "0.10.6"),
    "### Added\n\n- Curated release notes.\n\n### Fixed\n\n- A useful fix.\n",
  );
  assert.equal(
    extractChangelogEntry(changelog, "0.10.5"),
    "### Added\n\n- An older feature.\n",
  );
});

test("accepts CRLF changelogs", () => {
  assert.equal(
    extractChangelogEntry(changelog.replaceAll("\n", "\r\n"), "0.10.6"),
    "### Added\n\n- Curated release notes.\n\n### Fixed\n\n- A useful fix.\n",
  );
});

test("uses the release workflow's semver contract", () => {
  assert.equal(
    extractChangelogEntry(
      "## [0.10.6-rc.1] - 2026-08-22\n\n- Candidate notes.\n",
      "0.10.6-rc.1",
    ),
    "- Candidate notes.\n",
  );
});

test("rejects a missing, duplicate, empty, or malformed entry", () => {
  assert.throws(() => extractChangelogEntry(changelog, "0.10.7"), /no entry/u);
  assert.throws(
    () => extractChangelogEntry(
      `${changelog}\n## [0.10.6] - Unreleased\n\n- Again.\n`,
      "0.10.6",
    ),
    /multiple entries/u,
  );
  assert.throws(
    () => extractChangelogEntry(
      "## [0.10.6] - Unreleased\n\n## [0.10.5] - 2026-08-21\n\n- Old.\n",
      "0.10.6",
    ),
    /is empty/u,
  );
  assert.throws(
    () => extractChangelogEntry("## [0.10.6] - someday\n\n- Notes.\n", "0.10.6"),
    /YYYY-MM-DD/u,
  );
  assert.throws(
    () => extractChangelogEntry(changelog, "v0.10.6"),
    /Invalid release version/u,
  );
  assert.throws(
    () => extractChangelogEntry(changelog, "0.10.6", { requireDate: true }),
    /must have a release date/u,
  );
  assert.equal(
    extractChangelogEntry(changelog, "0.10.5", { requireDate: true }),
    "### Added\n\n- An older feature.\n",
  );
});

test("writes a new output file and refuses to overwrite it", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bifrost-changelog-entry."));
  try {
    const changelogPath = path.join(temp, "CHANGELOG.md");
    const outputPath = path.join(temp, "release-notes.md");
    fs.writeFileSync(changelogPath, changelog);
    const args = [
      "--version",
      "0.10.6",
      "--changelog",
      changelogPath,
      "--output",
      outputPath,
    ];
    main(args);
    assert.equal(
      fs.readFileSync(outputPath, "utf8"),
      "### Added\n\n- Curated release notes.\n\n### Fixed\n\n- A useful fix.\n",
    );
    assert.throws(() => main(args), /EEXIST/u);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
