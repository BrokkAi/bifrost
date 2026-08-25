import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildCratePublishMetadata,
  generateCratePublishMetadata,
} from "./generate-crate-publish-metadata.mjs";

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "crate-publish-metadata-"));
  const readme = "# Demo\n\nUnicode: cafe\u0301 and 🚀\n";
  fs.writeFileSync(path.join(directory, "README.md"), readme, "utf8");
  fs.writeFileSync(path.join(directory, "LICENSE.txt"), "license\n", "utf8");
  const packageRecord = {
    name: "demo-crate",
    version: "1.2.3",
    manifest_path: path.join(directory, "Cargo.toml"),
    dependencies: [
      {
        name: "serde",
        req: "^1.0",
        kind: null,
        rename: null,
        optional: false,
        uses_default_features: true,
        features: ["derive"],
        target: null,
        registry: null,
      },
      {
        name: "real-name",
        req: ">=2, <3",
        kind: "dev",
        rename: "alias",
        optional: true,
        uses_default_features: false,
        features: ["feature-a", "feature-b"],
        target: "cfg(unix)",
        registry: "https://registry.example/index",
      },
      {
        name: "build-helper",
        req: "=0.4.0",
        kind: "build",
        rename: null,
        optional: false,
        uses_default_features: true,
        features: [],
        target: "cfg(windows)",
        registry: null,
      },
    ],
    features: {
      zeta: ["dep:real-name"],
      default: ["zeta"],
      alpha: [],
    },
    authors: ["Alice <alice@example.test>"],
    description: "A test crate.",
    documentation: "https://docs.example.test/demo",
    homepage: "https://example.test/demo",
    readme: "README.md",
    keywords: ["demo", "release"],
    categories: ["development-tools"],
    license: null,
    license_file: "LICENSE.txt",
    repository: "https://example.test/repository",
    links: "demo-native",
    rust_version: "1.97",
  };
  return {
    directory,
    packageRecord,
    badges: {
      zeta: { repository: "demo", branch: "main" },
      alpha: { status: "actively-developed" },
    },
    readme,
  };
}

test("generates the Cargo publish object with exact dependency and field semantics", () => {
  const data = fixture();
  try {
    const metadata = buildCratePublishMetadata(data.packageRecord, {
      packageRoot: data.directory,
      badges: data.badges,
    });
    assert.deepEqual(metadata, {
      name: "demo-crate",
      vers: "1.2.3",
      deps: [
        {
          optional: false,
          default_features: true,
          name: "serde",
          features: ["derive"],
          version_req: "^1.0",
          target: null,
          kind: "normal",
        },
        {
          optional: true,
          default_features: false,
          name: "real-name",
          features: ["feature-a", "feature-b"],
          version_req: ">=2, <3",
          target: "cfg(unix)",
          kind: "dev",
          registry: "https://registry.example/index",
          explicit_name_in_toml: "alias",
        },
        {
          optional: false,
          default_features: true,
          name: "build-helper",
          features: [],
          version_req: "=0.4.0",
          target: "cfg(windows)",
          kind: "build",
        },
      ],
      features: {
        alpha: [],
        default: ["zeta"],
        zeta: ["dep:real-name"],
      },
      authors: ["Alice <alice@example.test>"],
      description: "A test crate.",
      documentation: "https://docs.example.test/demo",
      homepage: "https://example.test/demo",
      readme: data.readme,
      readme_file: "README.md",
      keywords: ["demo", "release"],
      categories: ["development-tools"],
      license: null,
      license_file: "LICENSE.txt",
      repository: "https://example.test/repository",
      badges: {
        alpha: { status: "actively-developed" },
        zeta: { branch: "main", repository: "demo" },
      },
      links: "demo-native",
      rust_version: "1.97",
    });
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test("produces deterministic compact bytes without a trailing newline", () => {
  const data = fixture();
  try {
    const first = generateCratePublishMetadata(data.packageRecord, { packageRoot: data.directory, badges: data.badges });
    const second = generateCratePublishMetadata(data.packageRecord, { packageRoot: data.directory, badges: data.badges });
    assert.deepEqual(first, second);
    assert.equal(first.at(-1), 0x7d);
    assert.equal(first.toString("utf8"), JSON.stringify(JSON.parse(first.toString("utf8"))));
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test("requires explicit badges because cargo metadata omits the top-level badges table", () => {
  const data = fixture();
  try {
    assert.throws(
      () => generateCratePublishMetadata(data.packageRecord, { packageRoot: data.directory }),
      /does not expose \[badges\]/u,
    );
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test("requires referenced README and license files and rejects escaping paths", () => {
  const data = fixture();
  try {
    const missingReadme = { ...data.packageRecord, readme: "missing.md" };
    assert.throws(
      () => generateCratePublishMetadata(missingReadme, { packageRoot: data.directory, badges: data.badges }),
      /ENOENT/u,
    );
    const escapingReadme = { ...data.packageRecord, readme: "../README.md" };
    assert.throws(
      () => generateCratePublishMetadata(escapingReadme, { packageRoot: data.directory, badges: data.badges }),
      /escapes the package root/u,
    );
    const missingLicense = { ...data.packageRecord, license_file: "missing.license" };
    assert.throws(
      () => generateCratePublishMetadata(missingLicense, { packageRoot: data.directory, badges: data.badges }),
      /license file does not exist/u,
    );
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test("rejects incomplete or unsupported cargo dependency metadata", () => {
  const data = fixture();
  try {
    const missingReq = {
      ...data.packageRecord,
      dependencies: [{ ...data.packageRecord.dependencies[0], req: undefined }],
    };
    assert.throws(
      () => generateCratePublishMetadata(missingReq, { packageRoot: data.directory, badges: data.badges }),
      /dependency 0\.req must be a string/u,
    );
    const unsupportedKind = {
      ...data.packageRecord,
      dependencies: [{ ...data.packageRecord.dependencies[0], kind: "runtime" }],
    };
    assert.throws(
      () => generateCratePublishMetadata(unsupportedKind, { packageRoot: data.directory, badges: data.badges }),
      /kind is unsupported/u,
    );
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test("CLI selects the exact package and writes the same bytes", () => {
  const data = fixture();
  try {
    const metadataPath = path.join(data.directory, "cargo-metadata.json");
    const badgesPath = path.join(data.directory, "badges.json");
    const outputPath = path.join(data.directory, "publish-metadata.json");
    fs.writeFileSync(metadataPath, JSON.stringify({ packages: [data.packageRecord] }), "utf8");
    fs.writeFileSync(badgesPath, JSON.stringify(data.badges), "utf8");
    const result = spawnSync(process.execPath, [
      "scripts/public/generate-crate-publish-metadata.mjs",
      "--cargo-metadata-file", metadataPath,
      "--package", data.packageRecord.name,
      "--version", data.packageRecord.version,
      "--package-root", data.directory,
      "--badges-file", badgesPath,
      "--output-file", outputPath,
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(
      fs.readFileSync(outputPath),
      generateCratePublishMetadata(data.packageRecord, { packageRoot: data.directory, badges: data.badges }),
    );
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});
