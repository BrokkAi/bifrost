import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { OpenPackError, prepareOpenPacks, readEnginePackProfile } from "../bin/open-packs.mjs";

const repository = "https://github.com/BrokkAi/bifrost-packs";
const rulesId = "bifrost.public.rules";
const semanticId = "bifrost.public.packs";
const profile = {
  engine_version: "0.13.0",
  build_identity: "a".repeat(64),
  model_set_sha256: "b".repeat(64),
  capability_contract_version: 1,
  schemas: {
    policy_document: [1], rql: [1], builtin_catalog: [1], policy_bundle: [],
    semantic_model_read: [5], semantic_model_write: [5], semantic_spec: [],
    release_index: [1], runtime: []
  },
  capabilities: []
};

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function tarArchive(files, entryType = "0") {
  const records = [];
  for (const [name, content] of Object.entries(files)) {
    const bytes = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, "utf8");
    writeOctal(header, 100, 8, 0o644);
    writeOctal(header, 108, 8, 0);
    writeOctal(header, 116, 8, 0);
    writeOctal(header, 124, 12, bytes.length);
    writeOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header[156] = entryType.charCodeAt(0);
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
    let checksum = 0;
    for (const byte of header) checksum += byte;
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    records.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  records.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(records));
}

function writeOctal(header, offset, length, value) {
  header.write(`${value.toString(8).padStart(length - 1, "0")}\0`, offset, length, "ascii");
}

function schemas() {
  return Object.fromEntries(Object.keys(profile.schemas).map((axis) => [axis, []]));
}

function makeRelease(packId, version, { qualification = "qualified", commit = "c", min = "0.12.0", max = "0.14.0", pin = "1.0.0", tagVersion = version } = {}) {
  const isRules = packId === rulesId;
  const contentFiles = isRules
    ? { "rules/demo/manifest.json": "{\"id\":\"demo\"}\n", "rules/demo/policies/example.rqlp": "policy demo {}\n" }
    : { "bifrost-semantic-packs/index.json": "{\"schema_version\":1,\"packs\":[]}\n" };
  const contents = Object.entries(contentFiles).map(([filePath, bytes]) => ({
    kind: isRules ? (filePath.endsWith("manifest.json") ? "policy-pack" : "policy") : "semantic-model",
    identity: `${packId}/${filePath}`,
    path: filePath,
    sha256: hash(bytes),
    languages: [],
    dependencies: [],
    schemas: schemas(),
    required_capabilities: []
  }));
  const archive = tarArchive(contentFiles);
  const artifactName = `${isRules ? "rules" : "semantic"}.tar.gz`;
  const manifest = {
    manifest_schema_version: 1,
    pack: { id: packId, repository, visibility: "public" },
    release_version: version,
    source: { repository, commit: commit.repeat(40).slice(0, 40), dirty: false },
    compatibility: {
      engine: { min_inclusive: min, max_exclusive: max },
      schemas: schemas(),
      capabilities: { required: [], provided: [], contract_version: 1 }
    },
    contents,
    artifacts: [{ name: artifactName, sha256: hash(archive), size_bytes: archive.byteLength, format: "tar.gz", role: isRules ? "policy" : "native" }],
    qualification: { status: qualification, evidence: qualification === "qualified" ? ["fixture qualification"] : [] },
    ...(isRules ? { release_dependencies: [{ pack_id: semanticId, release_version: pin, repository }] } : { release_dependencies: [] })
  };
  const tag = `${isRules ? "rules" : "packs"}/v${tagVersion}`;
  return { tag, manifest, archive, artifactName };
}

function makeV2Release(
  packId,
  version,
  {
    integrity = "verified",
    behavior = "qualified",
    commit = "e",
    requiredSchemas = {},
    requiredCapabilities = [],
    dependencyRepository = repository,
  } = {},
) {
  const isRules = packId === rulesId;
  const contentFiles = isRules
    ? {
        "rules/demo/manifest.json": JSON.stringify({
          id: "demo",
          policies: [
            {
              id: "example",
              path: "policies/example.rqlp",
              supported_languages: ["python"],
            },
          ],
        }) + "\n",
        "rules/demo/policies/example.rqlp": "policy demo {}\n",
      }
    : {
        "bifrost-semantic-packs/index.json":
          "{\"schema_version\":1,\"packs\":[]}\n",
      };
  const contents = Object.entries(contentFiles).map(([filePath, bytes]) => {
    const isCatalog = filePath.endsWith("manifest.json");
    const itemSchemas = schemas();
    if (isRules && !isCatalog) {
      for (const [axis, versions] of Object.entries(requiredSchemas))
        itemSchemas[axis] = [...versions];
    }
    return {
      kind: isRules
        ? isCatalog
          ? "policy-pack"
          : "policy"
        : "semantic-model",
      identity: isRules
        ? isCatalog
          ? "demo"
          : "demo.example"
        : "bifrost.public.packs/index",
      path: filePath,
      sha256: hash(bytes),
      languages: isRules && !isCatalog ? ["python"] : [],
      dependencies: [],
      schemas: itemSchemas,
      required_capabilities:
        isRules && !isCatalog ? [...requiredCapabilities] : [],
    };
  });
  const archive = tarArchive(contentFiles);
  const artifactName = `${isRules ? "rules" : "semantic"}.tar.gz`;
  const aggregateSchemas = schemas();
  for (const item of contents) {
    for (const [axis, versions] of Object.entries(item.schemas)) {
      aggregateSchemas[axis] = [...new Set([...aggregateSchemas[axis], ...versions])];
    }
  }
  const evidence = (axis, status) =>
    status === "pending" ? [] : [`fixture ${axis} evidence`];
  const manifest = {
    manifest_schema_version: 2,
    pack: { id: packId, repository, visibility: "public" },
    release_version: version,
    source: { repository, commit: commit.repeat(40).slice(0, 40), dirty: false },
    compatibility: {
      schemas: aggregateSchemas,
      capabilities: {
        required: [...requiredCapabilities],
        provided: [],
        contract_version: 1,
      },
    },
    contents,
    artifacts: [
      {
        name: artifactName,
        sha256: hash(archive),
        size_bytes: archive.byteLength,
        format: "tar.gz",
        role: isRules ? "source" : "native",
      },
    ],
    qualification: {
      integrity: { status: integrity, evidence: evidence("integrity", integrity) },
      behavior: { status: behavior, evidence: evidence("behavior", behavior) },
    },
    release_dependencies: isRules
      ? [
          {
            pack_id: semanticId,
            release_version: "1.0.0",
            repository: dependencyRepository,
          },
        ]
      : [],
    provenance: {
      engine_version: "0.12.0",
      build_identity: "fixture-generator",
      source_commit: "f".repeat(40),
    },
  };
  const tag = `${isRules ? "rules" : "packs"}/v${version}`;
  return { tag, manifest, archive, artifactName };
}

function buildFetch(releaseItems, { tagCommitOverrides = {}, unavailable = false } = {}) {
  const assets = new Map();
  const refs = new Map();
  const apiReleases = releaseItems.map((item) => {
    const commit = tagCommitOverrides[item.tag] ?? item.manifest.source.commit;
    refs.set(item.tag, commit);
    const manifestUrl = `https://github.com/BrokkAi/bifrost-packs/releases/download/${item.tag.replaceAll("/", "%2F")}/pack-release.json`;
    const artifactUrl = `https://github.com/BrokkAi/bifrost-packs/releases/download/${item.tag.replaceAll("/", "%2F")}/${item.artifactName}`;
    assets.set(manifestUrl, Buffer.from(JSON.stringify(item.manifest)));
    assets.set(artifactUrl, item.archive);
    return {
      tag_name: item.tag,
      draft: false,
      prerelease: item.manifest.release_version.includes("-"),
      assets: [
        { name: "pack-release.json", browser_download_url: manifestUrl },
        { name: item.artifactName, browser_download_url: artifactUrl }
      ]
    };
  });
  const calls = [];
  const fetchImpl = async (input) => {
    calls.push(String(input));
    if (unavailable) throw new TypeError("network unavailable");
    const url = new URL(String(input));
    if (url.pathname === "/repos/BrokkAi/bifrost-packs/releases") return jsonResponse(apiReleases);
    const refPrefix = "/repos/BrokkAi/bifrost-packs/git/ref/tags/";
    if (url.pathname.startsWith(refPrefix)) {
      const tag = url.pathname.slice(refPrefix.length);
      const commit = refs.get(tag);
      return commit ? jsonResponse({ object: { type: "commit", sha: commit } }) : new Response("missing", { status: 404 });
    }
    const artifact = assets.get(String(input));
    return artifact ? new Response(artifact) : new Response("missing", { status: 404 });
  };
  return { fetchImpl, calls };
}

function jsonResponse(value) {
  return new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
}

async function temporaryCache() {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), "bifrost-open-pack-test-"));
  return { parent, cacheDir: path.join(parent, "cache") };
}

function errorWithCode(code) {
  return (error) => error instanceof OpenPackError && error.code === code;
}

test("selects, verifies, and reuses one deterministic offline selection", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const releases = [makeRelease(rulesId, "1.0.0"), makeRelease(semanticId, "1.0.0")];
  const onlineA = buildFetch(releases);
  const onlineB = buildFetch(releases);
  const concurrent = await Promise.all([
    prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: onlineA.fetchImpl }),
    prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: onlineB.fetchImpl })
  ]);
  const first = concurrent.find((result) => !result.receipt.cache_reused);
  const concurrentlyReused = concurrent.find((result) => result.receipt.cache_reused);
  assert.ok(first);
  assert.ok(concurrentlyReused);
  assert.equal(concurrentlyReused.env.BIFROST_OPEN_POLICY_PACK_ROOT, first.env.BIFROST_OPEN_POLICY_PACK_ROOT);
  assert.equal(first.receipt.discovery_status, "online");
  assert.equal(first.receipt.cache_reused, false);
  assert.equal(first.receipt.receipt_schema_version, 1);
  assert.equal(first.receipt.status, "qualified");
  const persistedLegacyReceipt = JSON.parse(
    await fs.readFile(first.receipt.path, "utf8"),
  );
  assert.deepEqual(Object.keys(persistedLegacyReceipt).sort(), [
    "artifacts",
    "created_at",
    "engine_profile",
    "extracted_files",
    "inventory_fetched_at",
    "receipt_schema_version",
    "releases",
    "selection_id",
    "status",
    "verified_contents",
  ]);
  assert.equal(await fs.readFile(path.join(first.env.BIFROST_OPEN_POLICY_PACK_ROOT, "demo", "manifest.json"), "utf8"), "{\"id\":\"demo\"}\n");
  assert.equal(await fs.readFile(path.join(first.env.BIFROST_OPEN_SEMANTIC_PACK_BUNDLE, "index.json"), "utf8"), "{\"schema_version\":1,\"packs\":[]}\n");

  const offline = buildFetch(releases, { unavailable: true });
  const second = await prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: offline.fetchImpl, offline: true });
  assert.equal(second.env.BIFROST_OPEN_POLICY_PACK_ROOT, first.env.BIFROST_OPEN_POLICY_PACK_ROOT);
  assert.equal(second.receipt.selection_id, first.receipt.selection_id);
  assert.equal(second.receipt.discovery_status, "offline-cache");
  assert.equal(second.receipt.cache_reused, true);
  assert.equal(second.receipt.receipt_schema_version, 1);
  assert.equal(second.receipt.status, "qualified");
  assert.equal(offline.calls.length, 0);
  const selections = (await fs.readdir(path.join(cacheDir, "selections"))).filter((name) => !name.startsWith("."));
  assert.deepEqual(selections, [first.receipt.selection_id]);
});

test("a stale verified inventory survives transient network failure and is reported", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const releases = [makeRelease(rulesId, "1.0.0"), makeRelease(semanticId, "1.0.0")];
  const first = await prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: buildFetch(releases).fetchImpl });
  const indexPath = path.join(cacheDir, "manifest-index.json");
  const index = JSON.parse(await fs.readFile(indexPath, "utf8"));
  index.fetched_at = "2000-01-01T00:00:00.000Z";
  await fs.writeFile(indexPath, JSON.stringify(index));
  const stale = await prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: buildFetch(releases, { unavailable: true }).fetchImpl });
  assert.equal(stale.receipt.discovery_status, "stale-cache");
  assert.equal(stale.env.BIFROST_OPEN_POLICY_PACK_ROOT, first.env.BIFROST_OPEN_POLICY_PACK_ROOT);
  await assert.rejects(
    prepareOpenPacks({ cacheDir, engineProfile: profile, offline: true, refresh: true }),
    errorWithCode("invalid-arguments")
  );
});

test("cached artifact and extracted content corruption fail closed", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const releases = [makeRelease(rulesId, "1.0.0"), makeRelease(semanticId, "1.0.0")];
  const first = await prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: buildFetch(releases).fetchImpl });
  const artifactPath = path.join(cacheDir, "artifacts", releases[0].manifest.artifacts[0].sha256);
  await fs.writeFile(artifactPath, "corrupt");
  await assert.rejects(
    prepareOpenPacks({ cacheDir, engineProfile: profile, offline: true }),
    errorWithCode("integrity-error")
  );

  await fs.writeFile(artifactPath, releases[0].archive);
  const policyManifest = path.join(first.env.BIFROST_OPEN_POLICY_PACK_ROOT, "demo", "manifest.json");
  await fs.writeFile(policyManifest, "modified");
  await assert.rejects(
    prepareOpenPacks({ cacheDir, engineProfile: profile, offline: true }),
    errorWithCode("integrity-error")
  );
  assert.equal(await fs.readFile(policyManifest, "utf8"), "modified");
});

test("newer pending rules do not mask the newest older qualified complete pair", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const releases = [
    makeRelease(rulesId, "1.0.0", { pin: "1.0.0" }),
    makeRelease(rulesId, "2.0.0", { pin: "1.0.0", qualification: "pending", commit: "d" }),
    makeRelease(semanticId, "1.0.0")
  ];
  const result = await prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: buildFetch(releases).fetchImpl });
  assert.deepEqual(result.receipt.releases.map((release) => release.release_version), ["1.0.0", "1.0.0"]);
});

test("incompatible profiles and pending-only releases return typed diagnostics", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const releases = [makeRelease(rulesId, "1.0.0", { qualification: "pending" }), makeRelease(semanticId, "1.0.0", { qualification: "pending" })];
  await assert.rejects(
    prepareOpenPacks({ cacheDir, engineProfile: { ...profile, engine_version: "0.20.0" }, fetchImpl: buildFetch(releases).fetchImpl }),
    errorWithCode("no-compatible-release")
  );
  await assert.rejects(
    prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: buildFetch(releases).fetchImpl, refresh: true }),
    errorWithCode("pending")
  );
});

test("schema 2 uses declared schemas and capabilities without an engine-version gate", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const releases = [
    makeV2Release(rulesId, "1.0.0", {
      requiredSchemas: { rql: [1] },
      requiredCapabilities: ["policy.inspect"],
    }),
    makeV2Release(semanticId, "1.0.0"),
  ];
  const compatibleProfile = {
    ...profile,
    engine_version: "99.0.0",
    capabilities: ["policy.inspect"],
  };
  const result = await prepareOpenPacks({
    cacheDir,
    engineProfile: compatibleProfile,
    fetchImpl: buildFetch(releases).fetchImpl,
  });
  assert.equal(result.receipt.receipt_schema_version, 2);
  assert.equal(result.receipt.status, "qualified");
  assert.deepEqual(
    result.receipt.releases.map((release) => release.manifest_schema_version),
    [2, 2],
  );
  assert.equal(result.receipt.releases[0].provenance.engine_version, "0.12.0");
  assert.equal(result.receipt.releases[0].artifacts[0].role, "source");
  assert.equal(result.receipt.releases[1].artifacts[0].role, "native");
  assert.match(
    await fs.readFile(
      path.join(result.env.BIFROST_OPEN_POLICY_PACK_ROOT, "demo", "manifest.json"),
      "utf8",
    ),
    /"policies"/,
  );

  await assert.rejects(
    prepareOpenPacks({
      cacheDir: path.join(cacheDir, "missing-capability"),
      engineProfile: { ...compatibleProfile, capabilities: [] },
      fetchImpl: buildFetch(releases).fetchImpl,
    }),
    errorWithCode("no-compatible-release"),
  );
  await assert.rejects(
    prepareOpenPacks({
      cacheDir: path.join(cacheDir, "missing-schema"),
      engineProfile: {
        ...compatibleProfile,
        schemas: { ...profile.schemas, rql: [2] },
      },
      fetchImpl: buildFetch(releases).fetchImpl,
    }),
    errorWithCode("no-compatible-release"),
  );
});

test("schema 2 qualification gates integrity but preserves pending and limited behavior", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));

  for (const behavior of ["pending", "limited"]) {
    const releases = [
      makeV2Release(rulesId, "1.0.0", { behavior }),
      makeV2Release(semanticId, "1.0.0"),
    ];
    const result = await prepareOpenPacks({
      cacheDir: path.join(cacheDir, behavior),
      engineProfile: profile,
      fetchImpl: buildFetch(releases).fetchImpl,
    });
    assert.equal(result.receipt.receipt_schema_version, 2);
    assert.equal(result.receipt.status, "compatible");
    assert.equal(result.receipt.releases[0].qualification.behavior.status, behavior);
    assert.deepEqual(
      result.receipt.releases[0].qualification.behavior.evidence,
      behavior === "pending" ? [] : ["fixture behavior evidence"],
    );
    const reused = await prepareOpenPacks({
      cacheDir: path.join(cacheDir, behavior),
      engineProfile: profile,
      offline: true,
    });
    assert.equal(reused.receipt.receipt_schema_version, 2);
    assert.equal(reused.receipt.status, "compatible");
    assert.equal(reused.receipt.cache_reused, true);
    assert.equal(
      reused.receipt.releases[0].qualification.behavior.status,
      behavior,
    );
  }

  for (const integrity of ["pending", "failed"]) {
    const releases = [
      makeV2Release(rulesId, "1.0.0", { integrity }),
      makeV2Release(semanticId, "1.0.0"),
    ];
    const expectedCode = integrity === "pending" ? "pending" : "integrity-error";
    await assert.rejects(
      prepareOpenPacks({
        cacheDir: path.join(cacheDir, `integrity-${integrity}`),
        engineProfile: profile,
        fetchImpl: buildFetch(releases).fetchImpl,
      }),
      (error) => {
        assert.ok(error instanceof OpenPackError);
        assert.equal(error.code, expectedCode);
        if (integrity === "pending") {
          assert.equal(error.details.receipt_schema_version, 2);
          assert.equal(error.details.status, "pending");
          assert.equal(
            error.details.releases[0].qualification.integrity.status,
            releases[0].manifest.qualification.integrity.status,
          );
          assert.deepEqual(
            error.details.releases[0].qualification.integrity.evidence,
            releases[0].manifest.qualification.integrity.evidence,
          );
          assert.equal(
            error.details.releases[0].qualification.behavior.status,
            releases[0].manifest.qualification.behavior.status,
          );
        }
        return true;
      },
    );
  }

  const failedBehavior = [
    makeV2Release(rulesId, "1.0.0", { behavior: "failed" }),
    makeV2Release(semanticId, "1.0.0"),
  ];
  await assert.rejects(
    prepareOpenPacks({
      cacheDir: path.join(cacheDir, "failed-behavior"),
      engineProfile: profile,
      fetchImpl: buildFetch(failedBehavior).fetchImpl,
    }),
    (error) => {
      assert.equal(error.code, "no-compatible-release");
      assert.match(error.message, /failed behavior/);
      return true;
    },
  );
});

test("schema 2 validates exact requirements, evidence, dependency identity, and supported versions", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const cases = [
    {
      name: "unsupported-schema",
      code: "unsupported-manifest-schema",
      mutate: (release) => {
        release.manifest.manifest_schema_version = 3;
      },
    },
    {
      name: "engine-range-is-forbidden",
      code: "invalid-manifest",
      mutate: (release) => {
        release.manifest.compatibility.engine = {
          min_inclusive: "0.12.0",
          max_exclusive: "0.13.0",
        };
      },
    },
    {
      name: "content-schema-missing-from-aggregate",
      code: "invalid-manifest",
      mutate: (release) => {
        release.manifest.contents[1].schemas.rql = [1];
      },
    },
    {
      name: "content-capability-missing-from-aggregate",
      code: "invalid-manifest",
      mutate: (release) => {
        release.manifest.contents[1].required_capabilities = ["policy.inspect"];
      },
    },
    {
      name: "blank-evidence",
      code: "invalid-manifest",
      mutate: (release) => {
        release.manifest.qualification.integrity.evidence = ["  \t"];
      },
    },
    {
      name: "dependency-repository-mismatch",
      code: "no-compatible-release",
      mutate: (release) => {
        release.manifest.release_dependencies[0].repository =
          "https://github.com/other/bifrost-packs";
      },
    },
    {
      name: "missing-rules-catalog",
      code: "invalid-manifest",
      mutate: (release) => {
        release.manifest.contents = release.manifest.contents.filter(
          (item) => item.kind !== "policy-pack",
        );
      },
    },
  ];

  for (const scenario of cases) {
    const releases = [
      makeV2Release(rulesId, "1.0.0"),
      makeV2Release(semanticId, "1.0.0"),
    ];
    scenario.mutate(releases[0]);
    await assert.rejects(
      prepareOpenPacks({
        cacheDir: path.join(cacheDir, scenario.name),
        engineProfile: profile,
        fetchImpl: buildFetch(releases).fetchImpl,
      }),
      errorWithCode(scenario.code),
      scenario.name,
    );
  }
});

test("tag source mismatch and prerelease SemVer ranges are handled strictly", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const releases = [makeRelease(rulesId, "1.0.0"), makeRelease(semanticId, "1.0.0")];
  await assert.rejects(
    prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: buildFetch(releases, { tagCommitOverrides: { [releases[0].tag]: "f".repeat(40) } }).fetchImpl }),
    errorWithCode("integrity-error")
  );

  const rangeCache = path.join(parent, "semver-cache");
  const caseRange = [
    makeRelease(rulesId, "1.0.0", { min: "0.13.0-Alpha", max: "0.13.0-beta" }),
    makeRelease(semanticId, "1.0.0", { min: "0.13.0-Alpha", max: "0.13.0-beta" })
  ];
  const caseProfile = { ...profile, engine_version: "0.13.0-alpha" };
  const accepted = await prepareOpenPacks({ cacheDir: rangeCache, engineProfile: caseProfile, fetchImpl: buildFetch(caseRange).fetchImpl });
  assert.equal(accepted.receipt.status, "qualified");

  const hyphenCache = path.join(parent, "hyphen-cache");
  const hyphenRange = [
    makeRelease(rulesId, "1.0.0", { min: "0.13.0-alpha-gamma", max: "0.13.0-alpha-zeta" }),
    makeRelease(semanticId, "1.0.0", { min: "0.13.0-alpha-gamma", max: "0.13.0-alpha-zeta" })
  ];
  await assert.rejects(
    prepareOpenPacks({ cacheDir: hyphenCache, engineProfile: { ...profile, engine_version: "0.13.0-alpha-beta" }, fetchImpl: buildFetch(hyphenRange).fetchImpl }),
    errorWithCode("no-compatible-release")
  );
});

test("all declared schema versions and stable rules channel are required", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const partialSchemas = [makeRelease(rulesId, "1.0.0"), makeRelease(semanticId, "1.0.0")];
  for (const release of partialSchemas) {
    release.manifest.compatibility.schemas.rql = [1, 2];
  }
  await assert.rejects(
    prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: buildFetch(partialSchemas).fetchImpl }),
    errorWithCode("no-compatible-release")
  );
  const prereleaseOnly = [makeRelease(rulesId, "2.0.0-rc.1"), makeRelease(semanticId, "1.0.0")];
  await assert.rejects(
    prepareOpenPacks({ cacheDir, engineProfile: profile, fetchImpl: buildFetch(prereleaseOnly).fetchImpl, refresh: true }),
    errorWithCode("no-compatible-release")
  );
});

test("legacy profile command diagnostic is typed unsupported; malformed profiles fail closed", async () => {
  await assert.rejects(
    readEnginePackProfile("bifrost", {
      execFileImpl: async () => { throw Object.assign(new Error("old CLI"), { stderr: "Unknown argument: pack-engine-profile" }); }
    }),
    errorWithCode("unsupported")
  );
  await assert.rejects(
    readEnginePackProfile("bifrost", { execFileImpl: async () => ({ stdout: JSON.stringify({ ...profile, unexpected: true }) }) }),
    errorWithCode("invalid-engine-profile")
  );
});

test("verified archive hashes do not authorize traversal or links", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  for (const [name, archive] of [
    ["traversal", tarArchive({ "../escaped": "unsafe" })],
    ["symlink", tarArchive({ "rules/demo/manifest.json": "" }, "2")],
  ]) {
    const rules = makeRelease(rulesId, "1.0.0");
    rules.archive = archive;
    rules.manifest.artifacts[0].sha256 = hash(archive);
    rules.manifest.artifacts[0].size_bytes = archive.length;
    const releases = [rules, makeRelease(semanticId, "1.0.0")];
    const caseCache = path.join(cacheDir, name);
    await assert.rejects(
      prepareOpenPacks({ cacheDir: caseCache, engineProfile: profile, fetchImpl: buildFetch(releases).fetchImpl }),
      errorWithCode("integrity-error")
    );
    assert.deepEqual(await fs.readdir(path.join(caseCache, "selections")), []);
  }
});

test("unmodeled dependency graphs are invalid metadata rather than unavailable content", async (t) => {
  const { parent, cacheDir } = await temporaryCache();
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  for (const [name, make] of [
    ["schema-1", makeRelease],
    ["schema-2", makeV2Release],
  ]) {
    const releases = [make(rulesId, "1.0.0"), make(semanticId, "1.0.0")];
    releases[1].manifest.release_dependencies = [
      { pack_id: rulesId, release_version: "1.0.0", repository },
    ];
    await assert.rejects(
      prepareOpenPacks({
        cacheDir: path.join(cacheDir, name),
        engineProfile: profile,
        fetchImpl: buildFetch(releases).fetchImpl,
      }),
      errorWithCode("invalid-manifest"),
    );
  }
});
