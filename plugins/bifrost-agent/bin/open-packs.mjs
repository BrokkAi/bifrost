import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { gunzipSync } from "node:zlib";

const execFileAsync = promisify(execFile);
const OWNER = "BrokkAi";
const REPOSITORY = "bifrost-packs";
const REPOSITORY_URL = `https://github.com/${OWNER}/${REPOSITORY}`;
const API_ROOT = `https://api.github.com/repos/${OWNER}/${REPOSITORY}`;
const ROOT_PACK_ID = "bifrost.public.rules";
const SEMANTIC_PACK_ID = "bifrost.public.packs";
const SCHEMA_PATH = fileURLToPath(
  new URL("./pack-release.schema.json", import.meta.url),
);
const V1_SCHEMA_PATH = fileURLToPath(
  new URL("./pack-release.v1.schema.json", import.meta.url),
);
const MANIFEST_CACHE_TTL_MS = 60 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 20_000;
const PROFILE_TIMEOUT_MS = 10_000;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAX_API_PAGE_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 100_000;
const MAX_PAX_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 128;
const API_HEADERS = {
  accept: "application/vnd.github+json",
  "x-github-api-version": "2022-11-28",
  "user-agent": "Bifrost-Agent-Open-Pack-Cache",
};

export class OpenPackError extends Error {
  constructor(code, message, cause, details) {
    super(message, cause ? { cause } : undefined);
    this.name = "OpenPackError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

export function openPackCacheRootFor(
  env = process.env,
  platform = process.platform,
  homedir = os.homedir(),
) {
  let base;
  if (env.BIFROST_LAUNCHER_CACHE_DIR?.trim()) {
    base = path.resolve(env.BIFROST_LAUNCHER_CACHE_DIR.trim());
  } else if (platform === "darwin") {
    base = path.join(homedir, "Library", "Caches", "bifrost-agent");
  } else if (platform === "win32") {
    base = path.join(
      env.LOCALAPPDATA || path.join(homedir, "AppData", "Local"),
      "Bifrost",
      "AgentPlugin",
    );
  } else {
    base = path.join(
      env.XDG_CACHE_HOME || path.join(homedir, ".cache"),
      "bifrost-agent",
    );
  }
  return path.join(base, "open-pack-releases");
}

export async function readEnginePackProfile(
  binaryPath,
  { execFileImpl = execFileAsync, env = process.env } = {},
) {
  let result;
  try {
    result = await execFileImpl(binaryPath, ["pack-engine-profile"], {
      env,
      encoding: "utf8",
      timeout: PROFILE_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });
  } catch (error) {
    const output = `${error?.stderr ?? ""}\n${error?.stdout ?? ""}`;
    if (isUnknownProfileCommand(output)) {
      throw new OpenPackError(
        "unsupported",
        "This Bifrost binary does not support pack-engine-profile.",
        error,
      );
    }
    throw new OpenPackError(
      "profile-execution",
      `Could not read the Bifrost engine pack profile: ${messageOf(error)}`,
      error,
    );
  }
  let profile;
  try {
    profile = parseStrictJson(
      String(result?.stdout ?? ""),
      "invalid-engine-profile",
    );
    await validateEnginePackProfile(profile);
  } catch (error) {
    if (error instanceof OpenPackError) {
      throw error;
    }
    throw new OpenPackError(
      "invalid-engine-profile",
      `The Bifrost engine pack profile is invalid: ${messageOf(error)}`,
      error,
    );
  }
  return profile;
}

export async function prepareOpenPacks({
  cacheDir,
  engineProfile,
  fetchImpl = globalThis.fetch,
  offline = false,
  refresh = false,
}) {
  if (typeof fetchImpl !== "function") {
    throw new OpenPackError(
      "invalid-arguments",
      "fetchImpl must be a function.",
    );
  }
  if (offline && refresh) {
    throw new OpenPackError(
      "invalid-arguments",
      "offline and refresh cannot both be enabled.",
    );
  }
  await validateEnginePackProfile(engineProfile);
  const root = path.resolve(cacheDir ?? openPackCacheRootFor());

  const inventory = await loadOrDiscoverInventory({
    root,
    fetchImpl,
    offline,
    refresh,
  });
  const selected = resolveOpenPackSet(inventory.releases, engineProfile);
  if (selected.status === "pending") {
    throw new OpenPackError(
      "pending",
      selected.message,
      undefined,
      selected.receipt,
    );
  }
  if (selected.status === "invalid") {
    throw new OpenPackError("invalid-manifest", selected.message);
  }
  if (selected.status === "integrity-error") {
    throw new OpenPackError("integrity-error", selected.message);
  }
  if (selected.status !== "ready") {
    throw new OpenPackError("no-compatible-release", selected.message);
  }

  const rulesRelease = selected.releases.find(
    (item) => item.manifest.pack.id === ROOT_PACK_ID,
  );
  const semanticRelease = selected.releases.find(
    (item) => item.manifest.pack.id === SEMANTIC_PACK_ID,
  );
  if (!rulesRelease || !semanticRelease) {
    throw new OpenPackError(
      "invalid-manifest",
      "The selected rules release must resolve its exact semantic-pack dependency.",
    );
  }
  const rulesRole =
    rulesRelease.manifest.manifest_schema_version === 1 ? "policy" : "source";
  const policyArtifact = roleArtifact(rulesRelease.manifest, rulesRole);
  const nativeArtifact = roleArtifact(semanticRelease.manifest, "native");
  if (
    policyArtifact.format !== "tar.gz" ||
    nativeArtifact.format !== "tar.gz"
  ) {
    throw new OpenPackError(
      "invalid-manifest",
      "Selected rules source and native pack artifacts must use tar.gz format.",
    );
  }
  validateRulesSourceContents(rulesRelease.manifest);

  const artifactRecords = [];
  for (const release of selected.releases) {
    for (const artifact of release.manifest.artifacts) {
      const asset = release.assets[artifact.name];
      if (!asset) {
        throw new OpenPackError(
          "integrity-error",
          `Release ${release.tag} is missing declared asset ${artifact.name}.`,
        );
      }
      const artifactPath = await cacheArtifact({
        root,
        artifact,
        asset,
        fetchImpl,
        offline,
      });
      artifactRecords.push({
        pack_id: release.manifest.pack.id,
        release_version: release.manifest.release_version,
        name: artifact.name,
        role: artifact.role,
        size_bytes: artifact.size_bytes,
        sha256: artifact.sha256,
        cache_path: artifactPath,
      });
    }
  }

  const selectionIdentity = {
    engine_profile: engineProfile,
    releases: selected.releases.map((release) => ({
      pack_id: release.manifest.pack.id,
      release_version: release.manifest.release_version,
      source_commit: release.manifest.source.commit,
      tag: release.tag,
      manifest_sha256: release.manifest_sha256,
    })),
  };
  const selectionId = sha256(Buffer.from(canonicalJson(selectionIdentity)));
  const selectionsRoot = path.join(root, "selections");
  await fs.mkdir(selectionsRoot, { recursive: true });
  const finalPath = path.join(selectionsRoot, selectionId);
  const receiptPath = path.join(finalPath, "receipt.json");
  const archiveEntries = {
    source: await readPackArchive(
      pathForArtifact(artifactRecords, ROOT_PACK_ID, policyArtifact),
    ),
    semantic: await readPackArchive(
      pathForArtifact(artifactRecords, SEMANTIC_PACK_ID, nativeArtifact),
    ),
  };
  const expectedReceipt = buildSelectionReceipt({
    engineProfile,
    selectionId,
    selected,
    artifactRecords,
    archiveEntries,
    inventory,
  });
  const releaseContents = {
    [ROOT_PACK_ID]: rulesRelease.manifest,
    [SEMANTIC_PACK_ID]: semanticRelease.manifest,
  };

  const existing = await readExistingSelection({
    finalPath,
    receiptPath,
    expectedReceipt,
    releaseContents,
    inventory,
  });
  if (existing) return existing;

  const stage = await fs.mkdtemp(
    path.join(selectionsRoot, `.stage-${selectionId}-`),
  );
  try {
    const sourceRoot = path.join(stage, "source");
    const semanticRoot = path.join(stage, "semantic");
    await fs.mkdir(sourceRoot);
    await fs.mkdir(semanticRoot);
    await extractPackArchive(archiveEntries.source, sourceRoot);
    await extractPackArchive(archiveEntries.semantic, semanticRoot);
    await verifyManifestContents(rulesRelease.manifest, sourceRoot);
    await verifyManifestContents(semanticRelease.manifest, semanticRoot);
    await requireDirectory(path.join(sourceRoot, "rules"), "policy pack root");
    await requireRegularFile(
      path.join(semanticRoot, "bifrost-semantic-packs", "index.json"),
      "native semantic bundle index",
    );

    const storedReceipt = {
      ...expectedReceipt,
      created_at: new Date().toISOString(),
    };
    await writeAtomic(
      path.join(stage, "receipt.json"),
      `${JSON.stringify(storedReceipt, null, 2)}\n`,
    );
    try {
      await fs.rename(stage, finalPath);
    } catch (error) {
      if (!new Set(["EEXIST", "ENOTEMPTY", "EPERM"]).has(error?.code))
        throw error;
      const raced = await readExistingSelection({
        finalPath,
        receiptPath,
        expectedReceipt,
        releaseContents,
        inventory,
      });
      if (!raced) throw error;
      await fs.rm(stage, { recursive: true, force: true });
      return raced;
    }
    return formatSelectionResult(finalPath, storedReceipt, inventory, false);
  } catch (error) {
    await fs
      .rm(stage, { recursive: true, force: true })
      .catch((cleanupError) => {
        reportCacheCleanupFailure(
          `remove incomplete selection ${stage}`,
          cleanupError,
        );
      });
    if (error instanceof OpenPackError) throw error;
    throw new OpenPackError(
      "integrity-error",
      `Could not stage the verified open pack selection: ${messageOf(error)}`,
      error,
    );
  }
}

function isUnknownProfileCommand(output) {
  return /(?:unknown|unrecognized|unexpected)\s+(?:sub)?command[^\n]*pack-engine-profile|unknown argument\s*:?\s*['"]?pack-engine-profile|unexpected argument\s+['"]pack-engine-profile['"]|Found argument ['"]pack-engine-profile['"]/i.test(
    output,
  );
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function parseStrictJson(source, errorCode = "invalid-manifest") {
  const text = String(source);
  let index = 0;
  let depth = 0;
  const fail = (message) => {
    throw new OpenPackError(errorCode, `${message} at byte ${index}.`);
  };
  const enter = () => {
    depth += 1;
    if (depth > MAX_JSON_DEPTH) fail(`JSON nesting exceeds ${MAX_JSON_DEPTH}`);
  };
  const whitespace = () => {
    while (
      index < text.length &&
      /[\u0009\u000a\u000d\u0020]/.test(text[index])
    )
      index += 1;
  };
  const parseString = () => {
    const start = index;
    if (text[index] !== '"') fail("Expected JSON string");
    index += 1;
    while (index < text.length) {
      const character = text[index++];
      if (character === '"') {
        try {
          return JSON.parse(text.slice(start, index));
        } catch (error) {
          throw new OpenPackError(
            errorCode,
            `Invalid JSON string: ${messageOf(error)}`,
            error,
          );
        }
      }
      if (character === "\\") {
        if (index >= text.length) fail("Incomplete JSON escape");
        const escaped = text[index++];
        if (escaped === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(index, index + 4)))
            fail("Invalid Unicode escape");
          index += 4;
        } else if (!/["\\/bfnrt]/.test(escaped)) {
          fail("Invalid JSON escape");
        }
      } else if (character.charCodeAt(0) < 0x20) {
        fail("Control character in JSON string");
      }
    }
    fail("Unterminated JSON string");
  };
  const parseValue = () => {
    whitespace();
    const character = text[index];
    if (character === "{") {
      enter();
      index += 1;
      whitespace();
      const result = Object.create(null);
      const keys = new Set();
      if (text[index] === "}") {
        index += 1;
        depth -= 1;
        return result;
      }
      while (index < text.length) {
        whitespace();
        const key = parseString();
        if (keys.has(key)) fail(`Duplicate JSON key ${JSON.stringify(key)}`);
        keys.add(key);
        whitespace();
        if (text[index++] !== ":") fail("Expected colon after JSON key");
        result[key] = parseValue();
        whitespace();
        const separator = text[index++];
        if (separator === "}") {
          depth -= 1;
          return result;
        }
        if (separator !== ",") fail("Expected comma or closing object brace");
      }
      fail("Unterminated JSON object");
    }
    if (character === "[") {
      enter();
      index += 1;
      whitespace();
      const result = [];
      if (text[index] === "]") {
        index += 1;
        depth -= 1;
        return result;
      }
      while (index < text.length) {
        result.push(parseValue());
        whitespace();
        const separator = text[index++];
        if (separator === "]") {
          depth -= 1;
          return result;
        }
        if (separator !== ",") fail("Expected comma or closing array bracket");
      }
      fail("Unterminated JSON array");
    }
    if (character === '"') return parseString();
    const primitive =
      /(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/y;
    primitive.lastIndex = index;
    const match = primitive.exec(text);
    if (!match) fail("Invalid JSON value");
    index = primitive.lastIndex;
    return JSON.parse(match[0]);
  };

  const value = parseValue();
  whitespace();
  if (index !== text.length) fail("Trailing content after JSON value");
  return value;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateSchema(
  value,
  schema,
  root,
  location = "$",
  code = "invalid-manifest",
) {
  const reject = (message) => {
    throw new OpenPackError(code, `${location}: ${message}`);
  };
  if (schema.$ref) {
    let target = root;
    for (const component of schema.$ref.slice(2).split("/")) {
      target = target[component.replaceAll("~1", "/").replaceAll("~0", "~")];
    }
    return validateSchema(value, target, root, location, code);
  }
  if (schema.oneOf) {
    let matches = 0;
    for (const branch of schema.oneOf) {
      try {
        validateSchema(value, branch, root, location, code);
        matches += 1;
      } catch (error) {
        if (!(error instanceof OpenPackError)) throw error;
      }
    }
    if (matches !== 1) reject("expected exactly one schema alternative");
    return;
  }
  const types = {
    object: isRecord(value),
    array: Array.isArray(value),
    string: typeof value === "string",
    integer: Number.isSafeInteger(value),
    boolean: typeof value === "boolean",
    null: value === null,
  };
  if (schema.type && !types[schema.type]) reject(`expected ${schema.type}`);
  if (
    Object.hasOwn(schema, "const") &&
    (value !== schema.const || typeof value !== typeof schema.const)
  )
    reject("invalid constant");
  if (schema.enum && !schema.enum.includes(value)) reject("unsupported value");
  if (schema.type === "object") {
    const properties = schema.properties ?? {};
    const missing = (schema.required ?? []).filter(
      (key) => !Object.hasOwn(value, key),
    );
    if (missing.length) reject(`missing required fields ${missing.join(", ")}`);
    if (schema.additionalProperties === false) {
      const unknown = Object.keys(value).filter(
        (key) => !Object.hasOwn(properties, key),
      );
      if (unknown.length) reject(`unknown fields ${unknown.join(", ")}`);
    }
    for (const [key, child] of Object.entries(value)) {
      if (Object.hasOwn(properties, key))
        validateSchema(
          child,
          properties[key],
          root,
          `${location}.${key}`,
          code,
        );
    }
  } else if (schema.type === "array") {
    if (value.length < (schema.minItems ?? 0)) reject("too few entries");
    if (schema.uniqueItems) {
      const encoded = value.map(canonicalJson);
      if (new Set(encoded).size !== encoded.length)
        reject("duplicate array entries");
    }
    for (let index = 0; index < value.length; index += 1) {
      validateSchema(
        value[index],
        schema.items,
        root,
        `${location}[${index}]`,
        code,
      );
    }
  } else if (schema.type === "string") {
    if ([...value].length < (schema.minLength ?? 0))
      reject("string is too short");
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value))
      reject("string does not match its required pattern");
    if (schema.format === "uri") {
      let parsed;
      try {
        parsed = new URL(value);
      } catch {
        reject("must be an absolute HTTPS URI");
      }
      if (parsed.protocol !== "https:" || parsed.username || parsed.password)
        reject("must be an absolute HTTPS URI");
    }
  } else if (
    schema.type === "integer" &&
    value < (schema.minimum ?? Number.MIN_SAFE_INTEGER)
  ) {
    reject("integer is below its minimum");
  }
}

async function validateEnginePackProfile(profile) {
  const expected = [
    "build_identity",
    "capabilities",
    "capability_contract_version",
    "engine_version",
    "model_set_sha256",
    "schemas",
  ];
  if (
    !isRecord(profile) ||
    canonicalJson(Object.keys(profile).sort()) !== canonicalJson(expected)
  ) {
    throw new OpenPackError(
      "invalid-engine-profile",
      "Engine profile must contain exactly the six trusted profile fields.",
    );
  }
  let schema;
  try {
    schema = await readSchema(2);
    validateSemver(profile.engine_version);
    validateSchema(
      profile.schemas,
      schema.$defs["schema-set"],
      schema,
      "engine_profile.schemas",
      "invalid-engine-profile",
    );
    validateSchema(
      profile.capabilities,
      schema.$defs["string-set"],
      schema,
      "engine_profile.capabilities",
      "invalid-engine-profile",
    );
  } catch (error) {
    if (error instanceof OpenPackError) throw error;
    throw new OpenPackError(
      "invalid-engine-profile",
      `Engine profile schema validation failed: ${messageOf(error)}`,
      error,
    );
  }
  if (
    typeof profile.build_identity !== "string" ||
    !profile.build_identity ||
    !/^[0-9a-f]{64}$/.test(profile.model_set_sha256) ||
    !Number.isSafeInteger(profile.capability_contract_version) ||
    profile.capability_contract_version < 1
  ) {
    throw new OpenPackError(
      "invalid-engine-profile",
      "Engine build, model, or capability contract identity is invalid.",
    );
  }
}

const cachedSchemaTexts = new Map();
async function readSchema(version = 2) {
  if (version !== 1 && version !== 2) {
    throw new OpenPackError(
      "unsupported-manifest-schema",
      `Unsupported release manifest schema ${String(version)}.`,
    );
  }
  if (!cachedSchemaTexts.has(version)) {
    const schemaPath = version === 1 ? V1_SCHEMA_PATH : SCHEMA_PATH;
    try {
      cachedSchemaTexts.set(version, await fs.readFile(schemaPath, "utf8"));
    } catch (error) {
      throw new OpenPackError(
        "invalid-schema",
        `Could not read the bundled public schema ${version}: ${messageOf(error)}`,
        error,
      );
    }
  }
  return parseStrictJson(cachedSchemaTexts.get(version), "invalid-schema");
}

async function loadOrDiscoverInventory({ root, fetchImpl, offline, refresh }) {
  const indexPath = path.join(root, "manifest-index.json");
  let cached = null;
  if (!refresh) {
    cached = await readCachedInventory(root, indexPath);
  }
  if (
    cached &&
    (offline || Date.now() - cached.fetched_at_ms < MANIFEST_CACHE_TTL_MS)
  ) {
    return {
      ...cached,
      discovery_status: offline ? "offline-cache" : "fresh-cache",
    };
  }
  if (offline) {
    throw new OpenPackError(
      "unavailable",
      "No verified open-pack manifest cache is available for offline selection.",
    );
  }

  let discovered;
  try {
    discovered = await discoverInventory(root, fetchImpl);
  } catch (error) {
    if (
      cached &&
      !refresh &&
      error instanceof OpenPackError &&
      error.code === "unavailable"
    ) {
      return { ...cached, discovery_status: "stale-cache" };
    }
    if (error instanceof OpenPackError) throw error;
    throw new OpenPackError(
      "unavailable",
      `Could not discover public open-pack releases: ${messageOf(error)}`,
      error,
    );
  }
  return { ...discovered, discovery_status: "online" };
}

async function readCachedInventory(root, indexPath) {
  let rawIndex;
  try {
    rawIndex = await fs.readFile(indexPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw new OpenPackError(
      "integrity-error",
      `Could not read cached open-pack manifest index: ${messageOf(error)}`,
      error,
    );
  }
  let index;
  try {
    index = parseStrictJson(rawIndex, "integrity-error");
  } catch (error) {
    if (error instanceof OpenPackError) throw error;
    throw new OpenPackError(
      "integrity-error",
      `Cached open-pack manifest index is corrupt: ${messageOf(error)}`,
      error,
    );
  }
  if (
    !isRecord(index) ||
    index.schema_version !== 1 ||
    !Array.isArray(index.releases) ||
    typeof index.fetched_at !== "string"
  ) {
    throw new OpenPackError(
      "integrity-error",
      "Cached open-pack manifest index has an unsupported or invalid shape.",
    );
  }
  const fetchedAt = Date.parse(index.fetched_at);
  if (!Number.isFinite(fetchedAt)) {
    throw new OpenPackError(
      "integrity-error",
      "Cached open-pack manifest index has an invalid timestamp.",
    );
  }
  const seenTags = new Set();
  const releases = [];
  for (const record of index.releases) {
    validateCachedRecordShape(record);
    if (seenTags.has(record.tag)) {
      throw new OpenPackError(
        "integrity-error",
        `Cached manifest index repeats release tag ${record.tag}.`,
      );
    }
    seenTags.add(record.tag);
    const manifestPath = path.join(
      root,
      "manifests",
      record.manifest_sha256 + ".json",
    );
    let bytes;
    try {
      bytes = await fs.readFile(manifestPath);
    } catch (error) {
      throw new OpenPackError(
        "integrity-error",
        `Cached release manifest is missing for ${record.tag}.`,
        error,
      );
    }
    if (sha256(bytes) !== record.manifest_sha256) {
      throw new OpenPackError(
        "integrity-error",
        `Cached release manifest hash mismatch for ${record.tag}.`,
      );
    }
    const manifest = parseStrictJson(bytes.toString("utf8"), "integrity-error");
    await validateReleaseManifest(manifest);
    validateReleaseBinding(record, manifest);
    releases.push({ ...record, manifest });
  }
  assertNoAmbiguousVersions(releases);
  return {
    schema_version: 1,
    fetched_at: index.fetched_at,
    fetched_at_ms: fetchedAt,
    releases,
  };
}

function validateCachedRecordShape(record) {
  if (
    !isRecord(record) ||
    typeof record.tag !== "string" ||
    !/^[0-9a-f]{64}$/.test(record.manifest_sha256 ?? "") ||
    !/^[0-9a-f]{40}$/.test(record.tag_commit ?? "") ||
    typeof record.prerelease !== "boolean" ||
    !isRecord(record.assets)
  ) {
    throw new OpenPackError(
      "integrity-error",
      "Cached release record has an invalid shape.",
    );
  }
  for (const [name, asset] of Object.entries(record.assets)) {
    if (!isRecord(asset) || typeof asset.url !== "string") {
      throw new OpenPackError(
        "integrity-error",
        `Cached release asset ${name} has an invalid record.`,
      );
    }
    validateAssetUrl(asset.url, name, "integrity-error");
  }
}

async function discoverInventory(root, fetchImpl) {
  const apiReleases = await fetchAllReleasePages(fetchImpl);
  const releases = [];
  const tags = new Set();
  for (const apiRelease of apiReleases) {
    if (!isRecord(apiRelease) || typeof apiRelease.tag_name !== "string") {
      throw new OpenPackError(
        "invalid-manifest",
        "GitHub release listing contains an invalid release record.",
      );
    }
    const stream = releaseStreamForTag(apiRelease.tag_name);
    if (!stream) continue;
    if (apiRelease.draft === true) continue;
    if (tags.has(apiRelease.tag_name)) {
      throw new OpenPackError(
        "integrity-error",
        `GitHub release listing repeats tag ${apiRelease.tag_name}.`,
      );
    }
    tags.add(apiRelease.tag_name);
    if (!Array.isArray(apiRelease.assets)) {
      throw new OpenPackError(
        "invalid-manifest",
        `GitHub release ${apiRelease.tag_name} has no valid asset list.`,
      );
    }
    const assets = Object.create(null);
    for (const asset of apiRelease.assets) {
      if (
        !isRecord(asset) ||
        typeof asset.name !== "string" ||
        !asset.name ||
        typeof asset.browser_download_url !== "string"
      ) {
        throw new OpenPackError(
          "invalid-manifest",
          `GitHub release ${apiRelease.tag_name} has an invalid asset entry.`,
        );
      }
      if (Object.hasOwn(assets, asset.name)) {
        throw new OpenPackError(
          "invalid-manifest",
          `GitHub release ${apiRelease.tag_name} repeats asset ${asset.name}.`,
        );
      }
      validateAssetUrl(
        asset.browser_download_url,
        asset.name,
        "invalid-manifest",
      );
      assets[asset.name] = { url: asset.browser_download_url };
    }
    const manifestAsset = assets["pack-release.json"];
    if (!manifestAsset) {
      throw new OpenPackError(
        "invalid-manifest",
        `GitHub release ${apiRelease.tag_name} is missing pack-release.json.`,
      );
    }
    const rawManifest = await fetchBytes(
      manifestAsset.url,
      fetchImpl,
      MAX_MANIFEST_BYTES,
      "invalid-manifest",
    );
    const manifest = parseStrictJson(
      rawManifest.toString("utf8"),
      "invalid-manifest",
    );
    await validateReleaseManifest(manifest);
    if (
      manifest.pack.id !== stream.pack_id ||
      manifest.pack.repository !== REPOSITORY_URL
    ) {
      throw new OpenPackError(
        "invalid-manifest",
        `Release ${apiRelease.tag_name} has the wrong pack identity or repository.`,
      );
    }
    const expectedTag = `${stream.prefix}v${manifest.release_version}`;
    if (apiRelease.tag_name !== expectedTag) {
      throw new OpenPackError(
        "integrity-error",
        `Release tag ${apiRelease.tag_name} does not bind manifest version ${manifest.release_version}.`,
      );
    }
    const isPrerelease =
      parseSemver(manifest.release_version).prerelease.length > 0;
    if (apiRelease.prerelease !== isPrerelease) {
      throw new OpenPackError(
        "integrity-error",
        `GitHub prerelease flag does not match ${apiRelease.tag_name}.`,
      );
    }
    const tagCommit = await resolveTagCommit(apiRelease.tag_name, fetchImpl);
    if (tagCommit !== manifest.source.commit) {
      throw new OpenPackError(
        "integrity-error",
        `Tag ${apiRelease.tag_name} resolves to ${tagCommit}, but the manifest names ${manifest.source.commit}.`,
      );
    }
    const manifestHash = sha256(rawManifest);
    const record = {
      tag: apiRelease.tag_name,
      tag_commit: tagCommit,
      prerelease: isPrerelease,
      manifest_sha256: manifestHash,
      assets,
      manifest,
    };
    await writeAtomic(
      path.join(root, "manifests", `${manifestHash}.json`),
      rawManifest,
    );
    releases.push(record);
  }
  assertNoAmbiguousVersions(releases);
  const fetchedAt = new Date().toISOString();
  const index = {
    schema_version: 1,
    fetched_at: fetchedAt,
    releases: releases.map(({ manifest, ...record }) => record),
  };
  await writeAtomic(
    path.join(root, "manifest-index.json"),
    `${JSON.stringify(index, null, 2)}\n`,
    { replace: true },
  );
  return {
    schema_version: 1,
    fetched_at: fetchedAt,
    fetched_at_ms: Date.parse(fetchedAt),
    releases,
  };
}

function releaseStreamForTag(tag) {
  if (tag.startsWith("rules/"))
    return { prefix: "rules/", pack_id: ROOT_PACK_ID };
  if (tag.startsWith("packs/"))
    return { prefix: "packs/", pack_id: SEMANTIC_PACK_ID };
  return null;
}

async function fetchAllReleasePages(fetchImpl) {
  const releases = [];
  for (let page = 1; page <= 100; page += 1) {
    const url = new URL(`${API_ROOT}/releases`);
    url.searchParams.set("per_page", "100");
    url.searchParams.set("page", String(page));
    const bytes = await fetchBytes(
      url,
      fetchImpl,
      MAX_API_PAGE_BYTES,
      "unavailable",
    );
    let records;
    try {
      records = parseStrictJson(bytes.toString("utf8"), "invalid-manifest");
    } catch (error) {
      if (error instanceof OpenPackError) throw error;
      throw new OpenPackError(
        "invalid-manifest",
        `GitHub returned invalid release JSON: ${messageOf(error)}`,
        error,
      );
    }
    if (!Array.isArray(records) || records.length > 100) {
      throw new OpenPackError(
        "invalid-manifest",
        `GitHub release page ${page} is not a valid page of at most 100 releases.`,
      );
    }
    releases.push(...records);
    if (records.length < 100) return releases;
  }
  throw new OpenPackError(
    "unavailable",
    "GitHub release pagination exceeded the supported 100-page limit.",
  );
}

async function resolveTagCommit(tag, fetchImpl) {
  let url = `${API_ROOT}/git/ref/tags/${tag.split("/").map(encodeURIComponent).join("/")}`;
  const seen = new Set();
  for (let depth = 0; depth < 10; depth += 1) {
    const bytes = await fetchBytes(url, fetchImpl, 1024 * 1024, "unavailable");
    const reference = parseStrictJson(
      bytes.toString("utf8"),
      "invalid-manifest",
    );
    const object = reference?.object;
    if (!isRecord(object) || !/^[0-9a-f]{40}$/.test(object.sha ?? "")) {
      throw new OpenPackError(
        "integrity-error",
        `GitHub tag API returned an invalid object for ${tag}.`,
      );
    }
    if (object.type === "commit") return object.sha;
    if (object.type !== "tag" || seen.has(object.sha)) {
      throw new OpenPackError(
        "integrity-error",
        `GitHub tag ${tag} is not a valid commit or annotated-tag chain.`,
      );
    }
    seen.add(object.sha);
    url = `${API_ROOT}/git/tags/${object.sha}`;
  }
  throw new OpenPackError(
    "integrity-error",
    `GitHub tag ${tag} has an excessively deep annotated-tag chain.`,
  );
}

async function fetchBytes(url, fetchImpl, maxBytes, httpErrorCode) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetchImpl(String(url), {
      headers: API_HEADERS,
      signal: controller.signal,
      redirect: "follow",
    });
    if (!response?.ok) {
      const status = response?.status ?? "unknown";
      const code =
        [403, 429].includes(status) || status >= 500
          ? "unavailable"
          : httpErrorCode;
      throw new OpenPackError(
        code,
        `Request failed with HTTP ${status}: ${url}`,
      );
    }
    const chunks = [];
    let total = 0;
    if (response.body?.getReader) {
      const reader = response.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > maxBytes) {
            await reader.cancel();
            throw new OpenPackError(
              httpErrorCode === "unavailable" ? "unavailable" : httpErrorCode,
              `Response exceeded ${maxBytes} bytes: ${url}`,
            );
          }
          chunks.push(Buffer.from(value));
        }
      } finally {
        reader.releaseLock();
      }
      return Buffer.concat(chunks, total);
    }
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.byteLength > maxBytes) {
      throw new OpenPackError(
        httpErrorCode === "unavailable" ? "unavailable" : httpErrorCode,
        `Response exceeded ${maxBytes} bytes: ${url}`,
      );
    }
    return bytes;
  } catch (error) {
    if (error instanceof OpenPackError) throw error;
    const code =
      error?.name === "AbortError" || error?.cause?.name === "AbortError"
        ? "unavailable"
        : "unavailable";
    throw new OpenPackError(
      code,
      `Request failed for ${url}: ${messageOf(error)}`,
      error,
    );
  } finally {
    clearTimeout(timeout);
  }
}

function validateAssetUrl(value, name, code) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new OpenPackError(code, `Release asset ${name} has an invalid URL.`);
  }
  if (
    url.protocol !== "https:" ||
    url.hostname.toLowerCase() !== "github.com" ||
    !url.pathname.startsWith(`/${OWNER}/${REPOSITORY}/releases/download/`) ||
    url.username ||
    url.password
  ) {
    throw new OpenPackError(
      code,
      `Release asset ${name} is not a public ${OWNER}/${REPOSITORY} release download.`,
    );
  }
}

function validateReleaseBinding(record, manifest) {
  const stream = releaseStreamForTag(record.tag);
  if (
    !stream ||
    record.prerelease !==
      parseSemver(manifest.release_version).prerelease.length > 0 ||
    record.tag !== `${stream.prefix}v${manifest.release_version}` ||
    record.tag_commit !== manifest.source.commit ||
    manifest.pack.id !== stream.pack_id ||
    manifest.pack.repository !== REPOSITORY_URL
  ) {
    throw new OpenPackError(
      "integrity-error",
      `Cached release ${record.tag} no longer matches its manifest and source binding.`,
    );
  }
}

async function validateReleaseManifest(manifest) {
  if (!isRecord(manifest))
    throw new OpenPackError(
      "invalid-manifest",
      "Release manifest must be a JSON object.",
    );
  const schemaVersion = manifest.manifest_schema_version;
  if (!Number.isSafeInteger(schemaVersion) || ![1, 2].includes(schemaVersion)) {
    throw new OpenPackError(
      "unsupported-manifest-schema",
      `Unsupported release manifest schema ${String(schemaVersion)}.`,
    );
  }
  const schema = await readSchema(schemaVersion);
  validateSchema(manifest, schema, schema);
  if (
    manifest.source.repository !== manifest.pack.repository ||
    manifest.source.dirty ||
    manifest.pack.repository !== REPOSITORY_URL ||
    manifest.pack.visibility !== "public"
  ) {
    throw new OpenPackError(
      "invalid-manifest",
      "A public release must name its clean source commit and canonical public repository.",
    );
  }
  if (
    schemaVersion === 1 &&
    compareSemver(
      manifest.compatibility.engine.min_inclusive,
      manifest.compatibility.engine.max_exclusive,
    ) >= 0
  ) {
    throw new OpenPackError(
      "invalid-manifest",
      "Release engine compatibility range is empty.",
    );
  }
  const releaseRequirements = new Set(
    manifest.compatibility.capabilities.required,
  );
  const contentKeys = new Set();
  for (const item of manifest.contents) {
    validateSafeRelativePath(item.path, "content path", "invalid-manifest");
    const key = `${item.kind}\0${item.identity}\0${item.path}`;
    if (contentKeys.has(key))
      throw new OpenPackError(
        "invalid-manifest",
        "Release manifest repeats a content identity and path.",
      );
    contentKeys.add(key);
    if (
      item.required_capabilities.some(
        (capability) => !releaseRequirements.has(capability),
      )
    ) {
      throw new OpenPackError(
        "invalid-manifest",
        `Content ${item.identity} requires a capability absent from the release declaration.`,
      );
    }
    for (const [axis, versions] of Object.entries(item.schemas)) {
      if (
        versions.some(
          (version) => !manifest.compatibility.schemas[axis].includes(version),
        )
      ) {
        throw new OpenPackError(
          "invalid-manifest",
          `Content ${item.identity} requires a schema absent from the release declaration.`,
        );
      }
    }
  }
  const artifactNames = new Set();
  for (const artifact of manifest.artifacts) {
    validateSafeRelativePath(
      artifact.name,
      "artifact name",
      "invalid-manifest",
    );
    if (artifact.name.includes("/") || artifactNames.has(artifact.name)) {
      throw new OpenPackError(
        "invalid-manifest",
        "Release artifact names must be unique filenames.",
      );
    }
    if (
      !Number.isSafeInteger(artifact.size_bytes) ||
      artifact.size_bytes > MAX_ARTIFACT_BYTES
    ) {
      throw new OpenPackError(
        "invalid-manifest",
        `Artifact ${artifact.name} exceeds the supported ${MAX_ARTIFACT_BYTES}-byte size limit.`,
      );
    }
    artifactNames.add(artifact.name);
  }
  if (
    schemaVersion === 1 &&
    manifest.qualification.status === "qualified" &&
    (manifest.qualification.evidence.length === 0 ||
      !manifest.artifacts.some(
        (item) => item.role === "policy" || item.role === "native",
      ))
  ) {
    throw new OpenPackError(
      "invalid-manifest",
      "Qualified releases require evidence and a policy or native artifact.",
    );
  }
  if (schemaVersion === 2) {
    for (const axis of ["integrity", "behavior"]) {
      const state = manifest.qualification[axis];
      if (
        state.status !== "pending" &&
        !state.evidence.some((evidence) => evidence.trim().length > 0)
      ) {
        throw new OpenPackError(
          "invalid-manifest",
          `Schema 2 ${axis} qualification status ${state.status} requires nonblank evidence.`,
        );
      }
    }
  }
  const dependencyKeys = new Set();
  const dependencyVersions = new Map();
  for (const dependency of manifest.release_dependencies ?? []) {
    if (dependency.repository !== manifest.pack.repository) {
      throw new OpenPackError(
        "no-compatible-release",
        `Release ${manifest.pack.id} depends on another repository that this helper does not acquire.`,
      );
    }
    const key = `${dependency.pack_id}\0${dependency.release_version}\0${dependency.repository}`;
    if (dependencyKeys.has(key))
      throw new OpenPackError(
        "invalid-manifest",
        "Release manifest repeats an exact dependency.",
      );
    dependencyKeys.add(key);
    if (schemaVersion === 2) {
      const repositoryKey = `${dependency.pack_id}\0${dependency.repository}`;
      const previousVersion = dependencyVersions.get(repositoryKey);
      if (previousVersion && previousVersion !== dependency.release_version) {
        throw new OpenPackError(
          "invalid-manifest",
          `Conflicting exact release dependencies for ${dependency.pack_id} from ${dependency.repository}.`,
        );
      }
      dependencyVersions.set(repositoryKey, dependency.release_version);
    }
  }
}

function assertNoAmbiguousVersions(releases) {
  const precedence = new Map();
  for (const release of releases) {
    const key = `${release.manifest.pack.id}\0${precedenceKey(release.manifest.release_version)}`;
    const previous = precedence.get(key);
    if (previous && previous !== release.manifest_sha256) {
      throw new OpenPackError(
        "invalid-manifest",
        `Ambiguous release manifests share SemVer precedence for ${release.manifest.pack.id}.`,
      );
    }
    precedence.set(key, release.manifest_sha256);
  }
}

function precedenceKey(version) {
  const parsed = parseSemver(version);
  return `${parsed.major}.${parsed.minor}.${parsed.patch}-${parsed.prerelease.join(".")}`;
}

function parseSemver(version) {
  const match =
    typeof version === "string"
      ? /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(
          version,
        )
      : null;
  if (!match) {
    throw new OpenPackError(
      "invalid-manifest",
      `Invalid SemVer value ${JSON.stringify(version)}.`,
    );
  }
  const [, majorText, minorText, patchText, prereleaseText] = match;
  return {
    major: BigInt(majorText),
    minor: BigInt(minorText),
    patch: BigInt(patchText),
    prerelease: prereleaseText === undefined ? [] : prereleaseText.split("."),
  };
}

function validateSemver(version) {
  parseSemver(version);
}

function compareSemver(left, right) {
  const a = typeof left === "string" ? parseSemver(left) : left;
  const b = typeof right === "string" ? parseSemver(right) : right;
  for (const field of ["major", "minor", "patch"]) {
    if (a[field] < b[field]) return -1;
    if (a[field] > b[field]) return 1;
  }
  if (!a.prerelease.length && !b.prerelease.length) return 0;
  if (!a.prerelease.length) return 1;
  if (!b.prerelease.length) return -1;
  const count = Math.min(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < count; index += 1) {
    const first = a.prerelease[index];
    const second = b.prerelease[index];
    const firstNumeric = /^[0-9]+$/.test(first);
    const secondNumeric = /^[0-9]+$/.test(second);
    if (firstNumeric && secondNumeric) {
      const firstNumber = BigInt(first);
      const secondNumber = BigInt(second);
      if (firstNumber < secondNumber) return -1;
      if (firstNumber > secondNumber) return 1;
    } else if (firstNumeric !== secondNumeric) {
      return firstNumeric ? -1 : 1;
    } else {
      if (first < second) return -1;
      if (first > second) return 1;
    }
  }
  return Math.sign(a.prerelease.length - b.prerelease.length);
}

function resolveOpenPackSet(releases, engineProfile) {
  const candidates = releases
    .filter(
      (release) =>
        release.manifest.pack.id === ROOT_PACK_ID &&
        !release.prerelease &&
        releaseCompatible(release.manifest, engineProfile),
    )
    .sort((left, right) =>
      compareSemver(
        right.manifest.release_version,
        left.manifest.release_version,
      ),
    );
  if (candidates.length === 0) {
    return {
      status: "unavailable",
      message:
        "No public rules release is compatible with this Bifrost engine profile.",
    };
  }
  let pendingSet = null;
  let incompleteSet = null;
  let failedIntegrity = null;
  let failedBehavior = null;
  for (const root of candidates) {
    const dependencies = root.manifest.release_dependencies ?? [];
    if (
      dependencies.length !== 1 ||
      dependencies[0].pack_id !== SEMANTIC_PACK_ID
    ) {
      return {
        status: "invalid",
        message: `Rules release ${root.manifest.release_version} must pin exactly one ${SEMANTIC_PACK_ID} release.`,
      };
    }
    const pin = dependencies[0];
    const semantic = releases.find(
      (release) =>
        release.manifest.pack.id === pin.pack_id &&
        release.manifest.release_version === pin.release_version &&
        release.manifest.pack.repository === pin.repository,
    );
    if (!semantic || !releaseCompatible(semantic.manifest, engineProfile)) {
      incompleteSet ??= `Rules release ${root.manifest.release_version} has no compatible exact semantic dependency ${pin.release_version}.`;
      continue;
    }
    if ((semantic.manifest.release_dependencies ?? []).length) {
      return {
        status: "invalid",
        message: `Semantic release ${semantic.manifest.release_version} must not declare further release dependencies.`,
      };
    }
    const selected = [root, semantic];
    const states = selected.map((release) =>
      releaseQualificationState(release.manifest),
    );
    if (states.includes("integrity-failed")) {
      failedIntegrity ??= `A selected release declares failed integrity: ${formatQualificationSummary(selected)}.`;
      continue;
    }
    if (states.includes("behavior-failed")) {
      failedBehavior ??= `A selected release declares failed behavior: ${formatQualificationSummary(selected)}.`;
      continue;
    }
    if (states.includes("pending")) {
      pendingSet ??= selected;
      continue;
    }
    return { status: "ready", releases: selected };
  }
  if (pendingSet) {
    const receiptSchemaVersion = pendingSet.some(
      (release) => release.manifest.manifest_schema_version === 2,
    ) ? 2 : 1;
    const releasesInReceipt = pendingSet.map(({ tag, manifest }) => ({
      pack_id: manifest.pack.id,
      release_version: manifest.release_version,
      tag,
      qualification: manifest.qualification,
      ...(receiptSchemaVersion === 2
        ? { manifest_schema_version: manifest.manifest_schema_version }
        : {}),
    }));
    return {
      status: "pending",
      message: `No default-eligible complete release set is available; newest complete set has pending qualification: ${formatQualificationSummary(pendingSet)}.`,
      receipt: {
        ...(receiptSchemaVersion === 2
          ? { receipt_schema_version: 2, status: "pending" }
          : {}),
        releases: releasesInReceipt,
      },
    };
  }
  if (failedIntegrity) {
    return { status: "integrity-error", message: failedIntegrity };
  }
  return {
    status: "unavailable",
    message:
      incompleteSet ??
      failedBehavior ??
      "No complete compatible open pack release set is available.",
  };
}

function releaseCompatible(manifest, profile) {
  if (manifest.manifest_schema_version === 1) {
    const range = manifest.compatibility.engine;
    if (
      compareSemver(profile.engine_version, range.min_inclusive) < 0 ||
      compareSemver(profile.engine_version, range.max_exclusive) >= 0
    )
      return false;
  }
  const required = manifest.compatibility.capabilities.required;
  if (
    manifest.compatibility.capabilities.contract_version !==
      profile.capability_contract_version ||
    required.some((capability) => !profile.capabilities.includes(capability))
  )
    return false;
  for (const [axis, versions] of Object.entries(
    manifest.compatibility.schemas,
  )) {
    if (!versions.every((version) => profile.schemas[axis].includes(version)))
      return false;
  }
  for (const content of manifest.contents) {
    if (
      content.required_capabilities.some(
        (capability) => !profile.capabilities.includes(capability),
      )
    )
      return false;
    for (const [axis, versions] of Object.entries(content.schemas)) {
      if (!versions.every((version) => profile.schemas[axis].includes(version)))
        return false;
    }
  }
  return true;
}

function releaseQualificationState(manifest) {
  if (manifest.manifest_schema_version === 1) {
    return manifest.qualification.status === "qualified" ? "eligible" : "pending";
  }
  if (manifest.qualification.integrity.status === "failed")
    return "integrity-failed";
  if (manifest.qualification.behavior.status === "failed")
    return "behavior-failed";
  if (manifest.qualification.integrity.status === "pending") return "pending";
  return "eligible";
}

function formatQualificationSummary(releases) {
  return releases
    .map(({ manifest }) => {
      const identity = `${manifest.pack.id}@${manifest.release_version}`;
      if (manifest.manifest_schema_version === 1)
        return `${identity} (${manifest.qualification.status})`;
      return `${identity} (integrity=${manifest.qualification.integrity.status}, behavior=${manifest.qualification.behavior.status})`;
    })
    .join(", ");
}

function roleArtifact(manifest, role) {
  const matches = manifest.artifacts.filter(
    (artifact) => artifact.role === role,
  );
  if (matches.length !== 1) {
    throw new OpenPackError(
      "invalid-manifest",
      `Release ${manifest.pack.id}@${manifest.release_version} must declare exactly one ${role} artifact.`,
    );
  }
  return matches[0];
}

function validateRulesSourceContents(manifest) {
  if (manifest.manifest_schema_version !== 2) return;
  const catalogs = manifest.contents.filter(
    (item) =>
      item.kind === "policy-pack" &&
      item.path.startsWith("rules/") &&
      path.posix.basename(item.path) === "manifest.json",
  );
  const catalogRoots = new Set(
    catalogs.map((item) => path.posix.dirname(item.path)),
  );
  const hasPolicy = manifest.contents.some(
    (item) =>
      item.kind === "policy" &&
      [...catalogRoots].some((root) =>
        item.path.startsWith(`${root}/`),
      ),
  );
  if (catalogRoots.size === 0 || !hasPolicy) {
    throw new OpenPackError(
      "invalid-manifest",
      "Schema 2 rules source must index a rules catalog and policy content beneath that catalog.",
    );
  }
}

async function cacheArtifact({ root, artifact, asset, fetchImpl, offline }) {
  const artifactPath = path.join(root, "artifacts", artifact.sha256);
  let existing;
  try {
    existing = await fs.lstat(artifactPath);
  } catch (error) {
    if (error?.code !== "ENOENT")
      throw new OpenPackError(
        "integrity-error",
        `Could not inspect cached artifact ${artifact.name}: ${messageOf(error)}`,
        error,
      );
  }
  if (existing) {
    if (!existing.isFile() || existing.isSymbolicLink()) {
      throw new OpenPackError(
        "integrity-error",
        `Cached artifact ${artifact.name} is not a regular file.`,
      );
    }
    if (existing.size !== artifact.size_bytes) {
      throw new OpenPackError(
        "integrity-error",
        `Cached artifact ${artifact.name} has the wrong declared size.`,
      );
    }
    const bytes = await fs.readFile(artifactPath);
    if (
      bytes.byteLength !== artifact.size_bytes ||
      sha256(bytes) !== artifact.sha256
    ) {
      throw new OpenPackError(
        "integrity-error",
        `Cached artifact ${artifact.name} failed its declared size or SHA-256 check.`,
      );
    }
    return artifactPath;
  }
  if (offline)
    throw new OpenPackError(
      "unavailable",
      `Verified artifact ${artifact.name} is not cached for offline use.`,
    );
  if (!asset)
    throw new OpenPackError(
      "unavailable",
      `Release asset ${artifact.name} is unavailable.`,
    );
  const bytes = await fetchBytes(
    asset.url,
    fetchImpl,
    artifact.size_bytes,
    "unavailable",
  );
  if (
    bytes.byteLength !== artifact.size_bytes ||
    sha256(bytes) !== artifact.sha256
  ) {
    throw new OpenPackError(
      "integrity-error",
      `Downloaded artifact ${artifact.name} failed its declared size or SHA-256 check.`,
    );
  }
  await writeAtomic(artifactPath, bytes);
  return artifactPath;
}

function pathForArtifact(records, packId, artifact) {
  const record = records.find(
    (item) =>
      item.pack_id === packId &&
      item.name === artifact.name &&
      item.sha256 === artifact.sha256,
  );
  if (!record)
    throw new OpenPackError(
      "integrity-error",
      `Verified artifact cache record is missing for ${packId}/${artifact.name}.`,
    );
  return record.cache_path;
}

function buildSelectionReceipt({
  engineProfile,
  selectionId,
  selected,
  artifactRecords,
  archiveEntries,
  inventory,
}) {
  const usesSchema2 = selected.releases.some(
    (release) => release.manifest.manifest_schema_version === 2,
  );
  const fullyQualified = selected.releases.every((release) => {
    if (release.manifest.manifest_schema_version === 1)
      return release.manifest.qualification.status === "qualified";
    return (
      release.manifest.qualification.integrity.status === "verified" &&
      release.manifest.qualification.behavior.status === "qualified"
    );
  });
  return {
    receipt_schema_version: usesSchema2 ? 2 : 1,
    status: fullyQualified ? "qualified" : "compatible",
    engine_profile: engineProfile,
    selection_id: selectionId,
    inventory_fetched_at: inventory.fetched_at,
    releases: selected.releases.map((release) => ({
      pack_id: release.manifest.pack.id,
      release_version: release.manifest.release_version,
      source_commit: release.manifest.source.commit,
      tag: release.tag,
      tag_commit: release.tag_commit,
      manifest_sha256: release.manifest_sha256,
      ...(usesSchema2
        ? {
            manifest_schema_version: release.manifest.manifest_schema_version,
            ...(release.manifest.manifest_schema_version === 2
              ? { provenance: release.manifest.provenance ?? null }
              : {}),
          }
        : {}),
      qualification: release.manifest.qualification,
      artifacts: release.manifest.artifacts.map((artifact) => ({
        name: artifact.name,
        role: artifact.role,
        size_bytes: artifact.size_bytes,
        sha256: artifact.sha256,
      })),
    })),
    verified_contents: Object.fromEntries(
      selected.releases.map((release) => [
        release.manifest.pack.id,
        release.manifest.contents.map((item) => ({
          path: item.path,
          sha256: item.sha256,
        })),
      ]),
    ),
    extracted_files: {
      source: archiveFileRecords(archiveEntries.source),
      semantic: archiveFileRecords(archiveEntries.semantic),
    },
    artifacts: artifactRecords,
  };
}

async function readExistingSelection({
  finalPath,
  receiptPath,
  expectedReceipt,
  releaseContents,
  inventory,
}) {
  let stat;
  try {
    stat = await fs.lstat(finalPath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw new OpenPackError(
      "integrity-error",
      `Could not inspect cached pack selection: ${messageOf(error)}`,
      error,
    );
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new OpenPackError(
      "integrity-error",
      `Cached pack selection ${path.basename(finalPath)} is not a real directory.`,
    );
  }
  let bytes;
  try {
    await requireRegularFile(receiptPath, "cached pack selection receipt");
    bytes = await fs.readFile(receiptPath);
  } catch (error) {
    throw new OpenPackError(
      "integrity-error",
      `Cached pack selection receipt is missing or unsafe: ${messageOf(error)}`,
      error,
    );
  }
  const receipt = parseStrictJson(bytes.toString("utf8"), "integrity-error");
  const expectedFields = [
    "receipt_schema_version",
    "status",
    "engine_profile",
    "selection_id",
    "inventory_fetched_at",
    "releases",
    "verified_contents",
    "extracted_files",
    "artifacts",
  ];
  const validReceiptVersionAndStatus =
    receipt?.receipt_schema_version === 1
      ? receipt.status === "qualified"
      : receipt?.receipt_schema_version === 2 &&
        ["compatible", "qualified"].includes(receipt.status);
  if (
    !isRecord(receipt) ||
    Object.keys(receipt).some(
      (key) => !expectedFields.includes(key) && key !== "created_at",
    ) ||
    expectedFields.some((key) => !Object.hasOwn(receipt, key)) ||
    !validReceiptVersionAndStatus ||
    receipt.receipt_schema_version !== expectedReceipt.receipt_schema_version ||
    receipt.status !== expectedReceipt.status ||
    typeof receipt.created_at !== "string" ||
    !Number.isFinite(Date.parse(receipt.created_at)) ||
    typeof receipt.inventory_fetched_at !== "string" ||
    !Number.isFinite(Date.parse(receipt.inventory_fetched_at)) ||
    canonicalJson(receiptSelectionIdentity(receipt)) !==
      canonicalJson(receiptSelectionIdentity(expectedReceipt))
  ) {
    throw new OpenPackError(
      "integrity-error",
      `Cached pack selection receipt does not match the selected release set.`,
    );
  }
  for (const [packId, manifest] of Object.entries(releaseContents)) {
    const treeName = packId === ROOT_PACK_ID ? "source" : "semantic";
    const subtree = path.join(finalPath, treeName);
    await requireDirectory(subtree, `cached ${packId} extraction root`);
    await verifyExtractedTree(subtree, receipt.extracted_files?.[treeName]);
    await verifyManifestContents(manifest, subtree);
  }
  await requireDirectory(
    path.join(finalPath, "source", "rules"),
    "cached policy pack root",
  );
  await requireRegularFile(
    path.join(finalPath, "semantic", "bifrost-semantic-packs", "index.json"),
    "cached native semantic bundle index",
  );
  return formatSelectionResult(finalPath, receipt, inventory, true);
}

function receiptSelectionIdentity(receipt) {
  const {
    receipt_schema_version,
    status,
    engine_profile,
    selection_id,
    releases,
    verified_contents,
    extracted_files,
    artifacts,
  } = receipt;
  return {
    receipt_schema_version,
    status,
    engine_profile,
    selection_id,
    releases,
    verified_contents,
    extracted_files,
    artifacts,
  };
}

function formatSelectionResult(finalPath, receipt, inventory, reused) {
  return {
    env: {
      BIFROST_OPEN_SEMANTIC_PACK_BUNDLE: path.join(
        finalPath,
        "semantic",
        "bifrost-semantic-packs",
      ),
      BIFROST_OPEN_POLICY_PACK_ROOT: path.join(finalPath, "source", "rules"),
      BIFROST_SEMANTIC_PACK_CACHE_ROOT: path.resolve(
        path.dirname(path.dirname(finalPath)),
        "semantic-pack-catalog-v1",
      ),
    },
    receipt: {
      ...receipt,
      inventory_fetched_at: inventory.fetched_at,
      discovery_status: inventory.discovery_status,
      cache_reused: reused,
      path: path.join(finalPath, "receipt.json"),
    },
  };
}

async function writeAtomic(filePath, contents, { replace = false } = {}) {
  const bytes = Buffer.isBuffer(contents) ? contents : Buffer.from(contents);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const temporary = `${filePath}.tmp-${process.pid}-${randomUUID()}`;
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    if (replace) {
      await fs.rename(temporary, filePath);
    } else {
      try {
        await fs.link(temporary, filePath);
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        const current = await fs.readFile(filePath);
        if (!current.equals(bytes))
          throw new OpenPackError(
            "integrity-error",
            `Refusing to replace a conflicting cached file ${filePath}.`,
          );
      }
      await fs.rm(temporary, { force: true });
    }
  } catch (error) {
    await handle?.close().catch((cleanupError) => {
      reportCacheCleanupFailure(
        `close temporary cache file ${temporary}`,
        cleanupError,
      );
    });
    await fs.rm(temporary, { force: true }).catch((cleanupError) => {
      reportCacheCleanupFailure(
        `remove temporary cache file ${temporary}`,
        cleanupError,
      );
    });
    if (error instanceof OpenPackError) throw error;
    throw new OpenPackError(
      "integrity-error",
      `Could not atomically cache ${filePath}: ${messageOf(error)}`,
      error,
    );
  }
}

function reportCacheCleanupFailure(action, error) {
  process.stderr.write(`[bifrost] Could not ${action}: ${messageOf(error)}\n`);
}

function validateSafeRelativePath(value, label, code) {
  if (
    typeof value !== "string" ||
    !value ||
    value.includes("\\") ||
    value.includes("\0") ||
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value)
  ) {
    throw new OpenPackError(
      code,
      `${label} is not a safe relative POSIX path.`,
    );
  }
  const parts = value.split("/");
  if (
    parts.some(
      (part) =>
        !part ||
        part === "." ||
        part === ".." ||
        /[<>:"|?*\u0000-\u001f]/.test(part) ||
        /[. ]$/.test(part) ||
        /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part),
    )
  ) {
    throw new OpenPackError(
      code,
      `${label} contains an empty, current, or parent path component.`,
    );
  }
  return parts;
}

async function verifyManifestContents(manifest, root) {
  for (const item of manifest.contents) {
    const parts = validateSafeRelativePath(
      item.path,
      "manifest content path",
      "integrity-error",
    );
    let current = root;
    for (let index = 0; index < parts.length; index += 1) {
      current = path.join(current, parts[index]);
      let stat;
      try {
        stat = await fs.lstat(current);
      } catch (error) {
        throw new OpenPackError(
          "integrity-error",
          `Manifest content ${item.path} is missing: ${messageOf(error)}`,
          error,
        );
      }
      if (
        stat.isSymbolicLink() ||
        (index < parts.length - 1 && !stat.isDirectory()) ||
        (index === parts.length - 1 && !stat.isFile())
      ) {
        throw new OpenPackError(
          "integrity-error",
          `Manifest content ${item.path} traverses a link or is not a regular file.`,
        );
      }
    }
    const bytes = await fs.readFile(current);
    if (sha256(bytes) !== item.sha256)
      throw new OpenPackError(
        "integrity-error",
        `Manifest content ${item.path} failed its declared SHA-256 check.`,
      );
  }
}

async function requireDirectory(directory, label) {
  let stat;
  try {
    stat = await fs.lstat(directory);
  } catch (error) {
    throw new OpenPackError(
      "integrity-error",
      `${label} is missing: ${messageOf(error)}`,
      error,
    );
  }
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw new OpenPackError(
      "integrity-error",
      `${label} must be a real directory.`,
    );
}

async function requireRegularFile(filePath, label) {
  let stat;
  try {
    stat = await fs.lstat(filePath);
  } catch (error) {
    throw new OpenPackError(
      "integrity-error",
      `${label} is missing: ${messageOf(error)}`,
      error,
    );
  }
  if (!stat.isFile() || stat.isSymbolicLink())
    throw new OpenPackError(
      "integrity-error",
      `${label} must be a regular file.`,
    );
}

async function readPackArchive(archivePath) {
  const compressed = await fs.readFile(archivePath);
  let tar;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: MAX_UNPACKED_BYTES });
  } catch (error) {
    throw new OpenPackError(
      "integrity-error",
      `Pack artifact is not a bounded gzip tar archive: ${messageOf(error)}`,
      error,
    );
  }
  return parseTarEntries(tar);
}

function archiveFileRecords(entries) {
  return entries
    .filter((entry) => entry.type === "file")
    .map((entry) => ({
      path: entry.path,
      size_bytes: entry.bytes.byteLength,
      sha256: sha256(entry.bytes),
    }))
    .sort((left, right) =>
      left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
    );
}

async function extractPackArchive(entries, destination) {
  for (const entry of entries) {
    const target = path.join(destination, ...entry.path.split("/"));
    const relative = path.relative(destination, target);
    if (
      relative.startsWith(`..${path.sep}`) ||
      relative === ".." ||
      path.isAbsolute(relative)
    ) {
      throw new OpenPackError(
        "integrity-error",
        `Archive entry escapes its extraction root: ${entry.path}`,
      );
    }
    if (entry.type === "directory") {
      await fs.mkdir(target, { recursive: true, mode: 0o755 });
    } else {
      await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o755 });
      await fs.writeFile(target, entry.bytes, { flag: "wx", mode: 0o644 });
    }
  }
}

async function verifyExtractedTree(root, expectedFiles) {
  if (!Array.isArray(expectedFiles))
    throw new OpenPackError(
      "integrity-error",
      "Selection receipt has no extracted file inventory.",
    );
  const found = [];
  const pending = [{ absolute: root, relative: "" }];
  while (pending.length) {
    const current = pending.pop();
    const entries = await fs.readdir(current.absolute, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = path.join(current.absolute, entry.name);
      const relative = current.relative
        ? `${current.relative}/${entry.name}`
        : entry.name;
      const stat = await fs.lstat(absolute);
      if (stat.isSymbolicLink())
        throw new OpenPackError(
          "integrity-error",
          `Cached extraction contains a symbolic link at ${relative}.`,
        );
      if (stat.isDirectory()) pending.push({ absolute, relative });
      else if (stat.isFile()) {
        const bytes = await fs.readFile(absolute);
        found.push({
          path: relative,
          size_bytes: bytes.byteLength,
          sha256: sha256(bytes),
        });
      } else
        throw new OpenPackError(
          "integrity-error",
          `Cached extraction contains a special file at ${relative}.`,
        );
    }
  }
  found.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
  if (canonicalJson(found) !== canonicalJson(expectedFiles)) {
    throw new OpenPackError(
      "integrity-error",
      `Cached extraction tree ${path.basename(root)} differs from its verified archive inventory.`,
    );
  }
}

function parseTarEntries(tar) {
  const entries = [];
  const seen = new Map();
  const pathsWithDescendants = new Set();
  let offset = 0;
  let totalBytes = 0;
  let pendingPax = null;
  let zeroBlocks = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    offset += 512;
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      if (zeroBlocks === 2) break;
      continue;
    }
    if (zeroBlocks)
      throw new OpenPackError(
        "integrity-error",
        "Tar archive has data after an end marker.",
      );
    if (entries.length >= MAX_ARCHIVE_ENTRIES)
      throw new OpenPackError(
        "integrity-error",
        "Tar archive has too many entries.",
      );
    const storedChecksum = parseTarNumber(
      header.subarray(148, 156),
      "header checksum",
    );
    let checksum = 0;
    for (let index = 0; index < 512; index += 1)
      checksum += index >= 148 && index < 156 ? 32 : header[index];
    if (storedChecksum !== checksum)
      throw new OpenPackError(
        "integrity-error",
        "Tar header checksum is invalid.",
      );
    let name = tarString(header.subarray(0, 100));
    const prefix = tarString(header.subarray(345, 500));
    if (prefix) name = `${prefix}/${name}`;
    let size = parseTarNumber(header.subarray(124, 136), "entry size");
    const type = header[156] === 0 ? "0" : String.fromCharCode(header[156]);
    if (
      size > MAX_UNPACKED_BYTES ||
      offset + Math.ceil(size / 512) * 512 > tar.length
    ) {
      throw new OpenPackError(
        "integrity-error",
        `Tar entry ${name} has an invalid or oversized length.`,
      );
    }
    const data = tar.subarray(offset, offset + size);
    offset += Math.ceil(size / 512) * 512;
    if (type === "x") {
      if (pendingPax)
        throw new OpenPackError(
          "integrity-error",
          "Tar archive stacks PAX local headers.",
        );
      pendingPax = parsePax(data);
      continue;
    }
    if (type === "g" || type === "L" || type === "K")
      throw new OpenPackError(
        "integrity-error",
        "Tar archive uses unsupported global PAX or GNU link/name extensions.",
      );
    const pax = pendingPax ?? Object.create(null);
    pendingPax = null;
    if (Object.hasOwn(pax, "path")) name = pax.path;
    if (Object.hasOwn(pax, "size")) {
      if (!/^(0|[1-9][0-9]*)$/.test(pax.size))
        throw new OpenPackError(
          "integrity-error",
          `Tar entry ${name} has an invalid PAX size.`,
        );
      size = Number(pax.size);
      if (!Number.isSafeInteger(size) || size !== data.length)
        throw new OpenPackError(
          "integrity-error",
          `Tar PAX size disagrees with entry ${name}.`,
        );
    }
    const directory = type === "5";
    if (!directory && type !== "0" && type !== "7")
      throw new OpenPackError(
        "integrity-error",
        `Tar entry ${name} uses forbidden link or special type ${JSON.stringify(type)}.`,
      );
    if (type === "7")
      throw new OpenPackError(
        "integrity-error",
        `Tar entry ${name} is a contiguous file, which is unsupported.`,
      );
    if (directory && size !== 0)
      throw new OpenPackError(
        "integrity-error",
        `Tar directory ${name} has data.`,
      );
    if (directory && name.endsWith("/")) name = name.slice(0, -1);
    const parts = validateSafeRelativePath(
      name,
      "tar entry path",
      "integrity-error",
    );
    const normalized = parts.join("/");
    if (seen.has(normalized))
      throw new OpenPackError(
        "integrity-error",
        `Tar archive repeats path ${normalized}.`,
      );
    for (let index = 1; index < parts.length; index += 1) {
      const parent = parts.slice(0, index).join("/");
      if (seen.get(parent) === "file")
        throw new OpenPackError(
          "integrity-error",
          `Tar archive path ${normalized} descends through a file.`,
        );
      pathsWithDescendants.add(parent);
    }
    if (!directory && pathsWithDescendants.has(normalized))
      throw new OpenPackError(
        "integrity-error",
        `Tar archive file ${normalized} conflicts with an existing child path.`,
      );
    seen.set(normalized, directory ? "directory" : "file");
    totalBytes += directory ? 0 : size;
    if (totalBytes > MAX_UNPACKED_BYTES)
      throw new OpenPackError(
        "integrity-error",
        "Tar archive exceeds the unpacked byte limit.",
      );
    entries.push({
      path: normalized,
      type: directory ? "directory" : "file",
      bytes: data,
    });
  }
  if (
    zeroBlocks !== 2 ||
    offset > tar.length ||
    tar.subarray(offset).some((byte) => byte !== 0) ||
    pendingPax
  ) {
    throw new OpenPackError(
      "integrity-error",
      "Tar archive has a truncated or malformed end marker.",
    );
  }
  return entries;
}

function parseTarNumber(field, label) {
  if (field[0] & 0x80)
    throw new OpenPackError(
      "integrity-error",
      `Tar ${label} uses unsupported base-256 encoding.`,
    );
  const text = field.toString("ascii").replace(/\0.*$/s, "").trim();
  if (!text) return 0;
  if (!/^[0-7]+$/.test(text))
    throw new OpenPackError(
      "integrity-error",
      `Tar ${label} is not an octal number.`,
    );
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value))
    throw new OpenPackError("integrity-error", `Tar ${label} is too large.`);
  return value;
}

function tarString(field) {
  const nul = field.indexOf(0);
  return field.subarray(0, nul === -1 ? field.length : nul).toString("utf8");
}

function parsePax(data) {
  if (data.byteLength > MAX_PAX_BYTES)
    throw new OpenPackError(
      "integrity-error",
      "Tar PAX metadata exceeds its byte limit.",
    );
  const values = Object.create(null);
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0)
      throw new OpenPackError(
        "integrity-error",
        "Tar PAX record has no length separator.",
      );
    const digits = data.subarray(offset, space).toString("ascii");
    if (!/^[1-9][0-9]*$/.test(digits))
      throw new OpenPackError(
        "integrity-error",
        "Tar PAX record has an invalid length.",
      );
    const length = Number(digits);
    const end = offset + length;
    if (
      !Number.isSafeInteger(length) ||
      end > data.length ||
      data[end - 1] !== 0x0a
    )
      throw new OpenPackError(
        "integrity-error",
        "Tar PAX record length is inconsistent.",
      );
    const record = data.subarray(space + 1, end - 1).toString("utf8");
    const equals = record.indexOf("=");
    if (equals <= 0)
      throw new OpenPackError(
        "integrity-error",
        "Tar PAX record has no key/value separator.",
      );
    const key = record.slice(0, equals);
    const value = record.slice(equals + 1);
    if (
      Object.hasOwn(values, key) ||
      !new Set(["path", "size", "mtime", "uid", "gid", "uname", "gname"]).has(
        key,
      )
    ) {
      throw new OpenPackError(
        "integrity-error",
        `Tar PAX field ${key} is duplicate or unsupported.`,
      );
    }
    values[key] = value;
    offset = end;
  }
  return values;
}
