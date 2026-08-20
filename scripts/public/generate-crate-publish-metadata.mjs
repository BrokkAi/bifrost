#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { TextDecoder } from "node:util";

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const DEPENDENCY_KINDS = new Set(["normal", "dev", "build"]);

function requiredProperty(record, key, label) {
  if (!Object.prototype.hasOwnProperty.call(record, key)) {
    throw new TypeError(`${label} is missing Cargo metadata field ${key}.`);
  }
  return record[key];
}

function stringValue(value, label) {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string.`);
  return value;
}

function nullableString(value, label) {
  if (value === null) return null;
  return stringValue(value, label);
}

function stringArray(value, label) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new TypeError(`${label} must be an array of strings.`);
  }
  return value.slice();
}

function objectValue(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
  return value;
}

function utf8Compare(left, right) {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return leftBytes[index] - rightBytes[index];
  }
  return leftBytes.length - rightBytes.length;
}

function sortedObject(entries) {
  return Object.fromEntries(entries.sort(([left], [right]) => utf8Compare(left, right)));
}

function stringMap(value, label) {
  const object = objectValue(value, label);
  return sortedObject(
    Object.entries(object).map(([key, entry]) => [
      stringValue(key, `${label} key`),
      stringValue(entry, `${label}.${key}`),
    ]),
  );
}

function badgesObject(value) {
  const badges = objectValue(value, "badges");
  return sortedObject(
    Object.entries(badges).map(([badge, settings]) => [
      stringValue(badge, "badge name"),
      stringMap(settings, `badges.${badge}`),
    ]),
  );
}

function featuresObject(value) {
  const features = objectValue(value, "features");
  return sortedObject(
    Object.entries(features).map(([feature, values]) => [
      stringValue(feature, "feature name"),
      stringArray(values, `features.${feature}`),
    ]),
  );
}

function dependencyValue(dependency, index) {
  const label = `dependency ${index}`;
  objectValue(dependency, label);
  const name = stringValue(requiredProperty(dependency, "name", label), `${label}.name`);
  const req = stringValue(requiredProperty(dependency, "req", label), `${label}.req`);
  const kindValue = requiredProperty(dependency, "kind", label);
  if (kindValue !== null && typeof kindValue !== "string") {
    throw new TypeError(`${label}.kind must be null or a string.`);
  }
  const kind = kindValue === null ? "normal" : kindValue;
  if (!DEPENDENCY_KINDS.has(kind)) throw new TypeError(`${label}.kind is unsupported: ${kind}.`);
  const rename = requiredProperty(dependency, "rename", label);
  if (rename !== null && typeof rename !== "string") {
    throw new TypeError(`${label}.rename must be null or a string.`);
  }
  const registry = requiredProperty(dependency, "registry", label);
  if (registry !== null && typeof registry !== "string") {
    throw new TypeError(`${label}.registry must be null or a string.`);
  }
  if (registry === "") throw new TypeError(`${label}.registry must not be empty.`);
  const target = requiredProperty(dependency, "target", label);
  if (target !== null && typeof target !== "string") {
    throw new TypeError(`${label}.target must be null or a string.`);
  }
  const optional = requiredProperty(dependency, "optional", label);
  if (typeof optional !== "boolean") throw new TypeError(`${label}.optional must be boolean.`);
  const defaultFeatures = requiredProperty(dependency, "uses_default_features", label);
  if (typeof defaultFeatures !== "boolean") {
    throw new TypeError(`${label}.uses_default_features must be boolean.`);
  }

  const output = {
    optional,
    default_features: defaultFeatures,
    name,
    features: stringArray(requiredProperty(dependency, "features", label), `${label}.features`),
    version_req: req,
    target,
    kind,
  };
  // Cargo's NewCrateDependency skips these two fields when their value is null.
  if (registry !== null) output.registry = registry;
  if (rename !== null) output.explicit_name_in_toml = rename;
  return output;
}

function readUtf8File(filePath, label) {
  const content = fs.readFileSync(filePath);
  try {
    return UTF8_DECODER.decode(content);
  } catch (error) {
    throw new TypeError(`${label} must be valid UTF-8: ${error.message}`);
  }
}

function packageRelativePath(packageRoot, value, label) {
  if (path.isAbsolute(value)) throw new TypeError(`${label} must be relative to the package root.`);
  const root = path.resolve(packageRoot);
  const resolved = path.resolve(root, value);
  const relative = path.relative(root, resolved);
  if (relative === "" || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new TypeError(`${label} escapes the package root.`);
  }
  return resolved;
}

function readmeContent(packageRecord, packageRoot, suppliedContent) {
  const readme = requiredProperty(packageRecord, "readme", "package");
  if (readme === null) {
    if (suppliedContent !== undefined) throw new TypeError("Readme content was supplied but package.readme is null.");
    return null;
  }
  const readmePath = stringValue(readme, "package.readme");
  if (suppliedContent !== undefined) {
    if (typeof suppliedContent === "string") return suppliedContent;
    if (suppliedContent instanceof Uint8Array) {
      try {
        return UTF8_DECODER.decode(suppliedContent);
      } catch (error) {
        throw new TypeError(`Readme content must be valid UTF-8: ${error.message}`);
      }
    }
    throw new TypeError("Readme content must be a string or Uint8Array.");
  }
  return readUtf8File(packageRelativePath(packageRoot, readmePath, "package.readme"), "Readme content");
}

function verifyLicenseFile(packageRecord, packageRoot) {
  const licenseFile = requiredProperty(packageRecord, "license_file", "package");
  if (licenseFile === null) return null;
  const value = stringValue(licenseFile, "package.license_file");
  const resolved = packageRelativePath(packageRoot, value, "package.license_file");
  if (!fs.existsSync(resolved)) throw new Error(`Cargo license file does not exist: ${value}.`);
  return value;
}

function packageField(packageRecord, key, label = `package.${key}`) {
  return requiredProperty(packageRecord, key, "package") === null
    ? null
    : stringValue(requiredProperty(packageRecord, key, "package"), label);
}

function normalizePackageRecord(packageRecord, { packageRoot, readmeContent: suppliedReadmeContent, badges } = {}) {
  objectValue(packageRecord, "package record");
  const name = stringValue(requiredProperty(packageRecord, "name", "package"), "package.name");
  const version = stringValue(requiredProperty(packageRecord, "version", "package"), "package.version");
  const manifestPath = stringValue(requiredProperty(packageRecord, "manifest_path", "package"), "package.manifest_path");
  const root = path.resolve(packageRoot ?? path.dirname(manifestPath));
  if (!fs.existsSync(root)) throw new Error(`Cargo package root does not exist: ${root}.`);

  const dependencies = requiredProperty(packageRecord, "dependencies", "package");
  if (!Array.isArray(dependencies)) throw new TypeError("package.dependencies must be an array.");
  const packageBadges = badges ?? packageRecord.badges;
  if (packageBadges === undefined) {
    throw new Error("Cargo metadata does not expose [badges]; provide explicit badges content.");
  }

  const output = {
    name,
    vers: version,
    deps: dependencies.map(dependencyValue),
    features: featuresObject(requiredProperty(packageRecord, "features", "package")),
    authors: stringArray(requiredProperty(packageRecord, "authors", "package"), "package.authors"),
    description: packageField(packageRecord, "description"),
    documentation: packageField(packageRecord, "documentation"),
    homepage: packageField(packageRecord, "homepage"),
    readme: readmeContent(packageRecord, root, suppliedReadmeContent),
    readme_file: packageField(packageRecord, "readme"),
    keywords: stringArray(requiredProperty(packageRecord, "keywords", "package"), "package.keywords"),
    categories: stringArray(requiredProperty(packageRecord, "categories", "package"), "package.categories"),
    license: packageField(packageRecord, "license"),
    license_file: verifyLicenseFile(packageRecord, root),
    repository: packageField(packageRecord, "repository"),
    badges: badgesObject(packageBadges),
    links: packageField(packageRecord, "links"),
    rust_version: packageField(packageRecord, "rust_version"),
  };
  return output;
}

export function buildCratePublishMetadata(packageRecord, options = {}) {
  return normalizePackageRecord(packageRecord, options);
}

export function generateCratePublishMetadata(packageRecord, options = {}) {
  const metadata = buildCratePublishMetadata(packageRecord, options);
  return Buffer.from(JSON.stringify(metadata), "utf8");
}

function readJsonFile(filePath, label) {
  let value;
  try {
    value = JSON.parse(readUtf8File(filePath, label));
  } catch (error) {
    throw new TypeError(`${label} must contain valid JSON: ${error.message}`);
  }
  return value;
}

function requiredArgument(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is required.`);
  return value;
}

export function parseCliArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--help" || flag === "-h") return { help: true };
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`Missing value for ${flag}.`);
    switch (flag) {
      case "--cargo-metadata-file":
        options.cargoMetadataPath = value;
        break;
      case "--package":
        options.packageName = value;
        break;
      case "--version":
        options.version = value;
        break;
      case "--package-root":
        options.packageRoot = value;
        break;
      case "--badges-file":
        options.badgesPath = value;
        break;
      case "--output-file":
        options.outputPath = value;
        break;
      default:
        throw new Error(`Unknown option: ${flag}.`);
    }
    index += 1;
  }
  requiredArgument(options.cargoMetadataPath, "Cargo metadata file");
  requiredArgument(options.packageName, "Package name");
  requiredArgument(options.version, "Package version");
  requiredArgument(options.outputPath, "Output file");
  return options;
}

export const CLI_USAGE = `Usage: node scripts/public/generate-crate-publish-metadata.mjs \\
  --cargo-metadata-file FILE --package NAME --version VERSION --output-file FILE [options]

Options:
  --package-root DIR    Package root for README and license-file references
  --badges-file FILE    JSON object containing the Cargo [badges] table

The output is the exact compact UTF-8 JSON bytes sent as crates.io publish metadata.`;

function selectPackage(cargoMetadata, packageName, version) {
  objectValue(cargoMetadata, "Cargo metadata");
  if (!Array.isArray(cargoMetadata.packages)) throw new TypeError("Cargo metadata packages must be an array.");
  const matches = cargoMetadata.packages.filter((entry) => entry.name === packageName && entry.version === version);
  if (matches.length === 0) throw new Error(`No Cargo package matches ${packageName} ${version}.`);
  if (matches.length !== 1) throw new Error(`Cargo metadata has ${matches.length} matching packages for ${packageName} ${version}.`);
  return matches[0];
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseCliArgs(argv);
  if (options.help) {
    process.stdout.write(`${CLI_USAGE}\n`);
    return;
  }
  const cargoMetadata = readJsonFile(options.cargoMetadataPath, "Cargo metadata");
  const packageRecord = selectPackage(cargoMetadata, options.packageName, options.version);
  const badges = options.badgesPath === undefined ? packageRecord.badges : readJsonFile(options.badgesPath, "Badges");
  const metadataBytes = generateCratePublishMetadata(packageRecord, {
    packageRoot: options.packageRoot,
    badges,
  });
  fs.writeFileSync(options.outputPath, metadataBytes, { flag: "wx" });
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === currentFile) {
  main().catch((error) => {
    process.stderr.write(`generate-crate-publish-metadata: ${error.message}\n`);
    process.exitCode = 1;
  });
}
