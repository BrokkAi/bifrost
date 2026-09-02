#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "../..");
const output = join(
  repositoryRoot,
  "crates/bifrost-semantic-packs/models/go-stdlib-sync-atomic.json",
);
const declarationOutput = join(
  repositoryRoot,
  "crates/bifrost-semantic-packs/models/go-stdlib-sync-atomic-declarations.json",
);

function canonicalValue(hash, value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(length);
  hash.update(bytes);
}

function canonicalField(hash, name, value) {
  canonicalValue(hash, name);
  canonicalValue(hash, value);
}

function unsigned64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function declarationTypeId(name) {
  const hash = createHash("sha256");
  canonicalValue(hash, "bifrost.external-declaration.type.v1");
  canonicalField(hash, "ecosystem", "go");
  canonicalField(hash, "name", name);
  return `type.${hash.digest("hex")}`;
}

function declarationMemberId(owner, kind, isStatic, name, parameterTypes, returns) {
  const hash = createHash("sha256");
  canonicalValue(hash, "bifrost.external-declaration.member.v2");
  canonicalField(hash, "owner", owner);
  canonicalField(hash, "kind", JSON.stringify(kind));
  canonicalField(hash, "is_static", Buffer.from([isStatic ? 1 : 0]));
  canonicalField(hash, "parameter_arity", unsigned64(parameterTypes.length));
  canonicalField(hash, "name", name);
  canonicalField(hash, "generic_arity", unsigned64(0));
  canonicalValue(hash, "parameter_types");
  canonicalValue(hash, unsigned64(parameterTypes.length));
  for (const type of parameterTypes) canonicalValue(hash, JSON.stringify(type));
  canonicalField(hash, "return_type", JSON.stringify(returns ?? null));
  return `member.${hash.digest("hex")}`;
}

const named = (name) => ({ kind: "named", name, arguments: [], nullable: false });
const parameter = (name, type) => ({
  name,
  type,
  optional: false,
  variadic: false,
});

const input = (ordinal) => ({ kind: "parameter", ordinal });
const receiver = { kind: "receiver" };

function effect(location, operation) {
  return [{ kind: "atomic", location, operation }];
}

function summary(id, path, symbol, hasReceiver, parameterCount, operation) {
  return {
    id,
    target: {
      path,
      symbol,
      has_receiver: hasReceiver,
      parameter_count: parameterCount,
    },
    completeness: "complete",
    transfers: [],
    concurrency_effects: effect(hasReceiver ? receiver : input(0), operation),
  };
}

const integerTypes = [
  ["Int32", "int32"],
  ["Int64", "int64"],
  ["Uint32", "uint32"],
  ["Uint64", "uint64"],
  ["Uintptr", "uintptr"],
];
const freeTypes = [...integerTypes, ["Pointer", "unsafe.Pointer"]];
const summaries = [];
const moduleName = "sync/atomic";
const moduleId = declarationTypeId(moduleName);
const declarationTypes = [
  {
    id: moduleId,
    name: moduleName,
    type_kind: "module",
    visibility: "package",
    is_abstract: false,
    is_sealed: false,
    has_explicit_type_terms: false,
    type_parameters: [],
    type_parameter_constraints: [],
    embedded_types: [],
    hierarchy: [],
    aliases: ["atomic"],
    extension_surfaces: [],
    locator: {
      kind: "artifact",
      path: "src/sync/atomic/doc.go",
      symbol: moduleName,
    },
  },
];
const declarationMembers = [];

function declarationMember(owner, name, kind, path, parameterTypes, returns) {
  const isStatic = kind === "function";
  const member = {
    id: declarationMemberId(owner, kind, isStatic, name, parameterTypes, returns),
    owner,
    name,
    member_kind: kind,
    visibility: "public",
    is_static: isStatic,
    is_abstract: false,
    is_virtual: false,
    signature: {
      type_parameters: [],
      parameters: parameterTypes.map((type, index) => parameter(`value${index}`, type)),
      ...(returns ? { returns } : {}),
    },
    ...(isStatic ? {} : { receiver: { pointer: true } }),
    aliases: [],
    locator: {
      kind: "artifact",
      path,
      symbol: `${owner === moduleId ? moduleName : declarationTypes.find((type) => type.id === owner).name}.${name}`,
    },
  };
  declarationMembers.push(member);
}

for (const [suffix, type] of freeTypes) {
  const path =
    suffix === "Int64" || suffix === "Uint64"
      ? "src/sync/atomic/doc_64.go"
      : "src/sync/atomic/doc.go";
  for (const [operation, parameters, mode, parameterTypes, returns] of [
    ["Load", `addr *${type}`, "load", [named(`*${type}`)], named(type)],
    ["Store", `addr *${type}, val ${type}`, "store", [named(`*${type}`), named(type)], null],
    ["Swap", `addr *${type}, new ${type}`, "read_modify_write", [named(`*${type}`), named(type)], named(type)],
    [
      "CompareAndSwap",
      `addr *${type}, old, new ${type}`,
      "read_modify_write",
      [named(`*${type}`), named(type), named(type)],
      named("bool"),
    ],
  ]) {
    const name = `${operation}${suffix}`;
    summaries.push(
      summary(
        `sync.atomic.${name.toLowerCase()}`,
        path,
        `sync/atomic.${name}(${parameters})`,
        false,
        operation === "Load" ? 1 : operation === "CompareAndSwap" ? 3 : 2,
        mode,
      ),
    );
    declarationMember(moduleId, name, "function", path, parameterTypes, returns);
  }
  if (suffix !== "Pointer") {
    for (const [operation, parameterName] of [
      ["Add", "delta"],
      ["And", "mask"],
      ["Or", "mask"],
    ]) {
      const name = `${operation}${suffix}`;
      summaries.push(
        summary(
          `sync.atomic.${name.toLowerCase()}`,
          path,
          `sync/atomic.${name}(addr *${type}, ${parameterName} ${type})`,
          false,
          2,
          "read_modify_write",
        ),
      );
      declarationMember(
        moduleId,
        name,
        "function",
        path,
        [named(`*${type}`), named(type)],
        named(type),
      );
    }
  }
}

const typedFamilies = [
  ["Bool", "bool", false],
  ["Pointer", "*T", false],
  ...integerTypes.map(([name, type]) => [name, type, true]),
  ["Value", "any", false],
];
for (const [owner, type, arithmetic] of typedFamilies) {
  const path =
    owner === "Value"
      ? "src/sync/atomic/value.go"
      : "src/sync/atomic/type.go";
  const ownerName = `sync/atomic.${owner}`;
  const ownerId = declarationTypeId(ownerName);
  declarationTypes.push({
    id: ownerId,
    name: ownerName,
    type_kind: "struct",
    visibility: "public",
    is_abstract: false,
    is_sealed: false,
    has_explicit_type_terms: false,
    type_parameters: [],
    type_parameter_constraints: [],
    embedded_types: [],
    hierarchy: [],
    aliases: [],
    extension_surfaces: [],
    locator: { kind: "artifact", path, symbol: ownerName },
  });
  for (const [operation, parameters, parameterCount, mode, parameterTypes, returns] of [
    ["Load", "", 0, "load", [], named(type)],
    ["Store", `val ${type}`, 1, "store", [named(type)], null],
    ["Swap", `new ${type}`, 1, "read_modify_write", [named(type)], named(type)],
    [
      "CompareAndSwap",
      `old, new ${type}`,
      2,
      "read_modify_write",
      [named(type), named(type)],
      named("bool"),
    ],
  ]) {
    summaries.push(
      summary(
        `sync.atomic.${owner.toLowerCase()}.${operation.toLowerCase()}`,
        path,
        `sync/atomic.${owner}.${operation}(${parameters})`,
        true,
        parameterCount,
        mode,
      ),
    );
    declarationMember(ownerId, operation, "method", path, parameterTypes, returns);
  }
  if (arithmetic) {
    for (const [operation, parameterName] of [
      ["Add", "delta"],
      ["And", "mask"],
      ["Or", "mask"],
    ]) {
      summaries.push(
        summary(
          `sync.atomic.${owner.toLowerCase()}.${operation.toLowerCase()}`,
          path,
          `sync/atomic.${owner}.${operation}(${parameterName} ${type})`,
          true,
          1,
          "read_modify_write",
        ),
      );
      declarationMember(
        ownerId,
        operation,
        "method",
        path,
        [named(type)],
        named(type),
      );
    }
  }
}

summaries.sort((left, right) => left.id.localeCompare(right.id, "en"));
declarationTypes.sort((left, right) => left.id.localeCompare(right.id, "en"));
declarationMembers.sort((left, right) => left.id.localeCompare(right.id, "en"));
const pack = {
  schema_version: 2,
  pack_id: "bifrost.go.stdlib.sync-atomic",
  version: "1.0.0",
  producer: { name: "bifrost", version: "0.10.7" },
  language: "go",
  ecosystem: "go",
  compatibility: { bifrost: ">=0.10.7, <1.0.0", toolchains: [] },
  provenance: {
    source: "https://go.dev/src/sync/atomic/",
    revision: "go1.26.0-linux-amd64",
  },
  license: "BSD-3-Clause",
  completeness: "complete",
  safety: { generated_code_only: false, review_required: false },
  shards: [
    {
      id: "go.stdlib.sync-atomic.concurrency",
      activation: [{}],
      payload: { kind: "procedure_summaries", summaries },
    },
  ],
};
const rendered = `${JSON.stringify(pack, null, 2)}\n`;
const declarationPack = {
  schema_version: 2,
  pack_id: "bifrost.go.stdlib.sync-atomic-declarations",
  version: "1.0.0",
  producer: { name: "bifrost", version: "0.10.7" },
  language: "go",
  ecosystem: "go",
  compatibility: { bifrost: ">=0.10.7, <1.0.0", toolchains: [] },
  provenance: {
    source: "https://go.dev/src/sync/atomic/",
    revision: "go1.26.0-linux-amd64",
  },
  license: "BSD-3-Clause",
  completeness: "partial",
  safety: { generated_code_only: false, review_required: false },
  shards: [
    {
      id: "go.stdlib.sync-atomic.declarations",
      activation: [{}],
      payload: {
        kind: "declaration_facts",
        types: declarationTypes,
        members: declarationMembers,
        relations: [],
      },
    },
  ],
};
const declarationRendered = `${JSON.stringify(declarationPack, null, 2)}\n`;

if (process.argv.includes("--write")) {
  writeFileSync(output, rendered);
  writeFileSync(declarationOutput, declarationRendered);
  console.log(`wrote ${output}`);
  console.log(`wrote ${declarationOutput}`);
} else {
  let existing;
  let existingDeclarations;
  try {
    existing = readFileSync(output, "utf8");
    existingDeclarations = readFileSync(declarationOutput, "utf8");
  } catch {
    console.error(
      `${output} or ${declarationOutput} is missing; run this command with --write`,
    );
    process.exit(1);
  }
  if (existing !== rendered || existingDeclarations !== declarationRendered) {
    console.error(
      `${output} or ${declarationOutput} is stale; run this command with --write`,
    );
    process.exit(1);
  }
  console.log(
    `${output} and ${declarationOutput} are current (${summaries.length} summaries, ${declarationMembers.length} declarations)`,
  );
}
