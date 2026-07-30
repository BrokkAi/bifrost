---
title: Semantic-Model Packs
description: Author versioned external declaration facts and generated-code rules, then compile them to deterministic, defensively decoded artifacts.
---

Semantic-model packs are Bifrost's versioned interchange format for API facts
that do not come from workspace source and for declarative facts emitted by
framework or generator behavior. A producer can construct the public Rust
model directly or load reviewed YAML or JSON. Both paths compile through the
same validation and canonicalization pipeline.

> **Current runtime boundary:** compiling or decoding a semantic-model pack
> does not install, store, match, or activate it in Java, C#, or any other
> analyzer. This page documents the schema, artifact compiler, and exact Java
> and C# artifact producers. Runtime matching and installation are separate
> lifecycle work.

Packs do not contain executable code, arbitrary templates, fake source, or
procedure-effect/data-flow summaries. Generator expressions are bounded trees
of literals, declared scalar captures, ordered concatenation, and named ASCII
case transforms.

## Version and extension rules

Every source pack must contain `schema_version: 1`. The field is mandatory and
exact: omitted, zero, and future versions fail instead of falling back. Every
object rejects unknown fields, and every variant is explicitly tagged. A future
schema adds a new versioned Rust model and checked-in schema rather than
silently widening version one.

The machine-readable contract is
[`schemas/semantic-model-pack-v1.schema.json`](https://github.com/BrokkAi/bifrost/blob/master/schemas/semantic-model-pack-v1.schema.json).
It is generated from `AuthoredSemanticModelPack`; a repository test requires
the checked-in bytes to match the Rust-derived schema exactly.

YAML is a presentation syntax, not a second data model. Loading permits one
document and rejects duplicate keys, aliases, anchors, merge keys, includes,
property expansion, legacy boolean spellings, excessive nesting, excessive
events, and over-budget scalar or comment data. JSON and YAML both deserialize
directly into types that reject unknown fields.

## Envelope and activation

The envelope records a stable pack ID and semantic version, producer identity,
language and ecosystem, Bifrost/toolchain compatibility, provenance, an SPDX
license expression, completeness, safety metadata, and independently loadable
shards.

Each shard has one or more activation selectors. A selector can identify a
package, module, or declared toolchain using an exact name and optional SemVer
constraint. It may narrow activation by target, configuration, or a lowercase
SHA-256 artifact digest. The compiler derives sorted routing keys from these
selectors and, for rule shards, their trigger kinds. A later runtime can route
without reading unrelated payloads.

## Exact-artifact producers

Bifrost can construct declaration packs directly from one caller-selected
Java source JAR, Java class JAR, or .NET assembly. The producer API does not
discover dependencies, infer package coordinates from filenames, download
artifacts, solve classpaths, or install its result. Discovery remains an
analyzer concern; production receives the exact path together with explicit
pack, ecosystem, compatibility, activation, provenance, license, and safety
metadata.

The producer reads and hashes the exact bytes once under a caller-controlled
artifact limit. It copies the lowercase SHA-256 into every supplied activation
selector and returns it beside the authored pack. Archive entry counts,
per-entry and total uncompressed bytes, declaration records, signature depth,
diagnostic count, diagnostic text, and diagnostic locations are bounded.
Invalid input that cannot be identified produces no pack and, when the caller's
diagnostic budget permits, a bounded error diagnostic. Unsupported metadata or
an exhausted extraction limit can instead produce a useful `partial` pack with
stable diagnostic codes and a suppressed-diagnostic count.

Java source declarations are read from tree-sitter syntax. Java class
descriptors and generic Signature attributes use a bounded grammar parser; C#
types are read structurally from PE/CLI metadata. Producers emit public and
protected API types and members after applying enclosing-type visibility. Java
package-private declarations remain available to the legacy same-package
resolver but are not exported as reusable public API facts. Dependency entries
and assemblies remain external and are never added to `Project::all_files()`.

Declaration identity deliberately excludes origin. Equivalent Java source and
class declarations receive the same IDs, as do equivalent C# declarations
from another copy of the same semantic API. Source paths, JAR entries, assembly
metadata tokens, parameter names, and artifact digests do not participate in
those IDs. They do participate in locators, activation, or compiled pack bytes,
so a source pack and binary pack can share declaration IDs while retaining
different pack and shard digests. Member identity includes owner, kind, name,
generic arity, ordered parameter types, and return type. Including return type
preserves distinct CLI metadata members such as conversion operators even
though ordinary Java and C# source methods cannot overload only by return type.

Binary formats do not guarantee parameter names. `signature.parameters[].name`
is therefore optional: producers retain a source or binary name when it is
available and omit it otherwise rather than inventing `arg0`-style data.
Generic parameter names are retained from Java Signature or CLI GenericParam
metadata when present. Unsupported generic shapes make the result partial
instead of being flattened to a misleading string.

## Declaration-fact payload

A declaration shard contains typed records rather than arbitrary maps: types,
members, structured signatures and type references, explicit member ownership,
typed hierarchy edges, aliases, extension surfaces, navigation/reference
relations, and typed source or artifact locators. Type and member facts carry
visibility and relevant modifiers. Language-facing names retain ordinary
language spelling such as `TValue`, `_value`, or `getURL`; only pack and fact
identities use Bifrost's lowercase stable-ID grammar. The complete checked
fixture below is compiled by the integration suite.

<!-- semantic-model-doc-test:tests/fixtures/semantic-model-packs/declarations-v1.yaml -->
```yaml
schema_version: 1
pack_id: acme.widget
version: "1.2.0"
producer:
  name: artifact-scanner
  version: "2.0.0"
language: java
ecosystem: maven
compatibility:
  bifrost: ">=0.8.0, <1.0.0"
  toolchains:
    - name: jdk
      requirement: ">=17.0.0"
provenance:
  source: "https://repo.example/acme/widget-1.2.0.jar"
  revision: "sha256:example"
license: Apache-2.0
completeness: complete
safety:
  generated_code_only: false
  review_required: false
shards:
  - id: declarations.widget
    activation:
      - package:
          name: com.acme:widget
          version: ">=1.0.0, <2.0.0"
        targets: [jvm]
        configurations: [release]
    payload:
      kind: declaration_facts
      types:
        - id: type.widget
          name: com.acme.Widget
          type_kind: class
          visibility: public
          type_parameters: [t]
          hierarchy:
            - hierarchy_kind: extends
              target:
                kind: named
                name: java.lang.Object
          aliases: [com.acme.LegacyWidget]
          extension_surfaces: [com.acme.WidgetExtensions]
          locator:
            kind: artifact
            path: com/acme/Widget.class
            symbol: com.acme.Widget
      members:
        - id: member.widget.create
          owner: type.widget
          name: create
          member_kind: method
          visibility: public
          signature:
            parameters:
              - name: input
                type:
                  kind: named
                  name: java.lang.String
            returns:
              kind: named
              name: com.acme.Widget
          aliases: []
          locator:
            kind: artifact
            path: com/acme/Widget.class
            symbol: create(java.lang.String)
      relations:
        - id: relation.widget.navigation
          relation_kind: navigates_to
          from: member.widget.create
          to: type.widget
```

## Generator-rule payload

A generator shard declares a typed trigger, trigger-relative capture bindings,
and typed declaration, alias, or relation emissions. Capture sources identify
the matched node, enclosing declaration, resolved owner, one argument, an
argument suffix, or a named annotation argument. A projection then requests a
name, stable ID, type, text, or path. The compiler checks that each source is
available for its trigger and that its projection, declared value kind, and
cardinality agree.

A scalar expression cannot use an optional or repeated capture. Language-name
positions accept identifier or stable-ID captures, type positions accept only
type captures, and stable-ID positions accept only stable-ID captures. Unknown
captures and stable-ID templates with unsafe boundaries or case transforms fail
compilation.

<!-- semantic-model-doc-test:tests/fixtures/semantic-model-packs/generator-rules-v1.yaml -->
```yaml
schema_version: 1
pack_id: acme.builders
version: "1.0.0"
producer:
  name: policy-author
  version: "1.0.0"
language: java
ecosystem: maven
compatibility:
  bifrost: ">=0.8.0, <1.0.0"
provenance:
  source: "https://docs.example/acme-builders"
license: MIT
completeness: partial
safety:
  generated_code_only: true
  review_required: true
shards:
  - id: generators.builders
    activation:
      - package:
          name: com.acme:builders
          version: ">=1.0.0, <2.0.0"
    payload:
      kind: generator_rules
      rules:
        - id: rule.builder
          trigger:
            kind: annotation
            name: com.acme.GenerateBuilder
          captures:
            - name: owner_id
              binding:
                source:
                  kind: enclosing_declaration
                projection: stable_id
              value_kind: stable_id
              cardinality: one
            - name: entity
              binding:
                source:
                  kind: enclosing_declaration
                projection: name
              value_kind: identifier
              cardinality: one
            - name: entity_type
              binding:
                source:
                  kind: enclosing_declaration
                projection: type
              value_kind: type
              cardinality: one
          emissions:
            - kind: declaration
              id:
                op: concat
                values:
                  - op: capture
                    name: owner_id
                  - op: literal
                    value: .builder
              name:
                op: transform
                transform: pascal_case
                value:
                  op: capture
                  name: entity
              declaration:
                kind: member
                owner:
                  op: capture
                  name: owner_id
                member_kind: method
                visibility: public
                signature:
                  returns:
                    kind: capture
                    name: entity_type
```

## Canonical artifacts and digests

Compilation expands defaults, sorts semantic sets by stable ID, preserves
ordered parameters/capture paths/concatenation operands, and serializes compact
canonical JSON. Comments, YAML versus JSON, whitespace, and authored object
order therefore do not affect the compiled semantic bytes. Changing an ordered
parameter does.

The manifest remains uncompressed and readable. Each descriptor records the
payload kind, routing keys, raw and stored sizes, record count, declared and
referenced stable-ID inventories, encoding, and three lowercase SHA-256
digests:

- `semantic_sha256` identifies activation, compatibility, payload,
  completeness, and safety after normalization. Provenance, license, and
  storage encoding do not change it.
- `content_sha256` identifies the complete uncompressed shard, including
  provenance, license, producer, and pack version.
- `stored_sha256` identifies the bytes actually transported or stored and
  therefore changes when encoding changes.

The manifest has its own `semantic_sha256` over the ordered shard semantic
identities and a `content_sha256` over the entire manifest view except that
content field itself. The content digest therefore binds producer, provenance,
license, compatibility, inventories, routing, sizes, encodings, and every shard
digest while allowing those non-semantic fields to remain outside semantic
identity.

`content_sha256`, `stored_sha256`, and the manifest `content_sha256` are ordinary
SHA-256 of the exact byte sequence named above. Semantic hashes use
domain-separated length framing:
`SHA256(u64be(domain_length) || domain || u64be(byte_length) || bytes)`. The
shard domain is `bifrost.semantic-model.shard.semantic.v1`; the manifest domain
is `bifrost.semantic-model.manifest.v1`. “Canonical JSON” here means the compact
UTF-8 field order emitted by this schema's compiler, not RFC 8785.

Automatic storage uses fixed raw DEFLATE level 6 only when it saves at least
1 KiB and at least five percent. Otherwise the descriptor points to raw
canonical JSON. Encoding never changes semantic or content identity.

## Limits and defensive decoding

Default compilation limits source, each raw shard, and each stored shard to
64 MiB; the readable manifest to 16 MiB; the pack to 1 GiB raw; the pack to
4,096 shards and two million records; each shard to 250,000 records; strings to
16 KiB; and recursive type/template structures to depth 64. Callers can lower
these limits. Default compiler output is therefore accepted by the matching
default decoder limits.

Decoding checks the manifest and declared sizes before allocation, validates
the stored digest before decompression, streams DEFLATE into a bounded buffer,
requires the exact raw size and content digest, validates the authored semantics,
and re-normalizes decoded values to reject non-canonical JSON or semantic-set
ordering. Shard ID, payload kind, routing keys, declaration inventories, record
count, and semantic digest must agree with the descriptor. Manifest decoding
checks pack-wide declaration uniqueness and references; manifest-bound shard
decoding also requires every duplicated envelope field to agree. Truncation,
trailing compressed data, excessive expansion, corruption, invalid semantics,
or version mismatch fails closed.
