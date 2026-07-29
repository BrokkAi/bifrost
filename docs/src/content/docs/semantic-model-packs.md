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
> analyzer. This page documents the schema and artifact compiler delivered by
> issue #1145. Runtime matching and installation are separate lifecycle work.

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

## Declaration-fact payload

A declaration shard contains typed records rather than arbitrary maps: types,
members, structured signatures and type references, ownership/hierarchy/alias
or navigation relations, extension surfaces, and typed source or artifact
locators. The complete checked fixture below is compiled by the integration
suite.

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
          type_parameters: [t]
          supertypes:
            - kind: named
              id: java.lang.Object
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
          signature:
            parameters:
              - name: input
                type:
                  kind: named
                  id: java.lang.String
            returns:
              kind: named
              id: com.acme.Widget
          aliases: []
          locator:
            kind: artifact
            path: com/acme/Widget.class
            symbol: create(java.lang.String)
      relations:
        - id: relation.widget.owns-create
          relation_kind: owns
          from: type.widget
          to: member.widget.create
```

## Generator-rule payload

A generator shard declares a typed trigger, the captures that trigger must
supply, and typed declaration, alias, ownership, hierarchy, navigation, or
reference emissions. A scalar expression cannot use an optional or repeated
capture. Identifier positions accept only identifier captures, type positions
accept only type captures, and unknown captures fail compilation.

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
            - name: entity
              value_kind: identifier
              cardinality: one
            - name: entity_type
              value_kind: type
              cardinality: one
          emissions:
            - kind: declaration
              id:
                op: transform
                transform: snake_case
                value:
                  op: capture
                  name: entity
              name:
                op: transform
                transform: pascal_case
                value:
                  op: capture
                  name: entity
              declaration_kind: type
              type:
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
payload kind, routing keys, raw and stored sizes, record count, encoding, and
three lowercase SHA-256 digests:

- `semantic_sha256` identifies activation, compatibility, payload,
  completeness, and safety after normalization. Provenance, license, and
  storage encoding do not change it.
- `content_sha256` identifies the complete uncompressed shard, including
  provenance, license, producer, and pack version.
- `stored_sha256` identifies the bytes actually transported or stored and
  therefore changes when encoding changes.

Automatic storage uses fixed raw DEFLATE level 6 only when it saves at least
1 KiB and at least five percent. Otherwise the descriptor points to raw
canonical JSON. Encoding never changes semantic or content identity.

## Limits and defensive decoding

Default compilation limits source and each raw shard to 64 MiB, the pack to
1 GiB raw, the pack to 4,096 shards and two million records, each shard to
250,000 records, strings to 16 KiB, and recursive type/template structures to
depth 64. Callers can lower these limits.

Decoding checks the manifest and declared sizes before allocation, validates
the stored digest before decompression, streams DEFLATE into a bounded buffer,
requires the exact raw size and content digest, and reserializes decoded values
to reject non-canonical JSON. Shard ID, payload kind, routing keys, record count,
and semantic digest must agree with the descriptor. Truncation, trailing
compressed data, excessive expansion, corruption, or version mismatch fails
closed.
