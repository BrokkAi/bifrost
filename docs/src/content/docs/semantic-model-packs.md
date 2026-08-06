---
title: Semantic-Model Packs
description: Author, compile, install, select, and manage versioned semantic-model artifacts.
---

Semantic-model packs are Bifrost's versioned interchange format for API facts
that do not come from workspace source, declarative facts emitted by framework
or generator behavior, and reviewed external procedure behavior. A producer
can construct the public Rust model directly or load reviewed YAML or JSON.
Both paths compile through the same validation and canonicalization pipeline.

Compilation alone does not install, store, match, or activate a pack; those
operations belong to the catalog and generation-scoped runtime described below.

> **Current runtime boundary:** Bifrost can compile, defensively decode,
> install, strictly activate, and match semantic-model packs for one analyzer
> generation. A successful runtime acquisition also publishes an immutable
> declaration overlay for normal navigation and query result surfaces.
> Procedure-summary payloads can contribute exact external-call transfers to
> value-flow and taint when an embedding supplies the catalog and activation
> request to the production policy runtime. Workspace source bodies take
> precedence; missing, conflicting, incompatible, or incomplete summaries stay
> visible in the analysis outcome.

Together, the catalog and runtime can install, select, activate, account for, quarantine, and garbage-collect packs while keeping matching generation-local.

Packs do not contain executable code, arbitrary templates, fake source, or
unbounded evaluator inputs. Generator expressions are bounded trees of
literals, declared scalar captures, ordered concatenation, and named ASCII case
transforms. Procedure summaries are bounded typed records, not executable
models or source-text matching rules.

## Authoring and review tools

Build the authoring binary with the `release-tooling` feature. It extends the
existing release commands. It uses the production source parser, schema,
compiler, catalog, and activation resolver.

```text
cargo run -p brokk-bifrost-semantic-packs --features release-tooling \
  --bin bifrost-semantic-pack -- validate model.yaml

cargo run -p brokk-bifrost-semantic-packs --features release-tooling \
  --bin bifrost-semantic-pack -- lint model.yaml --format json

cargo run -p brokk-bifrost-semantic-packs --features release-tooling \
  --bin bifrost-semantic-pack -- compile model.yaml compiled-model
```

`validate` checks the exact production schema and compiler. `lint` also reports
duplicate IDs, unreachable or shadowed rules, ambiguous selectors, unused
captures, broad wildcard selectors, and conflicting emissions. Some duplicate
IDs and unknown capture references are compiler errors. The lint report keeps
those production diagnostics.

`compile` writes the canonical `manifest.json` and exact shard bytes. A second
run accepts identical files. It rejects an existing file with different bytes.
This behavior prevents an authoring command from replacing reviewed output.

Human output is the default. `--format json` returns a stable versioned report.
Status 0 means that the result is complete and has no finding. Status 1 means
that source or conformance findings exist. Status 2 means that arguments or
inputs are incompatible, or that a bounded operation is incomplete.

The smallest useful generator rule has one exact structured trigger, one
required capture, and one typed emission:

```yaml
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
            op: literal
            value: builder
          declaration:
            kind: member
            owner:
              op: capture
              name: owner_id
            member_kind: method
            visibility: public
```

The complete declaration example below shows a dependency-qualified rule. Its
package, version, target, configuration, and toolchain constraints must match
one complete activation-evidence row.

### Catalog inventory and activation evidence

`list CATALOG` shows installed packs, source attribution, and persisted catalog
activation references. Add an activation JSON file to resolve active packs and
show matched evidence, provenance, shadowing, incompatibility, and reasons:

```json
{
  "schema_version": 1,
  "bifrost_version": "0.8.21",
  "evidence": [
    {
      "language": "java",
      "ecosystem": "maven",
      "package": { "name": "com.acme:widget", "version": "1.5.0" },
      "toolchain": { "name": "jdk", "version": "17.0.1" },
      "target": "jvm",
      "configuration": "release"
    }
  ]
}
```

```text
bifrost-semantic-pack list /path/to/catalog activation.json --format json
```

The activation file can contain `controls`. Each control has `scope` (`user`
or `workspace`), `action` (`enable` or `disable`), `pack_id`, and optional
`version` or `manifest_digest` fields. A control cannot bypass compatibility.

### Workspace rules and trust

A repository can opt in to direct YAML or JSON files at this path:

```text
.bifrost/semantic-models/
```

Run `bifrost-semantic-pack workspace-check WORKSPACE` during review. Discovery
does not recurse. It rejects symbolic links, non-files, files outside the
canonical workspace, excessive files, and excessive source bytes. Each result
contains the exact source SHA-256 and compiled semantic digest.

Discovery is not ambient activation. The host must call
`discover_workspace_semantic_models`, register each accepted compiled pack as
an `EphemeralWorkspace` or durable `WorkspaceProduced` source, and supply an
explicit workspace activation control when review is required. The production
runtime then applies normal source precedence. Workspace sources outrank
installed and shipped sources. Exact authored source or artifact declarations
still outrank model-only overlay facts.

Workspace files are data only. The loader uses the normal safe YAML or JSON
parser. It does not load arbitrary code, follow links, execute a generator,
download content, or read outside the workspace trust boundary. A content edit
changes its review hash.

### Match debugging and conformance

Analyzer hosts can use these public library functions:

- `explain_semantic_model_site` identifies the pack, rule, source, activation
  evidence, captures, typed emissions, shadowing, and first failed predicate.
- `preview_semantic_model_emissions` shows declarations, relationships, and
  aliases for one active rule and an explicit capture map.
- `scan_unmapped_semantic_model_sites` scans normalized AST facts within file,
  node, and result limits. The caller supplies reviewed structured selectors
  and labels each family as `model_eligible_generator` or
  `inspectable_source_macro`.
- `run_semantic_model_conformance` checks a version-one golden fixture against
  the production overlay and matcher.

The scan classification is explicit. A call-shaped AST node does not prove
that generated output is safe to model. The scan never uses regular
expressions, source-text search, generator execution, or an implicit download.
An exhausted limit marks the report incomplete.

Conformance fixtures can assert symbols, owners, signatures, hierarchy,
relationships, forward definitions, inverse usages, authored anchors or
portable model URIs, provenance, completeness, and positive or negative
matches. Keep fixtures under review with the model. Run them after every model
change. The report uses `bifrost_semantic_model_conformance/v1` and returns
explicit missing expectations.

For a miss, first inspect `first_failed_predicate`. Then inspect activation
evidence and `shadowing`. A trigger mismatch means that the normalized node or
exact trigger name did not match. An unbound capture means that the structured
fact did not supply one required value. A conflict means that equal-precedence
rules failed closed, so production emitted neither rule.

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
selectors and, for rule shards, their trigger kinds. The runtime uses the keys
to avoid reading unrelated payloads, then strictly rechecks every populated
selector field. Missing evidence never satisfies a constraint.

Activation evidence is supplied as complete rows so a package, module,
toolchain, target, configuration, and artifact digest from different resolved
artifacts cannot be combined accidentally. Exact artifact evidence outranks
versioned coordinates, which outrank named coordinates and language-only
selectors. Ephemeral and durable workspace-produced sources outrank generated,
installed, pre-shipped, and embedded sources in that order. A workspace control
outranks a user control, but neither can bypass compatibility. Packs marked
`review_required` need an explicit compatible enable. Equal-rank conflicting
facts remain conflicts instead of becoming a last-write-wins answer.

The generation-scoped runtime owns every selected decoded shard and builds
exact-key postings for type and member IDs and names, aliases, relation IDs and
directions, and every schema-version-one generator trigger. Lookups do not read
SQLite, pack files, or unrelated postings; schema version one has no wildcard
fallback path. Work, index entries, working bytes, retained bytes, and
explanations are bounded. Cancellation, corruption, stale generations, and
exhausted budgets never publish a complete cached value.

## Catalog and lifecycle

`SemanticPackCatalog` stores durable packs beneath one caller-selected shared
root. The caller chooses the root explicitly so a host can apply its own
platform and configuration policy. Catalog metadata lives in a separately
versioned SQLite database. Immutable shard bytes live once at
`objects/sha256/<first-two-hex>/<remaining-hex>`, keyed by the SHA-256 of their
exact stored representation. The manifest content digest identifies the
complete pack; semantic and uncompressed-content digests retain their distinct
artifact roles.

Installation validates the canonical manifest and every manifest-bound shard
before publishing anything discoverable. Files are staged, synchronized, and
atomically moved into the content-addressed tree. A single metadata transaction
then publishes the complete pack, its normalized selectors, and its source.
Installing identical bytes from several workspaces or sources reuses the same
physical object while retaining every durable source attribution. Startup
reconciliation removes bounded abandoned staging and unreferenced final files;
it never promotes an orphan into an installed pack.

Candidate discovery narrows by language, ecosystem, and the populated package,
module, toolchain, or artifact selector index without reading shard payloads.
It then checks SemVer compatibility, target, configuration, and artifact
identity from validated catalog metadata. Candidates are opaque catalog
handles: callers can inspect their identity and source through accessors but
cannot alter the descriptor or provenance used by verified loading. Loading
rechecks the digest path, size, stored bytes, manifest envelope, and decoded
shard. Missing or corrupt durable content becomes a safe miss and is
quarantined in a writable catalog; a read-only catalog rejects durable
mutations and suppresses repeated attempts only for that process.

Durable source kinds are installed, generated, pre-shipped, and
workspace-produced. Embedded release resources and ephemeral-workspace packs
use the same complete validation and selector path but remain in the catalog
instance's session memory, so they are never copied into durable storage.
Persistent workspace active sets may reference only exact registered durable
sources. In-memory workspaces may reference only exact session sources because
they have no durable workspace identity that can own a cross-process
activation. Their activation accounting is tied to the workspace store's
lifetime. Catalog active-set identity is a domain-separated digest over the
full sorted manifest and source references, and durable activation rows protect
selected objects across processes.

That catalog identity is deliberately distinct from the runtime
`active_model_set_hash`. The runtime hash covers selected semantic shard
digests, payload kinds, and the matcher representation version but not
equivalent source attribution or storage encoding. Analyzer-snapshot caches use
a canonical activation-request key and retain only complete immutable
runtimes. Before publication, the runtime rechecks source generations and
coordinates selected catalog references with the workspace store. A failed or
incomplete build preserves the previous active set.

### Projection into synthetic analyzer declarations and model URIs

A ready declaration runtime publishes one immutable overlay in the analyzer
snapshot cache. The overlay owns typed type, member, hierarchy, and relation
rows plus exact indexes by stable fact ID, qualified name, alias, and location.
It is not part of the project filesystem: overlay records never appear in
`Project::all_files()`, never become `ProjectFile` values, and never trigger
file watching or source-cache operations.

The overlay also evaluates active generator-rule shards against the analyzer's
normalized structural facts. Schema-v1 language-construct and annotation
triggers, scalar matched-node/enclosing-declaration/argument captures, bounded
template expressions, and typed declaration, relation, and alias emissions are
supported. Fully qualified annotation triggers require the same qualified
spelling in the decorator AST span; an unqualified same-name annotation is not
a match. Resolved-owner/call triggers and repeated argument captures remain
inactive until the analyzer can supply their typed resolver evidence; Bifrost
does not replace that missing evidence with source-text matching.

Every overlay declaration has one honest location. If the pack's locator names
a real declaration in the current analyzer snapshot and the exact symbol and
path resolve, navigation uses that authored anchor and its real declaration
range. Otherwise Bifrost creates a deterministic, percent-encoded
`bifrost-model://v1/<pack-semantic-digest>/<record-kind>/<stable-record-id>`
URI with a deterministic virtual range. A model URI is a portable identity and
navigation target, not generated source. Source-reading tools render a bounded
typed description explicitly labeled as modeled content.

A unique `navigates_to` relation on a model-only declaration is followed by
definition and declaration navigation. Its target may be another unique
modeled declaration or an exact authored symbol. Multiple or conflicting
navigation targets fail closed, and an absent target is reported instead of
falling back to the model declaration.

Symbol search, symbol locations, definition and modeled-usage results,
CodeQuery declaration projections, MCP and Python JSON, and LSP workspace
symbol/type-hierarchy values preserve the overlay provenance. It includes the
active-model hash, pack semantic digest and identity/version, producer and
version, stable record ID, catalog source and activation explanation, origin,
proof kind, completeness, and ambiguity. Model relations are reported as
semantic facts and do not invent source snippets or call-site ranges.

Authored workspace declarations and exact navigable artifact declarations win
over model-only locations. A unique model fact fills information that authored
analysis does not have. Equivalent facts deduplicate; equal-rank differing
facts remain ambiguous, and definition, usage, hierarchy, and query consumers
must not select one. Catalog mutation generation and SQLite data-version are
part of runtime cache identity, so an install, replacement, quarantine, or
source removal cannot leave an old overlay attached to an unchanged analyzer
snapshot and activation request.

Accounting reports deduplicated installed and active bytes, physical objects,
logical and active shards, sources, lookup hits and misses, quarantined packs,
and activation counts by durable or session source. Pins, durable sources,
workspace activations, reader leases, and in-flight installation reservations
protect content from collection. Explicit bounded garbage collection removes
only old packs with none of those roots, rechecks each object under the catalog
write boundary, and reports bytes only when a file was actually removed.

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

## Preparing packs from local dependencies

Hosts can connect dependency discovery to the shared catalog without giving
the analysis library ownership of a global path. Open a
`SemanticPackCatalog` at the host-selected root, resolve exact records with
`resolve_jvm_semantic_pack_dependencies` or
`resolve_csharp_semantic_pack_dependencies`. Go hosts opt in through
`AnalyzerConfig::go.dependency_discovery`, call
`resolve_go_semantic_pack_dependencies`, and use `GoDependencyPackAdapter`.
Pass the returned
`DependencyDiscoveryOutcome` to `prepare_discovered_dependency_semantic_packs`
with the matching adapter. The discovery outcome carries bounded diagnostics,
completeness, cancellation, and input/resolution counts; an unresolved
coordinate or malformed dependency manifest therefore cannot collapse into a
successful empty dependency set. Preparation
never downloads packages, scans an entire package cache, or implicitly builds
a project. Maven and Gradle build-tool discovery remains explicitly offline
and opt-in.

Each generated-production key covers the ordered artifact roles and exact byte
digests, producer and adapter versions, semantic-pack schema version,
activation evidence, normalized ecosystem provenance, and every producer or
compiler limit that can affect output. Paths and mtimes are excluded. Artifact
locators stored by local-dependency adapters are content-addressed rather than
derived from a local filename. A second workspace using identical bytes and evidence through the
same catalog therefore reuses the verified manifest without invoking the
producer. A byte, coordinate, target, configuration, asset-role, adapter,
producer, or schema change creates a different production. Installation binds
the production key, generated source, and verified manifest in one catalog
transaction; corrupt bindings are safe misses, and garbage collection removes
bindings with their unreferenced manifests after the configured age. Generated
source attribution is cache metadata, not a permanent GC root; pins, active
sets, and leases protect generated packs that remain in use. Lookup verifies
the manifest and every referenced shard object before reporting reuse.

JVM records retain exact Maven coordinates and distinguish Maven reports,
Gradle reports, Maven repositories, Gradle coordinate-cache directories, and
explicit paths. A class JAR and optional source JAR form one production. Source
facts and locators win for shared stable declaration IDs, binary-only facts are
added, and incompatible facts make coverage partial with a bounded diagnostic.
The legacy resolver still retains package-private declarations that are not
exported as reusable public API facts. It consumes the same bounded dependency
discovery result, while retaining its compatibility projection for those
analyzer-only declarations.

.NET records retain NuGet package/version, target framework, configuration,
reference/compile/runtime role, and project-reference provenance. Reference
assets outrank compile and runtime duplicates for the same semantic assembly;
different targets and project-output configurations remain separate evidence.
Explicit assembly paths do not invent package coordinates.

Rust records use a passive, host-supplied evidence bundle. The bundle contains
Cargo metadata format-version-1 JSON, its `Cargo.lock`, the selected target and
configuration, selected workspace targets, exact per-package feature lists,
and an explicit rustdoc JSON artifact for every dependency API to index.
`resolve_rust_semantic_pack_dependencies` validates that registry, git, and
path packages are reachable from the selected targets and agree on package
version, source, checksum, crate name, target triple, rustdoc format, and
artifact binding. Dependency renames remain provenance; package and crate
identity do not change with the local binding name.

Bifrost does not run Cargo or rustdoc to create this evidence. It does not scan
Cargo caches or target directories, download crates, compile dependencies, run
build scripts, or load procedural macros. A host may generate rustdoc JSON in a
separately controlled build step and pass the resulting paths through
`RustAnalyzerConfig`. Bifrost then reads only those paths. The decoder is pinned
to one exact `rustdoc-types` format; missing, inconsistent, or unsupported
artifacts produce explicit incomplete coverage. Public procedural-macro names
may appear in a pack, but macro code is never loaded or executed. Exact nightly
toolchain strings are retained in production provenance and cache identity
rather than treated as semantic-version compatibility coordinates.

Go discovery asks only the configured `go` executable for machine-readable
`go env` and `go list` metadata. The child process has its ambient Go
configuration cleared, uses `GOTOOLCHAIN=local`, `GOPROXY=off`,
`GOSUMDB=off`, `GOENV=off`, and `CGO_ENABLED=0`, and receives the configured
GOOS, GOARCH, and build tags. When non-test files are excluded, a second
metadata-only `go list` with cgo enabled identifies cgo surfaces that the
disabled view would otherwise classify only as ignored. It never builds,
tests, runs, or generates a package and it never downloads a module or
toolchain. The selected standard
library, module-cache, local replacement, workspace, and vendor files become
exact source-set inputs; normalized relative paths and retained bytes determine
their identity, not absolute cache locations or mtimes.

Generated Go packs contain exported packages, types, aliases, functions,
variables, constants, methods, fields, structured signatures, type parameters
and constraints, underlying types, embeddings, receiver forms, and promoted
members. Exact import paths remain package identity even when the declared
package name differs from the path's last segment. Non-exported carrier types
may be retained to derive a public promoted surface, but overlay search and
navigation do not expose them. Activated facts participate in definition,
hover, signature, hierarchy, symbol, and whole-workspace reference paths while
dependency and GOROOT files remain outside `Project::all_files()`.

Coverage is explicitly partial when selected packages report errors, cgo or
generated source participates in the selected build, build constraints are
malformed or otherwise rejected by the configured Go toolchain, source is
malformed, or local artifacts, time, cancellation, or a configured bound stop
discovery. Files that the toolchain excludes for the exact target and tags do
not enter the pack and do not by themselves make that configured surface
partial. Cgo execution, compiler-equivalent type checking, SSA/body indexing,
`go generate`, and implicit network resolution are not provided. Go `internal`
package access is checked from canonical import paths, and authored workspace
declarations take precedence over otherwise matching pack facts.

Python environment records are intentionally more explicit. A host supplies a
declared interpreter implementation, version, platform, standard-library root,
optional bundled-stub roots, and selected distribution roots; Bifrost never
discovers `sys.path`, starts Python, imports a module, executes package setup,
or contacts a package index. It reads only `.pyi` and safe `.py` files plus
static `.dist-info`/`.egg-info` metadata. Precedence is deterministic: bundled
stubs, stub artifacts, inline `py.typed` source, then safe implementation
source. Dynamic exports, unsupported guards, malformed files, and missing
static surfaces remain partial coverage with diagnostics rather than invented
declarations. Hosts activate the result explicitly with
`WorkspaceAnalyzer::activate_python_environment_packs`; dependency files stay
outside `Project::all_files()`, and external navigation uses `bifrost-model:`
locations rather than synthetic workspace files.

The LSP host accepts the same explicit boundary in initialization options. All
paths are resolved from the workspace root; `semanticPackCatalog` is a
host-chosen writable catalog, never an interpreter or package-cache lookup.

```json
{
  "pythonEnvironment": {
    "implementation": "cpython",
    "version": "3.12.3",
    "platform": "macos-arm64",
    "standardLibraryRoot": "./.bifrost/python/stdlib",
    "bundledStubRoots": ["./.bifrost/python/stubs"],
    "distributionRoots": ["./.bifrost/python/site-packages"],
    "semanticPackCatalog": "./.bifrost/semantic-packs"
  }
}
```

Ruby records likewise use passive, host-supplied evidence. A
`RubyDependencyApiEvidence` row identifies one `Gemfile.lock` by path and
SHA-256, the exact Ruby version and platform, explicit approved archive roots,
and each selected gem's name, version, source, optional checksum, and `.gem`
archive path. `resolve_ruby_semantic_pack_dependencies` reads only those named
files. It does not run Ruby, Bundler, RubyGems, Sorbet, Steep, extension builds,
gem hooks, or generators; it does not scan gem caches or access the network.

The Ruby adapter reads a `.gem` as bounded nested tar and gzip streams without
extracting it. It projects RBS through the typed `ruby-rbs` parser and parses
RBI and ordinary Ruby declarations with tree-sitter. RBS takes precedence over
equivalent RBI, which takes precedence over ordinary source. Reopened scopes
and overloads are retained, while contradictory typed declarations make the
pack partial and remain visible as conflicts. Classes, modules, instance and
singleton methods, attributes, aliases, structured signatures, and ordered
`prepend`, `include`, and `extend` relations are supported. Unsupported dynamic
metaprogramming produces bounded partial diagnostics rather than speculative
facts.

An embedded host supplies the evidence explicitly:

```rust
use std::path::PathBuf;

use brokk_bifrost::{
    AnalyzerConfig, RubyAnalyzerConfig, RubyDependencyApiEvidence,
    RubyGemApiArtifact,
};

let config = AnalyzerConfig {
    ruby: RubyAnalyzerConfig {
        dependency_api_evidence: vec![RubyDependencyApiEvidence {
            lockfile_path: PathBuf::from("Gemfile.lock"),
            lockfile_sha256: "<lowercase-sha256>".into(),
            ruby_version: "3.4.1".into(),
            platform: "ruby".into(),
            approved_archive_roots: vec![PathBuf::from("/controlled/gems")],
            gems: vec![RubyGemApiArtifact {
                name: "rack".into(),
                version: "3.2.1".into(),
                source: "https://rubygems.org/".into(),
                checksum: Some("<lowercase-sha256>".into()),
                gem_archive_path: PathBuf::from("/controlled/gems/rack-3.2.1.gem"),
            }],
        }],
    },
    ..AnalyzerConfig::default()
};
```

Relative lockfile and archive paths are resolved against the project root;
canonical archive paths must remain under the project root or an explicit
approved root. Hosts then pass the discovery outcome to
`prepare_discovered_dependency_semantic_packs` with
`RubyDependencyPackAdapter`, compose its exact evidence into the activation
request, and activate it through the normal semantic-model runtime. Archive
members receive digest-qualified logical locations and never become project
files.

Preparation is bounded by dependency, artifact, total-byte, producer,
compiler, and diagnostic limits. It checks cancellation between file chunks,
JAR entries or source files, CLI metadata batches, and every
lookup/production/compile/install boundary. Missing, unreadable, malformed,
unsupported, cancelled, or over-budget inputs remain explicit partial
coverage; they never become an authoritative empty result. The returned
profile separates artifacts and bytes read from reused and generated packs.
Partial generated packs are reproduced instead of reused so their bounded,
actionable coverage diagnostics are reconstructed for every caller.

`DependencyPackPreparationOutcome::compose_activation_request` merges exact
successful evidence into a host-owned activation request. It returns no
request after cancellation or wholly unavailable partial preparation, so a
host cannot accidentally replace a previously complete workspace active set
with authoritative empty dependency coverage. Preparation itself never
publishes an analyzer overlay or workspace active set.

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

## Procedure-summary payload

A procedure-summary shard describes externally reviewed behavior without
activating it. Each record has a stable ID and a structured target consisting
of a canonical artifact-relative path, an exact symbol, receiver availability,
and parameter count. The compiler derives a pack-scoped model ID, a summary
contract version, and a content digest for every record; the defensive decoder
recomputes and verifies those fields.

Transfers connect a receiver or zero-based parameter to a normal return,
receiver, exceptional return, declared capture, or declared heap location.
Each transfer carries an explicit normal or exceptional exit kind, matching the
reusable-summary contract even when an exceptional exit writes a heap or
capture location.
Effects represent allocation, calls to another summary in the same pack,
escapes, unknown calls, unknown-call boundaries, and explicitly ambiguous call
sets. Inputs must exist on the target, outputs must reference a location of the
right kind, call targets must exist, and all collections have fixed validation
budgets. Duplicate targets and duplicate IDs are rejected across shards.

Completeness is explicit at both levels. A `partial` record remains partial
after compilation and decoding; a partial pack cannot claim a `complete`
record. Completeness is evidence metadata only and does not enable matching or
flow application.

```yaml
payload:
  kind: procedure_summaries
  summaries:
    - id: summary.helper
      target:
        path: com/acme/Flows.class
        symbol: helper(java.lang.String)
        has_receiver: true
        parameter_count: 1
      completeness: partial
      locations:
        - id: location.receiver-field
          location_kind: heap
      transfers:
        - input:
            kind: parameter
            ordinal: 0
          exit_kind: normal
          output:
            kind: normal_return
      effects:
        - kind: allocation
          event: event.helper.allocate
          output:
            kind: heap
            location: location.receiver-field
        - kind: unknown_call_boundary
          event: event.helper.unknown-boundary
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
