# Opaque / serialized column inventory -- Bifrost analyzer cache

Repo `/mnt/optane/bifrost-nlp`, branch `bifrost-nlp-ft`, HEAD `9263e2a5`.
Schema: `crates/bifrost-core/migrations/cache/0001..0017`. Current migration
count = 17, so this build's file is `bifrost_cache.v17.db`.

Labels: **[C]** = confirmed by reading code / measuring data.
**[I]** = inferred. **[U]** = unknown / unmeasured.

---

## 0. Census of non-scalar columns

| # | Table (migration) | Column | Type | Encoder | Rust type |
|---|---|---|---|---|---|
| 1 | `import_details` (0001) | `info` | BLOB | bincode legacy (`serialize_blob`) | `ImportInfo` |
| 2 | `unit_signature_metadata` (0001) | `metadata` | BLOB | bincode legacy, size-capped | `SignatureMetadata` |
| 3 | `code_units` (0012) | `fq_segments` | BLOB | hand-rolled `FQ2\0` framing | `FqName` segments |
| 4 | `structural_facts_snapshots` (0007) | `payload` | BLOB | bincode **varint**, reject-trailing | `StructuralFactsSnapshot` |
| 5 | `unit_cpp_template_metadata` (0008) | `metadata` | BLOB | bincode legacy | `CppTemplateMetadata` |
| 6 | `scala_exports` (0009) | `info` | BLOB | bincode legacy | `ScalaExportInfo` |
| 7 | `materialization_records` (0015) | `payload` | BLOB | bincode legacy | `MaterializationRecordPayload` |
| 8 | `unit_supertypes` (0002/0003) | `lookup_path` | **TEXT** | `serde_json` | *two* shapes: Scala `ScalaSupertypeLookupPath`, Ruby `{kind,target}` |
| 9 | `semantic_vectors` (0014) | `vector` | BLOB | fastrq quantizer (`quant::encode_vector`) | `Vec<f32>` code -- **legitimately binary** |
| 10 | `semantic_vectors` / `semantic_file_chunks` (0014) | `vector_hash` | BLOB(32) | content digest | **legitimately binary key** |
| 11 | `semantic_file_chunks` (0014) | `fts_tokens` | TEXT | `materialize::fts_text` | tokenized chunk text -- denormalized search payload, not a Rust struct |

Everything else in the schema is scalar. **[C]**

Two encoder families are in play and they are not interchangeable:
`serialize_blob` uses `bincode::serialize` (legacy default: **fixint**, u64
length prefixes, u32 enum discriminants, unlimited); `FileFacts::encode_snapshot`
uses `bincode::DefaultOptions().with_varint_encoding().reject_trailing_bytes()`.
Readers: `deserialize_blob` (legacy), `deserialize_limited_blob` /
`deserialize_signature_metadata_blob` (fixint + byte-limit + allow-trailing).
`crates/bifrost-analysis/src/analyzer/store/mod.rs:9050-9202`. **[C]**

---

## 1. `import_details.info` -- `ImportInfo`

### 1.1 Type tree (all scalars, no recursion) **[C]**

`brokk_bifrost_core::analyzer::model::ImportInfo`
(`crates/bifrost-core/src/analyzer/model.rs:2630`)

```
ImportInfo {
  raw_snippet: String,
  is_wildcard: bool,
  identifier: Option<String>,
  alias: Option<String>,
  path: Option<StructuredImportPath>,
  binder_span: Option<Span>,
}

StructuredImportPath {                       // model.rs:2573
  segments: Vec<String>,
  kind: Option<StructuredImportPathKind>,
  lexical_prefixes: Vec<String>,
  lexical_scopes: Vec<StructuredImportScope>,
  declaration_start_byte: usize,
}

StructuredImportPathKind = Namespace | ImportFrom | StaticMember   // 3 variants
StructuredImportScope { start_byte: usize, end_byte: usize }
Span { start_byte: usize, end_byte: usize }  // core/analyzer/structural/facts.rs:14
```

Depth is bounded at 3 and there is **no recursive/tree shape anywhere**. The only
unbounded parts are two `Vec<String>` (`segments`, `lexical_prefixes`) and one
`Vec<{usize,usize}>` (`lexical_scopes`).

### 1.2 Verified wire layout **[C]**

Decoded a real row (rust, `use serde::Deserialize;`), 140 bytes:

```
17 00.. "use serde::Deserialize;"   raw_snippet   (8-byte len prefix)
00                                   is_wildcard=false
01 0b 00.. "Deserialize"             identifier=Some
00                                   alias=None
01                                   path=Some
   02 00..  05 00.."serde" 0b 00.."Deserialize"   segments
   01 00 00 00 00                    kind=Some(Namespace)   (1 tag + u32 variant)
   00 00 00 00 00 00 00 00           lexical_prefixes = []
   00 00 00 00 00 00 00 00           lexical_scopes   = []
   ae 02 00 00 00 00 00 00           declaration_start_byte = 686
01 ba 02.. c5 02..                   binder_span = Some(698..709)
```

Useful scalar content is ~50 bytes; the other ~90 are length prefixes,
`Option` tags and duplicated text.

### 1.3 Per-language variance **[C]** (all construction sites read)

| Lang | site | `path` | `path.kind` | `lexical_prefixes` | `lexical_scopes` | `binder_span` | `alias` | notes |
|---|---|---|---|---|---|---|---|---|
| java | `java/imports.rs:752` | yes | `Namespace` / `StaticMember` | never | never | yes (unless wildcard) | never (Java has no aliases) | `is_wildcard` from `asterisk` token |
| python | `python/imports.rs:929,970,1022` | yes | `Namespace` / `ImportFrom` | never | never | yes, except multi-segment names & wildcards | yes | `from m import a, b` -> one row per name, segments = module++name |
| rust | `rust/imports.rs:592` (via `RustImportInfo`) | yes | `Namespace` | never | **yes** | yes | yes | also carries out-of-band `visibility` + `path` that are *not* in `ImportInfo` |
| go | `go/declarations.rs:185` | yes, **single segment** = whole `"a/b/c"` path | `Namespace` | never | never | only when renamed | yes | segments is `vec![path]`, so it is not really segmented |
| scala | `scala/imports.rs:452,561,601` | yes | **`None`** | **yes** | **yes** | yes (not for wildcard) | yes | only language populating `lexical_prefixes` |
| kotlin | `kotlin/imports.rs:113` | yes | **`None`** | never | never | yes | yes | comment says file-scoped, so no scopes |
| csharp | `csharp/imports.rs:260,292,301` | **never (`None`)** | - | - | - | **never** | yes (using-alias) | plain `using X` sets `is_wildcard = true` |
| js/ts | `js_ts/imports.rs:20,37,51,77,93,312` | **never** | - | - | - | yes for ES named/default/namespace, no for CommonJS | yes | namespace import sets `is_wildcard = true` |
| ruby | `ruby/imports.rs:24,376` | **never** | - | - | - | never | never | `identifier` holds the *require path string* |
| cpp | `cpp/declarations.rs:3202,3344` | **never** | - | - | - | never | never | only `raw_snippet` is meaningful |
| php | (via kotlin/`declarations.rs` family) | **[U]** | | | | | | not audited |

So the "shape" differs radically: three languages (cpp, ruby, csharp) store an
`ImportInfo` that is effectively `{raw_snippet, is_wildcard, identifier, alias}`,
and only Scala uses the full structure.

### 1.4 Cardinality and size **[C]**

Measured on a 39-file polyglot fixture (this repo's `crates/bifrost-core/src`
for Rust + hand-written files for the other nine languages) and on an existing
abseil (C++) cache at `/mnt/optane/tmp/bifrost-fird/abseil-cli-cache`.

Polyglot fixture, `import_details`:

| lang | rows | min | avg | max | sum |
|---|---|---|---|---|---|
| rust | 207 | 93 | 149 | 246 | 30 974 |
| python | 6 | 95 | 129 | 158 | 776 |
| java | 4 | 93 | 143 | 189 | 572 |
| scala | 3 | 101 | 158 | 197 | 474 |
| kotlin | 2 | 132 | 152 | 172 | 304 |
| go | 3 | 84 | 106 | 123 | 320 |
| typescript:ts | 4 | 64 | 75 | 91 | 300 |
| csharp | 3 | 40 | 66 | 99 | 200 |
| ruby | 2 | 37 | 43 | 50 | 87 |
| javascript | 1 | 47 | 47 | 47 | 47 |

abseil (873 cpp + 6 python blobs): 8 015 rows, 340 534 bytes total,
min 27 / avg 42 / max 211 -- **9.1 import rows per blob**.

Rust is the heavy case: 207 rows across 35 blobs ~ **5.9 imports/file at 149
bytes each**. On the rustc-scale trees the 0016 comment cites (35 370 files),
that extrapolates to ~200 k rows / ~30 MB **[I]**.

### 1.5 Readers **[C]**

Store-side entry points, all in `store/mod.rs`:

| fn | line | shape of question | who calls it |
|---|---|---|---|
| `read_import_infos` | 7462 | whole-blob hydration, `ORDER BY ordinal` | `hydrate_file_state_conn:5729` |
| `read_import_infos_bulk` | 6376 | bulk hydration, 900-oid chunks, joins `blob_meta` for completeness | `hydrate_file_states_conn:5863`, `hydrate_import_infos:2152`, `hydrate_import_facts_by_key:2200`, `:3181` |
| `import_infos_for_key_limited` | 2345 | bounded point read with a per-row byte cap (`MAX_LIMITED_QUERY_ROW_BYTES`); a row over the cap aborts the whole answer as *incomplete* | bounded query surfaces |

Every read is a **whole-blob deserialize**; there is no path that selects one
field. Field-level consumers:

| field | consumers | verdict |
|---|---|---|
| `raw_snippet` | ~40 sites; C# (`csharp/mod.rs:513,561,660,687...`), Go (`go/imports.rs:18,69,105,131`), Rust (`rust/imports.rs:268,310,347`) **re-parse it as text**; java/python use it as a dedupe key; `diff_analysis.rs:1117` renders it | heavily read, but mostly as a **regex/split substrate** -- see section 7 |
| `is_wildcard` | scala, python, java, kotlin_artifact, overlay, trace | hot |
| `identifier` / `alias` | mostly via `ImportInfo::local_name()` (12+ call sites) | hot |
| `path.segments` | scala (dozens), go, java, python, kotlin | hot |
| `path.kind` | only `go/...:1028,1058` (`== Namespace`) and `java/imports.rs:878,884` (`== StaticMember`) | narrow but load-bearing |
| `path.lexical_prefixes` | **Scala only** (`get_definition/scala.rs` x10, `scala/imports.rs:209`) | Scala-only |
| `path.lexical_scopes` | Scala (many), Rust (`overlay.rs:2097`), `navigation.rs:1783`, `scala_graph/syntax.rs` | Scala + Rust |
| `path.declaration_start_byte` | `lexical_environment.rs:603,689`, `python/mod.rs:467`, Scala (many), `scala_graph/*` | hot for visibility-at-byte |
| `binder_span` | **exactly one** reader: `structural/lexical_environment.rs:605` (`import_binder_node`) | single consumer |

No field is entirely dead, but `binder_span`, `path.kind`, and
`lexical_prefixes` each have one or two consumers.

### 1.6 Ordering / identity semantics **[C]**

- PK is `(blob_oid, lang, ordinal)`, `WITHOUT ROWID`. `ordinal` is the index in
  `FileState::imports`, i.e. **source order of the produced rows**, not of the
  source statements. Every reader uses `ORDER BY ordinal`, so order of
  appearance *is* a contract for the hydrated `Vec<ImportInfo>`.
- `import_details.ordinal` and `import_statements.ordinal` are **independent
  sequences**. Measured divergence in the fixture: scala 2 statements vs 3
  details; typescript 3 vs 4. Any redesign must not assume they co-key. **[C]**
- No `CHECK(ordinal >= 0)` (contrast `unit_ranges`, which does have range CHECKs).

---

## 2. `unit_signature_metadata.metadata` -- `SignatureMetadata`

### 2.1 Type tree **[C]** (`model.rs:298`; fields are private, accessed by getters)

```
SignatureMetadata {
  label: String,
  parameters: Vec<ParameterMetadata>,
  return_type_text: Option<String>,
  return_type_identity: Option<StructuredTypeIdentity>,
  declaration_only: bool,
  callable_arity: Option<CallableArity>,
  type_parameters: Vec<String>,
  bare_return_type_parameter: Option<String>,
  callable_linkage: Option<CallableLinkage>,          // External | Internal
  dispatch_extensibility: Option<DispatchExtensibility>,  // Open | Closed
  extension_receiver_type: Option<String>,
  extension_receiver_type_identity: Option<StructuredTypeIdentity>,
  extension_receiver_is_unconstrained_type_parameter: bool,
  field_is_static: bool,
  field_is_final: bool,
  companion_object: bool,
}

ParameterMetadata { label: String, start_byte: usize, end_byte: usize }
   // NB: start/end are offsets into `label` (the signature string), NOT the file.
   //     See `with_parameter_labels`, model.rs:~272.
CallableArity { required: usize, total: usize, repeated: bool }

StructuredTypeIdentity {                   // model.rs:851 -- THE tree-shaped part
  nodes: Vec<StructuredTypeNode>,          // flat post-order arena, u32 ids
  root: StructuredTypeNodeId(u32),
  // edge_count / string_bytes are #[serde(skip)] and recomputed on decode
}
StructuredTypeNode =                       // model.rs:737
    Named(StructuredTypeName)
  | Pointer(u32) | Reference(u32) | Array(u32) | Slice(u32)
  | Map { key: u32, value: u32 }
  | Generic { base: u32, arguments: Vec<u32> }
StructuredTypeName { path: Vec<String>, lexical_scope: Vec<String>, absolute: bool }
```

Bounds enforced at deserialize time, not by the schema: `MAX_STRUCTURED_TYPE_IDENTITY_NODES
= 20 000`, `..._EDGES = 40 000`, `MAX_STRUCTURED_TYPE_NAME_COMPONENTS = 1 024`,
`MAX_STRUCTURED_TYPE_IDENTITY_STRING_BYTES = 1 MiB`,
`MAX_SIGNATURE_METADATA_BLOB_BYTES = 8 MiB`. **[C]**

**This is the one analyzer blob with a genuinely tree-shaped part**
(`StructuredTypeIdentity`), and it is already stored as a flat arena because
recursion was a stack hazard. Everything *outside* the two
`StructuredTypeIdentity` fields is scalar or a flat list.

### 2.2 Per-language variance **[C]** (which builders each language calls)

| builder | languages that call it |
|---|---|
| `with_return_type_text` | cpp, csharp, go, java, kotlin, php, rust, scala |
| `with_return_type_identity` | cpp, csharp, go, rust, scala |
| `with_dispatch_extensibility` | cpp, csharp, go, python, ruby, rust, scala |
| `with_callable_arity` | cpp, csharp, java, kotlin, scala |
| `with_type_parameters` | csharp, scala |
| `with_bare_return_type_parameter` | csharp, scala |
| `with_extension_receiver_type` | csharp, go, kotlin, scala |
| `with_extension_receiver_type_identity` | csharp, go, scala |
| `with_declaration_only` | cpp, python |
| `with_callable_linkage` | **cpp only** |
| `with_extension_receiver_is_unconstrained_type_parameter` | **csharp only** |
| `with_field_modifiers` (`field_is_static`, `field_is_final`) | **java only** |
| `with_companion_object` | **kotlin only** (`kotlin/declarations.rs:317`) |

Extremely sparse per language: no language populates more than ~8 of the 16
fields, and 4 fields are single-language.

### 2.3 Cardinality and size **[C]**

abseil: 15 720 rows, 3 810 024 bytes, min 56 / avg 242 / max **29 280**;
5 rows over 2 KB. **17.9 rows per blob**, the largest blob family in that cache.

Polyglot fixture: rust 1 470 rows, avg 132, max 2 132, sum 195 KB;
other languages 1-4 rows each, avg 82-161.

### 2.4 Readers **[C]**

| fn | line | shape |
|---|---|---|
| `signature_metadata_map_for_file` | 6748 | bulk hydration |
| `read_signature_metadata` path in `hydrate_file_state_conn` | 7921 | whole-blob hydration |
| `signature_metadata_for_unit_limited_conn` | ~8058 | bounded point read, per-row byte cap |
| `usage_fact_row_from_row` | **6980** | **deserializes the blob inside a row mapper on the bulk usage-graph query** (`UsageFactRow.signature_metadata`) |

The last one matters: signature-metadata deserialization sits on the hot
whole-workspace usage-edge path, not only on hydration.

Field-level consumers (production, excluding tests):

| accessor | count | notes |
|---|---|---|
| `label()` | very high (count polluted by other types with `label()`) | also duplicated in `unit_signatures.text` -- see section 7 |
| `parameters()` | 9 | cpp arg binding, arity |
| `return_type_text()` | 13 | |
| `return_type_identity()` | 10 | |
| `callable_arity()` | 12 | |
| `type_parameters()` | 6 | |
| `extension_receiver_type()` | 6 | |
| `extension_receiver_type_identity()` | 5 | |
| `is_declaration_only()` | 2 | |
| `bare_return_type_parameter()` | 2 | |
| `field_is_static()` / `field_is_final()` | 1 each | `semantic_model/overlay.rs:2404-2406` |
| `callable_linkage()` | 1 | `cpp/identity.rs:82` |
| `dispatch_extensibility()` | 1 | `usages/receiver_query.rs:2179` |
| `extension_receiver_is_unconstrained_type_parameter()` | 1 | csharp |
| **`is_companion_object()`** | **0** | **written by kotlin, never read** -- drop candidate, not a migration candidate |

### 2.5 Ordering **[C]**

PK `(blob_oid, lang, unit_key, ordinal)`. `ordinal` pairs positionally with
`unit_signatures.ordinal` -- verified: in 100 % of measured rows the
`SignatureMetadata.label` bytes appear verbatim inside the blob at the matching
`(unit_key, ordinal)` (15 675/15 675 cpp, 45/45 python, 1 470/1 470 rust,
2-4/2-4 for the other eight languages). The pairing is a real contract that the
schema does not express (no FK, no shared key).

---

## 3. `code_units.fq_segments` -- `FqName` segments

### 3.1 Format **[C]** (`store/mod.rs:9055-9154`, `core/analyzer/fq_name.rs:191`)

Hand-rolled, **not** serde:

```
header (9 bytes): "FQ2\0" | mode u8 | package_segment_count u32-LE
body: repeat { kind u8 | text_len u32-LE | text UTF-8 }
mode: 0 = FQ_SEGMENTS_FULL       (whole identity stored, boundary meaningful)
      1 = FQ_SEGMENTS_PATH_TAIL  (content-stable tail only; the adapter
                                  recomputes the path-derived package prefix
                                  from the live ProjectFile; count field is 0)
kind (SegmentKind::persist_tag): 0 Path 1 Package 2 Type 3 Companion
                                 4 Nested 5 Member 6 Unknown
```

Interner IDs are process-local and deliberately never persisted. Decode
re-interns text+kind. No legacy-string fallback: a stale row is an error, and
the analysis epoch salt invalidates instead.

### 3.2 Per-language variance **[C]/[I]**

The *format* is uniform. What differs is `mode`, driven by
`LanguageAdapter::code_unit_package_is_path_derived`: languages whose package is
derived from the file path store `PATH_TAIL`; content-qualified languages
(java, kotlin, scala, go, csharp packages) store `FULL`. Exact per-language
mapping not enumerated here **[U]** -- the adapter trait method is the switch.
Segment `kind` mix is language-dependent (`Companion` is Scala/Python/Ruby/PHP,
`Nested` is python/php/ruby/cpp/java).

### 3.3 Cardinality and size **[C]**

One row per `code_units` row, i.e. **28.3 per blob** in abseil.
abseil: 24 906 non-null, min 15 / avg 52 / max **15 002**, sum **1 302 219 bytes**
(the second-largest blob family after signature metadata).
Fixture rust: 1 700 values, avg 46, max 123, sum 79 654.

### 3.4 Readers **[C]**

Exactly one: `hydrate_unit_fq` (`store/mod.rs:9111`), called from every
`code_units` row mapper (index 12 in the candidate-row projections; see
`usage_fact_row_from_row` and `search_candidate_row_from_row` comments). It is
whole-value hydration -- decode all segments, or fail.

### 3.5 Reverse smell **[C]**

`code_units.short_name`, `identifier`, `content_qualifier`, `exact_fqn`,
`normalized_fqn`, `simple_type_name` are all *projections of the same identity
that lives in the blob*. Migration 0012 states this explicitly: "The
`short_name`/`content_qualifier` columns stay populated because they back SQL
lookup indexes ... They are projections, not CodeUnit identity: hydration
requires this structured column." So the relational columns are derived and the
blob is authoritative -- the inverse of the direction AGENTS.md now wants.

---

## 4. `structural_facts_snapshots.payload` -- `StructuralFactsSnapshot`

### 4.1 Type tree **[C]** (`analysis/src/analyzer/structural/facts.rs:54-86`)

```
StructuralFactsSnapshot {
  nodes: Vec<SnapshotNode>,
  role_offsets: Vec<u32>,                  // CSR offsets, len == nodes.len()+1
  roles: Vec<SnapshotRoleTarget>,          // CSR values
  occurrence_role_offsets: Vec<u32>,       // CSR offsets, len == nodes.len()+1
  occurrence_roles: Vec<u8>,               // CSR values
}
SnapshotNode { kind: u8, construct: Option<String>, span: {u32,u32},
               parent: Option<u32>, name: Option<{u32,u32}>, subtree_end: u32 }
SnapshotRoleTarget { role: u8, spread: bool, keyword: Option<{u32,u32}>,
                     node: Option<u32>, span: {u32,u32}, name: Option<{u32,u32}> }
```

Code tables (all closed, all in `facts.rs`): `NormalizedKind` 0-25 (26 variants),
`Role` 0-9 (10 variants), `OccurrenceRole` 0-11 (12 variants).

`source` is **not** in the payload -- `decode_snapshot(source, payload)` takes the
live source and validates every span against it (UTF-8 boundary + length +
name-inside-node + parent-precedes-child + subtree-end well-formedness).

### 4.2 Assessment

This is **two CSR adjacency arrays plus a node arena** -- i.e. it *is* relational
shape (nodes table + role-edge table + occurrence-role table), but it is also
the one payload whose read pattern is genuinely "hydrate the whole thing into a
hot in-memory matcher arena and never query it in SQL." The migration comment
says exactly that. Encoding is varint bincode, so it is already compact.
Whether it counts as "queryable structure" is a design call, not a fact.

### 4.3 Cardinality / size **[C]/[U]**

Written only when a structural query actually runs
(`structural/provider.rs:421-436`, keyed by
`STRUCTURAL_FACTS_SNAPSHOT_VERSION = 6`). Both caches I measured are near-empty
for this table: abseil 0 rows; the fixture 1 row (scala, 396 bytes). Payload
scales with normalized node count; one policy run over 39 files built 3 927 fact
nodes total (~100 nodes/file), which at the observed varint sizes is ~2-4 KB per
file **[I]**. Not measured at scale **[U]**.

### 4.4 Lifecycle **[C]**

`upsert_structural_facts_snapshot` (`store/mod.rs:1466`) takes an IMMEDIATE
transaction, deletes all older versions for the blob, inserts, then adjusts
`blob_payload_costs.payload_bytes` by `-old_len + new_len`. So the snapshot's
byte length participates directly in the GC cost model.

---

## 5. `unit_cpp_template_metadata.metadata` -- `CppTemplateMetadata`

### 5.1 Type tree **[C]** (`model.rs:1484`)

```
CppTemplateMetadata {
  primary_name: String,
  primary_fq_name: String,
  parameters: Vec<CppTemplateParameterMetadata>,
  specialization_arguments: Vec<CppTemplateExpression>,
  alias_target: Option<CppTemplateAliasTargetMetadata>,
}
CppTemplateParameterMetadata { name: String, kind: CppTemplateParameterKind,
                               variadic: bool, default: Option<CppTemplateExpression> }
CppTemplateParameterKind = Type | Value | Template
CppTemplateAliasTargetMetadata { components: Vec<String>, global: bool,
                                 arguments: Option<Vec<CppTemplateExpression>> }
CppTemplateExpression { text: String, term: CppTemplateTerm }
CppTemplateTerm =                          // *** recursive ***
    Parameter(String)
  | Atom { kind: String, text: String }
  | Node { kind: String, children: Vec<CppTemplateTerm> }
```

`CppTemplateTerm` is a **boxed recursive tree** (unlike `StructuredTypeIdentity`,
it was never flattened to an arena). Depth is unbounded and there is no
deserialize cap -- a deeply nested template argument decodes by Rust recursion.
Worth flagging on its own merits.

### 5.2 Language **[C]**: C++ only. Written at
`cpp/declarations.rs:2137, 3276` (via `set_cpp_template_metadata`).

### 5.3 Cardinality / size **[C]**

abseil: 1 002 rows over 873 cpp blobs (~1.15/blob), min 43 / avg 337 / max 4 617,
sum 337 332. Fixture: 0 (no C++).

### 5.4 Readers **[C]**

`read_cpp_template_metadata` (8262, per-file) and
`cpp_template_metadata_map_for_file` (6767, bulk). Sole production consumer chain:
`CppAnalyzer::template_metadata` (`cpp/mod.rs:544`) -> `usages/cpp_graph/resolver.rs`.

Fields consumed:
- `primary_name` -- `resolver.rs:380` (constructor detection)
- `primary_fq_name` -- `resolver.rs:958` (template-family grouping)
- `specialization_arguments` -- `resolver.rs:2781, 2808, 3546, 3552, 3761-3762`
  and `cpp/declarations.rs:2159, 4588, 4793, 4864`; consumed **only as
  `.is_empty()` / length** in the resolver
- `parameters` -- `resolver.rs:2723, 3536, 7554-7569` (`cpp_bind_template_arguments`)
- `alias_target` -- `resolver.rs:2717, 3535`

No dead fields. But note: the resolver's dominant use of
`specialization_arguments` is a boolean "is this a specialization" -- that is a
column, not a payload.

---

## 6. `scala_exports.info` -- `ScalaExportInfo`

### 6.1 Type tree **[C]** (`analysis/src/analyzer/scala/imports.rs:19-34`)

```
ScalaExportInfo {
  owner_path: Vec<String>,
  selectors: Vec<ScalaExportSelector>,
  declaration_start_byte: usize,
}
ScalaExportSelector = Wildcard
                    | GivenWildcard
                    | Named { source_name: String, visible_name: Option<String> }
```

Flat, no recursion. This is a two-level list -- the classic "parent row +
child rows" shape.

### 6.2 Language **[C]**: Scala only. Written at
`scala/declarations.rs:643` into `FileState::scala_exports:
HashMap<CodeUnit, Vec<ScalaExportInfo>>`.

### 6.3 Cardinality / size **[C]**: fixture 1 row, 56 bytes; abseil 0.
Real Scala corpora unmeasured **[U]**.

### 6.4 Readers **[C]**

`read_scala_exports` (7839, per-file, `ORDER BY owner_key, ordinal`) and
`read_scala_exports_bulk` (6409). Consumers: `scala/mod.rs:388`
(`scala_exports_of(owner)`), `usages/scala_graph/inverted.rs:584-756`
(reads `owner_path`, `selectors`, `declaration_start_byte`),
`usages/get_definition/scala.rs:4977-4993`. All three fields consumed.

### 6.5 Key note

PK is `(blob_oid, lang, owner_key, ordinal)` with an FK to
`code_units(blob_oid, lang, unit_key)` -- this table already models the
owner relationally and only the *selector list* is opaque.

---

## 7. `materialization_records.payload` -- `MaterializationRecordPayload`

### 7.1 Type tree **[C]** (`core/analyzer/structural/materialization.rs:402`)

```
MaterializationRecordPayload =                       // externally tagged (bincode)
    GeneratedDeclaration   { site: Range, argument: Range, kind: GenerationKind }
  | DynamicGenerationSite  { site: Range, kind: GenerationKind }
  | Export                 { range: Range, form: ExportForm, exported_name: String }
  | RecoveredDeclaration   { recovery: Range }
  | ConfigurationConditional { range: Range }

Range { start_byte, end_byte, start_line, end_line : usize }   // model.rs:2263
GenerationKind = AccessorMacro | AliasMacro | PreprocessorDefinition
ExportForm = Named | DefaultNamed | DefaultAnonymous | CommonJsRoot | CommonJsMember
```

**This is the purest case in the inventory**: a 5-variant tagged union whose
entire content is 1-2 fixed byte/line ranges, one closed enum, and one optional
string. Zero variable-length structure except `exported_name`.

The `unit_key` half of the record is *already* a column (0015 split it out via
`MaterializationRecord::split()` / `::join()`), so the blob is literally "the
remainder we didn't bother to columnise".

### 7.2 Per-language variance **[C]**
(`materialization.rs:~440-500`, the `*_MATERIALIZATION_SUPPORT` tables)

| lang | variants emitted | source |
|---|---|---|
| ruby | `GeneratedDeclaration`, `DynamicGenerationSite` | `ruby/declarations.rs:423,456,484,524` |
| js/ts | `Export` (all five `ExportForm`s) | `js_ts/model.rs:89,113,151,163` |
| cpp | `GeneratedDeclaration` (PreprocessorDefinition), `RecoveredDeclaration`, `ConfigurationConditional` | CPP_MATERIALIZATION_SUPPORT |
| python | none persisted here (declaration-only state + implementation linkage axes) | PYTHON_MATERIALIZATION_SUPPORT |
| others | none | `NO_MATERIALIZATION_SUPPORT` |

### 7.3 Cardinality / size **[C]**

Fixture: ruby 7 rows all exactly **72 bytes** (= 4 tag + 32 + 32 + 4, exactly
the fixint layout); js 3 rows 49-62; ts 3 rows 49-55.
abseil: 2 741 rows, min 36 / avg 54 / max 72, sum 147 708 (**3.1 rows per blob**).

The size distribution is a giveaway: three discrete values. Nothing here needs
a blob.

### 7.4 Readers **[C]**

`read_materialization_records` (7811) and `materialization_records_for_file`
(6470/6481) -- both `ORDER BY ordinal`, both whole-value. Consumers:
`structural/materialization_rows.rs` (the row-family producer for
`DeclarationStateRow`, generation sites, export rows, implementation linkage) via
`TreeSitterAnalyzer::materialization_records_of` (`tree_sitter_analyzer.rs:3925`).

### 7.5 Integrity gap **[C]**

`materialization_records.unit_key` is an `INTEGER` with **no FK** to
`code_units(blob_oid, lang, unit_key)` -- the only FK is to `blobs`. The reader
does `unit_key.and_then(|key| by_key.get(&key))` and `MaterializationRecord::join`
returns `None` when a unit-requiring variant has no resolved unit, so a dangling
key **silently drops the record**. The FK the data implies is missing, and the
"requires_unit" rule (`GeneratedDeclaration`/`RecoveredDeclaration` need a unit;
the other three must not) is a `CHECK` the schema does not have.

---

## 8. `unit_supertypes.lookup_path` -- a TEXT column holding two JSON shapes

Migration 0002 added it as `TEXT NOT NULL DEFAULT ''`; migration 0003 changed
its meaning to "a JSON-encoded, parser-derived segment vector". **[C]**

Two *different* producers write two *different* JSON documents into the same
column, discriminated only by `lang`:

**Scala** (`scala/supertypes.rs:16-55`, `encode`/`decode` via `serde_json`):
```
ScalaSupertypeLookupPath {
  segments: Vec<String>,
  package_prefixes: Vec<String>,              // #[serde(default)]
  lexical_scopes: Vec<StructuredImportScope>, // #[serde(default)]
}
```
Read by `scala/mod.rs:431`, `scala/hierarchy.rs:433`,
`usages/get_definition/scala.rs:2653`, `usages/scala_graph/inverted.rs:853`,
all via `ScalaSupertypeLookupPath::decode(&str) -> Option<Self>` -- **which
swallows parse errors with `.ok()`**.

**Ruby** (`ruby/mixins.rs:164-196`, hand-built `serde_json::json!`):
```
{"kind": "superclass"|"include"|"prepend"|"extend", "target": "<raw target>"}
```
Read by `decode_owner_relation` (`ruby/mixins.rs:182`), which re-checks that
`target` equals the sibling `unit_supertypes.raw` column -- i.e. the JSON
**duplicates the adjacent relational column** and the reader uses the duplicate
as a consistency check.

Every other language writes `''` (measured: csharp 2/2 empty, java 2/2, python
1/1, typescript 1/1 empty; ruby 4/4 non-empty <=40 bytes; scala 2/2 non-empty
<=68 bytes). **[C]**

This is the strongest single "should be rows" case after
`materialization_records`: Ruby's payload is `(relation_kind ENUM, target TEXT)`
where target is already a column; Scala's is three ordered lists.

---

## 9. Semantic-index binary columns (confirm-and-move-on)

- `semantic_vectors.vector` BLOB + `dim` INTEGER. Written by
  `nlp/src/store.rs:204,390` as `quant::encode_vector(&[f32])`, a fastrq
  quantized code (not raw f32). Scored allocation-free straight from the stored
  bytes by `CodeScorer::score(&[u8])` (`nlp/src/quant.rs:55`). **Legitimately
  binary; SQL cannot usefully query it.** **[C]**
- `semantic_vectors.vector_hash` / `semantic_file_chunks.vector_hash` BLOB(32)
  with `CHECK(length(...) = 32)`. Content digest used as a dedup key.
  **Legitimately binary.** **[C]**
- `semantic_file_chunks.fts_tokens` TEXT: `fts_text(&chunk.source_text)`
  (`nlp/src/materialize.rs:177`), consumed only by the in-memory BM25/FTS build
  in `nlp/src/active_index.rs:91-211`. Not a serialized Rust struct; it is a
  denormalized search payload. Worth a note, not a migration. **[C]**
- `semantic_file_chunks.vector_hash` has an index but **no FK** to
  `semantic_vectors(vector_hash)` -- a gap the data implies. **[C]**

---

## 10. How parse products (FileState) are persisted

`FileState` (`tree_sitter_analyzer.rs:608-655`) is the parse product. Its
fields map to the cache as follows (`prepare_parsed_blob`, `store/mod.rs:~4600-4860`;
`hydrate_file_state_conn`, `:5671`): **[C]**

| FileState field | persisted as | shape |
|---|---|---|
| `source` | **not persisted** (re-read from ProjectFile; counted in `payload_bytes`) | - |
| `content_qualifier` | `blob_meta.content_package` | scalar |
| `package_name` | recomputed from adapter + live path | - |
| `declarations` / `definition_lookup_units` / `top_level_declarations` / `type_aliases` / `test_region_units` | `code_units` (+ `in_declarations`, `in_definition_lookup`, `top_level_ordinal`, `is_type_alias`, `in_test_region`) | **rows** |
| identity of each CodeUnit | `code_units.fq_segments` **BLOB** + scalar projections | **blob** |
| `ranges` | `unit_ranges` | rows |
| `children` | `unit_children` | rows |
| `signatures` | `unit_signatures` | rows |
| `signature_metadata` | `unit_signature_metadata` | **blob** |
| `cpp_template_metadata` | `unit_cpp_template_metadata` | **blob** |
| `raw_supertypes` | `unit_supertypes.raw` | rows |
| `supertype_lookup_paths` | `unit_supertypes.lookup_path` | **JSON TEXT** |
| `import_statements` | `import_statements` | rows |
| `imports` | `import_details.info` | **blob** |
| `scala_exports` | `scala_exports.info` | **blob** |
| `type_identifiers` | `type_identifiers` | rows |
| `ruby_method_dispatch_modes` | `ruby_method_dispatch_modes.mode` (0-2 CHECK) | rows |
| `scala_traits` | `scala_traits` | rows |
| `materialization_records` | `materialization_records` (unit_key col + **blob**) | mixed |
| `contains_tests` | `blob_meta.contains_tests` | scalar |
| `rust_usage_facts` | `rust_exports`, `rust_import_targets`, `rust_modules`, `rust_identifier_occurrences`, `rust_module_scopes`, `rust_module_routes`, `rust_module_route_gates`, `rust_item_macros` (0016/0017) | **fully relational** |
| `parse_errors` | **not persisted** (`None` on hydrate; LSP re-parses) | - |

Tree data proper (the tree-sitter tree) is never persisted. The only
tree-derived persistence is `structural_facts_snapshots` (a normalized-node
arena + CSR role edges, section 4) and the recursive `CppTemplateTerm` inside
`unit_cpp_template_metadata`.

Note also: `FileState.rust_usage_facts` is deliberately **not rehydrated** on a
cache hit -- "the query side reads those rows straight from SQL by blob oid
rather than through a materialized FileState." That is the pattern 0016/0017
established and the model for the rest.

---

## 11. Rust: what 0016/0017 already supersede

`rust_import_targets` (0016) vs `import_details.info` for `lang='rust'`. **[C]**

| `rust_import_targets` column | corresponding `ImportInfo` content | note |
|---|---|---|
| `module_path` TEXT | `path.segments[..n-1]` joined by `::` | Rust-side re-render; ImportInfo keeps them split |
| `imported_name` TEXT NULL | last of `path.segments`; NULL for glob | |
| `bound_name` TEXT NULL | `alias ?? imported_name` = `ImportInfo::local_name()` | `rust/facts.rs:349` builds it from `local_name()` |
| `is_glob` INTEGER | `is_wildcard` | |
| `owner_start` / `owner_end` | ~ innermost `path.lexical_scopes` entry | not identical: owner is the enclosing *module*, scopes are all enclosing blocks |
| `local_start` / `local_end` | non-NULL when the `use` is in a fn/block/closure -- derived from the same lexical scopes | |
| `owner_module` TEXT | **Rust-only**, not in `ImportInfo` (relative module name) | |
| `visibility` TEXT | **Rust-only**; lives on `RustImportInfo.visibility`, never entered `ImportInfo` | |
| `ordinal` | source order | same contract as `import_details.ordinal` |

**Not covered by 0016, still only in `import_details.info` for Rust:**
- `raw_snippet` -- and it is *load-bearing*: `rust/imports.rs:268, 310, 347` call
  `resolve_rust_import_fq_name(file, &package, &import.raw_snippet)`, i.e. Rust
  still re-parses the rendered snippet text.
- `path.declaration_start_byte` (`rust_import_targets` has owner/local spans but
  not the import's own start byte).
- `path.lexical_scopes` as a *list* (0016 flattens to one owner + one optional
  local span).
- `binder_span`.
- `path.kind` (always `Namespace` for Rust, so no information loss).

`rust_exports` (0016) is a filtered projection of the same `use` declarations --
so for Rust, one source construct currently lands in **three** places:
`import_statements.statement`, `import_details.info`, and
`rust_import_targets` (+ `rust_exports` for `pub use`). Measured in the fixture:
207 `import_statements` rows and 207 `import_details` rows for rust, byte-identical
raw text (section 12).

`rust_module_scopes` / `rust_module_routes` / `rust_module_route_gates` /
`rust_item_macros` (0017) have no `import_details` overlap.

Both 0016 and 0017 are the model of what the owner is asking for: closed
vocabularies as TEXT (`visibility`), spans as INTEGER columns, CSR-ish parent
links as `parent_ordinal`, a bitmask (`context_mask`) where a bitmask is
genuinely the right thing, and narrow purpose-built indexes.

**Caveat:** the release binary I measured with (`target/release/bifrost`,
2026-08-07) writes `bifrost_cache.v15.db`, i.e. it predates 0016/0017. So all
Rust-fact cardinalities are **[U]** -- I could not measure `rust_import_targets`
row sizes on real data.

---

## 12. Reverse smells -- already relational, then re-serialized or re-parsed

1. **`import_statements.statement` duplicates `ImportInfo.raw_snippet`.** **[C]**
   Measured: for csharp, go, java, javascript, kotlin, python, ruby, rust the
   statement text at the same ordinal appears verbatim inside the blob in
   **100 %** of rows (rust 207/207). Scala and TypeScript diverge because they
   emit a different number of rows into each table. The raw text is 15-53 % of
   the blob bytes (rust 17.9 %, csharp 43 %, javascript 53 %).

2. **`unit_signatures.text` duplicates `SignatureMetadata.label`.** **[C]**
   100 % byte-identical match at the same `(unit_key, ordinal)` across every
   language measured (abseil cpp 15 675/15 675). The label is 12-44 % of the
   metadata blob (rust 43.9 %, cpp 31.2 %).

3. **`code_units.*` name columns duplicate `fq_segments`** -- by design, and the
   blob is declared authoritative (section 3.5). **[C]**

4. **C# re-parses `raw_snippet` with string ops** while `ImportInfo.path` is
   `None` for C#: `csharp_using_namespace(&import.raw_snippet)` at
   `csharp/mod.rs:513, 561, 660, 687` and `csharp/imports.rs:143`, plus
   `raw_snippet.trim_start().starts_with("global using ")` at
   `csharp/mod.rs:660, 686, 714, 740, 764, 791, 817`. **[C]**

5. **Go re-parses `raw_snippet`** with `extract_go_import_path` at
   `go/imports.rs:18, 69, 105, 131` and `go/hierarchy.rs:778`, even though
   `path.segments[0]` already holds exactly that path. **[C]**

6. **Rust re-parses `raw_snippet`** via `resolve_rust_import_fq_name`
   (`rust/imports.rs:268, 310, 347`) though `path.segments` is populated. **[C]**

7. **C++ re-parses signature text for alias targets.**
   `cpp_alias_target_text(signature: &str)` (`usages/get_definition/cpp.rs:6786`)
   does `signature.split_once('=')` / `strip_prefix("typedef ")` /
   `rsplit_once(char::is_whitespace)` -- while `CppTemplateMetadata.alias_target`
   (`CppTemplateAliasTargetMetadata { components, global, arguments }`) is the
   structured answer sitting in the sibling blob. **[C]**

8. **Ruby's `lookup_path` JSON duplicates `unit_supertypes.raw`** and the reader
   uses the duplicate as a cross-check (`decode_owner_relation` rejects the row
   when `json.target != raw`). The only genuinely new bit is the 4-value
   relation kind, which is a `CHECK`-constrained TEXT/INTEGER column. **[C]**

9. **`blob_meta.*_count` columns are cached `COUNT(*)`s** of the child tables,
   maintained by the writer and consumed by the GC cost model
   (`persisted_blob_mutation_cost_*`, `store/mod.rs:8690-8790`). Pragmatically
   load-bearing (they replace 13 correlated subqueries per blob), but they are
   denormalization that a redesign will have to keep or replace deliberately.
   **[C]**

---

## 13. Ordering / identity semantics

- **`unit_ranges.ordinal = 0` means "primary range"** -- a hard convention baked
  into SQL: `LEFT JOIN unit_ranges AS primary_range ... AND primary_range.ordinal = 0`
  (`store/mod.rs:3141`). Ordinal is not just sequence; 0 is distinguished. **[C]**
- **`import_details.ordinal`** -- order of appearance in `FileState::imports`;
  a contract for the hydrated `Vec`. Not co-keyed with `import_statements.ordinal`
  (measured divergence, section 1.6). **[C]**
- **`unit_signatures.ordinal` <-> `unit_signature_metadata.ordinal`** -- positional
  pairing is a real, unexpressed contract (section 2.5). **[C]**
- **`materialization_records.ordinal`** -- "one row per record, in recording
  order" (0015 header); readers preserve it. **[C]**
- **`scala_exports` `(owner_key, ordinal)`** -- per-owner selector-clause order. **[C]**
- **`rust_module_scopes.ordinal`** -- ordinal 0 is always the file root and the
  rows are pre-order so a parent precedes its children; `parent_ordinal`
  references it. Ordinal is a structural id, not just sequence. **[C]**
- **`rust_modules.ordinal`** -- ordinal 0 is always the file root. **[C]**
- **`rust_module_route_gates`** -- `(route_ordinal, gate_ordinal)` outermost-first
  chain; `attach_rust_module_route_gate` (`store/mod.rs:7902`) errors if a gate
  names a missing route (an assertion, not a recovery path). **[C]**
- **`unit_children.ordinal`** is in the PK, so the same (parent, child) pair can
  legitimately repeat at different ordinals. **[C]**

---

## 14. Constraints the data implies but the schema lacks

Missing FKs **[C]**:
- `materialization_records.unit_key` -> `code_units(blob_oid, lang, unit_key)`.
  Currently only `blobs` is referenced; a dangling key silently drops the record.
- `semantic_file_chunks.vector_hash` -> `semantic_vectors(vector_hash)`
  (index only, no FK).
- `rust_module_routes.scope_ordinal` -> `rust_module_scopes(blob_oid, lang, ordinal)`.
- `rust_module_route_gates.route_ordinal` -> `rust_module_routes(blob_oid, lang, ordinal)`.
- `rust_modules` / `rust_exports` / `rust_import_targets` reference `blobs` but
  nothing constrains them to a blob that has `blob_meta` (contrast
  `structural_facts_snapshots` and `blob_payload_costs`, which FK to `blob_meta`).

Missing CHECKs **[C]**:
- No `ordinal >= 0` on `import_statements`, `import_details`,
  `unit_signatures`, `unit_signature_metadata`, `unit_supertypes`,
  `unit_children`, `materialization_records`, `scala_exports`, or any 0016/0017
  table. `unit_ranges` and `path_symbol_units` do have their CHECKs, so the gap
  is inconsistency rather than policy.
- No CHECK ties `materialization_records.unit_key IS NULL` to the payload
  variant (`MaterializationRecordPayload::requires_unit`) -- that invariant lives
  only in Rust (`materialization.rs:~420`).
- No byte/line ordering CHECK on the 0016/0017 span columns
  (`owner_start <= owner_end`, `body_start <= body_end`, ...), though
  `unit_ranges` has exactly that CHECK.
- `blobs.lang` / `code_units.lang` etc. are free TEXT with no closed vocabulary,
  while `semantic_pack_active_members.source_kind` shows the house style for a
  constrained TEXT enum. `code_units.kind` uses the other style
  (`INTEGER CHECK(kind BETWEEN 0 AND 5)` plus `CHECK(kind <> 5)` and a
  language-specific `CHECK(NOT (kind = 3 AND lang IN ('javascript','python','typescript')))`).
  Both styles are in the schema today; pick one.
- `rust_*` boolean columns (`is_glob`, `is_inline`, `imports_macros`,
  `test_gated`, `passthrough`, `workspace_produced` excepted) have no
  `IN (0,1)` CHECK, unlike the 0001 booleans which all do.

Cost-model gaps **[C]**:
- `persisted_blob_mutation_cost_fallback_sql` (`store/mod.rs:8742-8788`) sums
  `unit_signature_metadata`, `unit_cpp_template_metadata`, `import_details`,
  `scala_exports`, `structural_facts_snapshots` payload bytes -- but **not**
  `code_units.fq_segments` and **not** `materialization_records.payload`.
- The write-side computation (`store/mod.rs:8816-8825`) counts
  `materialization_records` but **not** `fq_segments`.
  So `fq_segments` -- 1.3 MB / 34 % of the measured non-signature blob bytes in
  abseil -- is invisible to the GC cost model in both paths.

---

## 15. SQLite-specific constraints shaping the design

- **STRICT everywhere.** Every table in the cache is `STRICT`, so the column
  type set is `INT / INTEGER / REAL / TEXT / BLOB / ANY`. No `NUMERIC`
  affinity games, no implicit coercion; a Rust `usize` must go through
  `usize_to_i64` and can fail (`store/mod.rs:9208`). **[C]**
- **`WITHOUT ROWID` on nearly every table**, with `blob_oid` first in every PK.
  That makes the PK the clustered order, so per-blob reads and per-blob
  `DELETE ... WHERE blob_oid = ?` cascades are range scans -- this is the existing
  performance contract and any new table should keep `(blob_oid, lang, ...)`
  leading. **[C]**
- **`WITHOUT ROWID` + large blobs is a real hazard.** `page_size` is 4096
  (measured). `unit_signature_metadata` is `WITHOUT ROWID` and its cap is
  `MAX_SIGNATURE_METADATA_BLOB_BYTES = 8 MiB`; abseil has rows at 29 KB. Large
  payloads in a `WITHOUT ROWID` table inflate the PK b-tree with overflow-page
  chains, which is exactly the index a range scan walks. Splitting big payloads
  into narrow rows *helps* here rather than hurting. **[C]**
- **`auto_vacuum = 2` (incremental), `journal_mode = WAL`, `foreign_keys = ON`**
  (`cache_db.rs:355, 873, 904-941`; verified on a live cache). FKs are enforced,
  so a new FK is a real behavioral change on write ordering, and migrations run
  with `foreign_keys` briefly OFF (`cache_db.rs:1052`) then re-validate with
  `validate_foreign_keys` (`:1356`). **[C]**
- **Content-hash `blob_oid` cascade convention.** `blob_oid TEXT NOT NULL
  CHECK(length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*')`, `(blob_oid,
  lang)` in `blobs` as the cascade root, `ON DELETE CASCADE` on every child.
  Two byte-identical files share one row, so **no column may be path-derived** --
  0016/0017 state this explicitly, and `fq_segments` mode 1 exists precisely to
  honor it. Any new table must obey the same rule. **[C]**
- **Generation filtering** (`blobs.generation`, `analysis_epochs.generation`,
  `require_current_generation`) and the `PARSED_BLOB_COMPLETE_CONDITION`
  predicate are joined into nearly every read. AGENTS.md wants these in views. **[C]**
- **Bounded-query byte budget.** Several read paths (`import_infos_for_key_limited`,
  `signature_metadata_for_unit_limited_conn`, `supertype_lookup_paths_for_unit_limited_conn`)
  first `SELECT length(col)` and refuse rows above `MAX_LIMITED_QUERY_ROW_BYTES`,
  returning an *incomplete* answer. That whole mechanism exists because a single
  row can be arbitrarily large -- narrow rows would make most of it unnecessary,
  but the incompleteness contract is visible to callers, so it cannot just be
  deleted. **[C]**
- **900-parameter chunking** (`oids.chunks(900)`) is the current bulk-read
  idiom, driven by `SQLITE_MAX_VARIABLE_NUMBER`. **[C]**
- **EXPLAIN QUERY PLAN pins already exist** in `store/mod.rs`,
  `nlp/src/active_index.rs`, and `tests/suite_persistence/semantic_pack_catalog.rs`.
  AGENTS.md asks for more of these on new queries. **[C]**

---

## 16. Ranking by "how relational is the hidden data" (evidence, not proposal)

| column | hidden shape | tree-shaped? | scale (abseil bytes) |
|---|---|---|---|
| `materialization_records.payload` | 5-variant union of 1-2 Ranges + closed enum + one String | no | 148 K |
| `unit_supertypes.lookup_path` | 2 language-specific JSON docs; Ruby's is `(enum, dup-of-`raw`)` | no | tiny |
| `import_details.info` | 6 scalars + 3 flat lists | no | 341 K |
| `scala_exports.info` | parent + child selector list | no | (unmeasured) |
| `code_units.fq_segments` | ordered `(kind, text)` list + 2 header scalars | no | 1 302 K |
| `unit_signature_metadata.metadata` | 14 scalars + param list + **2 type-shape arenas** | partly | 3 810 K |
| `unit_cpp_template_metadata.metadata` | 2 scalars + param list + **recursive `CppTemplateTerm`** | yes | 337 K |
| `structural_facts_snapshots.payload` | node arena + 2 CSR edge arrays | arena, read wholesale | (unmeasured) |
| `semantic_vectors.vector` | quantized code | n/a | n/a -- keep binary |

---

## 17. Measurement provenance

- abseil C++ cache: copy of `/mnt/optane/tmp/bifrost-fird/abseil-cli-cache/bifrost_cache.v15.db`
  (873 cpp + 6 python blobs, 24 906 code units, 38.7 MB). Opened read-only via a copy.
- Polyglot fixture: `crates/bifrost-core/src` (35 rust blobs) plus one hand-written
  file each for java, python, ts, js, go, scala, ruby, kotlin, csharp; analyzed with
  `target/release/bifrost --root . --tool get_active_workspace` and
  `BIFROST_SEMANTIC_INDEX=off`. Produced `bifrost_cache.v15.db`.
- **Caveat:** that binary predates migrations 0016/0017, so `rust_import_targets`,
  `rust_exports`, `rust_modules`, `rust_identifier_occurrences`,
  `rust_module_scopes`, `rust_module_routes`, `rust_module_route_gates`,
  `rust_item_macros` were **not measurable**. All 0016/0017 statements here come
  from reading the SQL and the Rust, not from data. **[U]**
- `structural_facts_snapshots` is near-empty in both caches (0 and 1 rows), so its
  size distribution is **[U]**.
