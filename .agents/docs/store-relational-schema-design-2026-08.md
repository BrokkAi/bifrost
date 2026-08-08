# Design: relational schema for the opaque-blob cleanup

Status: DESIGN FOR OWNER REVIEW. No implementation until approved. Author: Fable, 2026-08-08.
Substrate: `opaque-blob-inventory-v1.md` (session artifact; check into `.agents/docs/` with the
first implementation commit). Governing direction: AGENTS.md "SQL and the analyzer store"
(commit 9263e2a5). Style brief from the owner: Celko-clean where it does not cost performance;
Lukas Eder pragmatism where Celko's dogmatism should soften -- every softening below is named
as such.

One structural fact makes this migration cheap: caches are rebuildable artifacts. A schema
version bump invalidates and re-analysis rebuilds, so there is no dual-write period and no
data migration -- each change is new DDL + writer + reader in one commit, old column gone.
Backward compatibility is explicitly not a requirement (AGENTS.md).

## Census verdicts

| Column | Verdict |
|---|---|
| `import_details.info` (bincode `ImportInfo`) | relational; MERGE with `import_statements` |
| `unit_signature_metadata.metadata` (bincode) | relational; MERGE scalars into `unit_signatures`, children out |
| `unit_supertypes.lookup_path` (TEXT JSON, 2 shapes) | relational; the correctness fix |
| `materialization_records.payload` (bincode union) | columns + variant CHECKs |
| `code_units.fq_segments` (hand-rolled FQ2) | relational; authority inversion |
| `unit_cpp_template_metadata.metadata` (bincode, unbounded recursion) | relational arena |
| `scala_exports.info` (bincode) | relational, aligned with `rust_exports` (0016) |
| `structural_facts_snapshots.payload` | KEEP as blob (judgment call, below) |
| `semantic_vectors.vector`, `vector_hash` | KEEP (quantized codes; genuinely binary) |
| `semantic_file_chunks.fts_tokens` | KEEP (BM25 token stream, not a struct) |

## Cross-cutting rules (apply to every table below)

STRICT; `WITHOUT ROWID` with `(blob_oid, lang, ...)` leading so per-blob reads and cascades
stay clustered range scans; `ON DELETE CASCADE` from `blobs`; booleans `INT CHECK(x IN (0,1))`
(closes the 0016/0017 gap); `ordinal >= 0` CHECKs uniformly; span pairs get
`CHECK(start <= end)`; enums are TEXT with a closed `CHECK(x IN (...))` -- one enum style for
all NEW columns (the existing `code_units.kind INTEGER` stays: churning a working encoding is
Eder-pragmatism, and the language-conditional CHECK it carries is already doing its job).
Content-stability rule unchanged: nothing path-derived in any row. Every new table's rows are
counted by the batch cost model (closes the `fq_segments` accounting gap). New query pins are
EQP assertions.

## 1. Imports: one entity, one table (kills reverse smell #1)

`import_statements.statement` is byte-identical to `ImportInfo.raw_snippet` in 8 of 10
languages, and the two tables' ordinals are NOT co-keyed for Scala and TS -- the merge fixes
both by construction: one row per import binding, `import_details` dropped.

    import_statements(
      blob_oid, lang, ordinal,
      statement TEXT NOT NULL,              -- the raw snippet, single copy
      is_wildcard INT CHECK IN (0,1),
      identifier TEXT,                      -- NULL where the language has none
      alias TEXT,
      path_kind TEXT CHECK(path_kind IN ('namespace','static_member','import_from')),
      declaration_start_byte INT,
      binder_start INT, binder_end INT,     -- CHECK(binder_start <= binder_end)
      PRIMARY KEY(blob_oid, lang, ordinal)) WITHOUT ROWID, STRICT

    import_path_segments(blob_oid, lang, ordinal, seg_ordinal, segment TEXT NOT NULL,
      PRIMARY KEY(blob_oid, lang, ordinal, seg_ordinal))   -- position IS meaning: a sequence
                                                           -- attribute, not a surrogate
    import_lexical_scopes(blob_oid, lang, ordinal, scope_ordinal, start_byte, end_byte)
    import_lexical_prefixes(blob_oid, lang, ordinal, prefix_ordinal, prefix TEXT)

Celko point: the nullable scalars are genuinely optional attributes of one entity (cpp/ruby/
csharp never populate path or binder span; only Scala uses prefixes) -- sparse NULLs on one
table beat both EAV and ten per-language tables. Eder point: three narrow child tables cluster
under the same `(blob_oid, lang)` prefix, so hydrating one file's imports is still one range
scan neighborhood. Write-side cleanup rides along: Go segments properly (today
`segments = [whole_path]` while a consumer re-parses the raw text); C#'s twelve
`raw_snippet`-parsing sites get `path_kind`/segments populated so they stop string-splitting
(that is the Design-philosophy rule already, not new policy).

Rust note: `rust_import_targets` (0016) remains the Rust usage layer's table; this merge is the
cross-language layer. The overlap map says one Rust `use` lands in three or four places today;
after this change it is two, each with a distinct consumer (usage walks vs. generic import
surface), and collapsing further is a later decision once the retirement plan settles consumers.

## 2. Signatures: scalars in, children out (kills reverse smell #2 and the 29KB hazard)

`SignatureMetadata.label` is byte-identical to `unit_signatures.text` (15,675/15,675 measured).
The 14 scalars move onto `unit_signatures` as sparse nullable columns (same Celko/Eder argument
as imports; no language sets more than ~8). The positional-pairing contract between the two
tables -- real, and expressed nowhere -- dies by merger. `is_companion_object` has ZERO
readers: dropped, not migrated (re-add with its first reader).

Children:

    signature_parameters(blob_oid, lang, ordinal, param_ordinal, <ParameterMetadata fields as
      columns>, PRIMARY KEY(blob_oid, lang, ordinal, param_ordinal))

    signature_type_nodes(blob_oid, lang, ordinal, arena TEXT CHECK(arena IN ('params','return')),
      node_ordinal, parent_ordinal,          -- post-order arena preserved as rows
      <StructuredTypeNode scalar fields>,
      PRIMARY KEY(blob_oid, lang, ordinal, arena, node_ordinal))

The type arenas are the one genuine tree in the analyzer blobs, and they are already flat
post-order vectors -- rows are a transliteration, not a redesign. Two wins beyond hygiene: the
29,280-byte max row (the WITHOUT ROWID overflow-chain hazard the inventory flagged) becomes
narrow rows; and `usage_fact_row_from_row` -- which today bincode-decodes the whole struct
INSIDE the bulk usage-graph row mapper -- selects the two or three scalars it needs instead.
That is a measured hot path, not a hypothetical.

## 3. Supertype lookup paths: the correctness fix

One TEXT column holds Scala JSON (`{segments, package_prefixes, lexical_scopes}`) and Ruby JSON
(`{"kind": four-variant, "target": duplicate-of-sibling-column}`), decoded with
`serde_json::from_str(...).ok()` -- parse errors silently vanish. Replacement:

    unit_supertypes gains: relation_kind TEXT CHECK(relation_kind IN
      ('superclass','include','prepend','extend'))   -- Ruby's enum; NULL for other languages
    supertype_path_segments(...)      -- Scala's segments, shape-identical to
    supertype_lexical_scopes(...)     --   the import children above
    supertype_package_prefixes(...)

Ruby's JSON `target` duplicates the sibling `raw` column: dropped, `raw` authoritative. The
`.ok()` swallow becomes impossible -- there is nothing left to parse.

## 4. Materialization records: a union with honest constraints

Five variants of one-or-two ranges + a closed enum + one optional string, with the discrete
sizes 72/49-62/36 the inventory measured. Single-table union with variant CHECKs -- five tables
for three row shapes is Celko dogma softened, and the constraints carry the semantics:

    materialization_records(blob_oid, lang, ordinal, unit_key,
      variant TEXT NOT NULL CHECK(variant IN (<five>)),
      a_start INT NOT NULL, a_end INT NOT NULL CHECK(a_start <= a_end),
      b_start INT, b_end INT,
      detail TEXT,
      CHECK((b_start IS NULL) = (b_end IS NULL)),
      CHECK((unit_key IS NULL) = (variant IN (<the variants Rust today calls requires_unit=false>))),
      FOREIGN KEY(blob_oid, lang, unit_key) REFERENCES code_units ...)

The FK closes the inventory's sharpest constraint gap: today the reader SILENTLY DROPS records
whose `unit_key` does not resolve. `requires_unit` moves from a Rust method into a CHECK.

## 5. fq_segments: the authority inversion

Migration 0012 declared the blob authoritative and the `code_units` name columns "projections"
-- exactly inverse to the new direction, and the blob is invisible to the cost model (1.3 MB
uncounted in the abseil cache). Replacement:

    code_unit_fq_segments(blob_oid, lang, unit_key, seg_ordinal,
      seg_kind TEXT CHECK(...),           -- the FQ2 per-segment kind byte, named
      segment TEXT NOT NULL,
      PRIMARY KEY(blob_oid, lang, unit_key, seg_ordinal))
    code_units gains: fq_stable_prefix_len INT   -- the PATH_TAIL boundary: segments below this
                                                 -- index are the content-stable tail (mode 1);
                                                 -- NULL = fully stable (mode 0)

Content-stability is preserved by the same mechanism the blob's mode byte encodes today, as a
declared column instead of a header. This table becomes Rust's canonical identity source
(`fq_segments` + `short_name` is where Rust identity lives per the 0016 work) -- a convergence,
not a coincidence. The name columns on `code_units` stay as the denormalized read path -- named
load-bearing denormalization, same status as `blob_meta.*_count` (which also stays; it feeds
the GC cost model).

## 6. C++ template metadata: arena rows, and a hazard retired

`CppTemplateTerm` is a boxed recursive tree with no depth cap and no bounded deserializer --
the only decoder in the store that can be blown up by depth. Same arena treatment as signature
type nodes (`cpp_template_terms` table, parent_ordinal, post-order). `alias_target` becomes a
column, which retires reverse smell #5 (`cpp_alias_target_text` splitting signature text on '='
while the structured answer sat in the sibling blob). `specialization_arguments` is consumed
almost entirely as `.is_empty()`: store the terms anyway (they are read elsewhere), but the
hot consumers get `has_specialization_arguments INT` generated -- pragmatism, one derived
boolean, declared in schema.

## 7. scala_exports: align with the 0016 precedent

Same treatment as `rust_exports`: per-export rows (exported name, source path, glob flag, plus
whatever `ScalaExportInfo` fields the full inventory lists as read), shape-aligned so the two
languages' export tables read the same way. Fields with zero readers get the
`is_companion_object` treatment.

## JSON as an Eder exception (owner input, 2026-08-08)

JSON columns are an acceptable pragmatic exception -- SQLite's JSON1 plus generated columns
make them queryable and indexable, unlike bincode -- but they earn admission only when ALL of:

1. The shape is genuinely heterogeneous or open (a variant bag, per-language one-off extras),
   where fixed columns would mean either wide sparse NULLs at scale or a table per variant.
2. Nothing inside needs to be an FK target or carry per-field CHECKs -- invariants that matter
   go in real columns, always.
3. It is not read on a hot bulk path (json_extract in a row mapper beats a bincode decode but
   loses to a column), and rows stay well under the overflow-chain threshold.
4. The column carries `CHECK(json_valid(x))` at minimum, plus a shape discipline (one shape per
   column; a version key if the shape can evolve) -- the existing `lookup_path` column violated
   both and is this design's cautionary tale, with its silently-swallowed parse errors.
5. The view rule applies transitively: when a second reader wants a field, that field is
   promoted to a generated column with an expression index, not extracted ad hoc twice.

Applied to this census: nothing currently qualifies. `materialization_records` was the closest
call (a 5-variant union is JSON-shaped), but its `unit_key` FK and variant-tied nullability
CHECKs are exactly the invariants criterion 2 keeps in columns. The live escape hatch this
section exists for: if the sparse per-language scalar sets (signatures today: 14 fields, no
language sets more than ~8) grow past the point where NULL columns stay readable, a validated
per-language `extras` JSON column is the sanctioned pressure valve -- with its hot fields
promoted per criterion 5.

## Kept opaque, with reasons stated

- `structural_facts_snapshots.payload`: node arena + two CSR adjacency arrays, hydrated
  wholesale into a matcher arena, never queried in SQL, near-empty in both measured caches
  (scale unmeasured). Relationalizing a CSR nobody queries is purity without a customer --
  Eder's veto. Revisit if RQL ever wants SQL-side structural predicates. It does gain a byte
  count in the cost model.
- `semantic_vectors.vector`: fastrq quantized codes scored allocation-free from bytes. Binary
  is the correct type.
- `semantic_file_chunks.fts_tokens`: a token stream for BM25, not structure.

## Constraint repairs riding along (from the inventory's gap list)

FKs: `semantic_file_chunks.vector_hash -> semantic_vectors`;
`rust_module_routes.scope_ordinal -> rust_module_scopes`;
`rust_module_route_gates.route_ordinal -> rust_module_routes`. Ordinal semantics that are
contracts get comments in the DDL (`unit_ranges.ordinal = 0` is "primary range";
`rust_module_scopes.ordinal = 0` is the file root) -- documented, not redesigned; both are
load-bearing and tested.

## Encoding note

Where a blob survives an interim state, legacy-bincode's fixed-width integers are ~64%
overhead on small rows (measured: 140-byte row, ~50 bytes content). Not worth an encoding
migration on its own -- every table above deletes the encoding entirely, which is the better
fix.

## Order of implementation (by measured value, each its own migration + version bump)

1. Imports merge (feeds the retirement-plan cohorts and the future candidate-walk work;
   deletes 15-53% duplicate bytes).
2. Signature split (the hot row-mapper decode + the 29KB overflow hazard + the label dup).
3. Supertype JSON (correctness: swallowed parse errors).
4. Materialization columns (constraints; smallest).
5. fq_segments inversion (largest semantic surface; Rust identity convergence).
6. C++ template arena.
7. scala_exports.
Each step: frozen-equivalence pin against the blob decoder it replaces, EQP pins for the new
read paths, per-language suite parity. Steps are independent; any can ship alone.
