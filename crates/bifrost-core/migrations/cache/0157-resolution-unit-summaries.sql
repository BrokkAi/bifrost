-- Per-unit resolution summaries (derivation contract, kind 2: a fixpoint
-- summary at the unit of recursion). One summary describes one unit of one
-- language: a Rust crate, a Go package instance plus source role, or a JVM
-- project source set. It is derived at reconcile from the unit's own inputs and
-- from the output digests of the units it consumed, and it is read by keyed
-- lookups. The tables are language-neutral; a language supplies only its unit
-- definition and its derivation.
--
-- Validity rule, stated once for the writer and every reader: the summary is
-- `publication_state = 'complete'`, its `producer_epoch` and
-- `derivation_version` equal the active ones, and a version row for
-- (workspace_id, lang, generation, unit_key) is open at the selected revision.
-- Stale dependents are closed by the reconcile writer, never by readers.

-- Header. One row per distinct set of inputs (`summary_digest`), shared by every
-- workspace and revision that derives the same inputs. `output_digest` covers
-- the names surface only (exports, import resolutions, gaps) and not the
-- member coordinates, so an edit that leaves the surface equal leaves every
-- dependent's `summary_digest` equal (early cutoff). The three counts record
-- how many rows of the blob-referencing children were written: those children
-- cascade away when their blob row is replaced, and a count that no longer
-- matches tells the reconcile writer that the summary must be derived again.
CREATE TABLE resolution_unit_summaries (
  summary_id          INTEGER PRIMARY KEY,
  lang                TEXT NOT NULL CHECK(length(lang) > 0),
  unit_kind           TEXT NOT NULL CHECK(unit_kind IN ('go_package', 'rust_crate', 'jvm_source_set')),
  unit_key            BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  summary_digest      BLOB NOT NULL UNIQUE
    CHECK(typeof(summary_digest) = 'blob' AND length(summary_digest) = 32),
  producer_epoch      TEXT NOT NULL CHECK(length(producer_epoch) > 0),
  derivation_version  INTEGER NOT NULL CHECK(derivation_version > 0),
  complete            INTEGER NOT NULL CHECK(complete IN (0, 1)),
  member_count        INTEGER NOT NULL DEFAULT 0 CHECK(member_count >= 0),
  export_count        INTEGER NOT NULL DEFAULT 0 CHECK(export_count >= 0),
  import_count        INTEGER NOT NULL DEFAULT 0 CHECK(import_count >= 0),
  output_digest       BLOB
    CHECK(output_digest IS NULL OR (typeof(output_digest) = 'blob' AND length(output_digest) = 32)),
  publication_state   TEXT NOT NULL CHECK(publication_state IN ('building', 'complete')),
  CHECK((publication_state = 'complete') = (output_digest IS NOT NULL))
) STRICT;

-- Which summary is live for one unit at which workspace revisions. Reader
-- question: "what is this unit's summary at revision R". The partial index
-- answers "which units are live now" and "which units depend on U" starts from
-- the dependencies index below.
CREATE TABLE resolution_unit_summary_versions (
  workspace_id  TEXT NOT NULL CHECK(length(workspace_id) = 64),
  lang          TEXT NOT NULL CHECK(length(lang) > 0),
  generation    INTEGER NOT NULL CHECK(generation >= 0),
  unit_key      BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  valid_from    INTEGER NOT NULL CHECK(valid_from > 0),
  valid_until   INTEGER CHECK(valid_until IS NULL OR valid_until > valid_from),
  summary_id    INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id),
  PRIMARY KEY(workspace_id, lang, generation, unit_key, valid_from)
) WITHOUT ROWID, STRICT;
-- Reconcile closes every open row a pass did not rebind; unbound-header cleanup
-- seeks the summary side.
CREATE INDEX resolution_unit_summary_versions_open
  ON resolution_unit_summary_versions(workspace_id, lang, generation, unit_key)
  WHERE valid_until IS NULL;
CREATE INDEX resolution_unit_summary_versions_summary
  ON resolution_unit_summary_versions(summary_id);

-- The unit's own input set: the files that form it. Reader question: "which
-- units does this file belong to" (index on blob_id) and, for the writer, "what
-- does this summary say its members were".
CREATE TABLE resolution_unit_summary_members (
  summary_id      INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  member_ordinal  INTEGER NOT NULL CHECK(member_ordinal >= 0),
  blob_id         INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  rel_path        TEXT NOT NULL CHECK(length(rel_path) > 0),
  source_role     TEXT NOT NULL CHECK(length(source_role) > 0),
  PRIMARY KEY(summary_id, member_ordinal)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_unit_summary_members_blob
  ON resolution_unit_summary_members(blob_id, summary_id);

-- The consumed units. `consumed_output_digest` is the child's output digest at
-- derivation time; for an external or standard-library dependency it is the
-- digest of the provenance the derivation saw. Reader question: "which units
-- depend on unit U" (index on dependency_unit_key), and for the writer "did a
-- consumed output move".
CREATE TABLE resolution_unit_summary_dependencies (
  summary_id             INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  dependency_ordinal     INTEGER NOT NULL CHECK(dependency_ordinal >= 0),
  dependency_unit_key    BLOB NOT NULL
    CHECK(typeof(dependency_unit_key) = 'blob' AND length(dependency_unit_key) = 32),
  consumed_output_digest BLOB NOT NULL
    CHECK(typeof(consumed_output_digest) = 'blob' AND length(consumed_output_digest) = 32),
  boundary               TEXT NOT NULL CHECK(boundary IN ('workspace', 'external', 'standard')),
  -- Module path and version of a Go external package, as text; NULL otherwise.
  provenance             TEXT CHECK(provenance IS NULL OR length(provenance) > 0),
  PRIMARY KEY(summary_id, dependency_ordinal),
  UNIQUE(summary_id, dependency_unit_key)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_unit_summary_dependencies_unit
  ON resolution_unit_summary_dependencies(dependency_unit_key, summary_id);

-- Recorded inputs that are neither members nor child summaries: the producer
-- epoch and analysis generation, the derivation version, and the unit's slice
-- of the language's membership publication. `key_digest` names the input,
-- `digest` is what the derivation saw. Reader question: "which summaries read
-- input K" (index on key_digest).
CREATE TABLE resolution_unit_summary_reads (
  summary_id    INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  read_ordinal  INTEGER NOT NULL CHECK(read_ordinal >= 0),
  kind          TEXT NOT NULL CHECK(kind IN ('epoch', 'derivation', 'context_publication', 'configuration', 'pack')),
  key_digest    BLOB NOT NULL CHECK(typeof(key_digest) = 'blob' AND length(key_digest) = 32),
  digest        BLOB NOT NULL CHECK(typeof(digest) = 'blob' AND length(digest) = 32),
  PRIMARY KEY(summary_id, read_ordinal),
  UNIQUE(summary_id, key_digest)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_unit_summary_reads_key
  ON resolution_unit_summary_reads(key_digest, summary_id);

-- The unit's name surface. Readers: a point lookup seeks one name in one unit
-- (summary_id, namespace, identity_id); a reverse lookup seeks one declaration
-- (declaration_blob_id, declaration_site); the graph stage joins on identity_id.
-- `visibility` is 'exported' for a name other units may import and 'unit' for a
-- name only the unit's own files see; dependents read 'exported' rows only. The
-- primary key serves the point lookup (summary_id, identity_id, namespace) and
-- the graph join (summary_id, identity_id); a reader that lists a unit's
-- exports reads the key range of summary_id.
-- `declaration_key` is the blob-local semantic key of the definition.
CREATE TABLE resolution_unit_summary_exports (
  summary_id            INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  identity_id           INTEGER NOT NULL REFERENCES resolution_identities(id),
  namespace             TEXT NOT NULL CHECK(namespace IN ('type', 'value', 'callable', 'package', 'macro')),
  visibility            TEXT NOT NULL CHECK(visibility IN ('exported', 'unit')),
  origin                TEXT NOT NULL CHECK(origin IN ('declaration', 'alias', 'reexport', 'dot_import')),
  alias_dependency_ordinal INTEGER NULL,
  alias_identity_id     INTEGER NULL REFERENCES resolution_identities(id),
  declaration_blob_id   INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  declaration_site      INTEGER NOT NULL CHECK(declaration_site BETWEEN 0 AND 4294967295), -- resolution_semantic_sites.source_site
  declaration_key       INTEGER NOT NULL CHECK(declaration_key >= 0),
  CHECK((alias_dependency_ordinal IS NULL AND alias_identity_id IS NULL)
      = (origin IN ('declaration', 'dot_import'))),
  CHECK(origin NOT IN ('alias', 'reexport') OR alias_identity_id IS NOT NULL),
  FOREIGN KEY(summary_id, alias_dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal),
  PRIMARY KEY(summary_id, identity_id, namespace, declaration_blob_id, declaration_site)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_unit_summary_exports_declaration
  ON resolution_unit_summary_exports(declaration_blob_id, declaration_site);

-- Where each import declaration of each member file binds. `import_id` is the
-- blob's `source_imports.import_id`, which every import declaration has, so a
-- dot import (which has no `resolution_go_package_imports` row) has a row too.
-- `import_definition_key` is the blob-local
-- `resolution_go_package_imports.definition_key` of a named or blank import, so
-- the binding name stays in the unit's own blob and only the binding to a
-- dependency lives here; a dot import has none. Reader questions: "what does
-- this file's import bind to" (primary key) and "which files import unit U"
-- (join to the dependencies index through dependency_ordinal).
CREATE TABLE resolution_unit_summary_imports (
  summary_id              INTEGER NOT NULL,
  blob_id                 INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
  import_id               INTEGER NOT NULL CHECK(import_id >= 0),
  kind                    TEXT NOT NULL CHECK(kind IN ('named', 'blank', 'dot')),
  import_definition_key   INTEGER CHECK(import_definition_key IS NULL OR import_definition_key >= 0),
  dependency_ordinal      INTEGER,
  state                   TEXT NOT NULL CHECK(state IN ('resolved', 'unresolved', 'blank')),
  PRIMARY KEY(summary_id, blob_id, import_id),
  CHECK((kind = 'dot') = (import_definition_key IS NULL)),
  CHECK((kind = 'blank') = (state = 'blank')),
  CHECK(state IN ('unresolved', 'blank') OR dependency_ordinal IS NOT NULL),
  FOREIGN KEY(summary_id) REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  FOREIGN KEY(summary_id, dependency_ordinal)
    REFERENCES resolution_unit_summary_dependencies(summary_id, dependency_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_unit_summary_imports_dependency
  ON resolution_unit_summary_imports(summary_id, dependency_ordinal);

-- Why a summary is incomplete: incomplete_provider, unresolved_import,
-- conflicting_names, unit_summary_unavailable. `detail` is read whole.
CREATE TABLE resolution_unit_summary_gaps (
  summary_id  INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  gap_kind    TEXT NOT NULL CHECK(length(gap_kind) > 0),
  subject     TEXT NOT NULL,
  detail      BLOB NOT NULL CHECK(json_valid(detail, 8)),
  PRIMARY KEY(summary_id, gap_kind, subject)
) WITHOUT ROWID, STRICT;
