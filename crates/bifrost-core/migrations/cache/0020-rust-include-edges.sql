-- Per-file Rust `include!` edges and the host import bindings visible at each
-- one (ExecPlan `.agents/plans/port-optimization-arc-to-upstream.md`, Phase 2
-- step 3).
--
-- Rust's `include!("path")` splices another file's tokens into the host. The
-- included file keeps its own physical identity in the declaration index, but
-- its imports resolve at the HOST, so a usage found in an included file has to
-- be attributed through the host's crate, module and import bindings. That
-- attribution is an include-expansion ROUTE.
--
-- Upstream built every route eagerly into one whole-workspace map on the Rust
-- usage index. These two tables are the per-blob substrate the same routes are
-- composed from on demand: the reader starts at the file being asked about,
-- finds its candidate includers through `file_name`, verifies each candidate by
-- resolving that candidate's own `relative_path`, and walks upward. Nothing
-- workspace-sized is built or retained.
--
-- Every column is CONTENT-derived, never path-derived, for the same reason as
-- the `rust_*` tables above: the primary key is a content hash, so two
-- byte-identical files at different paths share one row set. `relative_path` is
-- therefore the literal as written and NOT the resolved target, and the host's
-- own package is not stored -- resolving either needs the live file's location,
-- which is the reader's job.

-- One row per `include!("...")` invocation in the file, in source order.
--
-- `relative_path` is the string literal exactly as written, after escape
-- decoding. `file_name` is its last path component, indexed: that index is what
-- turns "which files include me" from a workspace sweep into one indexed seek
-- returning CANDIDATES, under the same contract
-- `rust_identifier_occurrences` states. A candidate is confirmed only by
-- resolving its own `relative_path` against its own directory.
--
-- `include_start` is the invocation's start byte in the host, which the reader
-- needs twice: to pick the host bindings lexically in scope at the splice, and
-- to compute the module package the included tokens inherit.
CREATE TABLE rust_include_edges(
  blob_oid      TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  relative_path TEXT    NOT NULL,
  file_name     TEXT    NOT NULL,
  include_start INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_rust_include_edges_file_name
  ON rust_include_edges(lang, file_name);

-- The host's import bindings whose lexical scope contains one include
-- invocation, in the order the route composition applies them.
--
-- `edge_ordinal` joins back to `rust_include_edges.ordinal`. `kind` is the
-- `ImportKind` discriminant text ('named', 'namespace', 'glob'); a glob binds
-- no local name and records '*'. `module_package` is deliberately absent: it is
-- the host's package at the splice point, which is path-derived, so the reader
-- computes it while composing the route.
CREATE TABLE rust_include_host_bindings(
  blob_oid         TEXT    NOT NULL,
  lang             TEXT    NOT NULL,
  edge_ordinal     INTEGER NOT NULL,
  ordinal          INTEGER NOT NULL,
  local_name       TEXT    NOT NULL,
  module_specifier TEXT    NOT NULL,
  imported_name    TEXT,
  scope_start      INTEGER NOT NULL,
  kind             TEXT    NOT NULL,
  PRIMARY KEY(blob_oid, lang, edge_ordinal, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
