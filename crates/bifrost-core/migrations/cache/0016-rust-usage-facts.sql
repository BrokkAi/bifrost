-- Per-file Rust usage facts (ExecPlan `.agents/plans/rust-usage-index-v2.md`,
-- Milestone 1; design substrate `.agents/docs/intellij-indexing-research-2026-08.md`
-- section 7.5).
--
-- Rust usage analysis was answered by one process-heap index struct of
-- seventeen workspace-wide maps that cost minutes and about 10.8 GB to build
-- and was dropped wholesale on any file edit (issue #1758). These four tables
-- decompose the unit of storage from "the workspace" to "one blob", so a file
-- edit costs one re-parse and a handful of inserts and the old blob's rows
-- orphan for the existing GC. They are the forward per-file facts; the inverted
-- name-to-blob direction is the indexes below, and cross-file answers are
-- composed at query time from these rows instead of being materialized.
--
-- Every column is CONTENT-derived, never path-derived, because the primary key
-- is a content hash: two files with identical bytes share one blob row. Module
-- names are therefore recorded RELATIVE to the file's own root module and the
-- reader composes them with the live `ProjectFile`'s package name, exactly as
-- `code_units.content_qualifier` already does. Import and export paths are the
-- verbatim source spelling, unresolved.
--
-- `identifier` columns store the canonical identifier spelling with the `r#`
-- raw-identifier escape stripped (issue #1128), and compare under SQLite's
-- default BINARY collation: lookups are case-sensitive, matching the identifier
-- index contract these tables sit beside. They deliberately do NOT change the
-- adjacent `code_units` lookup contracts (#1088 definition-lookup-only units,
-- the case-sensitivity notes on `sql_search_definitions_by_suffix_pattern`).

-- One row per name a file re-exports through a non-private `use` declaration at
-- its root. A named re-export records the name it publishes (`exported_name`,
-- after any `as` alias), the module prefix it publishes from (`source_path`) and
-- the name it publishes from (`imported_name`). A glob re-export (`pub use a::*`)
-- publishes no single name, so `exported_name` and `imported_name` are NULL and
-- `is_glob` is 1.
--
-- These rows are a filtered projection of the same `use` declarations that feed
-- `rust_import_targets`, materialized separately on purpose: "which files export
-- the name X" is a different question from "which files import the module M",
-- and giving each its own narrow table plus its own index makes each one indexed
-- lookup rather than a scan-and-filter over the wider table.
CREATE TABLE rust_exports(
  blob_oid      TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  exported_name TEXT,
  source_path   TEXT    NOT NULL,
  imported_name TEXT,
  is_glob       INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_rust_exports_name ON rust_exports(exported_name);

-- One row per binding introduced by a `use` declaration anywhere in the file,
-- in source order. `module_path` is the `::`-joined prefix as written and
-- `imported_name` the final segment; a glob import records the whole written
-- path in `module_path`, leaves `bound_name`/`imported_name` NULL and sets
-- `is_glob`. `bound_name` is the name the import binds locally (the `as` alias
-- when present).
--
-- The owner columns reproduce the import's lexical reach without re-parsing:
-- `owner_module` is the enclosing module relative to the file root ('' at the
-- root), `owner_start`/`owner_end` its byte extent, and `local_start`/
-- `local_end` are non-NULL exactly when the `use` sits inside a function body,
-- block, or closure, in which case the binding is visible only in that span.
-- `visibility` is the declared visibility encoded by
-- `crate::analyzer::rust::imports::encode_rust_visibility`.
CREATE TABLE rust_import_targets(
  blob_oid      TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  module_path   TEXT    NOT NULL,
  bound_name    TEXT,
  imported_name TEXT,
  is_glob       INTEGER NOT NULL,
  visibility    TEXT    NOT NULL,
  owner_module  TEXT    NOT NULL,
  owner_start   INTEGER NOT NULL,
  owner_end     INTEGER NOT NULL,
  local_start   INTEGER,
  local_end     INTEGER,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_rust_import_targets_module ON rust_import_targets(module_path);
CREATE INDEX idx_rust_import_targets_bound ON rust_import_targets(bound_name);

-- Modules this file introduces, in source order, with `module_name` relative to
-- the file's own root module. Ordinal 0 is always the file root itself
-- (`module_name` = '', spanning the whole source), so a reader can answer
-- "which module encloses byte B" from these rows alone by taking the narrowest
-- containing extent.
--
-- `is_inline` is 1 when the module's body is in THIS file (the file root, and
-- every `mod name { ... }`), in which case `start_byte`/`end_byte` span that
-- body. It is 0 for a `mod name;` declaration whose body is a separate file, in
-- which case the extent spans the declaration item; resolving that declaration
-- to a file is a cross-file question answered at query time, not stored here.
CREATE TABLE rust_modules(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL,
  module_name TEXT    NOT NULL,
  is_inline   INTEGER NOT NULL,
  start_byte  INTEGER NOT NULL,
  end_byte    INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The inverted identifier index: which identifiers occur in this file, and in
-- what kind of context. One row per (blob, identifier); a name occurring in
-- several contexts ORs their bits into one `context_mask`
-- (`crate::analyzer::rust::facts`: 1 code, 2 comment, 4 string, 8 macro body).
--
-- This is the piece the store did not have. It turns "find usages of foo" from
-- "consult a workspace-wide graph" into "SELECT the blobs whose text mentions
-- foo, then verify each candidate". A hit is a CANDIDATE, never a usage: the
-- caller must still resolve it. That is the same contract IntelliJ's `IdIndex`
-- states for its own hits.
CREATE TABLE rust_identifier_occurrences(
  blob_oid     TEXT    NOT NULL,
  lang         TEXT    NOT NULL,
  identifier   TEXT    NOT NULL,
  context_mask INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, identifier),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX idx_rust_identifier_occurrences
  ON rust_identifier_occurrences(lang, identifier);
