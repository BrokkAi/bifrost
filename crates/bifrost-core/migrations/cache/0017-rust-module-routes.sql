-- Per-file Rust module-route facts: what the Cargo route index needs from a
-- file's syntax tree (issue #1793; ExecPlan `.agents/plans/rust-usage-index-v2.md`,
-- prerequisite of Milestone 4).
--
-- `RustCargoRouteIndex` was the last Rust structure that hydrated and parsed
-- EVERY analyzed file to build itself, and it was rebuilt for every analyzer
-- generation -- 34-44 s on the 35,370-file rustc tree, charged inside the three
-- second `scan_usages` budget, in cold, warm, edited and unedited cells alike.
-- These tables move the only thing that build read out of the tree into rows,
-- so the index composes from an indexed read instead of a whole-workspace parse.
--
-- The build reads exactly three things per file: the lexical scopes that `mod`
-- items are declared in, the external `mod name;` declarations themselves, and
-- the `macro_rules!` item macros the file defines. Everything else it does is
-- Cargo manifest topology, which stays on disk: the rustc tree's 347 manifests
-- are 207 KB and parse in 4.9 ms warm, so persisting them would buy nothing.
--
-- Every column here is CONTENT-derived, never path-derived, exactly as in
-- `0016-rust-usage-facts.sql`: two byte-identical files share one blob row, so
-- a stored value that depended on the file's location would be wrong for one of
-- them. Directory resolution, `#[path]` normalization and the on-disk existence
-- check therefore all happen in the reader, against the live `ProjectFile`.

-- The lexical scopes one file declares `mod` items in: the file root at ordinal
-- 0 (`parent_ordinal` NULL, empty `module_name`, spanning the whole source) and
-- one row per `mod name { ... }` body reachable from it, in pre-order so a
-- parent always precedes its children.
--
-- A scope exists to carry two things the reader cannot recover from the route
-- row alone. `path_attribute` is the `#[path = "..."]` value written on the
-- inline module, decoded from its string literal; it REPLACES the directory the
-- enclosing scope would otherwise contribute, and it is resolved step by step
-- against the file system because `#[path]` may escape upward and may traverse
-- a symbolic link. `imports_macros` is the `#[macro_use]` chain from the file
-- root down to this scope, which decides whether a `mod` item below it can
-- import macros into file scope at all.
--
-- `body_start`/`body_end` span the scope's body. Only ordinal 0's extent is
-- read today -- the item-macro visibility rules ask whether a definition's
-- scope is the whole file -- but recording it for every scope keeps the row
-- shape uniform and costs two integers.
CREATE TABLE rust_module_scopes(
  blob_oid       TEXT    NOT NULL,
  lang           TEXT    NOT NULL,
  ordinal        INTEGER NOT NULL,
  parent_ordinal INTEGER,
  module_name    TEXT    NOT NULL,
  path_attribute TEXT,
  imports_macros INTEGER NOT NULL,
  body_start     INTEGER NOT NULL,
  body_end       INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One row per `mod name;` declaration whose body lives in another file, keyed
-- to the scope it was written in. This is a CANDIDATE declaration, not a
-- resolved edge: which file (or files) it names depends on the declaring file's
-- own path and on what exists on disk, both of which the reader supplies.
--
-- `path_attribute` is the declaration's own `#[path = "..."]` value. When it is
-- present the declaration names exactly one file, resolved against the scope's
-- path-attribute directory; when it is NULL the declaration names
-- `<scope directory>/<module_name>.rs` and `<scope directory>/<module_name>/mod.rs`,
-- and both are taken if both exist, as Cargo's own resolution does not apply
-- here (this index models what the module tree can reach, not what rustc picks).
--
-- `visibility` is encoded by `crate::analyzer::rust::facts::encode_rust_visibility`,
-- as in `rust_import_targets`. `test_gated` is the bare `#[cfg(test)]` verdict
-- that makes the declared file test-only, and is deliberately false for every
-- composed predicate (see `rust_declaration_is_bare_cfg_test_gated`).
-- `declaration_end` is the item's end byte; the route index reads it as the
-- point after which a `#[macro_use] mod ...;` makes the child's macros visible.
CREATE TABLE rust_module_routes(
  blob_oid          TEXT    NOT NULL,
  lang              TEXT    NOT NULL,
  ordinal           INTEGER NOT NULL,
  scope_ordinal     INTEGER NOT NULL,
  module_name       TEXT    NOT NULL,
  path_attribute    TEXT,
  visibility        TEXT    NOT NULL,
  imports_macros    INTEGER NOT NULL,
  test_gated        INTEGER NOT NULL,
  declaration_start INTEGER NOT NULL,
  declaration_end   INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The macro invocations a route was found inside, outermost first.
--
-- An item macro can expand to `mod name;`, and whether it does is not a
-- property of the invoking file: it depends on which `macro_rules!` definition
-- the invoked name resolves to at that byte, which is decided by the
-- `#[macro_use]` module graph across files. Extraction therefore expands every
-- item-position macro invocation OPTIMISTICALLY and records the gate; the
-- reader keeps a gated route only when every gate resolves, at its recorded
-- byte, to a definition proven to replay its item parameters verbatim.
--
-- Almost every route is ungated and has no row here. A chain longer than one
-- means a macro invocation nested inside another macro's token tree.
CREATE TABLE rust_module_route_gates(
  blob_oid         TEXT    NOT NULL,
  lang             TEXT    NOT NULL,
  route_ordinal    INTEGER NOT NULL,
  gate_ordinal     INTEGER NOT NULL,
  macro_name       TEXT    NOT NULL,
  invocation_start INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, route_ordinal, gate_ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The `macro_rules!` definitions this file declares at item positions, with the
-- lexical window each is visible in and whether its every rule replays its item
-- parameters verbatim (`passthrough`). These are the definitions the route
-- index propagates along `#[macro_use]` edges to decide the gates above.
CREATE TABLE rust_item_macros(
  blob_oid      TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL,
  macro_name    TEXT    NOT NULL,
  visible_after INTEGER NOT NULL,
  scope_start   INTEGER NOT NULL,
  scope_end     INTEGER NOT NULL,
  passthrough   INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
