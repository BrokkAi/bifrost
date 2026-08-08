-- One import binding, one row (design `.agents/docs/store-relational-schema-design-2026-08.md`,
-- section "Imports: one entity, one table"; measured substrate
-- `.agents/docs/opaque-blob-inventory-2026-08.md`, section 1).
--
-- Until now an import was stored twice. `import_statements` held the raw source
-- text of an import declaration and `import_details` held a bincode `ImportInfo`
-- whose first field was the same text. That duplicate text measured 15 to 53
-- percent of the blob's bytes, and the two tables' `ordinal` columns were not
-- co-keyed: Scala emitted one statement row per declaration but one detail row
-- per selector, TypeScript one statement row per declaration but one detail row
-- per binding. No join between the two tables was ever sound.
--
-- The merge fixes both by construction. `import_details` is gone; the row here
-- IS the binding, and `statement` is that binding's own snippet, stored once.
-- The three child tables below hold the only variable-length parts of the
-- structured path. They cluster under the same `(blob_oid, lang, ordinal)`
-- prefix, so hydrating one file's imports stays one range-scan neighborhood,
-- and they cascade from this table, which cascades from `blobs`.
--
-- Every column is CONTENT-derived, never path-derived, because the primary key
-- is a content hash: two byte-identical files share one blob row.

DROP TABLE import_details;
DROP TABLE import_statements;

-- `is_wildcard` is the language's "bind everything under this path" form:
-- Java's and Kotlin's trailing `*`, Python's `import *`, Scala's `_`/`*`
-- selector, a TypeScript namespace import, and a plain C# `using`.
--
-- `is_global` is set when the import binds beyond its own file. C#'s
-- `global using` is the only form that sets it today. It is a column rather
-- than a text test because seven call sites used to detect it by matching the
-- prefix "global using " against the snippet.
--
-- `identifier` is the imported name as written and `alias` the name it is
-- renamed to; either may be absent, and `ImportInfo::local_name` prefers the
-- alias. Ruby puts the required path string in `identifier` because a `require`
-- has no name to import.
--
-- `declaration_start_byte` is NULL exactly when the import has no structured
-- path, which is the C++, Ruby, C#-before-this-migration, and JavaScript and
-- TypeScript case. It doubles as the path's presence marker: a structured path
-- always records the byte its declaration starts at, so a non-NULL value here
-- means the three child tables describe this row and a NULL means they hold
-- nothing for it. Storing a separate presence flag would let the two disagree.
--
-- `path_kind` distinguishes import forms the parser can already see, so that no
-- consumer re-derives them from text: `import pkg.mod` from `from pkg import
-- mod` (Python), and Java's `import static a.b.C.member`. Languages whose form
-- carries no such distinction leave it NULL.
--
-- The binder span is the byte extent of the token spelling the name this import
-- binds locally: the alias token when renamed, the imported name's own token
-- otherwise. It is what tells two bindings of one declaration
-- (`from pkg import alpha, beta`) apart structurally. It is NULL when no single
-- token spells the bound name, as for a wildcard.
CREATE TABLE import_statements(
  blob_oid               TEXT    NOT NULL,
  lang                   TEXT    NOT NULL,
  ordinal                INTEGER NOT NULL CHECK(ordinal >= 0),
  statement              TEXT    NOT NULL,
  is_wildcard            INTEGER NOT NULL CHECK(is_wildcard IN (0, 1)),
  is_global              INTEGER NOT NULL CHECK(is_global IN (0, 1)),
  identifier             TEXT,
  alias                  TEXT,
  path_kind              TEXT CHECK(path_kind IN ('namespace', 'import_from', 'static_member')),
  declaration_start_byte INTEGER CHECK(declaration_start_byte >= 0),
  binder_start           INTEGER CHECK(binder_start >= 0),
  binder_end             INTEGER CHECK(binder_end >= 0),
  CHECK((binder_start IS NULL) = (binder_end IS NULL)),
  CHECK(binder_start IS NULL OR binder_start <= binder_end),
  CHECK(path_kind IS NULL OR declaration_start_byte IS NOT NULL),
  PRIMARY KEY(blob_oid, lang, ordinal),
  FOREIGN KEY(blob_oid, lang)
    REFERENCES blobs(blob_oid, lang) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The import path, one segment per row, in path order. Position is meaning
-- here: `seg_ordinal` is a sequence attribute of the path, not a surrogate key,
-- and joining the segments back with the language's separator reproduces the
-- path as written. Go joins with '/', every other language with '.'.
CREATE TABLE import_path_segments(
  blob_oid    TEXT    NOT NULL,
  lang        TEXT    NOT NULL,
  ordinal     INTEGER NOT NULL CHECK(ordinal >= 0),
  seg_ordinal INTEGER NOT NULL CHECK(seg_ordinal >= 0),
  segment     TEXT    NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal, seg_ordinal),
  FOREIGN KEY(blob_oid, lang, ordinal)
    REFERENCES import_statements(blob_oid, lang, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The lexical containers surrounding the import, outermost first. An import
-- inside a block, a function body, or a template body binds only within that
-- extent, and these rows are how a reader answers "is this import visible at
-- byte B" without re-parsing. Scala and Rust are the languages that populate
-- them.
CREATE TABLE import_lexical_scopes(
  blob_oid      TEXT    NOT NULL,
  lang          TEXT    NOT NULL,
  ordinal       INTEGER NOT NULL CHECK(ordinal >= 0),
  scope_ordinal INTEGER NOT NULL CHECK(scope_ordinal >= 0),
  start_byte    INTEGER NOT NULL CHECK(start_byte >= 0),
  end_byte      INTEGER NOT NULL CHECK(end_byte >= 0),
  CHECK(start_byte <= end_byte),
  PRIMARY KEY(blob_oid, lang, ordinal, scope_ordinal),
  FOREIGN KEY(blob_oid, lang, ordinal)
    REFERENCES import_statements(blob_oid, lang, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The enclosing namespace or package prefixes in effect at the import
-- declaration, outermost first. Scala is the only language that populates them:
-- a `package a.b` clause followed by `package c` nests, and an import inside
-- that file resolves against the composed prefix.
CREATE TABLE import_lexical_prefixes(
  blob_oid       TEXT    NOT NULL,
  lang           TEXT    NOT NULL,
  ordinal        INTEGER NOT NULL CHECK(ordinal >= 0),
  prefix_ordinal INTEGER NOT NULL CHECK(prefix_ordinal >= 0),
  prefix         TEXT    NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal, prefix_ordinal),
  FOREIGN KEY(blob_oid, lang, ordinal)
    REFERENCES import_statements(blob_oid, lang, ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- `blob_meta` counted the two import tables separately. There is one table now,
-- so `import_count` and `import_statement_count` would hold the same number in
-- every row and the blob-integrity predicate would check one fact twice.
-- `import_count` goes; the surviving column keeps the name of the table it
-- counts. Dropping the column rather than rebuilding the table keeps this
-- migration additive for an already-populated cache: the rows, and the tables
-- whose foreign keys point at them, are left alone.
ALTER TABLE blob_meta DROP COLUMN import_count;
