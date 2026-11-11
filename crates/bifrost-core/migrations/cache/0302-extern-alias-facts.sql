-- Compatible upgrade: existing rows retain their meaning; version-suffixed store files
-- prevent older binaries from opening the expanded AliasQualified vocabulary.
-- #8430: sparse source-owned extern alias declarations and alias-qualified anchors.
CREATE TABLE resolution_extern_aliases (
 blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
 site INTEGER NOT NULL CHECK(site BETWEEN 0 AND 4294967295),
 scope INTEGER NOT NULL CHECK(scope BETWEEN 0 AND 4294967295),
 name TEXT NOT NULL CHECK(length(name)>0),
 PRIMARY KEY(blob_id,site)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_extern_aliases_scope_name ON resolution_extern_aliases(blob_id,scope,name);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_extern_alias_count INTEGER NOT NULL DEFAULT 0 CHECK(expected_extern_alias_count>=0);
-- Preserve both child families across the CHECK vocabulary rebuild.
CREATE TEMP TABLE extern_alias_saved_compilation_imports AS SELECT * FROM resolution_compilation_imports;
CREATE TEMP TABLE extern_alias_saved_global_extent AS SELECT * FROM csharp_global_using_extent;
DELETE FROM resolution_compilation_imports;
DELETE FROM csharp_global_using_extent;
CREATE TABLE resolution_root_imports_new (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  import_site INTEGER NOT NULL CHECK(import_site BETWEEN 0 AND 4294967295),
  root_scope INTEGER NOT NULL CHECK(root_scope BETWEEN 0 AND 4294967295),
  anchor TEXT NOT NULL CHECK(anchor IN ('lexical','absolute','alias_qualified')),
  position INTEGER CHECK(position IS NULL OR position >= 0),
  kind TEXT NOT NULL CHECK(kind IN ('named','glob')),
  bound_name TEXT,
  CHECK(kind <> 'glob' OR bound_name IS NULL),
  PRIMARY KEY(blob_id, import_site)
) WITHOUT ROWID, STRICT;
INSERT INTO resolution_root_imports_new SELECT * FROM resolution_root_imports;
DROP TABLE resolution_root_imports;
ALTER TABLE resolution_root_imports_new RENAME TO resolution_root_imports;
CREATE INDEX resolution_root_imports_binding ON resolution_root_imports(blob_id,root_scope,bound_name);
INSERT INTO resolution_compilation_imports SELECT * FROM extern_alias_saved_compilation_imports;
INSERT INTO csharp_global_using_extent SELECT * FROM extern_alias_saved_global_extent;
DROP TABLE extern_alias_saved_compilation_imports;
DROP TABLE extern_alias_saved_global_extent;
