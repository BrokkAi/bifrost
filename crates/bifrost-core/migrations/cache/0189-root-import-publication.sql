CREATE TABLE resolution_root_imports (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  import_site INTEGER NOT NULL CHECK(import_site BETWEEN 0 AND 4294967295),
  root_scope INTEGER NOT NULL CHECK(root_scope BETWEEN 0 AND 4294967295),
  anchor TEXT NOT NULL CHECK(anchor IN ('lexical','absolute')),
  position INTEGER CHECK(position IS NULL OR position >= 0),
  kind TEXT NOT NULL CHECK(kind IN ('named','glob')),
  bound_name TEXT,
  CHECK(kind <> 'glob' OR bound_name IS NULL),
  PRIMARY KEY(blob_id, import_site)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_root_imports_binding ON resolution_root_imports(blob_id, root_scope, bound_name);
CREATE TABLE resolution_root_import_segments (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  import_site INTEGER NOT NULL,
  position INTEGER NOT NULL CHECK(position >= 0),
  segment TEXT NOT NULL CHECK(length(segment) > 0),
  PRIMARY KEY(blob_id, import_site, position)
) WITHOUT ROWID, STRICT;
CREATE TABLE resolution_root_import_demands (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  import_site INTEGER NOT NULL,
  namespace INTEGER NOT NULL,
  name TEXT NOT NULL,
  target_kind TEXT CHECK(target_kind IS NULL OR target_kind IN ('named_reference','same_name_glob')),
  target_reference INTEGER CHECK(target_reference IS NULL OR target_reference BETWEEN 0 AND 4294967295),
  target_name TEXT,
  CHECK((target_kind='named_reference') = (target_reference IS NOT NULL)),
  CHECK((target_kind = 'named_reference') = (target_name IS NOT NULL)),
  CHECK(target_name IS NULL OR length(target_name) > 0),
  PRIMARY KEY(blob_id, import_site, namespace, name)
) WITHOUT ROWID, STRICT;
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_root_import_count INTEGER NOT NULL DEFAULT 0 CHECK(expected_root_import_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_root_import_segment_count INTEGER NOT NULL DEFAULT 0 CHECK(expected_root_import_segment_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_root_import_demand_count INTEGER NOT NULL DEFAULT 0 CHECK(expected_root_import_demand_count >= 0);
