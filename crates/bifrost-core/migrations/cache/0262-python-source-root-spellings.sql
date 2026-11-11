-- Lookup spellings name existing canonical providers, never new module identities.
CREATE TABLE python_unit_summary_spellings(
 summary_id INTEGER NOT NULL,
 module_name TEXT NOT NULL CHECK(length(module_name)>0),
 source_root TEXT NOT NULL,
 target_container TEXT NOT NULL,
 admitted INTEGER NOT NULL CHECK(admitted IN (0,1)),
 PRIMARY KEY(summary_id,module_name,source_root,target_container),
 FOREIGN KEY(summary_id,target_container)
  REFERENCES python_unit_summary_providers(summary_id,container_path) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX python_unit_summary_spellings_target
 ON python_unit_summary_spellings(summary_id,target_container,module_name,source_root);

-- Source-owned surviving extensions, evaluated once per parsed blob. Paths are
-- relative to the initializer directory; staging supplies the selected mount.
CREATE TABLE python_package_path_extensions(
 blob_id INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 directory TEXT NOT NULL CHECK(length(directory)>0),
 PRIMARY KEY(blob_id,ordinal)
) WITHOUT ROWID, STRICT;
