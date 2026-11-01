CREATE TABLE csharp_compilation_members (
 workspace_id TEXT NOT NULL, lang TEXT NOT NULL DEFAULT 'csharp' CHECK(lang='csharp'),
 generation INTEGER NOT NULL CHECK(generation>=0),
 compilation_id INTEGER NOT NULL REFERENCES csharp_compilations(compilation_id) ON DELETE CASCADE,
 rel_path TEXT NOT NULL CHECK(length(rel_path)>0),
 file_version_id INTEGER NOT NULL REFERENCES workspace_file_versions(file_version_id) ON DELETE CASCADE,
 valid_from INTEGER NOT NULL CHECK(valid_from>0),
 valid_until INTEGER CHECK(valid_until>valid_from),
 PRIMARY KEY(workspace_id,compilation_id,rel_path,valid_from),
 FOREIGN KEY(workspace_id,lang,generation,valid_from)
  REFERENCES workspace_revisions(workspace_id,lang,generation,revision) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- Path edits; per-compilation counts; FK parent deletion probes, respectively.
CREATE INDEX idx_csharp_members_path ON csharp_compilation_members(workspace_id,rel_path);
CREATE INDEX idx_csharp_members_snapshot ON csharp_compilation_members
 (workspace_id,lang,generation,compilation_id,valid_from,valid_until,file_version_id);
CREATE INDEX idx_csharp_members_file ON csharp_compilation_members(file_version_id);
CREATE INDEX idx_csharp_members_compilation ON csharp_compilation_members(compilation_id);
CREATE TABLE csharp_global_using_extent (
 workspace_id TEXT NOT NULL, lang TEXT NOT NULL DEFAULT 'csharp' CHECK(lang='csharp'),
 generation INTEGER NOT NULL CHECK(generation>=0),
 compilation_id INTEGER NOT NULL REFERENCES csharp_compilations(compilation_id) ON DELETE CASCADE,
 rel_path TEXT NOT NULL CHECK(length(rel_path)>0), blob_id INTEGER NOT NULL,
 import_site INTEGER NOT NULL CHECK(import_site BETWEEN 0 AND 4294967295),
 valid_from INTEGER NOT NULL CHECK(valid_from>0),
 valid_until INTEGER CHECK(valid_until>valid_from),
 PRIMARY KEY(workspace_id,compilation_id,valid_from,rel_path,import_site),
 FOREIGN KEY(blob_id,import_site) REFERENCES resolution_root_imports(blob_id,import_site) ON DELETE NO ACTION,
 FOREIGN KEY(workspace_id,lang,generation,valid_from)
  REFERENCES workspace_revisions(workspace_id,lang,generation,revision) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- Snapshot seek covers site hydration; path edit and FK probes follow.
CREATE INDEX idx_csharp_globals_snapshot ON csharp_global_using_extent
 (workspace_id,lang,generation,compilation_id,valid_from,valid_until,blob_id,import_site,rel_path);
CREATE INDEX idx_csharp_globals_path ON csharp_global_using_extent(workspace_id,rel_path);
CREATE INDEX idx_csharp_globals_import ON csharp_global_using_extent(blob_id,import_site);
CREATE INDEX idx_csharp_globals_compilation ON csharp_global_using_extent(compilation_id);
CREATE TABLE csharp_compilation_using_coverage (
 workspace_id TEXT NOT NULL, lang TEXT NOT NULL DEFAULT 'csharp' CHECK(lang='csharp'),
 generation INTEGER NOT NULL CHECK(generation>=0),
 compilation_id INTEGER NOT NULL REFERENCES csharp_compilations(compilation_id) ON DELETE CASCADE,
 valid_from INTEGER NOT NULL CHECK(valid_from>0),
 valid_until INTEGER CHECK(valid_until>valid_from),
 membership_complete INTEGER NOT NULL CHECK(membership_complete IN (0,1)),
 publications_expected INTEGER NOT NULL CHECK(publications_expected>=0),
 publications_installed INTEGER NOT NULL CHECK(publications_installed BETWEEN 0 AND publications_expected),
 metadata_complete INTEGER NOT NULL CHECK(metadata_complete IN (0,1)),
 -- JSONB array of diagnostic objects; no identities requiring relational constraints.
 reasons BLOB NOT NULL CHECK(json_valid(reasons,8) AND json_type(reasons)='array'),
 PRIMARY KEY(workspace_id,compilation_id,valid_from),
 FOREIGN KEY(workspace_id,lang,generation,valid_from)
  REFERENCES workspace_revisions(workspace_id,lang,generation,revision) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX idx_csharp_coverage_compilation ON csharp_compilation_using_coverage(compilation_id);

-- Applied publication transitions, including complete sources with no directives.
CREATE TABLE csharp_using_publications (
 blob_id INTEGER PRIMARY KEY REFERENCES blobs(id) ON DELETE NO ACTION,
 producer_epoch TEXT NOT NULL
) STRICT;
