-- Test-support caches contain format-7 Python source rows that do not retain
-- export policies, export operations/members, or the complete import route.
-- Delete every source marker: ON DELETE CASCADE removes its python_binding_*
-- and python_member_* dependents. Shared per-blob resolution_* source rows
-- are not removed.
-- New publication must supply the missing facts; defaults would invent them.
-- NATIVE_SOURCE_FORMAT remains 7 until #6108 admits production Python once.
-- Also invalidate all Python summaries and their selection intervals: environment
-- roots/providers/surfaces/export names/imports were derived from format-7 facts.
-- Non-cascading python_* audit (pragma_foreign_key_list, schema 208):
-- python_unit_summary_{export_names,imports,providers,roots,surfaces}: removed
-- through resolution_unit_summaries below, including shared summary children.
-- python_runtime_{acquisitions,environments,artifacts,artifact_members,
-- declared_environments,declared_extras,declared_inputs,declared_roots,
-- import_providers,scope_frontiers}: independent checked-runtime acquisition
-- inputs, written by publish_python_runtime_providers from supplied evidence;
-- never derived from binding facts or unit summaries, so preserved.
DELETE FROM resolution_unit_summary_versions WHERE summary_id IN
 (SELECT summary_id FROM resolution_unit_summaries WHERE lang='python');
DELETE FROM resolution_unit_summaries WHERE lang='python';

-- NOT NULL columns without defaults require empty tables; keep DELETE before ALTER.
DELETE FROM python_binding_source;

ALTER TABLE python_binding_source ADD COLUMN
 export_curated INTEGER NOT NULL -- 0=Absent, 1=Listed, 2=Unreadable.
 CHECK(export_curated BETWEEN 0 AND 2);
ALTER TABLE python_binding_source ADD COLUMN
 export_wildcard INTEGER NOT NULL -- 0=PublicNames, 1=Curated, 2=Unknown.
 CHECK(export_wildcard BETWEEN 0 AND 2);

-- route is an array of segment spellings in ordinal order: the first
-- module_segments entries are module segments; From adds its member last.
ALTER TABLE python_binding_imports ADD COLUMN
 route BLOB NOT NULL CHECK(json_valid(route, 8) AND json_type(route) = 'array');

CREATE TABLE python_binding_export_operations(
 blob_id INTEGER NOT NULL,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 -- kind: 0=ReplaceList, 1=ReplaceTuple, 2=AugmentList, 3=AugmentTuple,
 -- 4=Extend, 5=Append, 6=Delete, 7=Unknown.
 kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 7),
 readable INTEGER NOT NULL CHECK(readable IN (0,1)),
 -- members is an array of name spellings in member ordinal order.
 members BLOB NOT NULL CHECK(json_valid(members, 8) AND json_type(members) = 'array'),
 PRIMARY KEY(blob_id,ordinal),
 FOREIGN KEY(blob_id) REFERENCES python_binding_source(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
