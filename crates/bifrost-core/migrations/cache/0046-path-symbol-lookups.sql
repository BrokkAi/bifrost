-- Index the path-derived module rows by the names their lookups actually use,
-- and move the JavaScript/TypeScript import gate out of the view SQL.
--
-- A path-derived module unit is a declaration the analyzer invents for a file
-- whose module name comes from its path rather than from anything written in
-- the file: `pkg/service.py` is the module `pkg.service` although no line in it
-- says so. Python, JavaScript, and TypeScript have them; the languages that
-- write their package identity into the file text do not.
--
-- `workspace_file_path_symbol_rows` was indexed only on `exact_fqn` and
-- `normalized_fqn`, but the definition-lookup views map `identifier` onto
-- `short_name` and `exact_parent_tail` onto `package_name`. Every exact-name,
-- structural-children, structural-members, identifier, and package-types
-- question therefore had no index to seek, and the planner drove the whole arm
-- from `idx_workspace_file_versions_snapshot_blob` on (workspace, lang,
-- generation), which is every live file of the language, once per request. The
-- two new indexes give those shapes the seek they were missing:
-- `_short` serves the identifier and structural shapes, and `_package` serves
-- the ones that also bind the package.
--
-- `requires_imports` records, per row, whether the row only counts when its
-- file has at least one import statement. The old `workspace_path_symbols` view
-- decided that by naming 'javascript', 'typescript:ts', and 'typescript:tsx' in
-- SQL, which duplicated the adapter hook
-- `path_synthetic_module_requires_imports()` as three string literals in the
-- schema. The flag is a static property of the language's adapter, so storing
-- it on the row it applies to is exact and keeps the language names out of the
-- view. The backfill below names those three language keys once, which is
-- acceptable here because a migration is history rather than an interface:
-- rows written after this migration carry what the adapter said.
ALTER TABLE workspace_file_path_symbol_rows
  ADD COLUMN requires_imports INTEGER NOT NULL DEFAULT 0
    CHECK(requires_imports IN (0, 1));

UPDATE workspace_file_path_symbol_rows
   SET requires_imports = 1
 WHERE file_version_id IN (
   SELECT file_version_id FROM workspace_file_versions
   WHERE lang IN ('javascript', 'typescript:ts', 'typescript:tsx')
 );

CREATE INDEX idx_workspace_file_path_symbol_rows_short
  ON workspace_file_path_symbol_rows(short_name, file_version_id);

CREATE INDEX idx_workspace_file_path_symbol_rows_package
  ON workspace_file_path_symbol_rows(package_name, short_name, file_version_id);
