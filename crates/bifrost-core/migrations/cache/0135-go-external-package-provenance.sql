-- Keep the Go tool's provider kind and top-level module coordinate queryable
-- for selected source-less external package identities.
ALTER TABLE go_package_instances ADD COLUMN provider_kind TEXT NOT NULL
  DEFAULT 'workspace' CHECK(provider_kind IN ('workspace', 'standard', 'module'));
ALTER TABLE go_package_instances ADD COLUMN provider_module_path TEXT;
ALTER TABLE go_package_instances ADD COLUMN provider_module_version TEXT;
