-- Distinguish source-inventory placement from Go-tool-selected package
-- authority, and retain the parsed presence of leading build-constraint
-- comments so only affected source packages remain incomplete.
ALTER TABLE go_package_instances ADD COLUMN provider_provenance TEXT NOT NULL
  DEFAULT 'go_tool' CHECK(provider_provenance IN ('go_tool', 'source_inventory'));

ALTER TABLE source_go_manifests ADD COLUMN has_build_constraints INTEGER NOT NULL
  DEFAULT 0 CHECK(has_build_constraints IN (0, 1));

ALTER TABLE source_go_manifests ADD COLUMN build_selection_facts_version INTEGER NOT NULL
  DEFAULT 0 CHECK(build_selection_facts_version IN (0, 1));
