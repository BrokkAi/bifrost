-- #11570: replace derived equality counters and labels with raw lever identities.

-- Clear descendants explicitly, including NO ACTION edges, with FK enforcement on or off.

DELETE FROM csharp_compilation_items;

DELETE FROM csharp_compilation_members;

DELETE FROM csharp_compilation_selections;

DELETE FROM csharp_compilation_symbols;

DELETE FROM csharp_compilation_using_coverage;

DELETE FROM csharp_global_using_extent;

DELETE FROM csharp_project_references;

DELETE FROM go_context_domain_modules;

DELETE FROM go_package_files;

DELETE FROM go_package_imports;

DELETE FROM jvm_context_gaps;

DELETE FROM jvm_direct_dependencies;

DELETE FROM jvm_external_provider_publications;

DELETE FROM jvm_source_root_files;

DELETE FROM python_unit_summary_export_names;

DELETE FROM python_unit_summary_imports;

DELETE FROM python_unit_summary_spellings;

DELETE FROM resolution_unit_summary_consumed_units;

DELETE FROM resolution_unit_summary_dependency_names;

DELETE FROM resolution_unit_summary_exports;

DELETE FROM resolution_unit_summary_gaps;

DELETE FROM resolution_unit_summary_imports;

DELETE FROM resolution_unit_summary_reads;

DELETE FROM rust_crate_reconciliations;

DELETE FROM rust_resolution_unit_summary_binding_alternatives;

DELETE FROM rust_resolution_unit_summary_binding_blockers;

DELETE FROM rust_resolution_unit_summary_binding_completeness;

DELETE FROM rust_resolution_unit_summary_contexts;

DELETE FROM rust_resolution_unit_summary_effective_bindings;

DELETE FROM rust_resolution_unit_summary_exports;

DELETE FROM rust_resolution_unit_summary_file_naming;

DELETE FROM rust_resolution_unit_summary_gaps;

DELETE FROM rust_resolution_unit_summary_generated_names;

DELETE FROM rust_resolution_unit_summary_glob_imports;

DELETE FROM rust_resolution_unit_summary_glob_reexport_routes;

DELETE FROM rust_resolution_unit_summary_import_route_provenance;

DELETE FROM rust_resolution_unit_summary_import_routes;

DELETE FROM rust_resolution_unit_summary_inactive_placements;

DELETE FROM rust_resolution_unit_summary_inherent_impls;

DELETE FROM rust_resolution_unit_summary_macro_decisions;

DELETE FROM rust_resolution_unit_summary_public_surface_gaps;

DELETE FROM rust_resolution_unit_summary_reexport_routes;

DELETE FROM rust_resolution_unit_summary_root_routes;

DELETE FROM rust_resolution_unit_summary_trait_endpoints;

DELETE FROM rust_resolution_unit_summary_unresolved_inherent_impls;

DELETE FROM rust_resolution_unit_summary_versions;

DELETE FROM rust_source_listing_failures;

DELETE FROM csharp_compilations;

DELETE FROM go_package_instances;

DELETE FROM jvm_source_roots;

DELETE FROM python_unit_summary_surfaces;

DELETE FROM resolution_unit_summary_dependencies;

DELETE FROM resolution_unit_summary_input_files;

DELETE FROM resolution_unit_summary_versions;

DELETE FROM rust_resolution_unit_summary_binding_names;

DELETE FROM rust_resolution_unit_summary_container_attributes;

DELETE FROM rust_resolution_unit_summary_placement_attributes;

DELETE FROM rust_source_listing_certificates;

DELETE FROM csharp_compilation_sets;

DELETE FROM go_context_publications;

DELETE FROM jvm_projects;

DELETE FROM python_unit_summary_providers;

DELETE FROM resolution_unit_summary_placements;

DELETE FROM rust_resolution_unit_summary_binding_owners;

DELETE FROM go_context_selections;

DELETE FROM jvm_context_revisions;

DELETE FROM python_unit_summary_roots;

DELETE FROM resolution_unit_summary_containers;

DELETE FROM resolution_unit_summary_members;

DELETE FROM resolution_unit_summaries;

DROP TABLE csharp_compilation_sets;

CREATE TABLE "csharp_compilation_sets" (
    set_id INTEGER PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    lang TEXT NOT NULL CHECK(lang = 'csharp'),
    generation INTEGER NOT NULL,
    derivation_identity BLOB NOT NULL CHECK(typeof(derivation_identity)='blob' AND length(derivation_identity)=32),
    input_digest BLOB NOT NULL CHECK(length(input_digest) = 32),
    -- Digest of the rule rows below, for early cutoff by dependents.
    output_digest BLOB NOT NULL CHECK(length(output_digest) = 32),
    -- Positional [code, path, evidence] triples; read whole for diagnostics.
    gaps BLOB NOT NULL CHECK(json_valid(gaps, 8)),
    UNIQUE(workspace_id, lang, generation, derivation_identity, input_digest)
);

DROP TABLE go_context_selections;

CREATE TABLE go_context_selections (
  selection_id INTEGER PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'go'),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  base_profile_digest BLOB NOT NULL CHECK(length(base_profile_digest) = 32),
  domain_dir TEXT NOT NULL,
  gowork_path TEXT NOT NULL,
  profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
  derivation_identity BLOB NOT NULL CHECK(typeof(derivation_identity)='blob' AND length(derivation_identity)=32),
  UNIQUE(workspace_id, lang, generation, base_profile_digest, domain_dir, gowork_path, derivation_identity)
) STRICT;

CREATE INDEX go_context_selections_profile ON go_context_selections(profile_digest);

DROP TABLE jvm_context_revisions;

CREATE TABLE jvm_context_revisions (
  context_id INTEGER PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang IN ('java', 'kotlin', 'scala')),
  generation INTEGER NOT NULL CHECK(generation >= 0),
  revision INTEGER NOT NULL CHECK(revision > 0),
  derivation_identity BLOB NOT NULL CHECK(typeof(derivation_identity)='blob' AND length(derivation_identity)=32),
  UNIQUE(workspace_id, lang, generation, revision, derivation_identity),
  FOREIGN KEY(workspace_id, lang, generation, revision)
    REFERENCES workspace_revisions(workspace_id, lang, generation, revision) ON DELETE CASCADE
) STRICT;

DROP TABLE resolution_unit_summaries;

CREATE TABLE resolution_unit_summaries (
  summary_id          INTEGER PRIMARY KEY,
  lang                TEXT NOT NULL CHECK(length(lang) > 0),
  unit_kind           TEXT NOT NULL CHECK(unit_kind IN ('go_package', 'rust_crate', 'jvm_source_set', 'python_environment')),
  unit_key            BLOB NOT NULL CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32),
  summary_digest      BLOB NOT NULL UNIQUE
    CHECK(typeof(summary_digest) = 'blob' AND length(summary_digest) = 32),
  producer_epoch      TEXT NOT NULL CHECK(length(producer_epoch) > 0),
  derivation_identity BLOB NOT NULL CHECK(typeof(derivation_identity)='blob' AND length(derivation_identity)=32),
  complete            INTEGER NOT NULL CHECK(complete IN (0, 1)),
  member_count        INTEGER NOT NULL DEFAULT 0 CHECK(member_count >= 0),
  export_count        INTEGER NOT NULL DEFAULT 0 CHECK(export_count >= 0),
  import_count        INTEGER NOT NULL DEFAULT 0 CHECK(import_count >= 0),
  output_digest       BLOB
    CHECK(output_digest IS NULL OR (typeof(output_digest) = 'blob' AND length(output_digest) = 32)),
  publication_state   TEXT NOT NULL CHECK(publication_state IN ('building', 'complete')), lookup_digest BLOB NOT NULL
  DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
  CHECK(typeof(lookup_digest) = 'blob' AND length(lookup_digest) = 32),
  CHECK((publication_state = 'complete') = (output_digest IS NOT NULL))
) STRICT;

CREATE INDEX resolution_unit_summaries_lookup
  ON resolution_unit_summaries(lookup_digest);

DROP TABLE rust_source_listing_certificates;

CREATE TABLE rust_source_listing_certificates (
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'rust'),
  generation INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  derivation_identity BLOB NOT NULL CHECK(typeof(derivation_identity)='blob' AND length(derivation_identity)=32),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  PRIMARY KEY(workspace_id,lang,generation,revision),
  FOREIGN KEY(workspace_id,lang,generation,revision)
    REFERENCES workspace_revisions(workspace_id,lang,generation,revision) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

DROP TABLE jvm_external_provider_publications;

CREATE TABLE jvm_external_provider_publications (
    provider_id TEXT PRIMARY KEY NOT NULL,
    source_identity TEXT NOT NULL,
    projection_identity BLOB NOT NULL CHECK(typeof(projection_identity)='blob' AND length(projection_identity)=32),
    projected_rows_sha256 BLOB NOT NULL CHECK(length(projected_rows_sha256) = 32),
    owner_count INTEGER NOT NULL CHECK(owner_count >= 0),
    member_count INTEGER NOT NULL CHECK(member_count >= 0),
    supertype_count INTEGER NOT NULL CHECK(supertype_count >= 0)
) WITHOUT ROWID, STRICT;

CREATE TRIGGER jvm_external_provider_publications_no_update_after_seal
BEFORE UPDATE ON jvm_external_provider_publications
BEGIN SELECT RAISE(ABORT, 'sealed JVM provider certificate is immutable'); END;

DROP TABLE rust_crate_reconciliations;

CREATE TABLE rust_crate_reconciliations(
  workspace_id        TEXT NOT NULL CHECK(length(workspace_id) = 64),
  generation          INTEGER NOT NULL CHECK(generation >= 0),
  revision            INTEGER NOT NULL CHECK(revision > 0),
  derivation_identity BLOB NOT NULL CHECK(typeof(derivation_identity)='blob' AND length(derivation_identity)=32),
  PRIMARY KEY(workspace_id, generation)
) WITHOUT ROWID, STRICT;
