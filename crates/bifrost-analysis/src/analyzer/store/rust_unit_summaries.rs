//! Rust crate definition for the shared per-unit resolution summary.
//!
//! The topology tables remain Rust-owned. Their crate key is also the shared
//! summary unit key, which makes rust_crate_versions the crosswalk from a
//! summary version to its topology row.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
#[cfg(any(test, feature = "test-support"))]
use std::fmt::Debug;

use rusqlite::{Connection, OptionalExtension, params};

use super::unit_summaries::{
    ConsumedDependency, UnitDependency, UnitExport, UnitGap, UnitImport, UnitInputs, UnitMember,
    UnitOutputs, UnitRead, UnitSummaryLanguage,
};
use super::{AnalyzerStore, Result, StoreError, WorkspaceSnapshotId, WorkspaceSnapshots};
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::analyzer::store::resolution_prepare::resolution_rows::{language_code, namespace_code};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::rust_facts::decode_rust_visibility;
use brokk_bifrost_rust::imports::{
    resolve_rust_module_path_with_crate, resolve_rust_module_segments_with_crate,
};
use brokk_bifrost_rust::usage::{
    Domain as RustBindingDomain, ModuleKey as RustModuleKey, RustPathIdentity,
    direct_import_scope_for_module_with_identity,
};

/// Bump when the Rust summary's normalized rows or read set changes.
pub(crate) const RUST_UNIT_SUMMARY_DERIVATION_VERSION: i64 = 13;

pub(crate) const IMPORTING_FILES_FOR_MEMBER_SQL: &str = r#"
WITH target_declarations AS (
  SELECT target_unit.unit_key, target_export.module_path, target_export.namespace,
         target_export.name
  FROM main.blobs AS target_blob INDEXED BY sqlite_autoindex_blobs_1
  CROSS JOIN main.resolution_unit_summary_members AS target_member
    INDEXED BY resolution_unit_summary_members_blob
    ON target_member.blob_id = target_blob.id AND target_member.rel_path = ?2
  CROSS JOIN selected_rust_unit_summary_route_owners AS target_unit
    ON target_unit.summary_id = target_member.summary_id
  CROSS JOIN main.rust_resolution_unit_summary_exports AS target_export
    INDEXED BY rust_resolution_unit_summary_exports_declaration
    ON target_export.summary_id = target_member.summary_id
   AND target_export.declaration_member_ordinal = target_member.member_ordinal
   AND target_export.origin = 'declaration'
  WHERE target_blob.blob_oid = ?1 AND target_blob.lang = 'rust'
)
SELECT DISTINCT importer_member.rel_path
  FROM target_declarations AS target
  CROSS JOIN main.rust_resolution_unit_summary_import_routes AS route
    INDEXED BY rust_resolution_unit_summary_import_routes_target_identity
    ON route.target_unit_key = target.unit_key
   AND route.target_module_path = target.module_path
   AND route.target_name = target.name
   AND route.namespace = target.namespace
  CROSS JOIN selected_rust_unit_summary_route_owners AS importer_unit
    ON importer_unit.summary_id = route.summary_id
  CROSS JOIN main.resolution_unit_summary_members AS importer_member
    ON importer_member.summary_id = route.summary_id
   AND importer_member.member_ordinal = route.member_ordinal
"#;

// Direct named imports also exist without a Cargo module placement. Match
// their AST-owned segments against the selected path naming, just as the
// forward imported-code-unit reader does. Summary route rows alone cannot
// represent a `crate::` import between independently detached files.
const DIRECT_IMPORTERS_FOR_MEMBER_SQL: &str = r#"
WITH target_names AS (
  SELECT DISTINCT json_extract(name.value, '$[0]') AS short_name,
                  json_extract(name.value, '$[1]') AS exact_fqn
  FROM json_each(?3) AS name
  WHERE EXISTS (
    SELECT 1 FROM selected_workspace_file_versions AS files
    WHERE files.lang = 'rust' AND files.blob_oid = ?1 AND files.rel_path = ?2
  )
)
SELECT DISTINCT importer.rel_path, json(naming.package_components),
       json(naming.root_components), target.owner_module,
       json((SELECT json_group_array(segment.segment) FROM (
         SELECT segment FROM main.source_import_segments
         WHERE blob_id = source.blob_id AND import_id = source.import_id
         ORDER BY ordinal
       ) AS segment)), names.exact_fqn
FROM target_names AS names
CROSS JOIN main.source_imports AS source INDEXED BY idx_source_imports_identifier
  ON source.identifier = names.short_name AND source.is_wildcard = 0
CROSS JOIN main.source_rust_import_targets AS target
  ON target.blob_id = source.blob_id AND target.source_import_id = source.import_id
CROSS JOIN selected_rust_import_graph_members AS importer
  ON importer.blob_id = source.blob_id
CROSS JOIN main.rust_resolution_unit_summary_file_naming AS naming
  ON naming.summary_id = importer.summary_id
 AND naming.member_ordinal = importer.member_ordinal
WHERE target.is_extern_crate = 0
"#;

pub(crate) const DEVELOPMENT_CAPABILITY_SQL: &str = r#"
SELECT topologies.target_kind, topologies.crate_name,
       versions.manifest_file_version_id, inputs.source_bytes
FROM rust_crate_topologies AS topologies
JOIN rust_crate_versions AS versions INDEXED BY rust_crate_versions_topology
  ON versions.topology_id = topologies.topology_id
 AND versions.workspace_id = ?1 AND versions.lang = 'rust'
 AND versions.generation = ?2 AND versions.valid_from <= ?3
 AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
LEFT JOIN workspace_file_versions AS manifest
  ON manifest.file_version_id = versions.manifest_file_version_id
LEFT JOIN workspace_input_sources AS inputs
  ON inputs.content_oid = manifest.blob_oid
WHERE topologies.topology_id = ?4
"#;

pub(crate) const PACKAGE_ROWS_SQL: &str = r#"
WITH selected_units AS (
  SELECT versions.workspace_id, versions.generation, versions.summary_id,
         versions.unit_key
  FROM temp.selected_workspace_revisions AS selected
  CROSS JOIN main.resolution_unit_summary_versions AS versions
    ON versions.workspace_id = selected.workspace_id
   AND versions.lang = selected.lang
   AND versions.generation = selected.generation
  CROSS JOIN main.resolution_unit_summaries AS summaries
    ON summaries.summary_id = versions.summary_id
  CROSS JOIN main.resolution_producer_epochs AS epochs
    ON epochs.lang = versions.lang
   AND epochs.producer_epoch = summaries.producer_epoch
  CROSS JOIN main.rust_resolution_unit_summary_versions AS rust_versions
    ON rust_versions.workspace_id = versions.workspace_id
   AND rust_versions.lang = versions.lang
   AND rust_versions.generation = versions.generation
   AND rust_versions.unit_key = versions.unit_key
   AND rust_versions.valid_from = versions.valid_from
   AND rust_versions.summary_id = versions.summary_id
  WHERE selected.lang = 'rust'
    AND versions.valid_from <= selected.revision
    AND (versions.valid_until IS NULL OR selected.revision < versions.valid_until)
    AND summaries.lang = 'rust'
    AND summaries.unit_kind = 'rust_crate'
    AND summaries.publication_state = 'complete'
    AND summaries.derivation_version = ?1
)
SELECT members.rel_path, json(naming.package_components), contexts.crate_name,
       contexts.target_kind, blobs.blob_oid,
       EXISTS (
         SELECT 1 FROM main.rust_resolution_unit_summary_placements AS root
         WHERE root.summary_id = members.summary_id
           AND root.member_ordinal = members.member_ordinal
           AND root.module_path = 'crate'
       )
FROM selected_units AS units
JOIN main.resolution_unit_summary_members AS members
  ON members.summary_id = units.summary_id
JOIN temp.selected_workspace_file_versions AS files
  ON files.workspace_id = units.workspace_id
 AND files.lang = 'rust'
 AND files.generation = units.generation
 AND files.rel_path = members.rel_path
JOIN main.blobs AS blobs
  ON blobs.id = members.blob_id
 AND blobs.blob_oid = files.blob_oid
 AND blobs.lang = files.lang
 AND blobs.generation = files.generation
LEFT JOIN main.rust_resolution_unit_summary_contexts AS contexts
  ON contexts.summary_id = members.summary_id
LEFT JOIN main.rust_resolution_unit_summary_file_naming AS naming
  ON naming.summary_id = members.summary_id
 AND naming.member_ordinal = members.member_ordinal
"#;

pub(crate) const CARGO_ROUTE_ROWS_SQL: &str = r#"
WITH selected_units AS (
  SELECT versions.workspace_id, versions.generation, selected.revision,
         versions.summary_id, versions.unit_key,
         rust_versions.manifest_file_version_id
  FROM temp.selected_workspace_revisions AS selected
  CROSS JOIN main.resolution_unit_summary_versions AS versions
    ON versions.workspace_id = selected.workspace_id
   AND versions.lang = selected.lang
   AND versions.generation = selected.generation
  CROSS JOIN main.resolution_unit_summaries AS summaries
    ON summaries.summary_id = versions.summary_id
  CROSS JOIN main.resolution_producer_epochs AS epochs
    ON epochs.lang = versions.lang
   AND epochs.producer_epoch = summaries.producer_epoch
  CROSS JOIN main.rust_resolution_unit_summary_versions AS rust_versions
    ON rust_versions.workspace_id = versions.workspace_id
   AND rust_versions.lang = versions.lang
   AND rust_versions.generation = versions.generation
   AND rust_versions.unit_key = versions.unit_key
   AND rust_versions.valid_from = versions.valid_from
   AND rust_versions.summary_id = versions.summary_id
  WHERE selected.lang = 'rust'
    AND versions.valid_from <= selected.revision
    AND (versions.valid_until IS NULL OR selected.revision < versions.valid_until)
    AND summaries.lang = 'rust'
    AND summaries.unit_kind = 'rust_crate'
    AND summaries.derivation_version = ?1
    AND summaries.publication_state = 'complete'
)
SELECT parent.unit_key, parent_manifest.rel_path,
       parent_context.target_kind, parent_context.crate_name, parent_context.edition,
       parent_context.development_capable,
       CASE WHEN parent_blob.id IS NOT NULL THEN parent_member.rel_path END,
       json(parent_naming.root_components),
       dependency_names.extern_name, dependency_names.dependency_kind,
       dependencies.boundary, dependencies.dependency_unit_key,
       child_context.target_kind,
       CASE WHEN child_blob.id IS NOT NULL THEN child_member.rel_path END,
       json(child_naming.root_components),
       child_manifest.rel_path
FROM selected_units AS parent
JOIN main.rust_resolution_unit_summary_contexts AS parent_context
  ON parent_context.summary_id = parent.summary_id
LEFT JOIN main.workspace_file_versions AS parent_manifest
  ON parent_manifest.file_version_id = parent.manifest_file_version_id
LEFT JOIN main.rust_resolution_unit_summary_placements AS parent_placement
  ON parent_placement.summary_id = parent.summary_id
 AND parent_placement.module_path = 'crate'
LEFT JOIN main.resolution_unit_summary_members AS parent_member
  ON parent_member.summary_id = parent_placement.summary_id
 AND parent_member.member_ordinal = parent_placement.member_ordinal
LEFT JOIN main.workspace_file_versions AS parent_file
  ON parent_file.workspace_id = parent.workspace_id
 AND parent_file.lang = 'rust'
 AND parent_file.generation = parent.generation
 AND parent_file.input_kind = 'source'
 AND parent_file.valid_from <= parent.revision
 AND (parent_file.valid_until IS NULL OR parent.revision < parent_file.valid_until)
 AND parent_file.rel_path = parent_member.rel_path
LEFT JOIN main.blobs AS parent_blob
  ON parent_blob.id = parent_member.blob_id
 AND parent_blob.blob_oid = parent_file.blob_oid
 AND parent_blob.lang = parent_file.lang
 AND parent_blob.generation = parent_file.generation
LEFT JOIN main.rust_resolution_unit_summary_file_naming AS parent_naming
  ON parent_naming.summary_id = parent_member.summary_id
 AND parent_naming.member_ordinal = parent_member.member_ordinal
LEFT JOIN main.resolution_unit_summary_dependencies AS dependencies
  ON dependencies.summary_id = parent.summary_id
LEFT JOIN main.rust_resolution_unit_summary_dependency_names AS dependency_names
  INDEXED BY rust_resolution_unit_summary_dependency_names_ordinal
  ON dependency_names.summary_id = dependencies.summary_id
 AND dependency_names.dependency_ordinal = dependencies.dependency_ordinal
LEFT JOIN main.resolution_unit_summary_versions AS child_versions
  ON dependencies.boundary = 'workspace'
 AND child_versions.workspace_id = parent.workspace_id
 AND child_versions.lang = 'rust'
 AND child_versions.generation = parent.generation
 AND child_versions.unit_key = dependencies.dependency_unit_key
 AND child_versions.valid_from <= parent.revision
 AND (child_versions.valid_until IS NULL OR parent.revision < child_versions.valid_until)
LEFT JOIN main.resolution_unit_summaries AS child_summaries
  ON child_summaries.summary_id = child_versions.summary_id
 AND child_summaries.lang = 'rust'
 AND child_summaries.unit_kind = 'rust_crate'
 AND child_summaries.derivation_version = ?1
 AND child_summaries.publication_state = 'complete'
LEFT JOIN main.resolution_producer_epochs AS child_epochs
  ON child_epochs.lang = child_versions.lang
 AND child_epochs.producer_epoch = child_summaries.producer_epoch
LEFT JOIN main.rust_resolution_unit_summary_versions AS child_rust_versions
  ON child_rust_versions.workspace_id = child_versions.workspace_id
 AND child_rust_versions.lang = child_versions.lang
 AND child_rust_versions.generation = child_versions.generation
 AND child_rust_versions.unit_key = child_versions.unit_key
 AND child_rust_versions.valid_from = child_versions.valid_from
 AND child_rust_versions.summary_id = child_versions.summary_id
 AND child_epochs.lang IS NOT NULL
LEFT JOIN main.rust_resolution_unit_summary_contexts AS child_context
  ON child_context.summary_id = child_rust_versions.summary_id
LEFT JOIN main.workspace_file_versions AS child_manifest
  ON child_manifest.file_version_id = child_rust_versions.manifest_file_version_id
LEFT JOIN main.rust_resolution_unit_summary_placements AS child_placement
  ON child_placement.summary_id = child_rust_versions.summary_id
 AND child_placement.module_path = 'crate'
LEFT JOIN main.resolution_unit_summary_members AS child_member
  ON child_member.summary_id = child_placement.summary_id
 AND child_member.member_ordinal = child_placement.member_ordinal
LEFT JOIN main.workspace_file_versions AS child_file
  ON child_file.workspace_id = parent.workspace_id
 AND child_file.lang = 'rust'
 AND child_file.generation = parent.generation
 AND child_file.input_kind = 'source'
 AND child_file.valid_from <= parent.revision
 AND (child_file.valid_until IS NULL OR parent.revision < child_file.valid_until)
 AND child_file.rel_path = child_member.rel_path
LEFT JOIN main.blobs AS child_blob
  ON child_blob.id = child_member.blob_id
 AND child_blob.blob_oid = child_file.blob_oid
 AND child_blob.lang = child_file.lang
 AND child_blob.generation = child_file.generation
LEFT JOIN main.rust_resolution_unit_summary_file_naming AS child_naming
  ON child_naming.summary_id = child_member.summary_id
 AND child_naming.member_ordinal = child_member.member_ordinal
"#;

// A file can cease to be detached when a module declaration places it in a
// Cargo target. The scoped topology pass may still carry its detached unit;
// import graph readers use the explicit placement whenever one is selected.
pub(crate) const RUST_IMPORT_GRAPH_MEMBER_SELECTION_SQL: &str = r#"
CREATE TEMP VIEW IF NOT EXISTS selected_rust_import_graph_members AS
SELECT member.* FROM selected_rust_unit_members AS member
CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id = member.summary_id
WHERE context.target_kind <> 'detached' OR NOT EXISTS (
  SELECT 1 FROM selected_rust_unit_members AS attached
  CROSS JOIN main.rust_resolution_unit_summary_contexts AS attached_context
    ON attached_context.summary_id = attached.summary_id
  WHERE attached.workspace_id = member.workspace_id
    AND attached.generation = member.generation
    AND attached.blob_id = member.blob_id AND attached.rel_path = member.rel_path
    AND attached_context.target_kind <> 'detached'
);
"#;

pub(crate) const RUST_SUMMARY_BINDING_SURFACES_SQL: &str = r#"WITH RECURSIVE
requested_members AS (
  SELECT members.summary_id, members.member_ordinal, members.rel_path,
         json(naming.root_components) AS root_components
  FROM selected_rust_import_graph_members AS members
  CROSS JOIN main.rust_resolution_unit_summary_file_naming AS naming
    ON naming.summary_id = members.summary_id
   AND naming.member_ordinal = members.member_ordinal
  WHERE members.rel_path IN (SELECT value FROM json_each(?1))
),
binding_roots AS (
  SELECT members.summary_id, members.member_ordinal, members.rel_path,
         members.root_components, bindings.route_provenance_ordinal,
         bindings.module_path, bindings.name, bindings.namespace,
         bindings.visibility_kind, bindings.visibility_crate_root,
         bindings.visibility_module_path, bindings.target_unit_key,
         bindings.target_identity_id, bindings.target_declaration_key,
         route_source.import_id AS source_import_id,
         route_source.import_ordinal AS source_import_ordinal,
         route_source.target_unit_key AS edge_target_unit_key,
         bindings.target_module_path, bindings.target_name,
         route_source.target_unit_key AS first_target_unit_key,
         route_source.target_binding_module_path AS first_target_module_path,
         route_source.target_binding_name AS first_target_name
  FROM requested_members AS members
  CROSS JOIN main.rust_resolution_unit_summary_effective_bindings AS bindings
    INDEXED BY rust_resolution_unit_summary_effective_bindings_member_name
    ON bindings.summary_id = members.summary_id
   AND bindings.member_ordinal = members.member_ordinal
  LEFT JOIN main.rust_resolution_unit_summary_import_route_provenance AS route_source
    INDEXED BY rust_resolution_unit_summary_import_route_provenance_binding
    ON route_source.summary_id = bindings.summary_id
   AND route_source.member_ordinal = bindings.member_ordinal
   AND route_source.route_provenance_ordinal = bindings.route_provenance_ordinal
   AND route_source.hop_ordinal = 0
),
-- A consumed unit can publish the same names while moving a re-export's
-- origin. Early cutoff then reuses its consumers. Follow the symbolic target
-- in the selected summaries rather than the consumer's old origin/ordinal.
origin_targets(root_summary_id, root_member_ordinal, root_route_ordinal,
               unit_key, module_path, name, namespace) AS (
  SELECT roots.summary_id, roots.member_ordinal, roots.route_provenance_ordinal,
         COALESCE(roots.first_target_unit_key, roots.target_unit_key),
         COALESCE(roots.first_target_module_path, roots.target_module_path),
         COALESCE(roots.first_target_name, roots.target_name), roots.namespace
  FROM binding_roots AS roots WHERE roots.target_identity_id IS NOT NULL
  UNION
  SELECT targets.root_summary_id, targets.root_member_ordinal,
         targets.root_route_ordinal, exports.target_unit_key,
         exports.target_module_path, exports.target_name, targets.namespace
  FROM origin_targets AS targets
  CROSS JOIN selected_rust_unit_summary_route_owners AS owner
    ON owner.unit_key = targets.unit_key
  CROSS JOIN main.rust_resolution_unit_summary_exports AS exports
    ON exports.summary_id = owner.summary_id
   AND exports.module_path = targets.module_path AND exports.name = targets.name
   AND exports.namespace = targets.namespace
  WHERE exports.origin <> 'declaration'
),
roots AS (
  SELECT roots.summary_id, roots.member_ordinal, members.rel_path,
         json(naming.root_components) AS root_components,
         roots.route_provenance_ordinal, roots.module_path, roots.name, roots.namespace,
         roots.visibility_kind, roots.visibility_crate_root,
         roots.visibility_module_path, targets.unit_key AS target_unit_key,
         exports.identity_id AS target_identity_id, roots.target_declaration_key,
         route_source.import_id AS source_import_id,
         route_source.import_ordinal AS source_import_ordinal,
         route_source.target_unit_key AS edge_target_unit_key,
         targets.module_path AS target_module_path, targets.name AS target_name
  FROM origin_targets AS targets
  CROSS JOIN main.rust_resolution_unit_summary_effective_bindings AS roots
    INDEXED BY rust_resolution_unit_summary_effective_bindings_route
    ON roots.summary_id = targets.root_summary_id
   AND roots.member_ordinal = targets.root_member_ordinal
   AND roots.route_provenance_ordinal = targets.root_route_ordinal
  CROSS JOIN selected_rust_import_graph_members AS members
    ON members.summary_id = roots.summary_id
   AND members.member_ordinal = roots.member_ordinal
  CROSS JOIN main.rust_resolution_unit_summary_file_naming AS naming
    ON naming.summary_id = members.summary_id
   AND naming.member_ordinal = members.member_ordinal
  LEFT JOIN main.rust_resolution_unit_summary_import_route_provenance AS route_source
    INDEXED BY rust_resolution_unit_summary_import_route_provenance_binding
    ON route_source.summary_id = roots.summary_id
   AND route_source.member_ordinal = roots.member_ordinal
   AND route_source.route_provenance_ordinal = roots.route_provenance_ordinal
   AND route_source.hop_ordinal = 0
  CROSS JOIN selected_rust_unit_summary_route_owners AS owner
    ON owner.unit_key = targets.unit_key
  CROSS JOIN main.rust_resolution_unit_summary_exports AS exports
    ON exports.summary_id = owner.summary_id
   AND exports.module_path = targets.module_path AND exports.name = targets.name
   AND exports.namespace = targets.namespace AND exports.origin = 'declaration'
  UNION ALL
  SELECT summary_id, member_ordinal, rel_path, root_components,
         route_provenance_ordinal, module_path, name, namespace,
         visibility_kind, visibility_crate_root, visibility_module_path,
         target_unit_key, target_identity_id, target_declaration_key,
         source_import_id, source_import_ordinal, edge_target_unit_key,
         target_module_path, target_name
  FROM binding_roots WHERE target_declaration_key IS NOT NULL
),
-- Drive both origin arms from requested roots. Reordering from historical
-- exports/placements would scan those tables and automatically index roots.
route_graph(root_summary_id, root_member_ordinal, root_route_ordinal,
            root_rel_path, root_module_path, root_name, root_namespace,
            root_visibility_kind, root_visibility_crate_root,
            root_visibility_module_path, root_target_module_path, root_target_name,
            root_components, origin_file, origin_root_components,
            summary_id, route_ordinal, route_name, route_file,
            root_source_import_id, root_source_import_ordinal,
            route_source_import_id, route_source_import_ordinal,
            edge_target_unit_key) AS (
  SELECT roots.summary_id, roots.member_ordinal, roots.route_provenance_ordinal,
         roots.rel_path, roots.module_path, roots.name, roots.namespace,
         roots.visibility_kind, roots.visibility_crate_root,
         roots.visibility_module_path, roots.target_module_path, roots.target_name,
         roots.root_components, origin_member.rel_path,
         json(origin_naming.root_components), roots.summary_id,
         roots.route_provenance_ordinal, roots.name, roots.rel_path,
         roots.source_import_id, roots.source_import_ordinal,
         roots.source_import_id, roots.source_import_ordinal,
         roots.edge_target_unit_key
  FROM roots
  CROSS JOIN selected_rust_unit_summary_route_owners AS origin_owner
    ON origin_owner.unit_key = roots.target_unit_key
  CROSS JOIN main.rust_resolution_unit_summary_exports AS origin_export
    ON origin_export.summary_id = origin_owner.summary_id
   AND origin_export.module_path = roots.target_module_path
   AND origin_export.namespace = roots.namespace
   AND origin_export.name = roots.target_name
   AND origin_export.identity_id = roots.target_identity_id
   AND origin_export.origin = 'declaration'
  CROSS JOIN main.resolution_unit_summary_members AS origin_member
    ON origin_member.summary_id = origin_export.summary_id
   AND origin_member.member_ordinal = origin_export.declaration_member_ordinal
  CROSS JOIN main.rust_resolution_unit_summary_file_naming AS origin_naming
    ON origin_naming.summary_id = origin_member.summary_id
   AND origin_naming.member_ordinal = origin_member.member_ordinal
  WHERE roots.target_identity_id IS NOT NULL
  UNION ALL
  SELECT roots.summary_id, roots.member_ordinal, roots.route_provenance_ordinal,
         roots.rel_path, roots.module_path, roots.name, roots.namespace,
         roots.visibility_kind, roots.visibility_crate_root,
         roots.visibility_module_path, roots.target_module_path, roots.target_name,
         roots.root_components, origin_member.rel_path,
         json(origin_naming.root_components), roots.summary_id,
         roots.route_provenance_ordinal, roots.name, roots.rel_path,
         roots.source_import_id, roots.source_import_ordinal,
         roots.source_import_id, roots.source_import_ordinal,
         roots.edge_target_unit_key
  FROM roots
  CROSS JOIN selected_rust_unit_summary_route_owners AS origin_owner
    ON origin_owner.unit_key = roots.target_unit_key
  CROSS JOIN main.rust_resolution_unit_summary_placements AS origin_placement
    ON origin_placement.summary_id = origin_owner.summary_id
   AND origin_placement.module_path = roots.target_module_path
  CROSS JOIN main.resolution_unit_summary_members AS origin_member
    ON origin_member.summary_id = origin_placement.summary_id
   AND origin_member.member_ordinal = origin_placement.member_ordinal
  CROSS JOIN main.source_rust_module_declarations AS declaration
    ON declaration.blob_id = origin_member.blob_id
   AND declaration.declaration_id = roots.target_declaration_key
   AND declaration.module_name = roots.target_name
  CROSS JOIN main.rust_resolution_unit_summary_file_naming AS origin_naming
    ON origin_naming.summary_id = origin_member.summary_id
   AND origin_naming.member_ordinal = origin_member.member_ordinal
  WHERE roots.target_declaration_key IS NOT NULL
  UNION
  SELECT graph.root_summary_id, graph.root_member_ordinal,
         graph.root_route_ordinal, graph.root_rel_path,
         graph.root_module_path, graph.root_name, graph.root_namespace,
         graph.root_visibility_kind, graph.root_visibility_crate_root,
         graph.root_visibility_module_path, graph.root_target_module_path,
         graph.root_target_name, graph.root_components, graph.origin_file,
         graph.origin_root_components, target_owner.summary_id,
         target.route_provenance_ordinal, target.name, target_member.rel_path,
         graph.root_source_import_id, graph.root_source_import_ordinal,
         target.source_import_id, target.source_import_ordinal,
         graph.edge_target_unit_key
  FROM route_graph AS graph
  CROSS JOIN main.rust_resolution_unit_summary_import_route_provenance AS route
    INDEXED BY rust_resolution_unit_summary_import_route_provenance_binding
    ON route.summary_id = graph.summary_id
   AND route.route_provenance_ordinal = graph.route_ordinal
  CROSS JOIN selected_rust_unit_summary_route_owners AS target_owner
    ON target_owner.unit_key = route.target_unit_key
  CROSS JOIN main.rust_resolution_unit_summary_effective_bindings AS target
    INDEXED BY rust_resolution_unit_summary_effective_bindings_module_name
    ON target.summary_id = target_owner.summary_id
   AND target.module_path = route.target_binding_module_path
   AND target.name = route.target_binding_name AND target.namespace = route.namespace
  CROSS JOIN main.resolution_unit_summary_members AS target_member
    ON target_member.summary_id = target.summary_id
   AND target_member.member_ordinal = target.member_ordinal
)
SELECT graph.root_member_ordinal, graph.root_route_ordinal,
       graph.root_rel_path, graph.root_module_path, graph.root_name,
       graph.root_namespace, graph.root_visibility_kind,
       graph.root_visibility_crate_root, graph.root_visibility_module_path,
       graph.root_target_module_path, graph.root_target_name,
       graph.root_components, graph.origin_file, graph.origin_root_components,
       graph.route_name, graph.route_file, graph.root_source_import_id,
       graph.root_source_import_ordinal, graph.route_source_import_id,
       graph.route_source_import_ordinal,
       root_context.crate_name, root_context.target_kind,
       edge_context.crate_name, edge_context.target_kind
FROM route_graph AS graph
LEFT JOIN main.rust_resolution_unit_summary_contexts AS root_context
  ON root_context.summary_id = graph.root_summary_id
LEFT JOIN selected_rust_unit_summary_route_owners AS edge_owner
  ON edge_owner.unit_key = graph.edge_target_unit_key
LEFT JOIN main.rust_resolution_unit_summary_contexts AS edge_context
  ON edge_context.summary_id = edge_owner.summary_id"#;

pub(crate) const RUST_SUMMARY_BINDING_COMPLETENESS_SQL: &str = r#"
SELECT members.summary_id, members.rel_path, json(naming.package_components),
       json(naming.root_components), completeness.complete,
       completeness.gap_kind, completeness.gap_subject
FROM selected_rust_import_graph_members AS members
JOIN main.rust_resolution_unit_summary_file_naming AS naming
  ON naming.summary_id = members.summary_id
 AND naming.member_ordinal = members.member_ordinal
JOIN main.rust_resolution_unit_summary_binding_completeness AS completeness
  INDEXED BY rust_resolution_unit_summary_binding_completeness_member
  ON completeness.summary_id = members.summary_id
 AND completeness.member_ordinal = members.member_ordinal
WHERE members.rel_path IN (SELECT value FROM json_each(?1))
"#;

pub(crate) const RUST_SUMMARY_MODULE_CANDIDATES_SQL: &str = r#"
WITH candidates AS (
  SELECT CAST(json_extract(value, '$[0]') AS INTEGER) AS candidate_ordinal,
         CAST(json_extract(value, '$[1]') AS INTEGER) AS summary_id,
         json_extract(value, '$[2]') AS module_path
  FROM json_each(?1)
)
SELECT candidates.candidate_ordinal,
       containers.module_path IS NOT NULL,
       members.rel_path
FROM candidates
LEFT JOIN main.rust_resolution_unit_summary_containers AS containers
  ON containers.summary_id = candidates.summary_id
 AND containers.module_path = candidates.module_path
LEFT JOIN main.rust_resolution_unit_summary_placements AS placements
  ON placements.summary_id = containers.summary_id
 AND placements.module_path = containers.module_path
LEFT JOIN main.resolution_unit_summary_members AS members
  ON members.summary_id = placements.summary_id
 AND members.member_ordinal = placements.member_ordinal
"#;

#[derive(Debug)]
pub(crate) struct RustSummaryPackageRow {
    pub(crate) rel_path: String,
    pub(crate) package_components: Vec<String>,
    pub(crate) crate_name: String,
    pub(crate) target_kind: String,
    pub(crate) blob_oid: String,
    pub(crate) is_root_member: bool,
}

#[derive(Debug)]
pub(crate) struct RustSummaryBindingSurfaceRow {
    pub(crate) member_ordinal: i64,
    pub(crate) route_ordinal: i64,
    pub(crate) rel_path: String,
    pub(crate) module_path: String,
    pub(crate) name: String,
    pub(crate) namespace: String,
    pub(crate) visibility_kind: String,
    pub(crate) visibility_crate_root: Option<String>,
    pub(crate) visibility_module_path: Option<String>,
    pub(crate) origin_file: String,
    pub(crate) origin_root_components: String,
    pub(crate) origin_module_path: String,
    pub(crate) origin_name: String,
    pub(crate) root_components: String,
    pub(crate) route_name: String,
    pub(crate) route_file: String,
    pub(crate) source_import_id: Option<i64>,
    pub(crate) source_import_ordinal: Option<i64>,
    pub(crate) route_source_import_id: Option<i64>,
    pub(crate) route_source_import_ordinal: Option<i64>,
    pub(crate) root_crate_name: Option<String>,
    pub(crate) root_target_kind: Option<String>,
    pub(crate) edge_crate_name: Option<String>,
    pub(crate) edge_target_kind: Option<String>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RustSummaryBindingCompletenessRow {
    pub(crate) summary_id: i64,
    pub(crate) rel_path: String,
    pub(crate) package_components: String,
    pub(crate) root_components: String,
    pub(crate) complete: bool,
    pub(crate) gap_kind: String,
    pub(crate) gap_subject: String,
}

#[derive(Debug)]
pub(crate) struct RustSummaryModuleCandidateRow {
    pub(crate) candidate_ordinal: usize,
    pub(crate) present: bool,
    pub(crate) rel_path: Option<String>,
}

#[derive(Debug)]
pub(crate) struct RustSummaryCargoRouteRow {
    pub(crate) unit_key: [u8; 32],
    pub(crate) manifest_rel_path: Option<String>,
    pub(crate) target_kind: String,
    pub(crate) crate_name: String,
    pub(crate) edition: String,
    pub(crate) development_capable: bool,
    pub(crate) root_rel_path: Option<String>,
    pub(crate) root_package_components: Option<Vec<String>>,
    pub(crate) dependency_extern_name: Option<String>,
    pub(crate) dependency_kind: Option<String>,
    pub(crate) dependency_boundary: Option<String>,
    pub(crate) dependency_unit_key: Option<[u8; 32]>,
    pub(crate) dependency_target_kind: Option<String>,
    pub(crate) dependency_root_rel_path: Option<String>,
    pub(crate) dependency_root_package_components: Option<Vec<String>>,
    pub(crate) dependency_manifest_rel_path: Option<String>,
}

const STAGE_SCHEMA_SQL: &str = "CREATE TEMP TABLE IF NOT EXISTS rust_unit_summary_units(
    unit_id INTEGER PRIMARY KEY,
    topology_id INTEGER NOT NULL UNIQUE,
    crate_key BLOB NOT NULL UNIQUE,
    label TEXT NOT NULL
  ) STRICT;
  DELETE FROM temp.rust_unit_summary_units;";

const STAGE_UNITS_SQL: &str = "INSERT INTO temp.rust_unit_summary_units(topology_id, crate_key, label)
    SELECT versions.topology_id, versions.crate_key, topologies.crate_name || ' [' || topologies.target_kind || ']'
    FROM main.rust_crate_versions AS versions
    JOIN main.rust_crate_topologies AS topologies ON topologies.topology_id = versions.topology_id
    WHERE versions.workspace_id = ?1 AND versions.lang = 'rust' AND versions.generation = ?2
      AND versions.valid_from <= ?3 AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
      AND topologies.publication_state = 'complete'
    ORDER BY versions.crate_key";

// A library consumes its dev-dependencies, but they are inputs of its test
// targets: they must not order the units, or a library and the dev-dependency
// that depends on it form a cycle that unorders everything built on them.
const STAGE_DEPENDENCY_EDGES_SQL: &str = "INSERT OR IGNORE INTO temp.unit_summary_edges(unit_id, dependency_unit_id, orders)
    SELECT owner.unit_id, child.unit_id, MAX(dependencies.dependency_kind <> 'dev')
    FROM temp.rust_unit_summary_units AS owner
    JOIN main.rust_crate_dependencies AS dependencies ON dependencies.topology_id = owner.topology_id
      AND dependencies.boundary = 'workspace'
    JOIN temp.rust_unit_summary_units AS child ON child.crate_key = dependencies.dependency_crate_key
    GROUP BY owner.unit_id, child.unit_id";

const UNIT_SQL: &str = "SELECT units.topology_id, topologies.crate_key, units.label
    FROM temp.rust_unit_summary_units AS units
    JOIN main.rust_crate_topologies AS topologies ON topologies.topology_id = units.topology_id
    WHERE units.unit_id = ?1";

const MEMBERS_SQL: &str =
    "SELECT DISTINCT sources.blob_id, blobs.blob_oid, sources.rel_path, sources.source_kind
    FROM main.rust_crate_container_sources AS sources
    JOIN main.blobs AS blobs ON blobs.id = sources.blob_id
    WHERE sources.topology_id = ?1
    ORDER BY sources.rel_path, sources.source_kind, sources.blob_id";

const CONFIGURATION_READS_SQL: &str = "SELECT versions.rel_path, versions.blob_oid
    FROM main.workspace_file_versions AS versions
    WHERE versions.workspace_id = ?1 AND versions.lang = 'rust' AND versions.generation = ?2
      AND versions.input_kind = 'configuration' AND versions.valid_from <= ?3
      AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
    ORDER BY versions.rel_path";

const DEPENDENCIES_SQL: &str = "SELECT dependencies.extern_name, dependencies.boundary,
       dependencies.dependency_crate_key, dependencies.dependency_kind,
       child.unit_id, COALESCE(target.crate_name, dependencies.extern_name)
    FROM main.rust_crate_dependencies AS dependencies
    LEFT JOIN temp.rust_unit_summary_units AS child
      ON child.crate_key = dependencies.dependency_crate_key
    LEFT JOIN main.rust_crate_topologies AS target ON target.topology_id = child.topology_id
    WHERE dependencies.topology_id = ?1
    ORDER BY dependencies.extern_name";

const IMPORTS_SQL: &str =
    "SELECT sources.blob_id, imports.import_id, imports.alias, imports.identifier,
       sources.rel_path, segment.ordinal, segment.segment
    FROM (SELECT topology_id, blob_id, MIN(rel_path) AS rel_path
          FROM main.rust_crate_container_sources WHERE topology_id = ?1
          GROUP BY topology_id, blob_id) AS sources
    JOIN main.source_imports AS imports ON imports.blob_id = sources.blob_id
    LEFT JOIN main.source_import_segments AS segment
      ON segment.blob_id = imports.blob_id AND segment.import_id = imports.import_id
    ORDER BY sources.rel_path, sources.blob_id, imports.import_id, segment.ordinal";

const IMPORT_TARGET_KEYS_SQL: &str = "SELECT DISTINCT imports.target_crate_key
    FROM main.source_rust_import_targets AS targets
    JOIN main.rust_crate_imports AS imports
      ON imports.topology_id = ?1 AND imports.module_path = targets.module_path
     AND imports.blob_id = targets.blob_id AND imports.import_ordinal = targets.ordinal
    WHERE targets.blob_id = ?2 AND targets.source_import_id = ?3
    UNION
    SELECT DISTINCT imports.target_crate_key
    FROM main.source_rust_import_targets AS targets
    JOIN main.rust_crate_glob_imports AS imports
      ON imports.topology_id = ?1 AND imports.module_path = targets.module_path
     AND imports.blob_id = targets.blob_id AND imports.import_ordinal = targets.ordinal
    WHERE targets.blob_id = ?2 AND targets.source_import_id = ?3";

const EXPORTS_SQL: &str = "SELECT exports.module_path, exports.namespace, exports.name,
       exports.origin, exports.declaration_blob_id, exports.declaration_site,
       semantic.semantic_key
    FROM main.rust_crate_exports AS exports
    LEFT JOIN main.resolution_semantic_sites AS semantic
      ON semantic.blob_id = exports.declaration_blob_id
     AND semantic.source_site = exports.declaration_site
     AND semantic.semantic_role = 'definition'
    WHERE exports.topology_id = ?1 AND exports.visibility = 'public'
    ORDER BY exports.module_path, exports.namespace, exports.name";

// Resolve the source binder inside the retained topology/blob frame. Only
// target identity lookup below selects the current destination publication.
pub(super) const NAMED_REEXPORT_TARGETS_SQL: &str =
    "SELECT DISTINCT imports.target_crate_key, imports.target_module_path, imports.target_name
    FROM main.rust_crate_imports AS imports
    JOIN main.source_rust_import_targets AS source
      ON source.blob_id = imports.blob_id AND source.ordinal = imports.import_ordinal
    WHERE imports.topology_id = ?1 AND imports.module_path = ?2
      AND imports.namespace = ?3 AND imports.bound_name = ?4
      AND source.native_scope = imports.binder_scope
      AND source.bound_name = imports.bound_name AND source.is_glob = 0
      AND source.visibility <> 'private'
      AND EXISTS (
          SELECT 1 FROM main.rust_crate_container_sources AS member
          JOIN main.source_rust_module_scopes AS scope
            ON scope.blob_id = member.blob_id AND scope.ordinal = member.scope_ordinal
          WHERE member.topology_id = imports.topology_id
            AND member.container_path = imports.module_path AND member.blob_id = imports.blob_id
            AND scope.resolution_scope = imports.binder_scope
      )";

// Match the fixpoint's normalized target domains before ambiguity assembly.
// Constructor values carry their effective visibility in the same export rows.
const GLOB_REEXPORT_TARGETS_SQL: &str = "WITH candidates AS (
    SELECT routes.target_crate_key, routes.target_module_path, routes.module_path,
           target.visibility,
           CASE target.visibility
             WHEN 'public' THEN NULL
             WHEN 'private' THEN target.module_path
             WHEN 'crate' THEN 'crate'
             WHEN 'restricted' THEN target.restricted_module_path END AS target_domain
    FROM main.rust_crate_glob_reexport_routes AS routes
    JOIN main.rust_crate_versions AS versions
      ON versions.workspace_id = ?5 AND versions.lang = 'rust' AND versions.generation = ?6
     AND versions.crate_key = routes.target_crate_key
     AND versions.valid_from <= ?7 AND (versions.valid_until IS NULL OR ?7 < versions.valid_until)
    JOIN main.rust_crate_exports AS target
      ON target.topology_id = versions.topology_id
     AND target.module_path = routes.target_module_path
     AND target.namespace = ?3 AND target.name = ?4
    WHERE routes.topology_id = ?1 AND routes.module_path = ?2
    )
    SELECT DISTINCT target_crate_key, target_module_path FROM candidates
    WHERE visibility = 'public'
       OR (target_crate_key = ?8 AND target_domain IS NOT NULL
           AND (module_path = target_domain
                OR substr(module_path, 1, length(target_domain) + 2) = target_domain || '::'))";

const TARGET_IDENTITY_SQL: &str = "SELECT identities.id, identities.identity_digest,
       exports.declaration_blob_id, exports.declaration_site
    FROM main.rust_crate_versions AS versions
    JOIN main.rust_crate_exports AS exports ON exports.topology_id = versions.topology_id
    JOIN main.resolution_identities AS identities
      ON identities.semantic_language = ?8 AND identities.namespace = ?9 AND identities.spelling = ?7
    WHERE versions.workspace_id = ?1 AND versions.lang = 'rust' AND versions.generation = ?2
      AND versions.crate_key = ?3 AND versions.valid_from <= ?4
      AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)
      AND exports.module_path = ?5 AND exports.namespace = ?6 AND exports.name = ?7
      AND (?10 OR exports.visibility = 'public')
    LIMIT 1";

// This is an export-surface proof, not dependency-graph reachability. Match
// the canonical target coordinates and identity, or prove that the current
// selected direct dependency topology publicly reaches that canonical module.
pub(crate) const DEPENDENCY_REEXPORT_WITNESS_SQL: &str = concat!(
    "WITH live AS (",
    super::unit_summaries::live_summary_select!("zeroblob(32)"),
    ")
     SELECT EXISTS(
       SELECT 1 FROM live
       CROSS JOIN main.rust_resolution_unit_summary_exports AS exports
         INDEXED BY rust_resolution_unit_summary_exports_alias_target
         ON exports.summary_id = live.summary_id
       WHERE exports.origin <> 'declaration'
         AND exports.visibility = 'public' AND exports.namespace = ?10
         AND exports.target_unit_key = ?8 AND exports.target_module_path = ?9
         AND exports.target_name = ?11 AND exports.alias_identity_id = ?12
       UNION ALL
       SELECT 1 FROM live
       CROSS JOIN main.rust_crate_versions AS versions
         ON versions.workspace_id = ?1 AND versions.lang = ?2 AND versions.generation = ?3
        AND versions.crate_key = ?4 AND versions.valid_from <= ?5
        AND (versions.valid_until IS NULL OR ?5 < versions.valid_until)
       CROSS JOIN main.rust_crate_topologies AS topology
         ON topology.topology_id = versions.topology_id
        AND topology.publication_state = 'complete'
       CROSS JOIN main.rust_crate_public_module_reachability AS reachability
         ON reachability.topology_id = topology.topology_id
        AND reachability.target_crate_key = ?8
        AND reachability.target_module_path = ?9
     )"
);

const LOCAL_IMPORT_SQL: &str = "SELECT EXISTS(
    SELECT 1 FROM main.source_rust_import_targets AS targets
    JOIN main.rust_crate_imports AS imports
      ON imports.topology_id = ?1 AND imports.module_path = targets.module_path
     AND imports.blob_id = targets.blob_id AND imports.import_ordinal = targets.ordinal
    WHERE targets.blob_id = ?2 AND targets.source_import_id = ?3 AND imports.target_crate_key = ?4
    UNION
    SELECT 1 FROM main.source_rust_import_targets AS targets
    JOIN main.rust_crate_glob_imports AS imports
      ON imports.topology_id = ?1 AND imports.module_path = targets.module_path
     AND imports.blob_id = targets.blob_id AND imports.import_ordinal = targets.ordinal
    WHERE targets.blob_id = ?2 AND targets.source_import_id = ?3 AND imports.target_crate_key = ?4
  )";

// A forwarded public-surface gap describes the topology's reachability graph,
// not this unit's own export or import inventory. A declared `pub mod` whose
// file is missing has a known binding and a known failed lookup, like the
// `unplaced_module` gaps the binding-completeness writer already excludes
// (#5661). Folding it into every member here marked the whole crate incomplete,
// so the import graph could not publish and a single file addition rebuilt the
// entire workspace. The surface facts stay in `rust_crate_gaps` and the
// topology digest for reachability and change sensitivity.
const GAPS_SQL: &str = "SELECT gap_kind, subject, json(detail)
    FROM main.rust_crate_gaps
    WHERE topology_id = ?1 AND subject NOT LIKE 'public-module-surface:%'
    ORDER BY gap_kind, subject";

pub(crate) struct RustUnitSummaries;

/// The dependency ordinal, identity id and identity digest of a re-export target.
type ReexportTarget = (Option<usize>, i64, [u8; 32]);

#[cfg(any(test, feature = "test-support"))]
pub(super) fn assert_differential(conn: &Connection, snapshot: &WorkspaceSnapshotId) {
    let topology_count: usize = conn
        .query_row(
            "SELECT count(*) FROM main.rust_crate_versions AS versions
             JOIN main.rust_crate_topologies AS topology USING(topology_id)
             WHERE versions.workspace_id = ?1 AND versions.lang = 'rust'
               AND versions.generation = ?2 AND versions.valid_from <= ?3
               AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
               AND topology.publication_state = 'complete'",
            rusqlite::params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision
            ],
            |row| row.get(0),
        )
        .expect("count selected Rust topology versions");
    let crosswalk = {
        let mut statement = conn
            .prepare(
                "SELECT topology.topology_id, topology.crate_key, topology.crate_name,
                        summary.summary_id
                 FROM main.rust_crate_versions AS versions
                 JOIN main.rust_crate_topologies AS topology
                   ON topology.topology_id = versions.topology_id
                 JOIN main.resolution_unit_summary_versions AS summary
                   ON summary.workspace_id = versions.workspace_id
                  AND summary.lang = versions.lang AND summary.generation = versions.generation
                  AND summary.unit_key = versions.crate_key
                 JOIN main.resolution_unit_summaries AS headers
                   ON headers.summary_id = summary.summary_id
                 WHERE versions.workspace_id = ?1 AND versions.lang = 'rust'
                   AND versions.generation = ?2
                   AND versions.valid_from <= ?3
                   AND (versions.valid_until IS NULL OR ?3 < versions.valid_until)
                   AND summary.valid_from <= ?3
                   AND (summary.valid_until IS NULL OR ?3 < summary.valid_until)
                   AND headers.lang = 'rust' AND headers.unit_kind = 'rust_crate'
                   AND headers.publication_state = 'complete'
                 ORDER BY topology.crate_key",
            )
            .expect("prepare Rust summary crosswalk");
        statement
            .query_map(
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .expect("read Rust summary crosswalk")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect Rust summary crosswalk")
    };
    assert_eq!(
        topology_count,
        crosswalk.len(),
        "Rust topology-to-summary crosswalk missing rows at workspace {} generation {} revision {}",
        snapshot.workspace_id.as_str(),
        snapshot.generation.get(),
        snapshot.revision
    );

    for (topology_id, crate_key, crate_name, summary_id) in crosswalk {
        let expected_members = {
            let mut statement = conn
                .prepare(
                    "SELECT DISTINCT blob_id, rel_path, source_kind
                     FROM main.rust_crate_container_sources
                     WHERE topology_id = ?1",
                )
                .expect("prepare Rust topology members");
            statement
                .query_map([topology_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .expect("read Rust topology members")
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                .expect("collect Rust topology members")
        };
        let actual_members = {
            let mut statement = conn
                .prepare(
                    "SELECT blob_id, rel_path, source_role
                     FROM main.resolution_unit_summary_members
                     WHERE summary_id = ?1",
                )
                .expect("prepare Rust summary members");
            statement
                .query_map([summary_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .expect("read Rust summary members")
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                .expect("collect Rust summary members")
        };
        assert_set_equal(
            &format!("{crate_name} members"),
            &expected_members,
            &actual_members,
        );

        let expected_exports = {
            let mut statement = conn
                .prepare(
                    "SELECT namespace, name FROM main.rust_crate_exports
                     WHERE topology_id = ?1 AND visibility = 'public'",
                )
                .expect("prepare Rust topology exports");
            let names = statement
                .query_map([topology_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .expect("read Rust topology exports")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("collect Rust topology exports");
            names
                .into_iter()
                .map(|(namespace, name)| {
                    let (identity_id, _) = identity_for_name(conn, &namespace, &name)
                        .expect("lookup Rust export identity")
                        .unwrap_or_else(|| {
                            panic!(
                                "{crate_name} export {namespace}:{name} lacks its shared identity"
                            )
                        });
                    (identity_id, namespace)
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        let actual_exports = {
            let mut statement = conn
                .prepare(
                    "SELECT identity_id, namespace
                     FROM main.resolution_unit_summary_exports
                     WHERE summary_id = ?1 AND visibility = 'exported'",
                )
                .expect("prepare Rust summary exports");
            statement
                .query_map([summary_id], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .expect("read Rust summary exports")
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                .expect("collect Rust summary exports")
        };
        let missing_exports = expected_exports
            .difference(&actual_exports)
            .map(|(identity_id, namespace)| {
                let spelling: String = conn
                    .query_row(
                        "SELECT spelling FROM main.resolution_identities WHERE id = ?1",
                        [identity_id],
                        |row| row.get(0),
                    )
                    .expect("lookup missing Rust export spelling");
                let topology_rows = {
                    let mut statement = conn
                        .prepare(
                            "SELECT module_path, origin, declaration_blob_id, declaration_site
                             FROM main.rust_crate_exports
                             WHERE topology_id = ?1 AND namespace = ?2 AND name = ?3
                               AND visibility = 'public'
                             ORDER BY module_path, origin",
                        )
                        .expect("prepare missing Rust export detail");
                    statement
                        .query_map(params![topology_id, namespace, spelling], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        })
                        .expect("read missing Rust export detail")
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .expect("collect missing Rust export detail")
                };
                ((*identity_id, namespace.clone(), spelling), topology_rows)
            })
            .collect::<Vec<_>>();
        assert_set_equal(
            &format!("{crate_name} exports missing-details={missing_exports:?}"),
            &expected_exports,
            &actual_exports,
        );

        let expected_dependencies = {
            let mut statement = conn
                .prepare(
                    "SELECT extern_name, boundary, dependency_crate_key
                     FROM main.rust_crate_dependencies WHERE topology_id = ?1",
                )
                .expect("prepare Rust topology dependencies");
            statement
                .query_map([topology_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                })
                .expect("read Rust topology dependencies")
                .map(|row| {
                    let (extern_name, boundary, dependency_key) =
                        row.expect("decode Rust topology dependency");
                    let key = match (boundary.as_str(), dependency_key) {
                        ("workspace", Some(key)) => {
                            digest_from_row(key).expect("Rust workspace dependency key is 32 bytes")
                        }
                        ("external", None) => external_unit_key(&extern_name),
                        ("std", None) => standard_unit_key(&extern_name),
                        other => {
                            panic!("{crate_name} has invalid dependency boundary/key {other:?}")
                        }
                    };
                    let boundary = if boundary == "std" {
                        "standard".to_owned()
                    } else {
                        boundary
                    };
                    (boundary, key)
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        let actual_dependencies = {
            let mut statement = conn
                .prepare(
                    "SELECT boundary, dependency_unit_key
                     FROM main.resolution_unit_summary_dependencies
                     WHERE summary_id = ?1 AND boundary IN ('workspace', 'external', 'standard')",
                )
                .expect("prepare Rust summary dependencies");
            statement
                .query_map([summary_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .expect("read Rust summary dependencies")
                .map(|row| {
                    let (boundary, key) = row.expect("decode Rust summary dependency");
                    (
                        boundary,
                        digest_from_row(key).expect("Rust summary dependency key is 32 bytes"),
                    )
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(crate_key.len(), 32, "{crate_name} crate key width");
        assert_set_equal(
            &format!("{crate_name} dependencies"),
            &expected_dependencies,
            &actual_dependencies,
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
fn assert_set_equal<T: Ord + Debug>(
    label: &str,
    expected: &std::collections::BTreeSet<T>,
    actual: &std::collections::BTreeSet<T>,
) {
    let expected_only = expected.difference(actual).collect::<Vec<_>>();
    let actual_only = actual.difference(expected).collect::<Vec<_>>();
    assert!(
        expected_only.is_empty() && actual_only.is_empty(),
        "Rust summary differential failed for {label}: topology-only={expected_only:?}, summary-only={actual_only:?}"
    );
}

impl UnitSummaryLanguage for RustUnitSummaries {
    fn lang(&self) -> &'static str {
        "rust"
    }

    fn unit_kind(&self) -> &'static str {
        "rust_crate"
    }

    fn derivation_version(&self) -> i64 {
        RUST_UNIT_SUMMARY_DERIVATION_VERSION
    }

    fn stage(&self, conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<()> {
        conn.execute_batch(STAGE_SCHEMA_SQL)?;
        conn.execute(
            STAGE_UNITS_SQL,
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision
            ],
        )?;
        conn.execute(
            "INSERT INTO temp.unit_summary_work(unit_id)
             SELECT unit_id FROM temp.rust_unit_summary_units",
            [],
        )?;
        conn.execute(STAGE_DEPENDENCY_EDGES_SQL, [])?;
        Ok(())
    }

    fn clear_stage(&self, conn: &Connection) -> Result<()> {
        conn.execute("DELETE FROM temp.rust_unit_summary_units", [])?;
        Ok(())
    }

    fn inputs(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit_id: i64,
    ) -> Result<UnitInputs> {
        let (topology_id, unit_key, label): (i64, Vec<u8>, String) = conn
            .prepare_cached(UNIT_SQL)?
            .query_row([unit_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let unit_key = digest_from_row(unit_key)?;
        let mut members = Vec::new();
        {
            let mut statement = conn.prepare_cached(MEMBERS_SQL)?;
            let mut rows = statement.query([topology_id])?;
            while let Some(row) = rows.next()? {
                members.push(UnitMember {
                    blob_id: row.get(0)?,
                    blob_oid: row.get(1)?,
                    rel_path: row.get(2)?,
                    source_role: row.get(3)?,
                });
            }
        }

        let producer_epoch: String = conn.query_row(
            "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'rust'",
            [],
            |row| row.get(0),
        )?;
        let reads = read_rows(conn, snapshot, &producer_epoch)?;

        let mut dependencies = Vec::new();
        let mut dependency_keys = HashSet::new();
        {
            let mut statement = conn.prepare_cached(DEPENDENCIES_SQL)?;
            let mut rows = statement.query([topology_id])?;
            while let Some(row) = rows.next()? {
                let extern_name: String = row.get(0)?;
                let boundary: String = row.get(1)?;
                let crate_key: Option<Vec<u8>> = row.get(2)?;
                let dependency_kind: String = row.get(3)?;
                let dependency_unit_id: Option<i64> = row.get(4)?;
                let dependency_label: String = row.get(5)?;
                let (key, unit_id, boundary, provenance, external_digest) = match (
                    boundary.as_str(),
                    crate_key,
                ) {
                    ("workspace", Some(key)) => (
                        digest_from_row(key)?,
                        dependency_unit_id,
                        "workspace",
                        None,
                        None,
                    ),
                    ("external", None) => {
                        let key = external_unit_key(&extern_name);
                        let provenance = format!("cargo-external:{extern_name}:{dependency_kind}");
                        let digest = external_dependency_digest(
                            &extern_name,
                            &dependency_kind,
                            &producer_epoch,
                            &reads,
                        );
                        (key, None, "external", Some(provenance), Some(digest))
                    }
                    ("std", None) => {
                        let key = standard_unit_key(&extern_name);
                        let provenance = format!("rust-standard:{extern_name}:{dependency_kind}");
                        let digest = standard_dependency_digest(&extern_name, &producer_epoch);
                        (key, None, "standard", Some(provenance), Some(digest))
                    }
                    other => {
                        return Err(StoreError::corrupt(format!(
                            "{label}: invalid Rust dependency row {other:?} for {extern_name:?}/{dependency_kind:?}"
                        )));
                    }
                };
                if dependency_keys.insert(key) {
                    dependencies.push(UnitDependency {
                        unit_key: key,
                        unit_id,
                        label: format!("Rust dependency {dependency_label}"),
                        boundary,
                        provenance,
                        external_digest,
                    });
                }
            }
        }
        Ok(UnitInputs {
            unit_id,
            unit_key,
            label,
            members,
            reads,
            dependencies,
        })
    }

    fn derive(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        dependencies: &[ConsumedDependency],
        _producer_epoch: &str,
    ) -> Result<UnitOutputs> {
        let (topology_id, inventory_complete, public_surface_digest): (i64, bool, Vec<u8>) = conn
            .prepare_cached(
                "SELECT units.topology_id, topologies.inventory_complete,
                        topologies.export_surface_digest
                 FROM temp.rust_unit_summary_units AS units
                 JOIN main.rust_crate_topologies AS topologies USING(topology_id)
                 WHERE units.unit_id = ?1",
            )?
            .query_row([unit.unit_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        let public_surface_digest = digest_from_row(public_surface_digest)?;

        let mut gaps = BTreeMap::<(&'static str, String), String>::new();
        {
            let mut statement = conn.prepare_cached(GAPS_SQL)?;
            let mut rows = statement.query([topology_id])?;
            while let Some(row) = rows.next()? {
                let kind: String = row.get(0)?;
                let subject: String = row.get(1)?;
                let detail: String = row.get(2)?;
                gaps.insert((rust_gap_kind(&kind)?, subject), detail);
            }
        }
        for dependency in dependencies
            .iter()
            .filter(|dependency| !dependency.available)
        {
            gaps.insert(
                ("unit_summary_unavailable", dependency.label.clone()),
                "{}".to_owned(),
            );
        }

        let dependency_ordinals: HashMap<[u8; 32], usize> = dependencies
            .iter()
            .map(|dependency| (dependency.unit_key, dependency.ordinal))
            .collect();
        let dependency_keys_by_extern = {
            let mut statement = conn.prepare_cached(
                "SELECT extern_name, boundary, dependency_crate_key
                 FROM main.rust_crate_dependencies WHERE topology_id = ?1 ORDER BY extern_name",
            )?;
            let mut rows = statement.query([topology_id])?;
            let mut mapping = HashMap::new();
            while let Some(row) = rows.next()? {
                let extern_name: String = row.get(0)?;
                let boundary: String = row.get(1)?;
                let dependency_key: Option<Vec<u8>> = row.get(2)?;
                let key = match (boundary.as_str(), dependency_key) {
                    ("workspace", Some(key)) => digest_from_row(key)?,
                    ("external", None) => external_unit_key(&extern_name),
                    ("std", None) => standard_unit_key(&extern_name),
                    other => {
                        return Err(StoreError::corrupt(format!(
                            "{}: invalid dependency binding for {extern_name:?}: {other:?}",
                            unit.label
                        )));
                    }
                };
                mapping.insert(extern_name, key);
            }
            mapping
        };

        let mut exports = Vec::new();
        // Identity, namespace, declaration blob and declaration site.
        type ExportKey = (i64, String, i64, i64);
        // Identity digest, origin, alias dependency ordinal, alias digest and
        // declaration key.
        type ExportSignature = ([u8; 32], &'static str, Option<usize>, Option<[u8; 32]>, i64);
        let mut export_keys: HashMap<ExportKey, (ExportSignature, usize)> = HashMap::new();
        {
            let mut statement = conn.prepare_cached(EXPORTS_SQL)?;
            let mut rows = statement.query([topology_id])?;
            while let Some(row) = rows.next()? {
                let module_path: String = row.get(0)?;
                let namespace: String = row.get(1)?;
                let name: String = row.get(2)?;
                let rust_origin: String = row.get(3)?;
                let declaration_blob_id: i64 = row.get(4)?;
                let declaration_site: i64 = row.get(5)?;
                let declaration_key: Option<i64> = row.get(6)?;
                let Some(declaration_key) = declaration_key else {
                    return Err(StoreError::corrupt(format!(
                        "{}: public export {module_path}::{name} lacks a definition semantic site at blob {declaration_blob_id} site {declaration_site}",
                        unit.label
                    )));
                };
                let (identity_id, identity_digest) = identity_for_name(conn, &namespace, &name)?
                    .ok_or_else(|| {
                        StoreError::corrupt(format!(
                            "{}: public export {module_path}::{name} has no Rust name identity",
                            unit.label
                        ))
                    })?;
                let (origin, alias_dependency_ordinal, alias_identity_id, alias_identity_digest) =
                    if rust_origin == "declaration" {
                        ("declaration", None, None, None)
                    } else {
                        let target = self.reexport_target(
                            conn,
                            snapshot,
                            unit,
                            topology_id,
                            &module_path,
                            &namespace,
                            &name,
                            &rust_origin,
                            &dependency_ordinals,
                        )?;
                        let Some((dependency_ordinal, identity_id, identity_digest)) = target
                        else {
                            gaps.insert(
                                (
                                    "unresolved_reexport",
                                    format!("{module_path}::{namespace}:{name}"),
                                ),
                                "{\"reason\":\"reexport_target_unavailable\"}".to_owned(),
                            );
                            continue;
                        };
                        (
                            "reexport",
                            dependency_ordinal,
                            Some(identity_id),
                            Some(identity_digest),
                        )
                    };
                let (origin, alias_dependency_ordinal, alias_identity_id, alias_identity_digest) =
                    if origin == "reexport"
                        && alias_dependency_ordinal.is_none()
                        && alias_identity_id == Some(identity_id)
                    {
                        // `pub use` can expose a declaration under its existing
                        // identity inside this crate. The shared key is declaration
                        // based, so retain the direct declaration instead of a
                        // self-alias that carries no additional lookup information.
                        ("declaration", None, None, None)
                    } else {
                        (
                            origin,
                            alias_dependency_ordinal,
                            alias_identity_id,
                            alias_identity_digest,
                        )
                    };
                let export_key = (
                    identity_id,
                    namespace.clone(),
                    declaration_blob_id,
                    declaration_site,
                );
                let export_signature = (
                    identity_digest,
                    origin,
                    alias_dependency_ordinal,
                    alias_identity_digest,
                    declaration_key,
                );
                let export = UnitExport {
                    identity_id,
                    identity_digest,
                    namespace: namespace.clone(),
                    visibility: "exported",
                    origin,
                    alias_dependency_ordinal,
                    alias_identity_id,
                    alias_identity_digest,
                    declaration_blob_id,
                    declaration_site,
                    declaration_key,
                };
                if let Some((previous, index)) = export_keys.get(&export_key).copied() {
                    if previous == export_signature {
                        continue;
                    }
                    if previous.1 == "reexport"
                        && origin == "reexport"
                        && previous.0 == export_signature.0
                        && previous.3 == export_signature.3
                        && previous.4 == export_signature.4
                    {
                        // One declaration can be reached through two dependency
                        // routes. Keep a deterministic representative, like the
                        // equivalent enum exports normalized in f19adadba7.
                        if alias_dependency_ordinal < previous.2 {
                            exports[index] = export;
                            export_keys.insert(export_key, (export_signature, index));
                        }
                    } else if previous.1 == "declaration" && origin == "reexport" {
                        exports[index] = export;
                        export_keys.insert(export_key, (export_signature, index));
                    } else if previous.1 == "reexport" && origin == "declaration" {
                        continue;
                    } else {
                        return Err(StoreError::corrupt(format!(
                            "{}: Rust export {module_path}::{namespace}:{name} collides at declaration blob {declaration_blob_id} site {declaration_site} with different identity or re-export target: previous={previous:?}, current={export_signature:?}",
                            unit.label
                        )));
                    }
                } else {
                    let index = exports.len();
                    exports.push(export);
                    export_keys.insert(export_key, (export_signature, index));
                }
            }
        }

        let imports = self.imports(
            conn,
            topology_id,
            unit,
            &dependency_ordinals,
            &dependency_keys_by_extern,
        )?;
        for import in imports.iter().filter(|import| import.state == "unresolved") {
            gaps.entry(("unresolved_import", import.spelling.clone()))
                .or_insert_with(|| "{}".to_owned());
        }

        let gaps = gaps
            .into_iter()
            .map(|((kind, subject), detail)| UnitGap {
                kind,
                subject,
                detail,
            })
            .collect::<Vec<_>>();
        let complete = inventory_complete
            && !gaps.iter().any(|gap| {
                matches!(
                    gap.kind,
                    "unit_summary_unavailable"
                        | "unresolved_import"
                        | "unresolved_reexport"
                        | "open_export_inventory"
                        | "unresolved_visibility"
                )
            });
        Ok(UnitOutputs {
            exports,
            imports,
            gaps,
            complete,
            // Reuse the topology's producer digest so summary cutoff follows the same surface algorithm.
            public_surface_digest: Some(public_surface_digest),
        })
    }

    fn write_language_rows(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        dependencies: &[ConsumedDependency],
        summary_id: i64,
    ) -> Result<usize> {
        write_rust_summary_rows(conn, snapshot, unit, dependencies, summary_id)
    }

    fn write_language_version(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        summary_id: i64,
    ) -> Result<usize> {
        let valid_from: i64 = conn
            .query_row(
                "SELECT valid_from FROM resolution_unit_summary_versions
             WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2
               AND profile_digest = zeroblob(32) AND unit_key = ?3 AND summary_id = ?4 AND valid_until IS NULL",
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    unit.unit_key.as_slice(),
                    summary_id
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                StoreError::new(error.to_string()).context(format!(
                    "{}: reading shared summary version for key {:?}, summary {summary_id}",
                    unit.label, unit.unit_key
                ))
            })?;
        let (topology_id, manifest_file_version_id): (i64, Option<i64>) = conn
            .query_row(
                "SELECT topology_id, manifest_file_version_id FROM rust_crate_versions
             WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2
               AND crate_key = ?3 AND valid_from <= ?4
               AND (valid_until IS NULL OR ?4 < valid_until)",
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    unit.unit_key.as_slice(),
                    snapshot.revision
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| {
                StoreError::new(error.to_string()).context(format!(
                    "{}: reading manifest version for Rust topology {} at revision {}",
                    unit.label, unit.unit_id, snapshot.revision
                ))
            })?;
        conn.execute(
            "INSERT INTO rust_resolution_unit_summary_versions(
                 workspace_id, lang, generation, unit_key, valid_from, summary_id,
                 manifest_file_version_id, topology_id, profile_digest)
             VALUES(?1, 'rust', ?2, ?3, ?4, ?5, ?6, ?7, zeroblob(32))
             ON CONFLICT(workspace_id, lang, generation, unit_key, valid_from)
             DO UPDATE SET summary_id = excluded.summary_id,
                           manifest_file_version_id = excluded.manifest_file_version_id,
                           topology_id = excluded.topology_id",
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                unit.unit_key.as_slice(),
                valid_from,
                summary_id,
                manifest_file_version_id,
                topology_id
            ],
        )?;
        Ok(1)
    }
}

fn write_rust_summary_rows(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    unit: &UnitInputs,
    dependencies: &[ConsumedDependency],
    summary_id: i64,
) -> Result<usize> {
    let topology_id: i64 = conn.query_row(
        "SELECT topology_id FROM temp.rust_unit_summary_units WHERE unit_id = ?1",
        [unit.unit_id],
        |row| row.get(0),
    )?;
    for table in [
        "rust_resolution_unit_summary_gaps",
        "rust_resolution_unit_summary_contexts",
        "rust_resolution_unit_summary_containers",
        "rust_resolution_unit_summary_root_routes",
        "rust_resolution_unit_summary_trait_endpoints",
    ] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE summary_id = ?1"),
            [summary_id],
        )?;
    }
    let development_capable = rust_summary_development_capability(conn, snapshot, topology_id)?;
    // The remaining member/dependency children cascade as the shared children
    // are replaced by write_summary.
    let mut rows_written = 0;
    for sql in [
        "INSERT INTO rust_resolution_unit_summary_containers(
             summary_id, module_path, kind, placement)
             SELECT ?1, container_path, kind, placement FROM rust_crate_containers
             WHERE topology_id = ?2",
        "INSERT INTO rust_resolution_unit_summary_placements(
                 summary_id, module_path, member_ordinal, source_kind, scope_ordinal,
                 enum_scope_node_key, parent_module_path)
             SELECT ?1, sources.container_path, members.member_ordinal,
                    sources.source_kind, sources.scope_ordinal,
                    sources.enum_scope_node_key, sources.parent_container_path
             FROM rust_crate_container_sources AS sources
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id = ?1
              AND members.rel_path = sources.rel_path
              AND members.source_role = sources.source_kind
             WHERE sources.topology_id = ?2",
        "INSERT INTO rust_resolution_unit_summary_file_naming(
                 summary_id, member_ordinal, package_components, root_components)
             SELECT ?1, members.member_ordinal, naming.package_components,
                    naming.root_components
             FROM rust_crate_file_naming AS naming
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id = ?1 AND members.rel_path = naming.rel_path
             WHERE naming.topology_id = ?2",
        "INSERT INTO rust_resolution_unit_summary_gaps(summary_id, gap_kind, subject, detail)
             SELECT ?1, gap_kind, subject, detail FROM rust_crate_gaps
             WHERE topology_id = ?2 AND subject NOT LIKE 'public-module-surface:%'",
        "INSERT INTO rust_resolution_unit_summary_root_routes(
                 summary_id, member_ordinal, module_path, route_key,
                 reference_source_site, target_unit_key, target_module_path, target_name)
             SELECT ?1, members.member_ordinal, routes.module_path, routes.path_key,
                    routes.reference_source_site, routes.target_crate_key,
                    routes.target_module_path, routes.target_name
             FROM rust_crate_root_references AS routes
             JOIN rust_crate_container_sources AS sources
               ON sources.topology_id = routes.topology_id
              AND sources.container_path = routes.module_path
              AND sources.blob_id = routes.blob_id
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id = ?1 AND members.blob_id = sources.blob_id
              AND members.rel_path = sources.rel_path
              AND members.source_role = sources.source_kind
             WHERE routes.topology_id = ?2",
    ] {
        let written = conn.execute(sql, params![summary_id, topology_id])?;
        rows_written += written;
    }
    let context_written = conn.execute(
        "INSERT INTO rust_resolution_unit_summary_contexts(
             summary_id, target_kind, crate_name, edition, prelude, cfg_atoms,
             inventory_complete, development_capable)
         SELECT ?1, target_kind, crate_name, edition, prelude, cfg_atoms,
                inventory_complete, ?3
         FROM rust_crate_topologies WHERE topology_id = ?2",
        params![summary_id, topology_id, development_capable],
    )?;
    assert_eq!(
        context_written, 1,
        "{} has one Rust unit context",
        unit.label
    );
    rows_written += context_written;

    let member_ordinals = {
        let mut statement = conn.prepare_cached(
            "SELECT blob_id, rel_path, source_role, member_ordinal
             FROM resolution_unit_summary_members WHERE summary_id = ?1",
        )?;
        statement
            .query_map([summary_id], |row| {
                Ok((
                    (
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ),
                    row.get::<_, usize>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()?
    };

    let dependency_ordinals = dependencies
        .iter()
        .map(|dependency| (dependency.unit_key, dependency.ordinal))
        .collect::<HashMap<_, _>>();
    // The shared dependency rows list the unit's direct consumed dependencies.
    // A route can reach a unit they do not list: a unit reached through a
    // facade's re-export, or a sibling detached root. The route keeps the
    // target's unit key, and readers join the target's live summary by that
    // key, so such a target has no dependency ordinal.
    let dependency_ordinal_for = |target_unit_key: [u8; 32]| -> Option<usize> {
        if target_unit_key == unit.unit_key {
            None
        } else {
            dependency_ordinals.get(&target_unit_key).copied()
        }
    };
    let mut dependency_statement = conn.prepare_cached(
        "SELECT extern_name, boundary, dependency_crate_key, dependency_kind
         FROM rust_crate_dependencies WHERE topology_id = ?1 ORDER BY extern_name",
    )?;
    let mut dependency_rows = dependency_statement.query([topology_id])?;
    let mut insert_dependency_name = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_dependency_names(
             summary_id, dependency_ordinal, extern_name, dependency_kind)
         VALUES(?1, ?2, ?3, ?4)",
    )?;
    while let Some(row) = dependency_rows.next()? {
        let extern_name: String = row.get(0)?;
        let boundary: String = row.get(1)?;
        let crate_key: Option<Vec<u8>> = row.get(2)?;
        let dependency_kind: String = row.get(3)?;
        let unit_key = match (boundary.as_str(), crate_key) {
            ("workspace", Some(key)) => digest_from_row(key)?,
            ("external", None) => external_unit_key(&extern_name),
            ("std", None) => standard_unit_key(&extern_name),
            other => {
                return Err(StoreError::corrupt(format!(
                    "{}: invalid Rust dependency row for {extern_name:?}: {other:?}",
                    unit.label
                )));
            }
        };
        let ordinal = dependency_ordinals.get(&unit_key).ok_or_else(|| {
            StoreError::corrupt(format!(
                "{}: Rust dependency {extern_name:?} has no shared summary dependency row; dependencies={dependencies:?}",
                unit.label
            ))
        })?;
        insert_dependency_name.execute(params![
            summary_id,
            ordinal,
            extern_name,
            dependency_kind
        ])?;
        rows_written += 1;
    }

    // Both import readers below need only the canonical source import id.
    // Joining the base targets avoids materializing the full source view.
    let mut import_statement = conn.prepare_cached(
        "SELECT imports.module_path, imports.blob_id, imports.import_ordinal,
                imports.binder_scope, imports.namespace, imports.bound_name,
                imports.target_crate_key, imports.target_module_path, imports.target_name,
                targets.source_import_id, sources.rel_path, sources.source_kind
         FROM rust_crate_imports AS imports
         JOIN rust_crate_container_sources AS sources
           ON sources.topology_id = imports.topology_id
          AND sources.container_path = imports.module_path AND sources.blob_id = imports.blob_id
         LEFT JOIN rust_import_targets AS targets
           ON targets.blob_id = imports.blob_id AND targets.ordinal = imports.import_ordinal
         WHERE imports.topology_id = ?1
         ORDER BY imports.module_path, imports.blob_id, imports.binder_scope,
                  imports.namespace, imports.bound_name, imports.import_ordinal, sources.rel_path",
    )?;
    let mut import_rows = import_statement.query([topology_id])?;
    let mut insert_import = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_import_routes(
             summary_id, member_ordinal, import_id, route_ordinal, module_path,
             binder_scope, namespace, bound_name, target_unit_key, dependency_ordinal,
             target_module_path, target_name)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?;
    while let Some(row) = import_rows.next()? {
        let module_path: String = row.get(0)?;
        let blob_id: i64 = row.get(1)?;
        let route_ordinal: i64 = row.get(2)?;
        let binder_scope: i64 = row.get(3)?;
        let namespace: String = row.get(4)?;
        let bound_name: String = row.get(5)?;
        let target_unit_key = digest_from_row(row.get(6)?)?;
        let target_module_path: String = row.get(7)?;
        let target_name: String = row.get(8)?;
        let dependency_ordinal = dependency_ordinal_for(target_unit_key);
        let import_id: Option<i64> = row.get(9)?;
        let rel_path: String = row.get(10)?;
        let source_kind: String = row.get(11)?;
        let import_id = import_id.ok_or_else(|| {
            StoreError::corrupt(format!(
                "{}: resolved Rust import route has no source_imports.import_id: module={module_path:?}, blob={blob_id}, ordinal={route_ordinal}, name={bound_name:?}",
                unit.label
            ))
        })?;
        let member_ordinal = member_ordinals
            .get(&(blob_id, rel_path.clone(), source_kind.clone()))
            .copied()
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "{}: Rust import route has no shared member row: module={module_path:?}, blob={blob_id}, path={rel_path:?}, role={source_kind:?}",
                    unit.label
                ))
            })?;
        insert_import.execute(params![
            summary_id,
            member_ordinal,
            import_id,
            route_ordinal,
            module_path,
            binder_scope,
            namespace,
            bound_name,
            target_unit_key.as_slice(),
            dependency_ordinal,
            target_module_path,
            target_name
        ])?;
        rows_written += 1;
    }

    let mut glob_statement = conn.prepare_cached(
        "SELECT globs.module_path, globs.blob_id, globs.import_ordinal,
                globs.binder_scope, globs.target_crate_key, globs.target_module_path,
                targets.source_import_id, sources.rel_path, sources.source_kind
         FROM rust_crate_glob_imports AS globs
         JOIN rust_crate_container_sources AS sources
           ON sources.topology_id = globs.topology_id
          AND sources.container_path = globs.module_path AND sources.blob_id = globs.blob_id
         LEFT JOIN rust_import_targets AS targets
           ON targets.blob_id = globs.blob_id AND targets.ordinal = globs.import_ordinal
         WHERE globs.topology_id = ?1
         ORDER BY globs.module_path, globs.blob_id, globs.import_ordinal, sources.rel_path",
    )?;
    let mut glob_rows = glob_statement.query([topology_id])?;
    let mut insert_glob = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_glob_imports(
             summary_id, member_ordinal, source_import_id, route_ordinal, module_path,
             binder_scope, target_unit_key, dependency_ordinal, target_module_path)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    while let Some(row) = glob_rows.next()? {
        let module_path: String = row.get(0)?;
        let blob_id: i64 = row.get(1)?;
        let route_ordinal: i64 = row.get(2)?;
        let binder_scope: i64 = row.get(3)?;
        let target_unit_key = digest_from_row(row.get(4)?)?;
        let target_module_path: String = row.get(5)?;
        let dependency_ordinal = dependency_ordinal_for(target_unit_key);
        let source_import_id: Option<i64> = row.get(6)?;
        let rel_path: String = row.get(7)?;
        let source_kind: String = row.get(8)?;
        let source_import_id = source_import_id.ok_or_else(|| {
            StoreError::corrupt(format!(
                "{}: resolved Rust glob route has no source_imports.import_id: module={module_path:?}, blob={blob_id}, ordinal={route_ordinal}",
                unit.label
            ))
        })?;
        let member_ordinal = member_ordinals
            .get(&(blob_id, rel_path.clone(), source_kind.clone()))
            .copied()
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "{}: Rust glob route has no shared member row: module={module_path:?}, blob={blob_id}, path={rel_path:?}, role={source_kind:?}",
                    unit.label
                ))
            })?;
        insert_glob.execute(params![
            summary_id,
            member_ordinal,
            source_import_id,
            route_ordinal,
            module_path,
            binder_scope,
            target_unit_key.as_slice(),
            dependency_ordinal,
            target_module_path
        ])?;
        rows_written += 1;
    }

    let mut reexport_statement = conn.prepare_cached(
        "SELECT module_path, bound_name, target_crate_key, target_module_path,
                target_name, visibility, restricted_module_path
         FROM rust_crate_reexport_routes WHERE topology_id = ?1
         ORDER BY module_path, bound_name, target_crate_key, target_module_path, target_name",
    )?;
    let mut reexport_rows = reexport_statement.query([topology_id])?;
    let mut insert_reexport = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_reexport_routes(
             summary_id, module_path, bound_name, target_unit_key, dependency_ordinal,
             target_module_path, target_name, visibility, restricted_module_path)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    while let Some(row) = reexport_rows.next()? {
        let module_path: String = row.get(0)?;
        let bound_name: String = row.get(1)?;
        let target_unit_key = digest_from_row(row.get(2)?)?;
        let target_module_path: String = row.get(3)?;
        let target_name: String = row.get(4)?;
        let visibility: String = row.get(5)?;
        let restricted_module_path: Option<String> = row.get(6)?;
        let dependency_ordinal = dependency_ordinal_for(target_unit_key);
        insert_reexport.execute(params![
            summary_id,
            module_path,
            bound_name,
            target_unit_key.as_slice(),
            dependency_ordinal,
            target_module_path,
            target_name,
            visibility,
            restricted_module_path
        ])?;
        rows_written += 1;
    }

    let mut glob_reexport_statement = conn.prepare_cached(
        "SELECT module_path, target_crate_key, target_module_path, visibility,
                restricted_module_path
         FROM rust_crate_glob_reexport_routes WHERE topology_id = ?1
         ORDER BY module_path, target_crate_key, target_module_path",
    )?;
    let mut glob_reexport_rows = glob_reexport_statement.query([topology_id])?;
    let mut insert_glob_reexport = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_glob_reexport_routes(
             summary_id, module_path, target_unit_key, dependency_ordinal,
             target_module_path, visibility, restricted_module_path)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    while let Some(row) = glob_reexport_rows.next()? {
        let module_path: String = row.get(0)?;
        let target_unit_key = digest_from_row(row.get(1)?)?;
        let target_module_path: String = row.get(2)?;
        let visibility: String = row.get(3)?;
        let restricted_module_path: Option<String> = row.get(4)?;
        let dependency_ordinal = dependency_ordinal_for(target_unit_key);
        insert_glob_reexport.execute(params![
            summary_id,
            module_path,
            target_unit_key.as_slice(),
            dependency_ordinal,
            target_module_path,
            visibility,
            restricted_module_path
        ])?;
        rows_written += 1;
    }

    let mut export_statement = conn.prepare_cached(
        "SELECT module_path, namespace, name, origin, visibility,
                restricted_module_path, declaration_blob_id
         FROM rust_crate_exports WHERE topology_id = ?1
         ORDER BY module_path, namespace, name",
    )?;
    let mut export_rows = export_statement.query([topology_id])?;
    let mut insert_export = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_exports(
             summary_id, module_path, namespace, name, identity_id, visibility,
             restricted_module_path, origin, declaration_member_ordinal, declaration_site,
             alias_dependency_ordinal, target_unit_key, alias_identity_id,
             target_module_path, target_name)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
    )?;
    while let Some(row) = export_rows.next()? {
        let module_path: String = row.get(0)?;
        let namespace: String = row.get(1)?;
        let name: String = row.get(2)?;
        let origin: String = row.get(3)?;
        let visibility: String = row.get(4)?;
        let restricted_module_path: Option<String> = row.get(5)?;
        let declaration_blob_id: Option<i64> = row.get(6)?;
        let (identity_id, _) = identity_for_name(conn, &namespace, &name)?.ok_or_else(|| {
            StoreError::corrupt(format!(
                "{}: Rust summary export {module_path}::{namespace}:{name} has no identity",
                unit.label
            ))
        })?;
        let (
            declaration_member_ordinal,
            stored_site,
            alias_dependency_ordinal,
            target_unit_key,
            alias_identity_id,
            target_module_path,
            target_name,
        ) = if origin == "declaration" {
            let identities = conn
                .prepare_cached(
                    "SELECT catalog.shared_identity, catalog.identity_digest
                         FROM rust_crate_exports AS exports
                         JOIN resolution_semantic_sites AS site
                           ON site.blob_id = exports.declaration_blob_id
                          AND site.source_site = exports.declaration_site
                          AND site.semantic_role = 'definition'
                         JOIN resolution_semantic_catalog AS catalog
                           ON catalog.blob_id = site.blob_id
                          AND catalog.local_key = site.semantic_key
                         WHERE exports.topology_id = ?1 AND exports.module_path = ?2
                           AND exports.namespace = ?3 AND exports.name = ?4
                           AND exports.origin = 'declaration'",
                )?
                .query_map(params![topology_id, module_path, namespace, name], |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(
                identities.len(),
                1,
                "{}: expected one topology identity for {module_path}::{namespace}:{name}; identities={identities:?}",
                unit.label
            );
            let (shared_identity, local_identity_digest) =
                identities.into_iter().next().expect("one identity checked");
            assert_ne!(
                shared_identity.is_some(),
                local_identity_digest.is_some(),
                "{}: Rust declaration identity must be exactly shared or fragment-local: module={module_path:?}, namespace={namespace:?}, name={name:?}, shared={shared_identity:?}, local={local_identity_digest:?}",
                unit.label
            );
            let mut statement = conn.prepare_cached(
                "SELECT placement.member_ordinal, site.source_site
                     FROM rust_resolution_unit_summary_placements AS placement
                     JOIN resolution_unit_summary_members AS members
                       ON members.summary_id = placement.summary_id
                      AND members.member_ordinal = placement.member_ordinal
                     JOIN resolution_semantic_sites AS site
                       ON site.blob_id = members.blob_id
                      AND site.semantic_role = 'definition'
                     JOIN resolution_semantic_catalog AS catalog
                       ON catalog.blob_id = site.blob_id
                      AND catalog.local_key = site.semantic_key
                      AND ((?3 IS NOT NULL AND catalog.shared_identity = ?3)
                        OR (?4 IS NOT NULL AND catalog.identity_digest = ?4))
                     WHERE placement.summary_id = ?1 AND placement.module_path = ?2
                     ORDER BY placement.member_ordinal, site.source_site",
            )?;
            let mut declarations = statement
                .query_map(
                    params![
                        summary_id,
                        module_path,
                        shared_identity,
                        local_identity_digest
                    ],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            // A `#[macro_export]` macro is re-homed to the crate root while its
            // declaring file stays placed where the macro is written. The
            // declaration is that file's member, whatever module places it. A
            // macro's name is not its declaring file: a same-named module in the
            // root's file would match the root's placements, so a macro export
            // always takes its declaring file.
            if declarations.is_empty() || namespace == "macro" {
                let declaring_blob = declaration_blob_id.ok_or_else(|| {
                    StoreError::corrupt(format!(
                        "{}: Rust declaration export {module_path}::{namespace}:{name} has no declaring blob",
                        unit.label
                    ))
                })?;
                declarations = conn
                    .prepare_cached(
                        "SELECT members.member_ordinal, site.source_site
                         FROM resolution_unit_summary_members AS members
                         JOIN resolution_semantic_sites AS site
                           ON site.blob_id = members.blob_id
                          AND site.semantic_role = 'definition'
                         JOIN resolution_semantic_catalog AS catalog
                           ON catalog.blob_id = site.blob_id
                          AND catalog.local_key = site.semantic_key
                          AND ((?3 IS NOT NULL AND catalog.shared_identity = ?3)
                            OR (?4 IS NOT NULL AND catalog.identity_digest = ?4))
                         WHERE members.summary_id = ?1 AND members.blob_id = ?2
                         ORDER BY members.member_ordinal, site.source_site",
                    )?
                    .query_map(
                        params![
                            summary_id,
                            declaring_blob,
                            shared_identity,
                            local_identity_digest
                        ],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
            }
            // One declaration is one (blob, site). The same bytes at two member
            // paths declare it once; the lowest member ordinal names the export.
            let distinct_sites = declarations
                .iter()
                .map(|(_, site)| *site)
                .collect::<HashSet<_>>();
            if distinct_sites.len() != 1 {
                let candidates = conn
                    .prepare_cached(
                        "SELECT placement.member_ordinal, site.source_site,
                                    catalog.shared_identity, hex(catalog.identity_digest)
                             FROM rust_resolution_unit_summary_placements AS placement
                             JOIN resolution_unit_summary_members AS members
                               ON members.summary_id = placement.summary_id
                              AND members.member_ordinal = placement.member_ordinal
                             JOIN resolution_semantic_sites AS site
                               ON site.blob_id = members.blob_id
                              AND site.semantic_role = 'definition'
                             JOIN resolution_semantic_catalog AS catalog
                               ON catalog.blob_id = site.blob_id
                              AND catalog.local_key = site.semantic_key
                             WHERE placement.summary_id = ?1 AND placement.module_path = ?2
                             ORDER BY placement.member_ordinal, site.source_site",
                    )?
                    .query_map(params![summary_id, module_path], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                assert_eq!(
                    distinct_sites.len(),
                    1,
                    "{}: expected one live declaration for {module_path}::{namespace}:{name}; declarations={declarations:?}, candidates={candidates:?}",
                    unit.label
                );
            }
            let (member_ordinal, source_site) = declarations
                .into_iter()
                .next()
                .expect("one live declaration checked");
            (
                Some(member_ordinal),
                Some(source_site),
                None,
                None,
                None,
                None,
                None,
            )
        } else {
            let candidates = export_target_candidates(
                conn,
                snapshot,
                unit,
                topology_id,
                &module_path,
                &namespace,
                &name,
                &origin,
                &dependency_ordinals,
            )?;
            if candidates.len() > 1 && origin == "glob_reexport" {
                // Two glob imports bind this name to different declarations. Rust
                // binds neither, and a use of the name is ambiguous. The glob
                // routes keep both candidates; an export row names one target,
                // so it cannot describe this name.
                continue;
            }
            if candidates.is_empty() {
                // No live target: the name has no export row. It is the same gap
                // an unresolved re-export gets at derivation, so readers answer it
                // as incomplete rather than as a proved absence.
                conn.prepare_cached(
                    "INSERT OR IGNORE INTO rust_resolution_unit_summary_gaps(summary_id, gap_kind, subject, detail)
                     VALUES(?1, 'unresolved_reexport', ?2, jsonb('{\"reason\":\"reexport_target_unavailable\"}'))",
                )?
                .execute(params![summary_id, format!("{module_path}::{namespace}:{name}")])?;
                continue;
            }
            if candidates.len() > 1 {
                return Err(StoreError::corrupt(format!(
                    "{}: Rust re-export {module_path}::{namespace}:{name} has non-unique live targets: {candidates:?}",
                    unit.label
                )));
            }
            let target = candidates.into_iter().next().expect("one target checked");
            (
                None,
                None,
                target.dependency_ordinal,
                Some(target.target_unit_key),
                Some(target.identity.identity_id),
                Some(target.target_module_path),
                Some(target.target_name),
            )
        };
        insert_export.execute(params![
            summary_id,
            module_path,
            namespace,
            name,
            identity_id,
            visibility,
            restricted_module_path,
            origin,
            declaration_member_ordinal,
            stored_site,
            alias_dependency_ordinal,
            target_unit_key.map(|key| key.to_vec()),
            alias_identity_id,
            target_module_path,
            target_name
        ])?;
        rows_written += 1;
    }

    rows_written += conn.execute(
        "INSERT INTO rust_resolution_unit_summary_generated_names(
             summary_id, module_path, member_ordinal, invocation_occurrence_id,
             declaration_id, namespace, name, visibility, restricted_module_path,
             module_item)
         SELECT DISTINCT ?1, items.module_path, members.member_ordinal,
                items.invocation_occurrence_id, items.declaration_id, items.namespace,
                items.name, items.visibility, items.restricted_module_path,
                items.module_item
         FROM rust_crate_macro_items AS items
         JOIN rust_crate_container_sources AS sources
           ON sources.topology_id = items.topology_id
          AND sources.container_path = items.module_path AND sources.blob_id = items.blob_id
         JOIN resolution_unit_summary_members AS members
           ON members.summary_id = ?1 AND members.blob_id = sources.blob_id
          AND members.rel_path = sources.rel_path
          AND members.source_role = sources.source_kind
         WHERE items.topology_id = ?2",
        params![summary_id, topology_id],
    )?;
    rows_written += conn.execute(
        "INSERT INTO rust_resolution_unit_summary_macro_decisions(
             summary_id, member_ordinal, invocation_occurrence_id, decoration_cfg)
         SELECT DISTINCT ?1, members.member_ordinal, decisions.invocation_occurrence_id,
                decisions.decoration_cfg
         FROM rust_crate_decided_item_macros AS decisions
         JOIN rust_crate_container_sources AS sources
           ON sources.topology_id = decisions.topology_id AND sources.blob_id = decisions.blob_id
         JOIN resolution_unit_summary_members AS members
           ON members.summary_id = ?1 AND members.blob_id = sources.blob_id
          AND members.rel_path = sources.rel_path
          AND members.source_role = sources.source_kind
         WHERE decisions.topology_id = ?2",
        params![summary_id, topology_id],
    )?;
    rows_written += write_rust_trait_endpoints(
        conn,
        snapshot,
        unit,
        topology_id,
        summary_id,
        &dependency_ordinal_for,
    )?;
    rows_written += write_rust_effective_bindings(conn, snapshot, unit, summary_id)?;

    Ok(rows_written)
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
enum RustClosureDomain {
    Public,
    Crate(String),
    Module {
        crate_root: String,
        module_path: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct RustClosureBindingKey {
    member_ordinal: i64,
    module_path: String,
    name: String,
    namespace: String,
    origin_unit_key: [u8; 32],
    origin_identity_id: Option<i64>,
    origin_declaration_key: Option<i64>,
    origin_module_path: String,
    origin_name: String,
    domain: RustClosureDomain,
}

#[derive(Debug, Clone)]
struct RustClosureBinding {
    owner_unit_key: [u8; 32],
    key: RustClosureBindingKey,
    binder_scope: i64,
    route_ordinal: i64,
    first_import: Option<(i64, i64)>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct RustClosureBindingRef {
    unit_key: [u8; 32],
    module_path: String,
    name: String,
    namespace: String,
    identity_id: Option<i64>,
    declaration_key: Option<i64>,
    route_ordinal: i64,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct RustClosureProvenance {
    member_ordinal: i64,
    import_id: i64,
    import_ordinal: i64,
    route_ordinal: i64,
    target: RustClosureBindingRef,
}

#[derive(Debug, Clone)]
struct RustClosureImport {
    member_ordinal: i64,
    import_id: i64,
    import_ordinal: i64,
    binder_scope: i64,
    module_path: String,
    bound_name: Option<String>,
    namespace: Option<String>,
    target_unit_key: [u8; 32],
    target_module_path: String,
    target_name: Option<String>,
    domain: RustClosureDomain,
    importer_module: RustModuleKey,
    external_targets: Vec<RustClosureBinding>,
}

fn rust_closure_domain_from_columns(
    kind: &str,
    crate_root: Option<String>,
    module_path: Option<String>,
) -> Result<RustBindingDomain> {
    match (kind, crate_root, module_path) {
        ("public", None, None) => Ok(RustBindingDomain::Public),
        ("crate", Some(crate_root), None) => Ok(RustBindingDomain::Crate(crate_root)),
        ("module", Some(crate_root), Some(module_path)) => {
            let module = resolve_rust_module_path_with_crate(
                &crate_root,
                &crate_root,
                &module_path,
            )
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "invalid Rust summary visibility module {module_path:?} in crate {crate_root:?}"
                ))
            })?;
            Ok(RustBindingDomain::Module(RustModuleKey::with_crate_root(
                &crate_root,
                &module,
            )))
        }
        invalid => Err(StoreError::corrupt(format!(
            "invalid Rust summary binding domain {invalid:?}"
        ))),
    }
}

fn rust_closure_domain_columns(
    domain: &RustBindingDomain,
) -> (&'static str, Option<String>, Option<String>) {
    match domain {
        RustBindingDomain::Public => ("public", None, None),
        RustBindingDomain::Crate(crate_root) => ("crate", Some(crate_root.clone()), None),
        RustBindingDomain::Module(module) => (
            "module",
            Some(module.crate_root.clone()),
            Some(
                std::iter::once("crate")
                    .chain(module.components.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join("::"),
            ),
        ),
    }
}

fn rust_closure_module_key(module_path: &str, crate_root: &str) -> Result<RustModuleKey> {
    let package = resolve_rust_module_path_with_crate(crate_root, crate_root, module_path)
        .ok_or_else(|| {
            StoreError::corrupt(format!(
                "invalid Rust summary module path {module_path:?} in crate {crate_root:?}"
            ))
        })?;
    Ok(RustModuleKey::with_crate_root(crate_root, &package))
}

fn rust_closure_namespace_matches(import: Option<&str>, binding: &str) -> bool {
    import.is_none_or(|namespace| {
        namespace == binding || (namespace == "type" && binding == "module")
    })
}

fn rust_closure_binding_reference(binding: &RustClosureBinding) -> RustClosureBindingRef {
    RustClosureBindingRef {
        unit_key: binding.owner_unit_key,
        module_path: binding.key.module_path.clone(),
        name: binding.key.name.clone(),
        namespace: binding.key.namespace.clone(),
        identity_id: binding.key.origin_identity_id,
        declaration_key: binding.key.origin_declaration_key,
        route_ordinal: binding.route_ordinal,
    }
}

fn rust_closure_intersection(
    target: &RustBindingDomain,
    edge: &RustBindingDomain,
) -> Option<RustBindingDomain> {
    target.intersect(edge)
}

fn rust_closure_insert_binding(
    bindings: &mut BTreeMap<RustClosureBindingKey, RustClosureBinding>,
    next_route_ordinal: &mut i64,
    key: RustClosureBindingKey,
    binder_scope: i64,
    owner_unit_key: [u8; 32],
    first_import: Option<(i64, i64)>,
) -> (i64, bool) {
    if let Some(binding) = bindings.get(&key) {
        return (binding.route_ordinal, false);
    }
    let route_ordinal = *next_route_ordinal;
    *next_route_ordinal += 1;
    let binding = RustClosureBinding {
        owner_unit_key,
        key: key.clone(),
        binder_scope,
        route_ordinal,
        first_import,
    };
    assert!(bindings.insert(key, binding).is_none());
    (route_ordinal, true)
}

fn read_live_rust_closure_bindings(
    conn: &Connection,
    summary_id: i64,
    unit_key: [u8; 32],
    module_path: &str,
    name: Option<&str>,
) -> Result<Vec<RustClosureBinding>> {
    let sql = if name.is_some() {
        "SELECT member_ordinal, module_path, binder_scope, name, namespace,
                visibility_kind, visibility_crate_root, visibility_module_path,
                target_unit_key, target_identity_id, target_declaration_key,
                target_module_path, target_name, route_provenance_ordinal,
                source_import_id, source_import_ordinal
         FROM rust_resolution_unit_summary_effective_bindings
         WHERE summary_id = ?1 AND module_path = ?2 AND name = ?3
         ORDER BY name, namespace, route_provenance_ordinal"
    } else {
        "SELECT member_ordinal, module_path, binder_scope, name, namespace,
                visibility_kind, visibility_crate_root, visibility_module_path,
                target_unit_key, target_identity_id, target_declaration_key,
                target_module_path, target_name, route_provenance_ordinal,
                source_import_id, source_import_ordinal
         FROM rust_resolution_unit_summary_effective_bindings
         WHERE summary_id = ?1 AND module_path = ?2
         ORDER BY name, namespace, route_provenance_ordinal"
    };
    let mut statement = conn.prepare_cached(sql)?;
    let mut rows = if let Some(name) = name {
        statement.query(params![summary_id, module_path, name])?
    } else {
        statement.query(params![summary_id, module_path])?
    };
    let mut bindings = Vec::new();
    while let Some(row) = rows.next()? {
        let namespace: String = row.get(4)?;
        let domain =
            rust_closure_domain_from_columns(&row.get::<_, String>(5)?, row.get(6)?, row.get(7)?)?;
        let origin_unit_key = digest_from_row(row.get(8)?)?;
        let target_identity_id: Option<i64> = row.get(9)?;
        let target_declaration_key: Option<i64> = row.get(10)?;
        assert_ne!(
            target_identity_id.is_some(),
            target_declaration_key.is_some(),
            "one Rust closure binding has exactly one stable declaration key"
        );
        let key = RustClosureBindingKey {
            member_ordinal: row.get(0)?,
            module_path: row.get(1)?,
            name: row.get(3)?,
            namespace,
            origin_unit_key,
            origin_identity_id: target_identity_id,
            origin_declaration_key: target_declaration_key,
            origin_module_path: row.get(11)?,
            origin_name: row.get(12)?,
            domain: match domain {
                RustBindingDomain::Public => RustClosureDomain::Public,
                RustBindingDomain::Crate(crate_root) => RustClosureDomain::Crate(crate_root),
                RustBindingDomain::Module(module) => RustClosureDomain::Module {
                    crate_root: module.crate_root,
                    module_path: std::iter::once("crate")
                        .chain(module.components.iter().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join("::"),
                },
            },
        };
        let source_import_id: Option<i64> = row.get(14)?;
        let source_import_ordinal: Option<i64> = row.get(15)?;
        assert_eq!(
            source_import_id.is_some(),
            source_import_ordinal.is_some(),
            "one Rust closure binding has both or neither source import coordinates"
        );
        bindings.push(RustClosureBinding {
            owner_unit_key: unit_key,
            key,
            binder_scope: row.get(2)?,
            route_ordinal: row.get(13)?,
            first_import: source_import_id.zip(source_import_ordinal),
        });
    }
    Ok(bindings)
}

fn rust_closure_live_summary_id(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    unit_key: [u8; 32],
) -> Result<Option<i64>> {
    Ok(conn
        .prepare_cached(
            "SELECT versions.summary_id
             FROM resolution_unit_summary_versions AS versions
             JOIN resolution_unit_summaries AS summaries
               ON summaries.summary_id = versions.summary_id
             JOIN rust_resolution_unit_summary_versions AS rust_versions
               ON rust_versions.workspace_id = versions.workspace_id
              AND rust_versions.lang = versions.lang
              AND rust_versions.generation = versions.generation
              AND rust_versions.unit_key = versions.unit_key
              AND rust_versions.valid_from = versions.valid_from
              AND rust_versions.summary_id = versions.summary_id
             WHERE versions.workspace_id = ?1 AND versions.lang = 'rust'
               AND versions.generation = ?2 AND versions.unit_key = ?3
               AND versions.valid_from <= ?4
               AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)
               AND summaries.lang = 'rust' AND summaries.unit_kind = 'rust_crate'
               AND summaries.derivation_version = ?5
               AND summaries.publication_state = 'complete'",
        )?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                unit_key.as_slice(),
                snapshot.revision,
                RUST_UNIT_SUMMARY_DERIVATION_VERSION
            ],
            |row| row.get(0),
        )
        .optional()?)
}

fn write_rust_effective_bindings(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    unit: &UnitInputs,
    summary_id: i64,
) -> Result<usize> {
    let mut rows_written = 0;
    for table in [
        "rust_resolution_unit_summary_effective_bindings",
        "rust_resolution_unit_summary_import_route_provenance",
        "rust_resolution_unit_summary_binding_completeness",
    ] {
        rows_written += conn.execute(
            &format!("DELETE FROM {table} WHERE summary_id = ?1"),
            [summary_id],
        )?;
    }

    let members = {
        let mut statement = conn.prepare_cached(
            "SELECT members.member_ordinal, members.blob_id, members.rel_path,
                    json(naming.package_components), json(naming.root_components)
             FROM resolution_unit_summary_members AS members
             JOIN rust_resolution_unit_summary_file_naming AS naming
               ON naming.summary_id = members.summary_id
              AND naming.member_ordinal = members.member_ordinal
             WHERE members.summary_id = ?1 ORDER BY members.member_ordinal",
        )?;
        statement
            .query_map([summary_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut member_identity: HashMap<i64, RustPathIdentity> = HashMap::default();
    for (ordinal, _, _, package_json, root_json) in &members {
        let package: Vec<String> = serde_json::from_str(package_json).map_err(|error| {
            StoreError::corrupt(format!(
                "invalid Rust member package components {package_json:?}: {error}"
            ))
        })?;
        let root: Vec<String> = serde_json::from_str(root_json).map_err(|error| {
            StoreError::corrupt(format!(
                "invalid Rust member root components {root_json:?}: {error}"
            ))
        })?;
        member_identity.insert(
            *ordinal,
            RustPathIdentity {
                package: package.join("."),
                crate_root_package: root.join("."),
            },
        );
    }
    let root_member: Option<i64> = conn
        .query_row(
            "SELECT member_ordinal FROM rust_resolution_unit_summary_placements
             WHERE summary_id = ?1 AND module_path = 'crate'
             ORDER BY member_ordinal LIMIT 1",
            [summary_id],
            |row| row.get(0),
        )
        .optional()?;

    let mut bindings = BTreeMap::new();
    let mut next_route_ordinal = 0_i64;
    let mut provenance = BTreeSet::new();
    {
        let mut statement = conn.prepare_cached(
            "SELECT exports.module_path, exports.namespace, exports.name,
                    exports.identity_id, exports.visibility,
                    exports.restricted_module_path, exports.declaration_member_ordinal
             FROM rust_resolution_unit_summary_exports AS exports
             WHERE exports.summary_id = ?1 AND exports.origin = 'declaration'
               AND NOT (exports.namespace = 'type' AND EXISTS (
                 SELECT 1
                 FROM resolution_unit_summary_members AS members
                 JOIN source_native_declaration_bridges AS bridges
                   ON bridges.blob_id = members.blob_id
                 JOIN source_rust_module_declarations AS modules
                   ON modules.blob_id = bridges.blob_id
                  AND modules.declaration_id = bridges.declaration_id
                 JOIN rust_resolution_unit_summary_placements AS placements
                   ON placements.summary_id = members.summary_id
                  AND placements.member_ordinal = members.member_ordinal
                  AND placements.module_path = exports.module_path
                 WHERE members.summary_id = exports.summary_id
                   AND members.member_ordinal = exports.declaration_member_ordinal
                   AND bridges.source_site = exports.declaration_site
                   AND modules.module_name = exports.name
               ))
             ORDER BY exports.declaration_member_ordinal, exports.module_path,
                      exports.namespace, exports.name",
        )?;
        let mut rows = statement.query([summary_id])?;
        while let Some(row) = rows.next()? {
            let module_path: String = row.get(0)?;
            let namespace: String = row.get(1)?;
            let name: String = row.get(2)?;
            let identity_id: i64 = row.get(3)?;
            let visibility: String = row.get(4)?;
            let restricted_module_path: Option<String> = row.get(5)?;
            let member_ordinal: i64 = row.get(6)?;
            let identity = member_identity.get(&member_ordinal).ok_or_else(|| {
                StoreError::corrupt(format!(
                    "Rust declaration export has no member identity: member={member_ordinal}, path={module_path:?}, name={name:?}"
                ))
            })?;
            let root = &identity.crate_root_package;
            let domain = match visibility.as_str() {
                "public" => RustBindingDomain::Public,
                "crate" => RustBindingDomain::Crate(root.clone()),
                "private" => {
                    RustBindingDomain::Module(rust_closure_module_key(&module_path, root)?)
                }
                "restricted" => RustBindingDomain::Module(rust_closure_module_key(
                    restricted_module_path
                        .as_deref()
                        .expect("restricted path checked"),
                    root,
                )?),
                other => {
                    return Err(StoreError::corrupt(format!(
                        "invalid Rust export visibility {other:?}"
                    )));
                }
            };
            let key = RustClosureBindingKey {
                member_ordinal,
                module_path: module_path.clone(),
                name: name.clone(),
                namespace: namespace.clone(),
                origin_unit_key: unit.unit_key,
                origin_identity_id: Some(identity_id),
                origin_declaration_key: None,
                origin_module_path: module_path,
                origin_name: name,
                domain: match domain {
                    RustBindingDomain::Public => RustClosureDomain::Public,
                    RustBindingDomain::Crate(crate_root) => RustClosureDomain::Crate(crate_root),
                    RustBindingDomain::Module(module) => RustClosureDomain::Module {
                        crate_root: module.crate_root,
                        module_path: std::iter::once("crate")
                            .chain(module.components.iter().map(String::as_str))
                            .collect::<Vec<_>>()
                            .join("::"),
                    },
                },
            };
            let _ = rust_closure_insert_binding(
                &mut bindings,
                &mut next_route_ordinal,
                key,
                -1,
                unit.unit_key,
                None,
            );
        }
    }

    {
        let mut statement = conn.prepare_cached(
            "SELECT child.module_path, placement.parent_module_path,
                    parent.member_ordinal, declaration.declaration_id,
                    declaration.module_name, property.visibility
             FROM rust_resolution_unit_summary_containers AS child
             JOIN rust_resolution_unit_summary_placements AS placement
               ON placement.summary_id = child.summary_id
              AND placement.module_path = child.module_path
             JOIN rust_resolution_unit_summary_placements AS parent_placement
               ON parent_placement.summary_id = child.summary_id
              AND parent_placement.module_path = placement.parent_module_path
             JOIN resolution_unit_summary_members AS parent
               ON parent.summary_id = parent_placement.summary_id
              AND parent.member_ordinal = parent_placement.member_ordinal
             JOIN source_rust_module_declarations AS declaration
               ON declaration.blob_id = parent.blob_id
              AND child.module_path = placement.parent_module_path || '::' || declaration.module_name
             JOIN source_rust_declaration_properties AS property
               ON property.blob_id = declaration.blob_id
              AND property.declaration_id = declaration.declaration_id
             WHERE child.summary_id = ?1 AND child.kind = 'module'
               AND child.module_path <> 'crate'
             ORDER BY parent.member_ordinal, placement.parent_module_path,
                      declaration.module_name, declaration.declaration_id",
        )?;
        let mut rows = statement.query([summary_id])?;
        while let Some(row) = rows.next()? {
            let child_module_path: String = row.get(0)?;
            let parent_module_path: String = row.get(1)?;
            let member_ordinal: i64 = row.get(2)?;
            let declaration_key: i64 = row.get(3)?;
            let name: String = row.get(4)?;
            let visibility: String = row.get(5)?;
            let identity = member_identity.get(&member_ordinal).ok_or_else(|| {
                StoreError::corrupt(format!(
                    "Rust module declaration has no member path identity: member={member_ordinal}, module={child_module_path:?}"
                ))
            })?;
            let owner_package = resolve_rust_module_path_with_crate(
                &identity.crate_root_package,
                &identity.crate_root_package,
                &parent_module_path,
            )
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "invalid Rust parent module path {parent_module_path:?}"
                ))
            })?;
            let Some(domain) = direct_import_scope_for_module_with_identity(
                &owner_package,
                decode_rust_visibility(&visibility).ok_or_else(|| {
                    StoreError::corrupt(format!(
                        "invalid Rust module visibility {visibility:?} for {child_module_path:?}"
                    ))
                })?,
                root_member == Some(member_ordinal),
                identity,
            ) else {
                continue;
            };
            let domain = match domain {
                RustBindingDomain::Public => RustClosureDomain::Public,
                RustBindingDomain::Crate(crate_root) => RustClosureDomain::Crate(crate_root),
                RustBindingDomain::Module(module) => RustClosureDomain::Module {
                    crate_root: module.crate_root,
                    module_path: std::iter::once("crate")
                        .chain(module.components.iter().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join("::"),
                },
            };
            let key = RustClosureBindingKey {
                member_ordinal,
                module_path: parent_module_path.clone(),
                name: name.clone(),
                namespace: "module".to_owned(),
                origin_unit_key: unit.unit_key,
                origin_identity_id: None,
                origin_declaration_key: Some(declaration_key),
                origin_module_path: parent_module_path,
                origin_name: name,
                domain,
            };
            let _ = rust_closure_insert_binding(
                &mut bindings,
                &mut next_route_ordinal,
                key,
                -1,
                unit.unit_key,
                None,
            );
        }
    }

    let mut child_summary_ids: HashMap<[u8; 32], Option<i64>> = HashMap::default();
    let mut summary_for_target = |key| -> Result<Option<i64>> {
        if let Some(summary) = child_summary_ids.get(&key) {
            return Ok(*summary);
        }
        let summary = rust_closure_live_summary_id(conn, snapshot, key)?;
        child_summary_ids.insert(key, summary);
        Ok(summary)
    };

    let mut imports = Vec::new();
    {
        let mut statement = conn.prepare_cached(
            "SELECT routes.member_ordinal, routes.import_id, routes.route_ordinal,
                    routes.binder_scope, routes.module_path, routes.namespace,
                    routes.bound_name, routes.target_unit_key,
                    routes.target_module_path, routes.target_name,
                    targets.visibility, targets.local_start, targets.is_extern_crate
             FROM rust_resolution_unit_summary_import_routes AS routes
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id = routes.summary_id
              AND members.member_ordinal = routes.member_ordinal
             JOIN source_rust_import_targets AS targets
               ON targets.blob_id = members.blob_id
              AND targets.source_import_id = routes.import_id
             WHERE routes.summary_id = ?1
             ORDER BY routes.member_ordinal, routes.import_id,
                      routes.route_ordinal, routes.namespace, routes.bound_name",
        )?;
        let mut rows = statement.query([summary_id])?;
        while let Some(row) = rows.next()? {
            let member_ordinal: i64 = row.get(0)?;
            let import_id: i64 = row.get(1)?;
            let import_ordinal: i64 = row.get(2)?;
            let binder_scope: i64 = row.get(3)?;
            let module_path: String = row.get(4)?;
            let namespace: String = row.get(5)?;
            let bound_name: String = row.get(6)?;
            let target_unit_key = digest_from_row(row.get(7)?)?;
            let target_module_path: String = row.get(8)?;
            let target_name: String = row.get(9)?;
            let visibility: String = row.get(10)?;
            let local_start: Option<i64> = row.get(11)?;
            let is_extern_crate: bool = row.get(12)?;
            if local_start.is_some() || is_extern_crate || target_name == "self" {
                continue;
            }
            let identity = member_identity.get(&member_ordinal).ok_or_else(|| {
                StoreError::corrupt(format!(
                    "Rust import route has no member path identity: member={member_ordinal}, import_id={import_id}"
                ))
            })?;
            let owner_package = resolve_rust_module_path_with_crate(
                &identity.crate_root_package,
                &identity.crate_root_package,
                &module_path,
            )
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "invalid Rust import owner module path {module_path:?}"
                ))
            })?;
            let Some(domain) = direct_import_scope_for_module_with_identity(
                &owner_package,
                decode_rust_visibility(&visibility).ok_or_else(|| {
                    StoreError::corrupt(format!(
                        "invalid Rust import visibility {visibility:?} for import {import_id}"
                    ))
                })?,
                root_member == Some(member_ordinal),
                identity,
            ) else {
                continue;
            };
            let target_domain = match domain {
                RustBindingDomain::Public => RustClosureDomain::Public,
                RustBindingDomain::Crate(crate_root) => RustClosureDomain::Crate(crate_root),
                RustBindingDomain::Module(module) => RustClosureDomain::Module {
                    crate_root: module.crate_root,
                    module_path: std::iter::once("crate")
                        .chain(module.components.iter().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join("::"),
                },
            };
            let crate_root = &identity.crate_root_package;
            let importer_module = rust_closure_module_key(&module_path, crate_root)?;
            let mut route = RustClosureImport {
                member_ordinal,
                import_id,
                import_ordinal,
                binder_scope,
                module_path,
                bound_name: Some(bound_name),
                namespace: Some(namespace),
                target_unit_key,
                target_module_path,
                target_name: Some(target_name),
                domain: target_domain,
                importer_module,
                external_targets: Vec::new(),
            };
            if route.target_unit_key != unit.unit_key
                && let Some(child_summary_id) = summary_for_target(route.target_unit_key)?
            {
                route.external_targets = read_live_rust_closure_bindings(
                    conn,
                    child_summary_id,
                    route.target_unit_key,
                    &route.target_module_path,
                    route.target_name.as_deref(),
                )?;
                route.external_targets.retain(|binding| {
                    rust_closure_namespace_matches(
                        route.namespace.as_deref(),
                        &binding.key.namespace,
                    )
                });
            }
            imports.push(route);
        }
    }
    {
        let mut statement = conn.prepare_cached(
            "SELECT globs.member_ordinal, globs.source_import_id, globs.route_ordinal,
                    globs.binder_scope, globs.module_path, globs.target_unit_key,
                    globs.target_module_path, targets.visibility, targets.local_start
             FROM rust_resolution_unit_summary_glob_imports AS globs
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id = globs.summary_id
              AND members.member_ordinal = globs.member_ordinal
             JOIN source_rust_import_targets AS targets
               ON targets.blob_id = members.blob_id
              AND targets.source_import_id = globs.source_import_id
             WHERE globs.summary_id = ?1
             ORDER BY globs.member_ordinal, globs.source_import_id,
                      globs.route_ordinal, globs.module_path",
        )?;
        let mut rows = statement.query([summary_id])?;
        while let Some(row) = rows.next()? {
            let member_ordinal: i64 = row.get(0)?;
            let import_id: i64 = row.get(1)?;
            let import_ordinal: i64 = row.get(2)?;
            let binder_scope: i64 = row.get(3)?;
            let module_path: String = row.get(4)?;
            let target_unit_key = digest_from_row(row.get(5)?)?;
            let target_module_path: String = row.get(6)?;
            let visibility: String = row.get(7)?;
            let local_start: Option<i64> = row.get(8)?;
            if local_start.is_some() {
                continue;
            }
            let identity = member_identity.get(&member_ordinal).ok_or_else(|| {
                StoreError::corrupt(format!(
                    "Rust glob route has no member path identity: member={member_ordinal}, import_id={import_id}"
                ))
            })?;
            let owner_package = resolve_rust_module_path_with_crate(
                &identity.crate_root_package,
                &identity.crate_root_package,
                &module_path,
            )
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "invalid Rust glob owner module path {module_path:?}"
                ))
            })?;
            let Some(domain) = direct_import_scope_for_module_with_identity(
                &owner_package,
                decode_rust_visibility(&visibility).ok_or_else(|| {
                    StoreError::corrupt(format!(
                        "invalid Rust glob visibility {visibility:?} for import {import_id}"
                    ))
                })?,
                root_member == Some(member_ordinal),
                identity,
            ) else {
                continue;
            };
            let target_domain = match domain {
                RustBindingDomain::Public => RustClosureDomain::Public,
                RustBindingDomain::Crate(crate_root) => RustClosureDomain::Crate(crate_root),
                RustBindingDomain::Module(module) => RustClosureDomain::Module {
                    crate_root: module.crate_root,
                    module_path: std::iter::once("crate")
                        .chain(module.components.iter().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join("::"),
                },
            };
            let mut route = RustClosureImport {
                member_ordinal,
                import_id,
                import_ordinal,
                binder_scope,
                module_path: module_path.clone(),
                bound_name: None,
                namespace: None,
                target_unit_key,
                target_module_path,
                target_name: None,
                domain: target_domain,
                importer_module: rust_closure_module_key(
                    &module_path,
                    &identity.crate_root_package,
                )?,
                external_targets: Vec::new(),
            };
            if route.target_unit_key != unit.unit_key
                && let Some(child_summary_id) = summary_for_target(route.target_unit_key)?
            {
                route.external_targets = read_live_rust_closure_bindings(
                    conn,
                    child_summary_id,
                    route.target_unit_key,
                    &route.target_module_path,
                    None,
                )?;
            }
            imports.push(route);
        }
    }
    imports.sort_by(|left, right| {
        left.member_ordinal
            .cmp(&right.member_ordinal)
            .then_with(|| left.import_id.cmp(&right.import_id))
            .then_with(|| left.import_ordinal.cmp(&right.import_ordinal))
            .then_with(|| left.target_unit_key.cmp(&right.target_unit_key))
            .then_with(|| left.target_module_path.cmp(&right.target_module_path))
    });

    let mut unresolved_complete = BTreeSet::new();
    loop {
        let mut inserted_any = false;
        let mut pending_provenance = BTreeSet::new();
        for import in &imports {
            let candidates = if import.target_unit_key == unit.unit_key {
                bindings
                    .values()
                    .filter(|binding| {
                        binding.key.module_path == import.target_module_path
                            && import
                                .target_name
                                .as_deref()
                                .is_none_or(|name| binding.key.name == name)
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                import.external_targets.clone()
            };
            for candidate in candidates {
                if import.namespace.as_deref().is_some_and(|namespace| {
                    !rust_closure_namespace_matches(Some(namespace), &candidate.key.namespace)
                }) {
                    continue;
                }
                let target_domain = rust_closure_domain_from_columns(
                    match &candidate.key.domain {
                        RustClosureDomain::Public => "public",
                        RustClosureDomain::Crate(_) => "crate",
                        RustClosureDomain::Module { .. } => "module",
                    },
                    match &candidate.key.domain {
                        RustClosureDomain::Crate(root)
                        | RustClosureDomain::Module {
                            crate_root: root, ..
                        } => Some(root.clone()),
                        RustClosureDomain::Public => None,
                    },
                    match &candidate.key.domain {
                        RustClosureDomain::Module { module_path, .. } => Some(module_path.clone()),
                        _ => None,
                    },
                )?;
                let edge_domain = rust_closure_domain_from_columns(
                    match &import.domain {
                        RustClosureDomain::Public => "public",
                        RustClosureDomain::Crate(_) => "crate",
                        RustClosureDomain::Module { .. } => "module",
                    },
                    match &import.domain {
                        RustClosureDomain::Crate(root)
                        | RustClosureDomain::Module {
                            crate_root: root, ..
                        } => Some(root.clone()),
                        RustClosureDomain::Public => None,
                    },
                    match &import.domain {
                        RustClosureDomain::Module { module_path, .. } => Some(module_path.clone()),
                        _ => None,
                    },
                )?;
                let effective_domain = rust_closure_intersection(&target_domain, &edge_domain);
                let Some(effective_domain) = effective_domain else {
                    continue;
                };
                if !effective_domain.contains_module(&import.importer_module) {
                    continue;
                }
                let alias_name = import
                    .bound_name
                    .as_deref()
                    .unwrap_or(candidate.key.name.as_str())
                    .to_owned();
                let domain = match effective_domain {
                    RustBindingDomain::Public => RustClosureDomain::Public,
                    RustBindingDomain::Crate(crate_root) => RustClosureDomain::Crate(crate_root),
                    RustBindingDomain::Module(module) => RustClosureDomain::Module {
                        crate_root: module.crate_root,
                        module_path: std::iter::once("crate")
                            .chain(module.components.iter().map(String::as_str))
                            .collect::<Vec<_>>()
                            .join("::"),
                    },
                };
                let key = RustClosureBindingKey {
                    member_ordinal: import.member_ordinal,
                    module_path: import.module_path.clone(),
                    name: alias_name,
                    namespace: candidate.key.namespace.clone(),
                    origin_unit_key: candidate.key.origin_unit_key,
                    origin_identity_id: candidate.key.origin_identity_id,
                    origin_declaration_key: candidate.key.origin_declaration_key,
                    origin_module_path: candidate.key.origin_module_path.clone(),
                    origin_name: candidate.key.origin_name.clone(),
                    domain,
                };
                let (route_ordinal, inserted) = rust_closure_insert_binding(
                    &mut bindings,
                    &mut next_route_ordinal,
                    key,
                    import.binder_scope,
                    unit.unit_key,
                    Some((import.import_id, import.import_ordinal)),
                );
                inserted_any |= inserted;
                pending_provenance.insert(RustClosureProvenance {
                    member_ordinal: import.member_ordinal,
                    import_id: import.import_id,
                    import_ordinal: import.import_ordinal,
                    route_ordinal,
                    target: rust_closure_binding_reference(&candidate),
                });
            }
        }
        provenance.extend(pending_provenance);
        if !inserted_any {
            break;
        }
    }

    {
        let mut statement = conn.prepare_cached(
            "SELECT members.member_ordinal, targets.module_path
             FROM resolution_unit_summary_members AS members
             JOIN source_rust_import_targets AS targets ON targets.blob_id = members.blob_id
             WHERE members.summary_id = ?1 AND targets.is_glob = 1
               AND NOT EXISTS (
                 SELECT 1 FROM rust_resolution_unit_summary_glob_imports AS routes
                 WHERE routes.summary_id = members.summary_id
                   AND routes.member_ordinal = members.member_ordinal
                   AND routes.source_import_id = targets.source_import_id
               )",
        )?;
        for row in statement.query_map([summary_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })? {
            let (member, subject) = row?;
            unresolved_complete.insert((member, "unresolved_import".to_owned(), subject));
        }
    }

    for import in &imports {
        let found = if import.target_unit_key == unit.unit_key {
            bindings.values().any(|binding| {
                binding.key.module_path == import.target_module_path
                    && import
                        .target_name
                        .as_deref()
                        .is_none_or(|name| binding.key.name == name)
                    && import
                        .namespace
                        .as_deref()
                        .is_none_or(|namespace| binding.key.namespace == namespace)
            })
        } else {
            !import.external_targets.is_empty()
        };
        // A named import binds its name whether or not its target resolves, so
        // its surface is known; only a glob's unresolved target leaves the names
        // it would bind unknown.
        if !found && import.bound_name.is_none() {
            unresolved_complete.insert((
                import.member_ordinal,
                "unresolved_import".to_owned(),
                import.module_path.clone(),
            ));
        }
    }

    let mut insert_binding = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_effective_bindings(
             summary_id, member_ordinal, module_path, binder_scope, name, namespace,
             visibility_kind, visibility_crate_root, visibility_module_path,
             target_unit_key, target_identity_id, target_declaration_key,
             target_module_path, target_name, route_provenance_ordinal,
             source_import_id, source_import_ordinal)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
    )?;
    for binding in bindings.values() {
        let (visibility_kind, visibility_crate_root, visibility_module_path) =
            rust_closure_domain_columns(&match &binding.key.domain {
                RustClosureDomain::Public => RustBindingDomain::Public,
                RustClosureDomain::Crate(crate_root) => {
                    RustBindingDomain::Crate(crate_root.clone())
                }
                RustClosureDomain::Module {
                    crate_root,
                    module_path,
                } => rust_closure_domain_from_columns(
                    "module",
                    Some(crate_root.clone()),
                    Some(module_path.clone()),
                )?,
            });
        let source = binding.first_import;
        insert_binding.execute(params![
            summary_id,
            binding.key.member_ordinal,
            binding.key.module_path,
            binding.binder_scope,
            binding.key.name,
            binding.key.namespace,
            visibility_kind,
            visibility_crate_root,
            visibility_module_path,
            binding.key.origin_unit_key.as_slice(),
            binding.key.origin_identity_id,
            binding.key.origin_declaration_key,
            binding.key.origin_module_path,
            binding.key.origin_name,
            binding.route_ordinal,
            source.map(|(import_id, _)| import_id),
            source.map(|(_, import_ordinal)| import_ordinal)
        ])?;
        rows_written += 1;
    }
    let mut insert_provenance = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_import_route_provenance(
             summary_id, member_ordinal, import_id, import_ordinal,
             route_provenance_ordinal, hop_ordinal, target_unit_key,
             target_binding_module_path, target_binding_name, namespace,
             target_identity_id, target_declaration_key,
             target_route_provenance_ordinal)
         VALUES(?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?;
    for route in provenance {
        insert_provenance.execute(params![
            summary_id,
            route.member_ordinal,
            route.import_id,
            route.import_ordinal,
            route.route_ordinal,
            route.target.unit_key.as_slice(),
            route.target.module_path,
            route.target.name,
            route.target.namespace,
            route.target.identity_id,
            route.target.declaration_key,
            route.target.route_ordinal
        ])?;
        rows_written += 1;
    }

    let gaps = {
        let mut statement = conn.prepare_cached(
            "SELECT gap_kind, subject FROM rust_resolution_unit_summary_gaps
             WHERE summary_id = ?1 ORDER BY gap_kind, subject",
        )?;
        statement
            .query_map([summary_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut insert_completeness = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_binding_completeness(
             summary_id, member_ordinal, complete, gap_kind, gap_subject)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    for (member_ordinal, ..) in &members {
        // Named unresolved imports are not gaps for the surface: their bound names
        // are known. Unresolved globs are added from `unresolved_complete` below.
        let mut member_gaps: BTreeSet<(String, String)> = gaps
            .iter()
            // A missing module has no names to inject into another member.
            // Its named declaration and failed lookup stay known. Unresolved
            // glob expansion is the member-local gap recorded separately.
            .filter(|(kind, _)| !matches!(kind.as_str(), "unresolved_import" | "unplaced_module"))
            .cloned()
            .collect();
        member_gaps.extend(
            unresolved_complete
                .iter()
                .filter(|(member, _, _)| member == member_ordinal)
                .map(|(_, kind, subject)| (kind.clone(), subject.clone())),
        );
        if member_gaps.is_empty() {
            insert_completeness.execute(params![summary_id, member_ordinal, 1, "complete", ""])?;
            rows_written += 1;
        } else {
            for (kind, subject) in member_gaps {
                insert_completeness.execute(params![
                    summary_id,
                    member_ordinal,
                    0,
                    kind,
                    subject
                ])?;
                rows_written += 1;
            }
        }
    }
    Ok(rows_written)
}

fn rust_summary_development_capability(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    topology_id: i64,
) -> Result<bool> {
    let (target_kind, crate_name, manifest_file_version_id, manifest_bytes): (
        String,
        String,
        Option<i64>,
        Option<Vec<u8>>,
    ) = conn.query_row(
        DEVELOPMENT_CAPABILITY_SQL,
        params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.get(),
            snapshot.revision,
            topology_id
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(manifest_file_version_id.is_some(), manifest_bytes.is_some());
    let Some(manifest_bytes) = manifest_bytes else {
        assert_eq!(target_kind, "detached");
        return Ok(false);
    };
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .map_err(|error| StoreError::corrupt(format!("Cargo manifest is not UTF-8: {error}")))?;
    let manifest: toml::Value = toml::from_str(manifest_text)
        .map_err(|error| StoreError::corrupt(format!("invalid Cargo manifest: {error}")))?;
    let development_capable = match target_kind.as_str() {
        "lib" => manifest
            .get("lib")
            .and_then(|target| target.get("test"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(true),
        "bin" => manifest
            .get("bin")
            .and_then(toml::Value::as_array)
            .and_then(|targets| {
                targets.iter().find(|target| {
                    target
                        .get("name")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|name| name.replace('-', "_") == crate_name)
                })
            })
            .and_then(|target| target.get("test"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(true),
        "example" | "test" | "bench" => true,
        "build" => false,
        "detached" => unreachable!("detached Rust topology has no manifest"),
        kind => panic!("unknown Rust target kind {kind:?}"),
    };
    Ok(development_capable)
}

fn write_rust_trait_endpoints(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    unit: &UnitInputs,
    topology_id: i64,
    summary_id: i64,
    dependency_ordinal_for: &impl Fn([u8; 32]) -> Option<usize>,
) -> Result<usize> {
    const RESOLVED_ENDPOINTS_SQL: &str = "WITH impl_placements AS (
        SELECT impls.*, owners.container_path AS owner_module_path,
               members.member_ordinal, relation.relation_key,
               relation.impl_start_byte, relation.impl_end_byte,
               relation.terminal_spelling AS subject_spelling,
               (SELECT trait_side.terminal_spelling
                  FROM resolution_trait_implementations AS trait_side
                 WHERE trait_side.blob_id = relation.blob_id
                   AND trait_side.relation_key = relation.relation_key
                   AND trait_side.side = 'trait'
                   AND trait_side.terminal_spelling IS NOT NULL) AS trait_spelling
          FROM rust_crate_trait_impls AS impls
          JOIN resolution_trait_implementations AS relation
            ON relation.blob_id = impls.impl_blob_id AND relation.impl_site = impls.impl_site
           AND relation.side = 'subject' AND relation.terminal_spelling IS NOT NULL
          JOIN rust_crate_container_sources AS owners
            ON owners.topology_id = impls.topology_id
           AND owners.blob_id = impls.impl_blob_id AND owners.rel_path = impls.impl_rel_path
          JOIN resolution_unit_summary_members AS members
            ON members.summary_id = ?1 AND members.blob_id = owners.blob_id
           AND members.rel_path = owners.rel_path AND members.source_role = owners.source_kind
          JOIN source_rust_module_scopes AS scopes
            ON scopes.blob_id = impls.impl_blob_id AND scopes.ordinal = owners.scope_ordinal
          LEFT JOIN source_rust_module_declarations AS scope_declarations
            ON scope_declarations.blob_id = scopes.blob_id
           AND scope_declarations.declaration_id = scopes.declaration_id
         WHERE impls.topology_id = ?2 AND owners.scope_ordinal IS NOT NULL
           AND (scopes.declaration_id IS NULL OR
                (scope_declarations.body_start_byte IS NOT NULL
                 AND scope_declarations.body_start_byte <= relation.impl_start_byte
                 AND relation.impl_end_byte <= scope_declarations.body_end_byte))
           AND NOT EXISTS(
               SELECT 1 FROM source_rust_module_scopes AS child_scopes
               JOIN source_rust_module_declarations AS child_declarations
                 ON child_declarations.blob_id = child_scopes.blob_id
                AND child_declarations.declaration_id = child_scopes.declaration_id
               WHERE child_scopes.blob_id = scopes.blob_id
                 AND child_scopes.parent_ordinal = scopes.ordinal
                 AND child_declarations.body_start_byte <= relation.impl_start_byte
                 AND relation.impl_end_byte <= child_declarations.body_end_byte)
      ), endpoints AS (
        SELECT owner_module_path, member_ordinal, relation_key AS source_relation_key,
               'subject' AS endpoint_role, impl_site, impl_declaration_id,
               subject_declaration_blob_id AS target_blob_id,
               subject_declaration_site AS target_site, subject_rel_path AS target_rel_path,
               subject_spelling AS spelling
          FROM impl_placements
        UNION ALL
        SELECT owner_module_path, member_ordinal, relation_key,
               'trait', impl_site, impl_declaration_id, trait_declaration_blob_id,
               trait_declaration_site, trait_rel_path, trait_spelling
          FROM impl_placements
      )
      SELECT endpoints.owner_module_path, endpoints.member_ordinal,
             endpoints.source_relation_key, endpoints.endpoint_role, endpoints.impl_site,
             endpoints.impl_declaration_id, targets.crate_key, exports.module_path,
             names.identity_id, names.declaration_member_ordinal, endpoints.spelling
        FROM endpoints
        JOIN rust_crate_exports AS exports INDEXED BY rust_crate_exports_declaration
          ON exports.declaration_blob_id = endpoints.target_blob_id
         AND exports.declaration_site = endpoints.target_site
         AND exports.namespace = 'type' AND exports.origin = 'declaration'
         -- A declaration is content-addressed: a byte-identical file in another
         -- topology declares the same (blob, site). When this unit declares it
         -- itself, that declaration is the endpoint; the other topology's row
         -- names a different crate.
         AND (exports.topology_id = ?2 OR NOT EXISTS(
               SELECT 1 FROM rust_crate_exports AS own
               WHERE own.topology_id = ?2
                 AND own.declaration_blob_id = endpoints.target_blob_id
                 AND own.declaration_site = endpoints.target_site
                 AND own.namespace = 'type' AND own.origin = 'declaration'))
        JOIN rust_crate_container_sources AS target_sources
          ON target_sources.topology_id = exports.topology_id
         AND target_sources.container_path = exports.module_path
         AND target_sources.blob_id = exports.declaration_blob_id
         AND target_sources.rel_path = endpoints.target_rel_path
        JOIN rust_crate_topologies AS targets ON targets.topology_id = exports.topology_id
         -- Retained topologies can export the same content-addressed declaration.
         -- Select the target at this snapshot before naming its summary endpoint.
         AND (targets.topology_id = ?2 OR EXISTS(
               SELECT 1 FROM rust_crate_versions AS versions
                    INDEXED BY rust_crate_versions_topology
               WHERE versions.topology_id = targets.topology_id
                 AND versions.workspace_id = ?3 AND versions.lang = 'rust'
                 AND versions.generation = ?4 AND versions.valid_from <= ?5
                 AND (versions.valid_until IS NULL OR ?5 < versions.valid_until)))
        LEFT JOIN resolution_unit_summary_versions AS target_versions
          ON target_versions.workspace_id = ?3 AND target_versions.lang = 'rust'
         AND target_versions.generation = ?4 AND target_versions.unit_key = targets.crate_key
         AND target_versions.valid_from <= ?5
         AND (target_versions.valid_until IS NULL OR ?5 < target_versions.valid_until)
        LEFT JOIN rust_resolution_unit_summary_exports AS names
          ON names.summary_id = CASE WHEN targets.crate_key = ?6
                                     THEN ?1 ELSE target_versions.summary_id END
         AND names.module_path = exports.module_path AND names.namespace = exports.namespace
         AND names.name = exports.name AND names.origin = 'declaration'
         AND names.declaration_site = exports.declaration_site
       ORDER BY endpoints.owner_module_path, endpoints.member_ordinal,
                endpoints.source_relation_key, endpoints.endpoint_role,
                names.identity_id IS NULL";
    const UNRESOLVED_ENDPOINTS_SQL: &str = "WITH impl_placements AS (
        SELECT owners.container_path AS owner_module_path, members.member_ordinal,
               relation.relation_key, unresolved.side, unresolved.impl_site,
               unresolved.impl_declaration_id, unresolved.spelling, unresolved.reason,
               unresolved.target_module_path, relation.impl_start_byte, relation.impl_end_byte,
               scopes.ordinal AS owner_scope
        FROM rust_crate_unresolved_trait_impls AS unresolved
        JOIN resolution_trait_implementations AS relation
          ON relation.blob_id = unresolved.impl_blob_id
         AND relation.impl_site = unresolved.impl_site AND relation.side = unresolved.side
         AND relation.terminal_spelling = unresolved.spelling
        JOIN rust_crate_container_sources AS owners
          ON owners.topology_id = unresolved.topology_id
         AND owners.blob_id = unresolved.impl_blob_id
         AND owners.rel_path = unresolved.impl_rel_path
        JOIN resolution_unit_summary_members AS members
          ON members.summary_id = ?1 AND members.blob_id = owners.blob_id
         AND members.rel_path = owners.rel_path AND members.source_role = owners.source_kind
        JOIN source_rust_module_scopes AS scopes
          ON scopes.blob_id = unresolved.impl_blob_id AND scopes.ordinal = owners.scope_ordinal
        LEFT JOIN source_rust_module_declarations AS scope_declarations
          ON scope_declarations.blob_id = scopes.blob_id
         AND scope_declarations.declaration_id = scopes.declaration_id
       WHERE unresolved.topology_id = ?2 AND owners.scope_ordinal IS NOT NULL
         AND (scopes.declaration_id IS NULL OR
              (scope_declarations.body_start_byte IS NOT NULL
               AND scope_declarations.body_start_byte <= relation.impl_start_byte
               AND relation.impl_end_byte <= scope_declarations.body_end_byte))
         AND NOT EXISTS(
             SELECT 1 FROM source_rust_module_scopes AS child_scopes
             JOIN source_rust_module_declarations AS child_declarations
               ON child_declarations.blob_id = child_scopes.blob_id
              AND child_declarations.declaration_id = child_scopes.declaration_id
             WHERE child_scopes.blob_id = scopes.blob_id
               AND child_scopes.parent_ordinal = scopes.ordinal
               AND child_declarations.body_start_byte <= relation.impl_start_byte
               AND relation.impl_end_byte <= child_declarations.body_end_byte)
      )
      SELECT owner_module_path, member_ordinal, relation_key, side, impl_site,
             impl_declaration_id, spelling, reason, target_module_path
        FROM impl_placements
       ORDER BY owner_module_path, member_ordinal, relation_key, side";

    let mut insert = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_trait_endpoints(
             summary_id, member_ordinal, owner_module_path, source_relation_key,
             endpoint_role, endpoint_state, impl_site, impl_declaration_id,
             target_unit_key, target_module_path, target_identity_id,
             local_target_member_ordinal, dependency_ordinal,
             unresolved_spelling, unresolved_reason)
         VALUES(?1, ?2, ?3, ?4, ?5, 'resolved', ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, NULL)",
    )?;
    // Resolved rows sort before an unnamed row of the same endpoint, so an
    // endpoint another topology resolved keeps its identity.
    let mut insert_unnamed = conn.prepare_cached(
        "INSERT OR IGNORE INTO rust_resolution_unit_summary_trait_endpoints(
             summary_id, member_ordinal, owner_module_path, source_relation_key,
             endpoint_role, endpoint_state, impl_site, impl_declaration_id,
             target_unit_key, target_module_path, target_identity_id,
             local_target_member_ordinal, dependency_ordinal,
             unresolved_spelling, unresolved_reason)
         VALUES(?1, ?2, ?3, ?4, ?5, 'unresolved', ?6, ?7, NULL, ?8, NULL, NULL, NULL, ?9,
                'bound_without_declaration')",
    )?;
    let mut written = 0;
    let mut statement = conn.prepare_cached(RESOLVED_ENDPOINTS_SQL)?;
    let mut rows = statement.query(params![
        summary_id,
        topology_id,
        snapshot.workspace_id.as_str(),
        snapshot.generation.get(),
        snapshot.revision,
        unit.unit_key.as_slice()
    ])?;
    while let Some(row) = rows.next()? {
        let owner_module_path: String = row.get(0)?;
        let member_ordinal: usize = row.get(1)?;
        let source_relation_key: i64 = row.get(2)?;
        let endpoint_role: String = row.get(3)?;
        let impl_site: u32 = row.get(4)?;
        let impl_declaration_id: Option<u32> = row.get(5)?;
        let target_unit_key = digest_from_row(row.get(6)?)?;
        let target_module_path: String = row.get(7)?;
        let target_identity_id: Option<i64> = row.get(8)?;
        let target_member_ordinal: Option<usize> = row.get(9)?;
        let Some(target_identity_id) = target_identity_id else {
            // The declaration is indexed but the summary cannot name it: the
            // owning unit has no live summary in this pass (a unit on or behind
            // a dependency cycle is derived before a unit it consumes). The
            // endpoint is an open boundary spelled as written, the same shape an
            // unindexed trait gets.
            let spelling: Option<String> = row.get(10)?;
            let spelling = spelling.ok_or_else(|| {
                StoreError::corrupt(format!(
                    "{}: Rust {endpoint_role} endpoint has no spelling: relation={source_relation_key}, site={impl_site}, target={target_unit_key:?}::{target_module_path}",
                    unit.label
                ))
            })?;
            insert_unnamed.execute(params![
                summary_id,
                member_ordinal,
                owner_module_path,
                source_relation_key,
                endpoint_role,
                impl_site,
                impl_declaration_id,
                target_module_path,
                spelling
            ])?;
            written += 1;
            continue;
        };
        let dependency_ordinal = dependency_ordinal_for(target_unit_key);
        let local_target_member_ordinal = if target_unit_key == unit.unit_key {
            Some(target_member_ordinal.expect("declaration exports have a member ordinal"))
        } else {
            None
        };
        insert.execute(params![
            summary_id,
            member_ordinal,
            owner_module_path,
            source_relation_key,
            endpoint_role,
            impl_site,
            impl_declaration_id,
            target_unit_key.as_slice(),
            target_module_path,
            target_identity_id,
            local_target_member_ordinal,
            dependency_ordinal
        ])?;
        written += 1;
    }
    drop(rows);
    drop(statement);

    let mut insert = conn.prepare_cached(
        "INSERT INTO rust_resolution_unit_summary_trait_endpoints(
             summary_id, member_ordinal, owner_module_path, source_relation_key,
             endpoint_role, endpoint_state, impl_site, impl_declaration_id,
             target_unit_key, target_module_path, target_identity_id,
             local_target_member_ordinal, dependency_ordinal,
             unresolved_spelling, unresolved_reason)
         VALUES(?1, ?2, ?3, ?4, ?5, 'unresolved', ?6, ?7, NULL, ?8, NULL, NULL, NULL, ?9, ?10)",
    )?;
    let mut statement = conn.prepare_cached(UNRESOLVED_ENDPOINTS_SQL)?;
    let mut rows = statement.query(params![summary_id, topology_id])?;
    while let Some(row) = rows.next()? {
        insert.execute(params![
            summary_id,
            row.get::<_, usize>(1)?,
            row.get::<_, String>(0)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, u32>(4)?,
            row.get::<_, Option<u32>>(5)?,
            row.get::<_, Option<String>>(8)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?
        ])?;
        written += 1;
    }
    Ok(written)
}

#[derive(Debug)]
struct ExportTargetIdentity {
    identity_id: i64,
    identity_digest: [u8; 32],
    declaration_blob_id: i64,
    declaration_site: i64,
}

#[derive(Debug)]
struct ExportTargetCandidate {
    target_unit_key: [u8; 32],
    target_module_path: String,
    target_name: String,
    identity: ExportTargetIdentity,
    // The consumed first hop can differ from the canonical target's unit.
    dependency_ordinal: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
fn export_target_candidates(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    unit: &UnitInputs,
    topology_id: i64,
    module_path: &str,
    namespace: &str,
    name: &str,
    origin: &str,
    dependency_ordinals: &HashMap<[u8; 32], usize>,
) -> Result<Vec<ExportTargetCandidate>> {
    let candidates = if origin == "glob_reexport" {
        let mut statement = conn.prepare_cached(GLOB_REEXPORT_TARGETS_SQL)?;
        statement
            .query_map(
                params![
                    topology_id,
                    module_path,
                    namespace,
                    name,
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision,
                    unit.unit_key.as_slice()
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        name.to_owned(),
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        let mut statement = conn.prepare_cached(NAMED_REEXPORT_TARGETS_SQL)?;
        statement
            .query_map(params![topology_id, module_path, namespace, name], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    // A spelling identity alone does not identify a declaration. Keep the
    // canonical unit and the declaration's source coordinates in this key.
    let mut resolved = HashMap::new();
    for (key, target_module_path, target_name) in candidates {
        let target_unit_key = digest_from_row(key)?;
        let same_unit = target_unit_key == unit.unit_key;
        let Some(identity) = target_identity(
            conn,
            snapshot,
            &target_unit_key,
            &target_module_path,
            namespace,
            &target_name,
            same_unit,
        )?
        else {
            return Ok(Vec::new());
        };
        let dependency_ordinal = if same_unit {
            None
        } else if let Some(ordinal) = dependency_ordinals.get(&target_unit_key) {
            Some(*ordinal)
        } else {
            let producer_epoch: String = conn.query_row(
                "SELECT producer_epoch FROM main.resolution_producer_epochs WHERE lang = 'rust'",
                [],
                |row| row.get(0),
            )?;
            let mut statement = conn.prepare_cached(DEPENDENCY_REEXPORT_WITNESS_SQL)?;
            let mut first_hop = None;
            for (dependency_key, ordinal) in dependency_ordinals {
                if first_hop.is_some_and(|previous| previous <= *ordinal) {
                    continue;
                }
                let witnesses_target: bool = statement.query_row(
                    params![
                        snapshot.workspace_id.as_str(),
                        "rust",
                        snapshot.generation.get(),
                        dependency_key.as_slice(),
                        snapshot.revision,
                        producer_epoch,
                        RUST_UNIT_SUMMARY_DERIVATION_VERSION,
                        target_unit_key.as_slice(),
                        target_module_path,
                        namespace,
                        target_name,
                        identity.identity_id
                    ],
                    |row| row.get(0),
                )?;
                if witnesses_target {
                    first_hop = Some(*ordinal);
                }
            }
            let Some(first_hop) = first_hop else {
                // Do not let an unproven candidate disappear behind another
                // candidate and turn an incomplete export into a unique one.
                return Ok(Vec::new());
            };
            Some(first_hop)
        };
        let declaration = (
            target_unit_key,
            identity.identity_id,
            identity.declaration_blob_id,
            identity.declaration_site,
        );
        let candidate = ExportTargetCandidate {
            target_unit_key,
            target_module_path,
            target_name,
            identity,
            dependency_ordinal,
        };
        // Other routes to the same declaration can have different first hops
        // or aliases. Select the smallest ordinal, then stable coordinates.
        match resolved.entry(declaration) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let previous = entry.get();
                if (
                    candidate.dependency_ordinal,
                    &candidate.target_module_path,
                    &candidate.target_name,
                ) < (
                    previous.dependency_ordinal,
                    &previous.target_module_path,
                    &previous.target_name,
                ) {
                    entry.insert(candidate);
                }
            }
        }
    }
    let mut resolved = resolved.into_values().collect::<Vec<_>>();
    resolved.sort_by(|left, right| {
        (
            left.target_unit_key,
            &left.target_module_path,
            &left.target_name,
        )
            .cmp(&(
                right.target_unit_key,
                &right.target_module_path,
                &right.target_name,
            ))
    });
    Ok(resolved)
}

impl RustUnitSummaries {
    fn imports(
        &self,
        conn: &Connection,
        topology_id: i64,
        unit: &UnitInputs,
        dependency_ordinals: &HashMap<[u8; 32], usize>,
        dependency_keys_by_extern: &HashMap<String, [u8; 32]>,
    ) -> Result<Vec<UnitImport>> {
        struct Pending {
            blob_id: i64,
            import_id: i64,
            alias: Option<String>,
            identifier: Option<String>,
            rel_path: String,
            segments: Vec<String>,
        }
        let mut imports = Vec::new();
        let mut statement = conn.prepare_cached(IMPORTS_SQL)?;
        let mut rows = statement.query([topology_id])?;
        let mut current: Option<Pending> = None;
        let mut finish = |pending: Option<Pending>| -> Result<()> {
            let Some(pending) = pending else {
                return Ok(());
            };
            let mut segments = pending.segments;
            if segments.is_empty()
                && let Some(identifier) = pending.identifier.as_deref()
            {
                segments.push(identifier.to_owned());
            }
            if segments.is_empty() {
                return Err(StoreError::corrupt(format!(
                    "{}: Rust import {} at {} has no structured source path",
                    unit.label, pending.import_id, pending.rel_path
                )));
            }
            let spelling = segments.join("::");
            let root = segments[0].as_str();
            let is_local = matches!(root, "crate" | "self" | "super")
                || conn.query_row(
                    LOCAL_IMPORT_SQL,
                    params![
                        topology_id,
                        pending.blob_id,
                        pending.import_id,
                        unit.unit_key.as_slice()
                    ],
                    |row| row.get::<_, bool>(0),
                )?;
            if is_local {
                return Ok(());
            }
            let direct_key = dependency_keys_by_extern.get(root).copied();
            let target_key =
                import_target_key(conn, topology_id, pending.blob_id, pending.import_id)?;
            let dependency_key = direct_key.or(target_key);
            let dependency_ordinal =
                dependency_key.and_then(|key| dependency_ordinals.get(&key).copied());
            let blank = pending.alias.as_deref() == Some("_");
            let state = if blank {
                "blank"
            } else if dependency_ordinal.is_some() {
                "resolved"
            } else {
                "unresolved"
            };
            imports.push(UnitImport {
                blob_id: pending.blob_id,
                import_id: pending.import_id,
                // Rust has no Go-style package definition key. The source import
                // declaration id is its blob-local binding key.
                kind: if blank { "blank" } else { "named" },
                definition_key: Some(pending.import_id),
                spelling,
                dependency_ordinal,
                state,
            });
            Ok(())
        };
        while let Some(row) = rows.next()? {
            let key = (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?);
            if current
                .as_ref()
                .is_none_or(|pending| (pending.blob_id, pending.import_id) != key)
            {
                finish(current.take())?;
                current = Some(Pending {
                    blob_id: key.0,
                    import_id: key.1,
                    alias: row.get(2)?,
                    identifier: row.get(3)?,
                    rel_path: row.get(4)?,
                    segments: Vec::new(),
                });
            }
            if let Some(segment) = row.get::<_, Option<String>>(6)? {
                current
                    .as_mut()
                    .expect("the current import owns its source path segment")
                    .segments
                    .push(segment);
            }
        }
        finish(current.take())?;
        Ok(imports)
    }

    #[allow(clippy::too_many_arguments)]
    fn reexport_target(
        &self,
        conn: &Connection,
        snapshot: &WorkspaceSnapshotId,
        unit: &UnitInputs,
        topology_id: i64,
        module_path: &str,
        namespace: &str,
        name: &str,
        rust_origin: &str,
        dependency_ordinals: &HashMap<[u8; 32], usize>,
    ) -> Result<Option<ReexportTarget>> {
        let mut candidates = export_target_candidates(
            conn,
            snapshot,
            unit,
            topology_id,
            module_path,
            namespace,
            name,
            rust_origin,
            dependency_ordinals,
        )?;
        if candidates.len() != 1 {
            return Ok(None);
        }
        let target = candidates.pop().expect("one target checked");
        Ok(Some((
            target.dependency_ordinal,
            target.identity.identity_id,
            target.identity.identity_digest,
        )))
    }
}

fn read_rows(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    producer_epoch: &str,
) -> Result<Vec<UnitRead>> {
    let mut reads = Vec::new();
    let mut statement = conn.prepare_cached(CONFIGURATION_READS_SQL)?;
    let mut rows = statement.query(params![
        snapshot.workspace_id.as_str(),
        snapshot.generation.get(),
        snapshot.revision
    ])?;
    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        let oid: String = row.get(1)?;
        reads.push(UnitRead {
            kind: "configuration",
            key_digest: read_key("rust-configuration", Some(path.as_str())),
            digest: value_digest("rust-configuration-oid", oid.as_bytes()),
        });
    }
    reads.push(UnitRead {
        kind: "epoch",
        key_digest: read_key("rust-producer-epoch", None),
        digest: value_digest("rust-producer-epoch", producer_epoch.as_bytes()),
    });
    reads.push(UnitRead {
        kind: "derivation",
        key_digest: read_key("rust-unit-summary-derivation", None),
        digest: value_digest(
            "rust-unit-summary-derivation",
            &RUST_UNIT_SUMMARY_DERIVATION_VERSION.to_be_bytes(),
        ),
    });
    Ok(reads)
}

fn identity_for_name(
    conn: &Connection,
    namespace: &str,
    name: &str,
) -> Result<Option<(i64, [u8; 32])>> {
    let namespace = rust_namespace_code(namespace)?;
    let row = conn
        .prepare_cached(
            "SELECT id, identity_digest FROM main.resolution_identities
             WHERE semantic_language = ?1 AND namespace = ?2 AND spelling = ?3",
        )?
        .query_row(
            params![
                language_code(crate::analyzer::Language::Rust),
                namespace,
                name
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(id, digest)| Ok((id, digest_from_row(digest)?)))
        .transpose()
}

fn target_identity(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    crate_key: &[u8; 32],
    module_path: &str,
    namespace: &str,
    name: &str,
    same_unit: bool,
) -> Result<Option<ExportTargetIdentity>> {
    let namespace_code = rust_namespace_code(namespace)?;
    let row = conn
        .prepare_cached(TARGET_IDENTITY_SQL)?
        .query_row(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                crate_key.as_slice(),
                snapshot.revision,
                module_path,
                namespace,
                name,
                language_code(crate::analyzer::Language::Rust),
                namespace_code,
                same_unit
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(identity_id, digest, declaration_blob_id, declaration_site)| {
            Ok(ExportTargetIdentity {
                identity_id,
                identity_digest: digest_from_row(digest)?,
                declaration_blob_id,
                declaration_site,
            })
        },
    )
    .transpose()
}

fn import_target_key(
    conn: &Connection,
    topology_id: i64,
    blob_id: i64,
    import_id: i64,
) -> Result<Option<[u8; 32]>> {
    let mut statement = conn.prepare_cached(IMPORT_TARGET_KEYS_SQL)?;
    let keys = statement
        .query_map(params![topology_id, blob_id, import_id], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if keys.len() > 1 {
        return Ok(None);
    }
    keys.into_iter().next().map(digest_from_row).transpose()
}

fn rust_namespace_code(namespace: &str) -> Result<i64> {
    let namespace = match namespace {
        "type" => ResolutionNamespace::Type,
        "value" => ResolutionNamespace::Value,
        "macro" => ResolutionNamespace::Macro,
        other => {
            return Err(StoreError::corrupt(format!(
                "Rust crate export has unsupported namespace {other:?}"
            )));
        }
    };
    Ok(namespace_code(namespace))
}

fn rust_gap_kind(kind: &str) -> Result<&'static str> {
    match kind {
        "external_dependency" => Ok("external_dependency"),
        "unsupported_manifest" => Ok("unsupported_manifest"),
        "inactive_placement" => Ok("inactive_placement"),
        "unknown_activation" => Ok("unknown_activation"),
        "unplaced_module" => Ok("unplaced_module"),
        "duplicate_placement" => Ok("duplicate_placement"),
        "unresolved_import" => Ok("unresolved_import"),
        "unresolved_reexport" => Ok("unresolved_reexport"),
        "open_export_inventory" => Ok("open_export_inventory"),
        "unresolved_visibility" => Ok("unresolved_visibility"),
        "unresolved_trait_impl" => Ok("unresolved_trait_impl"),
        other => Err(StoreError::corrupt(format!(
            "Rust crate topology has unknown gap kind {other:?}"
        ))),
    }
}

fn read_key(name: &str, key: Option<&str>) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-unit-summary-read-key:v1");
    hash.field("name", name.as_bytes());
    if let Some(key) = key {
        hash.field("key", key.as_bytes());
    }
    hash.finish()
}

fn value_digest(kind: &str, value: &[u8]) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-unit-summary-input:v1");
    hash.field("kind", kind.as_bytes());
    hash.field("value", value);
    hash.finish()
}

fn external_unit_key(extern_name: &str) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-external-unit:v1");
    hash.field("extern-name", extern_name.as_bytes());
    hash.finish()
}

fn standard_unit_key(name: &str) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-standard-unit:v1");
    hash.field("crate-name", name.as_bytes());
    hash.finish()
}

fn external_dependency_digest(
    extern_name: &str,
    dependency_kind: &str,
    producer_epoch: &str,
    reads: &[UnitRead],
) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-external-dependency:v1");
    hash.field("extern-name", extern_name.as_bytes());
    hash.field("dependency-kind", dependency_kind.as_bytes());
    hash.field("producer-epoch", producer_epoch.as_bytes());
    let mut configuration: Vec<_> = reads
        .iter()
        .filter(|read| read.kind == "configuration")
        .collect();
    configuration.sort_by_key(|read| read.key_digest);
    for read in configuration {
        hash.field("configuration-key", &read.key_digest);
        hash.field("configuration-oid", &read.digest);
    }
    hash.finish()
}

fn standard_dependency_digest(name: &str, producer_epoch: &str) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"bifrost-rust-standard-dependency:v1");
    hash.field("crate-name", name.as_bytes());
    hash.field("producer-epoch", producer_epoch.as_bytes());
    hash.finish()
}

fn digest_from_row(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| StoreError::corrupt(format!("digest is {} bytes", bytes.len())))
}

impl AnalyzerStore {
    pub(crate) fn rust_summary_binding_completeness_rows(
        &self,
        snapshots: &WorkspaceSnapshots,
        rel_paths: &[String],
    ) -> Result<Vec<RustSummaryBindingCompletenessRow>> {
        if rel_paths.is_empty() {
            return Ok(Vec::new());
        }
        let requested_paths = serde_json::to_string(rel_paths).map_err(|error| {
            StoreError::corrupt(format!(
                "Rust binding-completeness paths serialize: {error}"
            ))
        })?;
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        conn.execute_batch(RUST_IMPORT_GRAPH_MEMBER_SELECTION_SQL)?;
        let tx = conn.transaction()?;
        let mut statement = tx.prepare_cached(RUST_SUMMARY_BINDING_COMPLETENESS_SQL)?;
        let mut rows = statement
            .query_map([requested_paths], |row| {
                Ok(RustSummaryBindingCompletenessRow {
                    summary_id: row.get(0)?,
                    rel_path: row.get(1)?,
                    package_components: row.get(2)?,
                    root_components: row.get(3)?,
                    complete: row.get(4)?,
                    gap_kind: row.get(5)?,
                    gap_subject: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        // Inline/include placements can repeat the same file-level context.
        rows.sort_unstable();
        rows.dedup();
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn rust_summary_module_candidate_rows(
        &self,
        snapshots: &WorkspaceSnapshots,
        candidates: &[(i64, String)],
    ) -> Result<Vec<RustSummaryModuleCandidateRow>> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let requested_candidates = candidates
            .iter()
            .enumerate()
            .map(|(ordinal, (summary_id, module_path))| (ordinal, summary_id, module_path))
            .collect::<Vec<_>>();
        let serialized_candidates =
            serde_json::to_string(&requested_candidates).map_err(|error| {
                StoreError::corrupt(format!("Rust module candidates serialize: {error}"))
            })?;
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        let tx = conn.transaction()?;
        let mut statement = tx.prepare_cached(RUST_SUMMARY_MODULE_CANDIDATES_SQL)?;
        let rows = statement
            .query_map([serialized_candidates], |row| {
                Ok(RustSummaryModuleCandidateRow {
                    candidate_ordinal: row.get(0)?,
                    present: row.get(1)?,
                    rel_path: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn rust_summary_binding_surface_rows(
        &self,
        snapshots: &WorkspaceSnapshots,
        rel_paths: &[String],
    ) -> Result<Vec<RustSummaryBindingSurfaceRow>> {
        if rel_paths.is_empty() {
            return Ok(Vec::new());
        }
        let requested_paths = serde_json::to_string(rel_paths).map_err(|error| {
            StoreError::corrupt(format!("Rust binding-surface paths serialize: {error}"))
        })?;
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        conn.execute_batch(RUST_IMPORT_GRAPH_MEMBER_SELECTION_SQL)?;
        let tx = conn.transaction()?;
        let mut statement = tx.prepare_cached(RUST_SUMMARY_BINDING_SURFACES_SQL)?;
        let raw_rows = statement
            .query_map([requested_paths], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, Option<i64>>(16)?,
                    row.get::<_, Option<i64>>(17)?,
                    row.get::<_, Option<i64>>(18)?,
                    row.get::<_, Option<i64>>(19)?,
                    row.get::<_, Option<String>>(20)?,
                    row.get::<_, Option<String>>(21)?,
                    row.get::<_, Option<String>>(22)?,
                    row.get::<_, Option<String>>(23)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let rows = raw_rows
            .into_iter()
            .map(
                |(
                    member_ordinal,
                    route_ordinal,
                    rel_path,
                    module_path,
                    name,
                    namespace,
                    visibility_kind,
                    visibility_crate_root,
                    visibility_module_path,
                    origin_module_path,
                    origin_name,
                    root_components,
                    origin_file,
                    origin_root_components,
                    route_name,
                    route_file,
                    source_import_id,
                    source_import_ordinal,
                    route_source_import_id,
                    route_source_import_ordinal,
                    root_crate_name,
                    root_target_kind,
                    edge_crate_name,
                    edge_target_kind,
                )| {
                    RustSummaryBindingSurfaceRow {
                        member_ordinal,
                        route_ordinal,
                        rel_path,
                        module_path,
                        name,
                        namespace,
                        visibility_kind,
                        visibility_crate_root,
                        visibility_module_path,
                        origin_file,
                        origin_root_components,
                        origin_module_path,
                        origin_name,
                        root_components,
                        route_name,
                        route_file,
                        source_import_id,
                        source_import_ordinal,
                        route_source_import_id,
                        route_source_import_ordinal,
                        root_crate_name,
                        root_target_kind,
                        edge_crate_name,
                        edge_target_kind,
                    }
                },
            )
            .collect();
        drop(statement);
        tx.commit()?;
        Ok(rows)
    }

    /// Find live Rust source files whose persisted summary import routes name
    /// a declaration in `rel_path`. This is the reverse-importer query used by
    /// Rust relevance and usage candidate selection; it stays demand-shaped
    /// and does not build a workspace-wide reverse index in the analyzer.
    pub(crate) fn rust_summary_importing_file_paths(
        &self,
        snapshots: &WorkspaceSnapshots,
        blob_oid: &str,
        rel_path: &str,
        target_names: &[(String, String)],
    ) -> Result<Vec<String>> {
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        conn.execute_batch(RUST_IMPORT_GRAPH_MEMBER_SELECTION_SQL)?;
        let tx = conn.transaction()?;
        let mut statement = tx.prepare_cached(IMPORTING_FILES_FOR_MEMBER_SQL)?;
        let mut paths = statement
            .query_map(params![blob_oid, rel_path], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        drop(statement);
        let mut statement = tx.prepare_cached(DIRECT_IMPORTERS_FOR_MEMBER_SQL)?;
        let target_names =
            serde_json::to_string(target_names).expect("Rust declaration-name tuples serialize");
        let candidates = statement.query_map(params![blob_oid, rel_path, target_names], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        for candidate in candidates {
            let (importer, package_json, root_json, owner_module, segments_json, target) =
                candidate?;
            let decode = |json: &str| -> Result<Vec<String>> {
                serde_json::from_str(json).map_err(|error| {
                    StoreError::corrupt(format!(
                        "invalid Rust direct import components {json:?}: {error}"
                    ))
                })
            };
            let package = decode(&package_json)?.join(".");
            let root = decode(&root_json)?.join(".");
            let owner = brokk_bifrost_rust::usage_queries::compose_module(&package, &owner_module);
            let segments = decode(&segments_json)?;
            if resolve_rust_module_segments_with_crate(&owner, &root, &segments).as_deref()
                == Some(&target)
            {
                paths.push(importer);
            }
        }
        drop(statement);
        paths.sort_unstable();
        paths.dedup();
        tx.commit()?;
        Ok(paths)
    }

    pub(crate) fn rust_summary_package_rows(
        &self,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<Vec<RustSummaryPackageRow>> {
        let Some(snapshot) = snapshots.get("rust") else {
            return Ok(Vec::new());
        };
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        let tx = conn.transaction()?;
        super::require_current_generation(&tx, "rust", snapshot.generation)?;
        let mut statement = tx.prepare_cached(PACKAGE_ROWS_SQL)?;
        let raw_rows = statement
            .query_map([RUST_UNIT_SUMMARY_DERIVATION_VERSION], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut rows = Vec::with_capacity(raw_rows.len());
        for (rel_path, package_components, crate_name, target_kind, blob_oid, is_root_member) in
            raw_rows
        {
            let package_components = package_components.ok_or_else(|| {
                StoreError::corrupt(format!(
                    "live Rust summary member {rel_path:?} has no package naming row"
                ))
            })?;
            let crate_name = crate_name.ok_or_else(|| {
                StoreError::corrupt(format!(
                    "live Rust summary member {rel_path:?} has no crate context row"
                ))
            })?;
            let target_kind = target_kind.ok_or_else(|| {
                StoreError::corrupt(format!(
                    "live Rust summary member {rel_path:?} has no target kind"
                ))
            })?;
            rows.push(RustSummaryPackageRow {
                rel_path,
                package_components: serde_json::from_str(&package_components).map_err(|error| {
                    StoreError::corrupt(format!(
                        "invalid Rust package components {package_components:?}: {error}"
                    ))
                })?,
                crate_name,
                target_kind,
                blob_oid,
                is_root_member,
            });
        }
        drop(statement);
        tx.commit()?;
        Ok(rows)
    }

    pub(crate) fn rust_summary_cargo_route_rows(
        &self,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<Vec<RustSummaryCargoRouteRow>> {
        let Some(snapshot) = snapshots.get("rust") else {
            return Ok(Vec::new());
        };
        let mut conn = self.read_conn_for_workspace(snapshots)?;
        let tx = conn.transaction()?;
        super::require_current_generation(&tx, "rust", snapshot.generation)?;
        let mut statement = tx.prepare_cached(CARGO_ROUTE_ROWS_SQL)?;
        let raw_rows = statement
            .query_map([RUST_UNIT_SUMMARY_DERIVATION_VERSION], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, Option<String>>(15)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut rows = Vec::with_capacity(raw_rows.len());
        for (
            unit_key,
            manifest_rel_path,
            target_kind,
            crate_name,
            edition,
            development_capable,
            root_rel_path,
            root_package_components,
            dependency_extern_name,
            dependency_kind,
            dependency_boundary,
            dependency_unit_key,
            dependency_target_kind,
            dependency_root_rel_path,
            dependency_root_package_components,
            dependency_manifest_rel_path,
        ) in raw_rows
        {
            let unit_key = digest_from_row(unit_key)?;
            let dependency_unit_key = dependency_unit_key.map(digest_from_row).transpose()?;
            let root_package_components = root_package_components
                .map(|value| {
                    serde_json::from_str(&value).map_err(|error| {
                        StoreError::corrupt(format!(
                            "invalid Rust root package components {value:?}: {error}"
                        ))
                    })
                })
                .transpose()?;
            let dependency_root_package_components = dependency_root_package_components
                .map(|value| {
                    serde_json::from_str(&value).map_err(|error| {
                        StoreError::corrupt(format!(
                            "invalid Rust dependency root package components {value:?}: {error}"
                        ))
                    })
                })
                .transpose()?;
            if dependency_boundary.is_some() {
                if dependency_extern_name.is_none() || dependency_kind.is_none() {
                    return Err(StoreError::corrupt(format!(
                        "Rust summary dependency has no name or kind: unit={unit_key:?}, name={dependency_extern_name:?}, kind={dependency_kind:?}, boundary={dependency_boundary:?}"
                    )));
                }
            } else {
                assert!(dependency_extern_name.is_none());
                assert!(dependency_kind.is_none());
                assert!(dependency_unit_key.is_none());
            }
            rows.push(RustSummaryCargoRouteRow {
                unit_key,
                manifest_rel_path,
                target_kind,
                crate_name,
                edition,
                development_capable,
                root_rel_path,
                root_package_components,
                dependency_extern_name,
                dependency_kind,
                dependency_boundary,
                dependency_unit_key,
                dependency_target_kind,
                dependency_root_rel_path,
                dependency_root_package_components,
                dependency_manifest_rel_path,
            });
        }
        drop(statement);
        tx.commit()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use brokk_bifrost_test_macros::hardwon;

    use crate::AnalyzerConfig;
    use crate::analyzer::WorkspaceAnalyzer;
    use crate::analyzer::store::AnalyzerStore;
    use crate::inline_project::InlineTestProject;

    include!("rust_forwarded_surface_tests.rs");

    fn live_summaries(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, (i64, Vec<u8>)> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT topology.crate_name, summaries.summary_id, summaries.output_digest
                 FROM rust_crate_versions AS topology_versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN resolution_unit_summary_versions AS summary_versions
                   ON summary_versions.workspace_id = topology_versions.workspace_id
                  AND summary_versions.lang = topology_versions.lang
                  AND summary_versions.generation = topology_versions.generation
                  AND summary_versions.unit_key = topology_versions.crate_key
                  AND summary_versions.valid_until IS NULL
                 JOIN resolution_unit_summaries AS summaries
                   ON summaries.summary_id = summary_versions.summary_id
                 WHERE topology_versions.lang = 'rust'
                   AND topology_versions.valid_until IS NULL
                   AND topology.target_kind = 'lib'
                   AND summaries.publication_state = 'complete'
                 ORDER BY topology.crate_name",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .map(|row| {
                let (name, summary_id, output_digest) = row.unwrap();
                (name, (summary_id, output_digest))
            })
            .collect()
    }

    fn changed_summaries(
        before: &BTreeMap<String, (i64, Vec<u8>)>,
        after: &BTreeMap<String, (i64, Vec<u8>)>,
    ) -> BTreeSet<String> {
        assert_eq!(
            before.keys().collect::<Vec<_>>(),
            after.keys().collect::<Vec<_>>()
        );
        before
            .iter()
            .filter(|(name, (summary_id, _))| after[*name].0 != *summary_id)
            .map(|(name, _)| name.clone())
            .collect()
    }

    type SummaryRootRoute = (i64, String, i64, i64, Vec<u8>, String, String);

    fn summary_root_routes(
        workspace: &WorkspaceAnalyzer,
        summary_id: i64,
    ) -> Vec<SummaryRootRoute> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT member_ordinal, module_path, route_key, reference_source_site,
                    target_unit_key, target_module_path, target_name
             FROM rust_resolution_unit_summary_root_routes
             WHERE summary_id = ?1
             ORDER BY member_ordinal, module_path, route_key",
        )
        .unwrap()
        .query_map([summary_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    #[test]
    #[hardwon("ae10707fd23b: Rust topology ids and multi-namespace declarations were misread")]
    fn summary_detail_rows_crosswalk_the_selected_topology() {
        let names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
        let members = names
            .iter()
            .map(|name| format!("\"pkg_{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut fixture = InlineTestProject::new().file(
            "Cargo.toml",
            format!("[workspace]\nmembers = [{members}]\nresolver = \"2\"\n"),
        );
        for name in names {
            fixture = fixture
                .file(
                    format!("pkg_{name}/Cargo.toml"),
                    format!(
                        "[package]\nname = \"unit_{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    ),
                )
                .file(
                    format!("pkg_{name}/src/lib.rs"),
                    format!("pub struct {name}Item;\npub fn {name}() {{}}\n"),
                );
        }
        let fixture = fixture.build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT topology.crate_name, contexts.crate_name
                 FROM rust_crate_versions AS topology_versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN resolution_unit_summary_versions AS summary_versions
                   ON summary_versions.workspace_id = topology_versions.workspace_id
                  AND summary_versions.lang = topology_versions.lang
                  AND summary_versions.generation = topology_versions.generation
                  AND summary_versions.unit_key = topology_versions.crate_key
                  AND summary_versions.valid_until IS NULL
                 JOIN rust_resolution_unit_summary_versions AS rust_versions
                   ON rust_versions.summary_id = summary_versions.summary_id
                 JOIN rust_resolution_unit_summary_contexts AS contexts
                   ON contexts.summary_id = rust_versions.summary_id
                 WHERE topology_versions.lang = 'rust'
                   AND topology_versions.valid_until IS NULL
                   AND topology.target_kind = 'lib'
                 ORDER BY topology.crate_name",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows.len(), names.len(), "published Rust contexts: {rows:?}");
        assert!(
            rows.iter()
                .all(|(topology_name, summary_name)| topology_name == summary_name),
            "summary detail rows must join their selected topology: {rows:?}"
        );
    }

    #[test]
    fn rust_summary_binding_surface_reader_seeks_in_both_statistics_states() {
        use crate::analyzer::store::planner_statistics::pinned_plans::{
            explain_pin, pinned, prepare_pin_context,
        };
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::types::Value;

        let fixture = InlineTestProject::with_language(crate::analyzer::Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"binding_surface_plan\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub struct Item; pub fn run() {}\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().expect("fixture store");
        let conn = store.conn.lock().expect("fixture store connection");
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn)
            .expect("revisioned workspace views");
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .expect("clear workspace selections");
        conn.execute(
            "INSERT INTO selected_workspace_revisions
             SELECT workspace_id, lang, generation, revision FROM workspace_heads
             WHERE lang = 'rust'",
            [],
        )
        .expect("select fixture Rust workspace");
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        prepare_pin_context(&conn);
        let mut pin = pinned("rust_unit_summary_import_graph_binding_surfaces");
        pin.params = vec![Value::Text(serde_json::json!(["src/lib.rs"]).to_string())];

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            for index in [
                "rust_resolution_unit_summary_effective_bindings_member_name",
                "rust_resolution_unit_summary_import_route_provenance_binding",
                "rust_resolution_unit_summary_effective_bindings_module_name",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(index)),
                    "{state:?}: binding surface reader must seek {index}: {plan:?}"
                );
            }
            assert!(
                plan.iter()
                    .all(|row| !row.contains("AUTOMATIC") && !row.contains("TEMP B-TREE")),
                "{state:?}: binding surface reader builds no transient index or sort: {plan:?}"
            );
        }
    }

    #[test]
    fn rust_summary_binding_completeness_reader_seeks_in_both_statistics_states() {
        use crate::analyzer::store::planner_statistics::pinned_plans::{
            explain_pin, pinned, prepare_pin_context,
        };
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::types::Value;

        let fixture = InlineTestProject::with_language(crate::analyzer::Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"binding_completeness_plan\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub struct Item; pub fn run() {}\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().expect("fixture store");
        let conn = store.conn.lock().expect("fixture store connection");
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn)
            .expect("revisioned workspace views");
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .expect("clear workspace selections");
        conn.execute(
            "INSERT INTO selected_workspace_revisions
             SELECT workspace_id, lang, generation, revision FROM workspace_heads
             WHERE lang = 'rust'",
            [],
        )
        .expect("select fixture Rust workspace");
        crate::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        prepare_pin_context(&conn);
        let mut pin = pinned("rust_unit_summary_import_graph_binding_completeness");
        pin.params = vec![Value::Text(serde_json::json!(["src/lib.rs"]).to_string())];

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            assert!(
                plan.iter()
                    .any(|row| row
                        .contains("rust_resolution_unit_summary_binding_completeness_member")),
                "{state:?}: binding completeness reader must seek its member index: {plan:?}"
            );
            assert!(
                plan.iter()
                    .all(|row| !row.contains("AUTOMATIC") && !row.contains("TEMP B-TREE")),
                "{state:?}: binding completeness reader builds no transient index or sort: {plan:?}"
            );
        }
    }

    #[test]
    fn rust_summary_module_candidate_reader_seeks_in_both_statistics_states() {
        use crate::analyzer::store::planner_statistics::pinned_plans::{
            explain_pin, pinned, prepare_pin_context,
        };
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::types::Value;

        let store = AnalyzerStore::open_ephemeral().expect("ephemeral planner store");
        let conn = store.conn.lock().expect("planner store connection");
        prepare_pin_context(&conn);
        let mut pin = pinned("rust_unit_summary_import_graph_module_candidates");
        pin.params = vec![Value::Text(
            serde_json::json!([[0, 1, "crate"]]).to_string(),
        )];

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            for access in [
                "SEARCH containers USING PRIMARY KEY",
                "SEARCH placements USING PRIMARY KEY",
                "SEARCH members USING PRIMARY KEY",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(access)),
                    "{state:?}: module candidate reader must seek by primary key at {access}: {plan:?}"
                );
            }
            assert!(
                plan.iter()
                    .all(|row| !row.contains("AUTOMATIC") && !row.contains("TEMP B-TREE")),
                "{state:?}: module candidate reader builds no transient index or sort: {plan:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#4920: one enum reexported through two dependencies failed Rust summary reconciliation"
    )]
    fn reexport_routes_to_one_declaration_keep_the_smallest_dependency_ordinal() {
        // Swap the module paths as well as source order so EXPORTS_SQL visits
        // the direct and indirect dependency routes in both orders.
        for selection_source in [
            "pub mod traits { pub use infer::traits::*; pub mod project { pub use middle::traits::Reveal; } }\n",
            "pub mod traits { pub use middle::traits::Reveal; pub mod project { pub use infer::traits::*; } }\n",
        ] {
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", "[workspace]\nmembers = [\"middle\", \"infer\", \"selection\"]\nresolver = \"2\"\n")
                .file("middle/Cargo.toml", "[package]\nname = \"middle\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
                .file("middle/src/lib.rs", "pub mod traits { pub enum Reveal { UserFacing, All } }\n")
                .file("infer/Cargo.toml", "[package]\nname = \"infer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nmiddle = { path = \"../middle\" }\n")
                .file("infer/src/lib.rs", "pub mod traits { pub mod project { pub use middle::traits::Reveal; } pub use self::project::Reveal; pub use middle::traits::*; }\n")
                .file("selection/Cargo.toml", "[package]\nname = \"selection\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nmiddle = { path = \"../middle\" }\ninfer = { path = \"../infer\" }\n")
                .file("selection/src/lib.rs", selection_source)
                .build();
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            // A failed unit publishes nothing; every library must have a live
            // summary after fresh reconciliation (also checked by differential).
            let summaries = live_summaries(&workspace);
            assert_eq!(summaries.len(), 3, "live Rust summaries: {summaries:?}");
            let conn = workspace.store().unwrap().read_conn().unwrap();
            let (count, ordinal, minimum): (i64, i64, i64) = conn
                .query_row(
                    "SELECT count(*), MIN(exports.alias_dependency_ordinal),
                       (SELECT MIN(dependency_ordinal)
                        FROM resolution_unit_summary_dependencies WHERE summary_id = ?1)
                     FROM resolution_unit_summary_exports AS exports
                     JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                     JOIN resolution_unit_summary_exports AS declaration
                       ON declaration.summary_id = ?2
                      AND declaration.identity_id = exports.identity_id
                      AND declaration.namespace = exports.namespace
                      AND declaration.declaration_blob_id = exports.declaration_blob_id
                      AND declaration.declaration_site = exports.declaration_site
                     WHERE exports.summary_id = ?1 AND identities.spelling = 'Reveal'
                       AND exports.namespace = 'type' AND exports.origin = 'reexport'",
                    rusqlite::params![summaries["selection"].0, summaries["middle"].0],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(count, 1, "one shared export for the enum declaration");
            assert_eq!(ordinal, minimum, "smallest dependency ordinal wins");
        }
    }

    fn vector_reexport_fixture() -> crate::inline_project::BuiltInlineTestProject {
        // Vector's root package depends only on vector-lib. The declaration
        // lives in vector-core, which is deliberately not a direct dependency
        // of vector. Keep this fixture free of external packs and dependencies.
        InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"vector\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [workspace]\nmembers = [\"lib/vector-lib\", \"lib/vector-core\"]\nresolver = \"2\"\n\
                 [dependencies]\nvector-lib = { path = \"lib/vector-lib\" }\n",
            )
            .file("src/lib.rs", "pub use vector_lib::event::Event;\n")
            .file(
                "lib/vector-lib/Cargo.toml",
                "[package]\nname = \"vector-lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\nvector-core = { path = \"../vector-core\" }\n",
            )
            .file("lib/vector-lib/src/lib.rs", "pub use vector_core::event;\n")
            .file(
                "lib/vector-core/Cargo.toml",
                "[package]\nname = \"vector-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("lib/vector-core/src/lib.rs", "pub mod event;\n")
            .file("lib/vector-core/src/event.rs", "pub enum Event { Log, Metric }\n")
            .build()
    }

    #[test]
    #[hardwon("#5133: a public module alias can leave a forwarded module's physical subtree")]
    fn vector_forwarded_module_alias_outside_subtree_publishes_first_hop() {
        let fixture = vector_reexport_fixture();
        fixture
            .file("lib/vector-core/src/lib.rs")
            .write("pub mod event;\npub mod outside;\n")
            .unwrap();
        fixture
            .file("lib/vector-core/src/event.rs")
            .write("pub use crate::outside as alias;\n")
            .unwrap();
        std::fs::write(
            fixture.root().join("lib/vector-core/src/outside.rs"),
            "pub enum Event { Log, Metric }\n",
        )
        .unwrap();
        fixture
            .file("src/lib.rs")
            .write("pub use vector_lib::event::alias::Event;\n")
            .unwrap();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let topologies = vector_topologies(&workspace);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let targets = conn
            .prepare(super::NAMED_REEXPORT_TARGETS_SQL)
            .unwrap()
            .query_map(
                rusqlite::params![topologies["vector"], "crate", "type", "Event"],
                |row| Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            targets,
            vec![("crate::outside".to_owned(), "Event".to_owned())],
            "the shared route algorithm must retain the canonical module alias target"
        );
        let topology_has_event: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM rust_crate_exports
                 WHERE topology_id = ?1 AND module_path = 'crate'
                   AND namespace = 'type' AND name = 'Event' AND visibility = 'public')",
                [topologies["vector"]],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            topology_has_event,
            "the legal alias must exist in the topology oracle"
        );
        drop(conn);
        assert_vector_event_export(
            &workspace,
            "vector",
            "lib/vector-core/src/outside.rs",
            "vector_lib",
        );
    }

    #[test]
    #[hardwon("#5133: a transitive reexport disappeared from the shared Rust summary")]
    fn vector_transitive_reexport_publishes_the_direct_dependency_and_complete_header() {
        let fixture = vector_reexport_fixture();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(summaries.len(), 3, "live Rust summaries: {summaries:?}");
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT identities.spelling, exports.namespace, exports.origin,
                        dependency_names.extern_name, declaration_members.rel_path,
                        summaries.complete, summaries.publication_state,
                        rust_exports.target_unit_key = leaf.unit_key,
                        rust_exports.target_module_path, rust_exports.target_name,
                        rust_exports.alias_identity_id = declaration.identity_id
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 JOIN resolution_unit_summaries AS summaries USING(summary_id)
                 JOIN rust_resolution_unit_summary_dependency_names AS dependency_names
                   ON dependency_names.summary_id = exports.summary_id
                  AND dependency_names.dependency_ordinal = exports.alias_dependency_ordinal
                 JOIN resolution_unit_summary_exports AS declaration
                   ON declaration.summary_id = ?2
                  AND declaration.declaration_blob_id = exports.declaration_blob_id
                  AND declaration.declaration_site = exports.declaration_site
                  AND declaration.namespace = exports.namespace
                 JOIN resolution_unit_summary_members AS declaration_members
                   ON declaration_members.summary_id = declaration.summary_id
                  AND declaration_members.blob_id = declaration.declaration_blob_id
                 JOIN resolution_unit_summaries AS leaf ON leaf.summary_id = declaration.summary_id
                 JOIN rust_resolution_unit_summary_exports AS rust_exports
                   ON rust_exports.summary_id = exports.summary_id
                  AND rust_exports.module_path = 'crate'
                  AND rust_exports.name = identities.spelling
                  AND rust_exports.namespace = exports.namespace
                 WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                 ORDER BY exports.namespace",
            )
            .unwrap()
            .query_map(
                rusqlite::params![summaries["vector"].0, summaries["vector_core"].0],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, bool>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, bool>(10)?,
                    ))
                },
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(
                "Event".to_owned(),
                "type".to_owned(),
                "reexport".to_owned(),
                "vector_lib".to_owned(),
                "lib/vector-core/src/event.rs".to_owned(),
                true,
                "complete".to_owned(),
                true,
                "crate::event".to_owned(),
                "Event".to_owned(),
                true,
            )],
            "the shared first hop is vector_lib and the Rust target is the canonical vector_core leaf"
        );
    }

    #[test]
    #[hardwon("#5133: local imports polluted module aliases and suppressed module glob exports")]
    fn module_native_reexport_selector_5133_keeps_local_bindings_and_restricted_exports() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"module_scope\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                r#"pub mod chosen {
    pub enum Item { First }
    pub enum ModuleHidden { First }
}
pub mod other {
    pub enum Item { Second }
    pub enum ModuleHidden { Second }
    pub enum LocalOnly { Second }
}
pub use crate::chosen as Alias;
pub use crate::chosen::*;
use crate::other::ModuleHidden;
pub(crate) use crate::chosen::Item as RestrictedNamed;
pub mod restricted {
    pub(crate) use crate::chosen::*;
}
pub fn public_local() {
    pub use crate::other as Alias;
    pub use crate::other::Item;
    pub use crate::other::*;
    pub(crate) use crate::other::LocalOnly as LocalRestricted;
}
pub fn private_local() {
    use crate::other as Alias;
    use crate::other::Item;
}
pub fn enclosing() {
    pub mod nested {
        pub use crate::chosen::Item as NestedItem;
    }
}
"#,
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(summaries.len(), 1, "complete module summary: {summaries:?}");
        let conn = workspace.store().unwrap().read_conn().unwrap();
        let summary_id = summaries["module_scope"].0;
        let rows = conn
            .prepare(
                "SELECT module_path, name, visibility, target_module_path, target_name
                 FROM rust_resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND namespace = 'type'
                   AND origin IN ('reexport', 'glob_reexport')
                 ORDER BY module_path, name",
            )
            .unwrap()
            .query_map([summary_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let expected = [
            ("crate", "Alias", "public", "crate", "chosen"),
            ("crate", "Item", "public", "crate::chosen", "Item"),
            ("crate", "RestrictedNamed", "crate", "crate::chosen", "Item"),
            (
                "crate::nested",
                "NestedItem",
                "public",
                "crate::chosen",
                "Item",
            ),
            (
                "crate::restricted",
                "Item",
                "crate",
                "crate::chosen",
                "Item",
            ),
            (
                "crate::restricted",
                "ModuleHidden",
                "crate",
                "crate::chosen",
                "ModuleHidden",
            ),
        ]
        .map(|(module, name, visibility, target_module, target)| {
            (
                module.to_owned(),
                name.to_owned(),
                visibility.to_owned(),
                target_module.to_owned(),
                target.to_owned(),
            )
        });
        assert_eq!(rows, expected, "only module-native imports produce exports");
        let retained: (i64, i64) = conn
            .query_row(
                "SELECT count(*), count(DISTINCT imports.binder_scope)
                 FROM rust_resolution_unit_summary_import_routes AS imports
                 WHERE imports.summary_id = ?1 AND imports.module_path = 'crate'
                   AND imports.bound_name = 'Alias' AND imports.namespace = 'type'",
                [summary_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            retained,
            (3, 3),
            "module, public local, and private local aliases remain usable"
        );
        let gaps: Vec<(String, String)> = conn
            .prepare(
                "SELECT gap_kind, subject FROM resolution_unit_summary_gaps
                 WHERE summary_id = ?1 ORDER BY gap_kind, subject",
            )
            .unwrap()
            .query_map([summary_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            gaps.is_empty(),
            "valid local public imports are not reexport gaps: {gaps:?}"
        );
    }

    // Keep cross-store comparisons independent of database-local ids. The
    // declaration path and source site identify the same source in either store.
    fn vector_surface(workspace: &WorkspaceAnalyzer) -> Vec<(String, String, String, i64)> {
        let summary_id = live_summaries(workspace)["vector"].0;
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT identities.spelling, exports.namespace, members.rel_path, exports.declaration_site
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             JOIN resolution_unit_summary_members AS members
               ON members.blob_id = exports.declaration_blob_id
             WHERE exports.summary_id = ?1
             GROUP BY identities.spelling, exports.namespace, members.rel_path, exports.declaration_site
             ORDER BY identities.spelling, exports.namespace, members.rel_path, exports.declaration_site",
        )
        .unwrap()
        .query_map([summary_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    fn vector_topologies(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, i64> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT topology.crate_name, versions.topology_id
             FROM rust_crate_versions AS versions
             JOIN rust_crate_topologies AS topology USING(topology_id)
             WHERE versions.lang = 'rust' AND versions.valid_until IS NULL
               AND topology.target_kind = 'lib'
             ORDER BY topology.crate_name",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(|row| row.unwrap())
        .collect()
    }

    fn vector_lib_surface_digest(workspace: &WorkspaceAnalyzer) -> Vec<u8> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.query_row(
            "SELECT topologies.export_surface_digest
             FROM rust_crate_versions AS versions
             JOIN rust_crate_topologies AS topologies USING(topology_id)
             WHERE versions.lang = 'rust' AND versions.valid_until IS NULL
               AND topologies.crate_name = 'vector_lib' AND topologies.target_kind = 'lib'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn assert_vector_event_export(
        workspace: &WorkspaceAnalyzer,
        unit: &str,
        expected_path: &str,
        expected_first_hop: &str,
    ) {
        let summary_id = live_summaries(workspace)[unit].0;
        let conn = workspace.store().unwrap().read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT DISTINCT identities.spelling, exports.namespace, exports.origin,
                        exports.visibility, members.rel_path,
                        exports.alias_dependency_ordinal, names.extern_name,
                        summaries.complete, summaries.publication_state
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 JOIN resolution_unit_summaries AS summaries USING(summary_id)
                 JOIN resolution_unit_summary_members AS members
                   ON members.blob_id = exports.declaration_blob_id
                 LEFT JOIN rust_resolution_unit_summary_dependency_names AS names
                   ON names.summary_id = exports.summary_id
                  AND names.dependency_ordinal = exports.alias_dependency_ordinal
                 WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                 ORDER BY exports.namespace",
            )
            .unwrap()
            .query_map([summary_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(
                "Event".to_owned(),
                "type".to_owned(),
                "reexport".to_owned(),
                "exported".to_owned(),
                expected_path.to_owned(),
                Some(0),
                Some(expected_first_hop.to_owned()),
                true,
                "complete".to_owned(),
            )],
            "{unit} retains its actual Event export with a complete header"
        );
        let gaps: Vec<(String, String)> = conn
            .prepare(
                "SELECT gap_kind, subject FROM resolution_unit_summary_gaps
                 WHERE summary_id = ?1 ORDER BY gap_kind, subject",
            )
            .unwrap()
            .query_map([summary_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert!(
            gaps.iter().all(|(kind, _)| kind != "unresolved_reexport"),
            "{unit} has no unresolved reexport gap: {gaps:?}"
        );
    }

    fn vector_terminal_alias_fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"vector\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [workspace]\nmembers = [\"lib/vector-lib\", \"lib/vector-core\"]\nresolver = \"2\"\n\
                 [dependencies]\nvector-lib = { path = \"lib/vector-lib\" }\n",
            )
            .file("src/lib.rs", "pub use vector_lib::Event;\n")
            .file(
                "lib/vector-lib/Cargo.toml",
                "[package]\nname = \"vector-lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\nvector-core = { path = \"../vector-core\" }\n",
            )
            .file("lib/vector-lib/src/lib.rs", "pub use vector_core::Event;\n")
            .file(
                "lib/vector-core/Cargo.toml",
                "[package]\nname = \"vector-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "lib/vector-core/src/lib.rs",
                "pub enum Event { Log, Metric }\nfn private_body() -> u8 { 1 }\n",
            )
            .build()
    }

    fn assert_vector_body_then_manifest_churn(
        fixture: &crate::inline_project::BuiltInlineTestProject,
        declaration_path: &str,
        body_changed_source: &str,
        manifest_path: &str,
        facade_event_path: &str,
    ) {
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = live_summaries(&workspace);
        let initial_topologies = vector_topologies(&workspace);
        assert_eq!(initial.len(), 3, "initial vector summaries: {initial:?}");
        assert_eq!(initial_topologies.len(), 3, "initial vector topologies");
        assert_vector_event_export(&workspace, "vector", facade_event_path, "vector_lib");
        assert_vector_matches_fresh_store(fixture, &workspace);

        let initial_blob: i64 = workspace
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT declaration_blob_id FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                   AND exports.origin = 'declaration'",
                [initial["vector_core"].0],
                |row| row.get(0),
            )
            .unwrap();

        let declaration = fixture.file(declaration_path);
        declaration.write(body_changed_source).unwrap();
        workspace = workspace.update(&BTreeSet::from([declaration]));
        let after_body = live_summaries(&workspace);
        assert_eq!(
            changed_summaries(&initial, &after_body),
            BTreeSet::from(["vector_core".to_owned()]),
            "changing only the private body rederives the declaring crate"
        );
        let after_body_topologies = vector_topologies(&workspace);
        assert_eq!(
            initial_topologies["vector_lib"], after_body_topologies["vector_lib"],
            "equal published output retains the dependent facade topology"
        );
        assert_eq!(
            initial_topologies["vector"], after_body_topologies["vector"],
            "equal published output retains the consumer topology"
        );
        assert_ne!(
            initial["vector_core"].0, after_body["vector_core"].0,
            "core summary is rederived for the new declaration blob"
        );
        let after_body_blob: i64 = workspace
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT declaration_blob_id FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                   AND exports.origin = 'declaration'",
                [after_body["vector_core"].0],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(
            initial_blob, after_body_blob,
            "core Event declaration blob changes"
        );
        assert_eq!(
            initial["vector_core"].1, after_body["vector_core"].1,
            "private body does not change core's published output"
        );
        assert_eq!(
            initial["vector_lib"], after_body["vector_lib"],
            "facade summary is retained across equal core output"
        );
        assert_eq!(
            initial["vector"], after_body["vector"],
            "consumer summary is retained across equal facade output"
        );
        assert_vector_event_export(&workspace, "vector", facade_event_path, "vector_lib");
        assert_vector_matches_fresh_store(fixture, &workspace);

        let manifest = fixture.file(manifest_path);
        let manifest_path = fixture.root().join(manifest_path);
        let manifest_text = std::fs::read_to_string(&manifest_path).unwrap();
        std::fs::write(&manifest_path, format!("{manifest_text}# refresh\n")).unwrap();
        workspace = workspace.update(&BTreeSet::from([manifest]));
        let after_manifest = live_summaries(&workspace);
        assert_ne!(
            after_body["vector"].0, after_manifest["vector"].0,
            "manifest raw-read refresh rederives the consumer summary"
        );
        assert_eq!(
            after_body_topologies["vector"],
            vector_topologies(&workspace)["vector"],
            "manifest refresh retains the consumer topology frame"
        );
        assert_eq!(
            after_body_blob,
            workspace
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT declaration_blob_id FROM resolution_unit_summary_exports AS exports
                     JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                     WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                       AND exports.origin = 'declaration'",
                    [after_manifest["vector_core"].0],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            "manifest refresh leaves the current core declaration blob intact"
        );
        assert_vector_event_export(&workspace, "vector", facade_event_path, "vector_lib");
        assert_vector_matches_fresh_store(fixture, &workspace);
    }

    #[test]
    #[hardwon("#5133: retained module exports hid declaration blob churn on manifest refresh")]
    fn vector_module_reexport_body_churn_then_manifest_refresh_matches_fresh_store() {
        let fixture = vector_reexport_fixture();
        fixture
            .file("lib/vector-core/src/event.rs")
            .write("pub enum Event { Log, Metric }\nfn private_body() -> u8 { 1 }\n")
            .unwrap();
        assert_vector_body_then_manifest_churn(
            &fixture,
            "lib/vector-core/src/event.rs",
            "pub enum Event { Log, Metric }\nfn private_body() -> u8 { 2 }\n",
            "Cargo.toml",
            "lib/vector-core/src/event.rs",
        );
    }

    #[test]
    #[hardwon("#5133: retained terminal aliases hid declaration blob churn on manifest refresh")]
    fn vector_terminal_alias_body_churn_then_manifest_refresh_matches_fresh_store() {
        let fixture = vector_terminal_alias_fixture();
        assert_vector_body_then_manifest_churn(
            &fixture,
            "lib/vector-core/src/lib.rs",
            "pub enum Event { Log, Metric }\nfn private_body() -> u8 { 2 }\n",
            "Cargo.toml",
            "lib/vector-core/src/lib.rs",
        );
    }

    fn assert_vector_consumed_live_facade(workspace: &WorkspaceAnalyzer) {
        let summaries = live_summaries(workspace);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let consumed: Vec<u8> = conn
            .query_row(
                "SELECT dependencies.consumed_output_digest
             FROM resolution_unit_summary_dependencies AS dependencies
             JOIN resolution_unit_summaries AS facade
               ON facade.unit_key = dependencies.dependency_unit_key AND facade.summary_id = ?2
             WHERE dependencies.summary_id = ?1",
                rusqlite::params![summaries["vector"].0, summaries["vector_lib"].0],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            consumed, summaries["vector_lib"].1,
            "consumer recorded the live facade output"
        );
    }

    fn assert_vector_matches_fresh_store(
        fixture: &crate::inline_project::BuiltInlineTestProject,
        workspace: &WorkspaceAnalyzer,
    ) {
        // This constructor opens a new ephemeral store. Reconciliation against
        // the incremental store would reuse the very summary keys under test.
        let fresh = fixture.workspace_analyzer(AnalyzerConfig::default());
        assert!(!std::ptr::eq(
            workspace.store().unwrap().as_ref(),
            fresh.store().unwrap().as_ref(),
        ));
        let digests = |analyzer: &WorkspaceAnalyzer| {
            live_summaries(analyzer)
                .into_iter()
                .map(|(name, (_, digest))| (name, digest))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(
            digests(workspace),
            digests(&fresh),
            "fresh-store published outputs"
        );
        assert_eq!(
            vector_surface(workspace),
            vector_surface(&fresh),
            "fresh-store consumer exports"
        );
    }

    #[test]
    #[hardwon("#5133: withdrawing a forwarded module must republish its named downstream alias")]
    fn vector_transitive_reexport_edits_match_fresh_store_and_cut_off_equal_output() {
        let fixture = vector_reexport_fixture();
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let mut previous = live_summaries(&workspace);
        assert_eq!(vector_surface(&workspace).len(), 1, "initial Event export");
        assert_vector_consumed_live_facade(&workspace);
        for (path, source, expected_changed) in [
            (
                "lib/vector-core/src/lib.rs",
                "pub mod event;\nfn private_body() -> u8 { 2 }\n",
                BTreeSet::from(["vector_core".to_owned()]),
            ),
            // An unrelated child export is outside the module the facade forwards.
            (
                "lib/vector-core/src/lib.rs",
                "pub mod event;\npub fn unrelated() {}\n",
                BTreeSet::from(["vector_core".to_owned(), "vector_lib".to_owned()]),
            ),
        ] {
            let file = fixture.file(path);
            file.write(source).unwrap();
            workspace = workspace.update(&BTreeSet::from([file]));
            let incremental = live_summaries(&workspace);
            assert_eq!(
                changed_summaries(&previous, &incremental),
                expected_changed,
                "{path}"
            );
            assert_eq!(
                previous["vector_lib"].1, incremental["vector_lib"].1,
                "equal facade output: {path}"
            );
            assert_eq!(
                previous["vector"], incremental["vector"],
                "consumer is reused: {path}"
            );
            assert_vector_consumed_live_facade(&workspace);
            assert_vector_matches_fresh_store(&fixture, &workspace);
            previous = incremental;
        }

        // Withdraw the module that actually supplies vector::Event, rather than
        // adding an unrelated facade name that leaves that route intact.
        let facade = fixture.file("lib/vector-lib/src/lib.rs");
        facade.write("// event is no longer forwarded\n").unwrap();
        workspace = workspace.update(&BTreeSet::from([facade.clone()]));
        let withdrawn = live_summaries(&workspace);
        assert_eq!(
            changed_summaries(&previous, &withdrawn),
            BTreeSet::from(["vector_lib".to_owned(), "vector".to_owned(),])
        );
        assert_ne!(previous["vector_lib"].1, withdrawn["vector_lib"].1);
        assert_ne!(previous["vector"].1, withdrawn["vector"].1);
        assert!(
            vector_surface(&workspace).is_empty(),
            "withdrawn Event must not survive in shared rows"
        );
        let header: (bool, String) = workspace.store().unwrap().read_conn().unwrap().query_row(
            "SELECT complete, publication_state FROM resolution_unit_summaries WHERE summary_id = ?1",
            [withdrawn["vector"].0], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(
            header,
            (false, "complete".to_owned()),
            "unresolved reexport seals an incomplete header"
        );
        assert_vector_consumed_live_facade(&workspace);
        assert_vector_matches_fresh_store(&fixture, &workspace);

        facade.write("pub use vector_core::event;\n").unwrap();
        workspace = workspace.update(&BTreeSet::from([facade]));
        let restored = live_summaries(&workspace);
        assert_eq!(
            changed_summaries(&withdrawn, &restored),
            BTreeSet::from(["vector_lib".to_owned(), "vector".to_owned(),])
        );
        assert_eq!(previous["vector_lib"].1, restored["vector_lib"].1);
        assert_eq!(previous["vector"].1, restored["vector"].1);
        assert_eq!(vector_surface(&workspace).len(), 1, "restored Event export");
        assert_vector_consumed_live_facade(&workspace);
        assert_vector_matches_fresh_store(&fixture, &workspace);
    }

    #[test]
    #[hardwon(
        "#5133: a removed descendant of a forwarded module must not leave a stale consumer export"
    )]
    fn vector_transitive_reexport_descendant_removal_withdraws_consumer() {
        let fixture = vector_reexport_fixture();
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let before = live_summaries(&workspace);
        let original_facade_surface_digest = vector_lib_surface_digest(&workspace);
        assert_eq!(vector_surface(&workspace).len(), 1);
        let leaf = fixture.file("lib/vector-core/src/event.rs");
        leaf.write("// Event was removed; the forwarded event module still exists\n")
            .unwrap();
        workspace = workspace.update(&BTreeSet::from([leaf]));
        let after = live_summaries(&workspace);
        // Print before assertions so a contract gap identifies the precise
        // cutoff and digests even when the stale consumer fails the test.
        eprintln!(
            "descendant removal before={before:?}, after={after:?}, consumer={:?}",
            vector_surface(&workspace)
        );
        assert_ne!(before["vector_core"].1, after["vector_core"].1);
        assert_ne!(
            before["vector_lib"].1, after["vector_lib"].1,
            "the facade publishes the forwarded module's descendant surface"
        );
        assert_ne!(
            original_facade_surface_digest,
            vector_lib_surface_digest(&workspace),
            "the facade topology digest includes the forwarded descendant surface"
        );
        assert_ne!(
            before["vector"].0, after["vector"].0,
            "consumer must republish"
        );
        assert!(
            vector_surface(&workspace).is_empty(),
            "removed Event must not survive in shared rows"
        );
        assert_vector_consumed_live_facade(&workspace);
        assert_vector_matches_fresh_store(&fixture, &workspace);

        let leaf = fixture.file("lib/vector-core/src/event.rs");
        leaf.write("pub enum Event { Log, Metric }\n").unwrap();
        workspace = workspace.update(&BTreeSet::from([leaf]));
        let restored = live_summaries(&workspace);
        assert_eq!(
            changed_summaries(&after, &restored),
            BTreeSet::from([
                "vector_core".to_owned(),
                "vector_lib".to_owned(),
                "vector".to_owned()
            ])
        );
        assert_eq!(
            original_facade_surface_digest,
            vector_lib_surface_digest(&workspace),
            "restoring the original descendant restores the facade surface digest"
        );
        assert_eq!(vector_surface(&workspace).len(), 1, "restored Event export");
        assert_vector_consumed_live_facade(&workspace);
        assert_vector_matches_fresh_store(&fixture, &workspace);
    }

    #[test]
    #[hardwon(
        "#5133: restricted tuple constructors escaped through enclosing and cross-crate reexports"
    )]
    fn restricted_tuple_constructor_is_not_exported_but_public_constructor_is() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"core\", \"facade\", \"consumer\"]\nresolver = \"2\"\n")
            .file("core/Cargo.toml", "[package]\nname = \"constructor_core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("core/src/lib.rs", "pub mod transform;\n")
            .file("core/src/transform/mod.rs", "mod outputs;\npub use outputs::{OutputBuffer, Mixed, Public, Unit, Empty, NonExhaustive};\n")
            .file("core/src/transform/outputs.rs", "pub struct OutputBuffer(pub(super) Vec<u8>);\n\
                pub struct Mixed(pub u8, pub(crate) u8, u8);\n\
                pub struct Public(pub u8);\n\
                pub struct Unit;\n\
                pub struct Empty();\n\
                #[non_exhaustive]\npub struct NonExhaustive(pub u8);\n")
            .file("facade/Cargo.toml", "[package]\nname = \"constructor_facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nconstructor_core = { path = \"../core\" }\n")
            .file("facade/src/lib.rs", "pub use constructor_core::transform;\n")
            .file("consumer/Cargo.toml", "[package]\nname = \"constructor_consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nconstructor_facade = { path = \"../facade\" }\n")
            .file("consumer/src/lib.rs", "pub use constructor_facade::transform::{OutputBuffer, Mixed, Public, Unit, Empty, NonExhaustive};\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(summaries.len(), 3, "constructor summaries: {summaries:?}");
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let expected = vec![
            ("Empty".to_owned(), "type".to_owned()),
            ("Empty".to_owned(), "value".to_owned()),
            ("Mixed".to_owned(), "type".to_owned()),
            ("NonExhaustive".to_owned(), "type".to_owned()),
            ("OutputBuffer".to_owned(), "type".to_owned()),
            ("Public".to_owned(), "type".to_owned()),
            ("Public".to_owned(), "value".to_owned()),
            ("Unit".to_owned(), "type".to_owned()),
            ("Unit".to_owned(), "value".to_owned()),
        ];
        for (name, module) in [
            ("constructor_core", "crate::transform::outputs"),
            ("constructor_core", "crate::transform"),
            ("constructor_consumer", "crate"),
        ] {
            let summary_id = summaries[name].0;
            // The topology is the differential oracle: assert the corrected
            // visibility there independently instead of accepting oracle agreement.
            for sql in [
                "SELECT name, namespace FROM rust_crate_exports AS exports
                 JOIN rust_crate_versions AS versions USING(topology_id)
                 JOIN resolution_unit_summary_versions AS summaries
                   ON summaries.workspace_id = versions.workspace_id
                  AND summaries.lang = versions.lang AND summaries.generation = versions.generation
                  AND summaries.unit_key = versions.crate_key AND summaries.valid_until IS NULL
                 WHERE summaries.summary_id = ?1 AND versions.valid_until IS NULL
                   AND exports.module_path = ?2 AND exports.visibility = 'public'
                 ORDER BY name, namespace",
                "SELECT name, namespace FROM rust_resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND module_path = ?2 AND visibility = 'public'
                 ORDER BY name, namespace",
            ] {
                let rows = conn
                    .prepare(sql)
                    .unwrap()
                    .query_map(rusqlite::params![summary_id, module], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    rows, expected,
                    "{name} {module}: type survives; only legal constructors are public; query={sql}"
                );
            }
        }
        // A module facade has no copied descendant export rows. Its published
        // module must keep the core target, not flatten OutputBuffer into a value.
        let facade_route: (bool, String, String) = conn.query_row(
            "SELECT exports.target_unit_key = core.unit_key, exports.target_module_path, exports.target_name
             FROM rust_resolution_unit_summary_exports AS exports
             JOIN resolution_unit_summaries AS core ON core.summary_id = ?2
             WHERE exports.summary_id = ?1 AND exports.module_path = 'crate'
               AND exports.name = 'transform' AND exports.namespace = 'type'",
            rusqlite::params![summaries["constructor_facade"].0, summaries["constructor_core"].0],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(
            facade_route,
            (true, "crate".to_owned(), "transform".to_owned())
        );
        for name in [
            "constructor_core",
            "constructor_facade",
            "constructor_consumer",
        ] {
            let rows = conn
                .prepare(
                    "SELECT identities.spelling, exports.namespace
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 WHERE exports.summary_id = ?1 AND identities.spelling IN
                   ('OutputBuffer', 'Mixed', 'Public', 'Unit', 'Empty', 'NonExhaustive')
                 ORDER BY identities.spelling, exports.namespace",
                )
                .unwrap()
                .query_map([summaries[name].0], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let expected_rows = if name == "constructor_facade" {
                Vec::new()
            } else {
                expected.clone()
            };
            assert_eq!(
                rows, expected_rows,
                "{name}: shared public constructor projection"
            );
        }
    }

    #[test]
    #[hardwon("#5133: a tuple field attribute before pub hid a legal public constructor")]
    fn attributed_public_tuple_fields_keep_the_constructor_public() {
        let fixture = InlineTestProject::with_language(crate::analyzer::Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"attributed_constructor\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "#![allow(dead_code)]\n\
                 pub struct Attributed(#[allow(dead_code)] pub u8, #[allow(dead_code)] pub String);\n\
                 pub struct Mixed(#[allow(dead_code)] pub u8, #[allow(dead_code)] u8);\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(summaries.len(), 1, "fixture summaries: {summaries:?}");

        // Rust permits construction of Attributed because every tuple field is
        // public, even though each field has an attribute before its modifier.
        // Mixed remains non-constructible outside the crate because one field
        // is private.
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        for sql in [
            "SELECT name, namespace FROM rust_crate_exports
             JOIN rust_crate_versions USING(topology_id)
             JOIN resolution_unit_summary_versions
               ON resolution_unit_summary_versions.workspace_id = rust_crate_versions.workspace_id
              AND resolution_unit_summary_versions.lang = rust_crate_versions.lang
              AND resolution_unit_summary_versions.generation = rust_crate_versions.generation
              AND resolution_unit_summary_versions.unit_key = rust_crate_versions.crate_key
              AND resolution_unit_summary_versions.valid_until IS NULL
             WHERE resolution_unit_summary_versions.summary_id = ?1
               AND rust_crate_versions.valid_until IS NULL
               AND rust_crate_exports.module_path = 'crate'
               AND rust_crate_exports.visibility = 'public'
               AND rust_crate_exports.name IN ('Attributed', 'Mixed')
             ORDER BY name, namespace",
            "SELECT identities.spelling, exports.namespace
             FROM rust_resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             WHERE exports.summary_id = ?1 AND exports.module_path = 'crate'
               AND exports.visibility = 'public'
               AND identities.spelling IN ('Attributed', 'Mixed')
             ORDER BY identities.spelling, exports.namespace",
            "SELECT identities.spelling, exports.namespace
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             WHERE exports.summary_id = ?1 AND exports.visibility = 'exported'
               AND identities.spelling IN ('Attributed', 'Mixed')
             ORDER BY identities.spelling, exports.namespace",
        ] {
            let rows = conn
                .prepare(sql)
                .unwrap()
                .query_map([summaries["attributed_constructor"].0], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                rows,
                vec![
                    ("Attributed".to_owned(), "type".to_owned()),
                    ("Attributed".to_owned(), "value".to_owned()),
                    ("Mixed".to_owned(), "type".to_owned()),
                ],
                "public Rust tuple constructor rows from analyzer store; query={sql}"
            );
        }
        let complete: bool = conn
            .query_row(
                "SELECT complete = 1 FROM resolution_unit_summaries WHERE summary_id = ?1",
                [summaries["attributed_constructor"].0],
                |row| row.get(0),
            )
            .unwrap();
        assert!(complete, "shared summary header must be complete");
    }

    #[test]
    #[hardwon("#5133: an earlier narrow glob route hid the same declaration's later public route")]
    fn restricted_tuple_constructor_wider_glob_route_reaches_named_downstream_alias() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"core\", \"facade\", \"consumer\"]\nresolver = \"2\"\n")
            .file("core/Cargo.toml", "[package]\nname = \"glob_core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("core/src/lib.rs", "pub enum Item { First, Second }\n")
            .file("facade/Cargo.toml", "[package]\nname = \"glob_facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nglob_core = { path = \"../core\" }\n")
            .file("facade/src/lib.rs", "mod narrow { pub(crate) use glob_core::*; }\n\
                mod wide { pub use glob_core::*; }\n\
                pub mod api {\n\
                    pub(crate) use crate::narrow::*;\n\
                    pub use crate::wide::*;\n\
                }\n\
                pub use api::Item as Exported;\n")
            .file("consumer/Cargo.toml", "[package]\nname = \"glob_consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nglob_facade = { path = \"../facade\" }\n")
            .file("consumer/src/lib.rs", "pub use glob_facade::Exported as Visible;\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn.prepare(
            "SELECT contexts.crate_name, exports.module_path, exports.name, exports.visibility
             FROM rust_resolution_unit_summary_exports AS exports
             JOIN rust_resolution_unit_summary_contexts AS contexts USING(summary_id)
             JOIN resolution_unit_summary_versions AS versions
               ON versions.summary_id = exports.summary_id AND versions.valid_until IS NULL
             WHERE (contexts.crate_name = 'glob_facade' AND
                      ((exports.module_path = 'crate::api' AND exports.name = 'Item') OR
                       (exports.module_path = 'crate' AND exports.name = 'Exported')))
                OR (contexts.crate_name = 'glob_consumer' AND exports.module_path = 'crate' AND exports.name = 'Visible')
             ORDER BY contexts.crate_name, exports.module_path, exports.name",
        ).unwrap().query_map([], |row| Ok((
            row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    "glob_consumer".to_owned(),
                    "crate".to_owned(),
                    "Visible".to_owned(),
                    "public".to_owned(),
                ),
                (
                    "glob_facade".to_owned(),
                    "crate".to_owned(),
                    "Exported".to_owned(),
                    "public".to_owned(),
                ),
                (
                    "glob_facade".to_owned(),
                    "crate::api".to_owned(),
                    "Item".to_owned(),
                    "public".to_owned(),
                ),
            ],
            "the later wider route must widen and reschedule the same declaration"
        );
        let shared: Vec<(String, String)> = conn.prepare(
            "SELECT contexts.crate_name, identities.spelling
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             JOIN rust_resolution_unit_summary_contexts AS contexts USING(summary_id)
             JOIN resolution_unit_summary_versions AS versions
               ON versions.summary_id = exports.summary_id AND versions.valid_until IS NULL
             WHERE identities.spelling IN ('Exported', 'Visible') ORDER BY contexts.crate_name, identities.spelling",
        ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            shared,
            vec![
                ("glob_consumer".to_owned(), "Visible".to_owned()),
                ("glob_facade".to_owned(), "Exported".to_owned())
            ]
        );
        let core_sources: Vec<String> = conn
            .prepare(
                "SELECT DISTINCT members.rel_path
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id = ?2
              AND members.blob_id = exports.declaration_blob_id
             WHERE exports.summary_id = ?1 AND identities.spelling = 'Visible'
             ORDER BY members.rel_path",
            )
            .unwrap()
            .query_map(
                rusqlite::params![summaries["glob_consumer"].0, summaries["glob_core"].0],
                |row| row.get(0),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap();
        assert_eq!(core_sources, vec!["core/src/lib.rs"]);
    }

    #[test]
    #[hardwon("#5133: a private glob candidate caused a false ambiguity with a public item")]
    fn rust_glob_export_ignores_inaccessible_private_candidate() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"glob_visibility\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "mod a { pub fn item() {} }\nmod b { fn item() {} }\npub use a::*;\npub use b::*;\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        let summary_id = summaries["glob_visibility"].0;
        let conn = workspace.store().unwrap().read_conn().unwrap();

        let shared: Vec<(String, String)> = conn
            .prepare(
                "SELECT identities.spelling, exports.namespace
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 WHERE exports.summary_id = ?1
                   AND identities.spelling = 'item' AND exports.visibility = 'exported'
                 ORDER BY identities.spelling, exports.namespace",
            )
            .unwrap()
            .query_map([summary_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(shared, vec![("item".to_owned(), "value".to_owned())]);

        let rust_root: Vec<(String, String, String)> = conn
            .prepare(
                "SELECT name, namespace, visibility
                 FROM rust_resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND module_path = 'crate' AND name = 'item'
                 ORDER BY name, namespace",
            )
            .unwrap()
            .query_map([summary_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rust_root,
            vec![("item".to_owned(), "value".to_owned(), "public".to_owned())]
        );
    }

    #[test]
    fn body_edit_stops_at_rust_output_digest_and_public_item_reaches_direct_dependents() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"base\", \"alpha\", \"beta\", \"leaf\"]\nresolver = \"2\"\n",
            )
            .file(
                "base/Cargo.toml",
                "[package]\nname = \"base_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("base/src/lib.rs", "pub fn first() -> u32 { 1 }\n")
            .file(
                "alpha/Cargo.toml",
                "[package]\nname = \"alpha_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file(
                "alpha/src/lib.rs",
                "pub use base_unit::first; pub fn alpha() -> u32 { crate::first() }\n",
            )
            .file(
                "beta/Cargo.toml",
                "[package]\nname = \"beta_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file(
                "beta/src/lib.rs",
                "pub use base_unit::first; pub fn beta() -> u32 { crate::first() }\n",
            )
            .file(
                "leaf/Cargo.toml",
                "[package]\nname = \"leaf_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nalpha_unit = { path = \"../alpha\" }\n",
            )
            .file(
                "leaf/src/lib.rs",
                "pub fn leaf() -> u32 { alpha_unit::alpha() }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = live_summaries(&workspace);
        assert_eq!(initial.len(), 4, "live Rust summaries: {initial:?}");
        let initial_alpha_routes = summary_root_routes(&workspace, initial["alpha_unit"].0);
        let initial_beta_routes = summary_root_routes(&workspace, initial["beta_unit"].0);
        assert!(
            !initial_alpha_routes.is_empty(),
            "alpha root routes: {initial_alpha_routes:?}"
        );
        assert!(
            !initial_beta_routes.is_empty(),
            "beta root routes: {initial_beta_routes:?}"
        );

        let base_path = fixture.root().join("base/src/lib.rs");
        let body_edit = "pub fn first() -> u32 { 2 }\n";
        std::fs::write(&base_path, body_edit).unwrap();
        let body_update = workspace.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_body = live_summaries(&body_update);
        assert_eq!(
            changed_summaries(&initial, &after_body),
            BTreeSet::from(["base_unit".to_owned()]),
            "body-only edit should derive just its Rust crate"
        );
        assert_eq!(
            initial["base_unit"].1, after_body["base_unit"].1,
            "body-only edit must preserve the crate output digest"
        );
        assert_eq!(
            summary_root_routes(&body_update, after_body["alpha_unit"].0),
            initial_alpha_routes,
            "body-only target edits leave alpha's live root-route rows untouched"
        );
        assert_eq!(
            summary_root_routes(&body_update, after_body["beta_unit"].0),
            initial_beta_routes,
            "body-only target edits leave beta's live root-route rows untouched"
        );

        let public_item_edit = format!("{body_edit}pub fn second() -> u32 {{ 2 }}\n");
        std::fs::write(&base_path, public_item_edit).unwrap();
        let public_update = body_update.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_public_item = live_summaries(&public_update);
        assert_eq!(
            changed_summaries(&after_body, &after_public_item),
            BTreeSet::from([
                "alpha_unit".to_owned(),
                "base_unit".to_owned(),
                "beta_unit".to_owned(),
            ]),
            "an exported item should derive its crate and direct dependents only"
        );
        assert_eq!(
            summary_root_routes(&public_update, after_public_item["alpha_unit"].0),
            initial_alpha_routes,
            "an exported target change republishes alpha's root routes with its new summary"
        );
        assert_eq!(
            summary_root_routes(&public_update, after_public_item["beta_unit"].0),
            initial_beta_routes,
            "an exported target change republishes beta's root routes with its new summary"
        );
        assert_eq!(
            after_body["alpha_unit"].1, after_public_item["alpha_unit"].1,
            "an importing crate keeps its output digest"
        );
        assert_eq!(
            after_body["beta_unit"].1, after_public_item["beta_unit"].1,
            "an importing crate keeps its output digest"
        );
    }

    #[test]
    #[ignore = "finds real bug: the legacy topology reconcile keeps a glob-chain export after its target unit drops the name; the test-only differential reports it"]
    fn a_name_reached_through_a_glob_chain_follows_its_target_on_edit() {
        // leaf names `first` through its own glob re-export of alpha, and alpha
        // glob-re-exports base_unit. leaf's stored route is a pointer to its own
        // crate root, so the answer depends on alpha's live glob rows and on
        // base_unit's live exports. Removing `first` from base_unit must make the
        // answer unresolved, whichever summary rows are stale.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"base\", \"alpha\", \"leaf\"]\nresolver = \"2\"\n",
            )
            .file(
                "base/Cargo.toml",
                "[package]\nname = \"base_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("base/src/lib.rs", "pub fn first() -> u32 { 1 }\n")
            .file(
                "alpha/Cargo.toml",
                "[package]\nname = \"alpha_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file("alpha/src/lib.rs", "pub use base_unit::*;\n")
            .file(
                "leaf/Cargo.toml",
                "[package]\nname = \"leaf_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nalpha_unit = { path = \"../alpha\" }\n",
            )
            .file(
                "leaf/src/lib.rs",
                "pub use alpha_unit::*;\npub fn leaf() -> u32 { crate::first() }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let status_of = |analyzer: &WorkspaceAnalyzer| {
            let result = crate::searchtools::get_definitions_by_location_with_cancellation(
                analyzer.analyzer(),
                crate::searchtools::GetDefinitionParams {
                    references: vec![crate::searchtools::DefinitionReferenceQuery {
                        path: "leaf/src/lib.rs".to_owned(),
                        line: Some(2),
                        column: Some(31),
                    }],
                },
                None,
            );
            result.results[0].status.clone()
        };
        assert_eq!(
            status_of(&workspace),
            "resolved",
            "crate::first resolves before the edit"
        );

        std::fs::write(
            fixture.root().join("base/src/lib.rs"),
            "pub fn second() -> u32 { 2 }\n",
        )
        .unwrap();
        let update = workspace.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        assert_ne!(
            status_of(&update),
            "resolved",
            "crate::first must not resolve once base_unit no longer exports first"
        );
    }

    type BindingProjection = Vec<(String, String, String, Vec<u8>, String)>;
    type ProvenanceProjection = Vec<(i64, i64, String, Vec<u8>, String)>;

    fn summary_binding_projection(
        workspace: &WorkspaceAnalyzer,
        summary_id: i64,
    ) -> BindingProjection {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT module_path, name, namespace, target_unit_key, target_name
             FROM rust_resolution_unit_summary_effective_bindings
             WHERE summary_id = ?1
             ORDER BY module_path, name, namespace, target_unit_key",
        )
        .unwrap()
        .query_map([summary_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    fn summary_provenance_projection(
        workspace: &WorkspaceAnalyzer,
        summary_id: i64,
    ) -> ProvenanceProjection {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT import_ordinal, hop_ordinal, target_binding_name, target_unit_key, namespace
             FROM rust_resolution_unit_summary_import_route_provenance
             WHERE summary_id = ?1
             ORDER BY import_ordinal, hop_ordinal, target_unit_key",
        )
        .unwrap()
        .query_map([summary_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    #[test]
    fn target_export_republishes_importer_binding_rows_and_body_edit_does_not() {
        // `alpha` re-exports `base_unit::first`, so its effective bindings and
        // import-route provenance depend on base's binding closure. A body-only
        // edit in base leaves that closure unchanged; a new public item changes
        // base's summary, so alpha must republish under its new summary id with
        // the same binding rows.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"base\", \"alpha\"]\nresolver = \"2\"\n",
            )
            .file(
                "base/Cargo.toml",
                "[package]\nname = \"base_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("base/src/lib.rs", "pub fn first() -> u32 { 1 }\n")
            .file(
                "alpha/Cargo.toml",
                "[package]\nname = \"alpha_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file(
                "alpha/src/lib.rs",
                "pub use base_unit::first; pub fn alpha() -> u32 { crate::first() }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = live_summaries(&workspace);
        let alpha_id = initial["alpha_unit"].0;
        let initial_bindings = summary_binding_projection(&workspace, alpha_id);
        let initial_provenance = summary_provenance_projection(&workspace, alpha_id);
        assert!(
            initial_bindings.iter().any(|row| row.1 == "first"),
            "alpha effective bindings must carry the re-exported target: {initial_bindings:?}"
        );
        assert!(
            !initial_provenance.is_empty(),
            "alpha import-route provenance must cite the re-exported import"
        );

        let base_path = fixture.root().join("base/src/lib.rs");
        std::fs::write(&base_path, "pub fn first() -> u32 { 2 }\n").unwrap();
        let body_update = workspace.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_body = live_summaries(&body_update);
        assert_eq!(
            after_body["alpha_unit"].0, alpha_id,
            "a body-only target edit must not republish alpha"
        );
        assert_eq!(
            summary_binding_projection(&body_update, alpha_id),
            initial_bindings,
            "a body-only target edit must leave alpha's effective bindings unchanged"
        );
        assert_eq!(
            summary_provenance_projection(&body_update, alpha_id),
            initial_provenance,
            "a body-only target edit must leave alpha's import-route provenance unchanged"
        );

        std::fs::write(
            &base_path,
            "pub fn first() -> u32 { 2 }\npub fn second() -> u32 { 2 }\n",
        )
        .unwrap();
        let export_update = body_update.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_export = live_summaries(&export_update);
        let republished_id = after_export["alpha_unit"].0;
        assert_ne!(
            republished_id, alpha_id,
            "an exported target change must republish alpha under a new summary"
        );
        assert_eq!(
            summary_binding_projection(&export_update, republished_id),
            initial_bindings,
            "an exported target change must republish alpha's effective bindings with the same rows"
        );
        assert_eq!(
            summary_provenance_projection(&export_update, republished_id),
            initial_provenance,
            "an exported target change must republish alpha's import-route provenance with the same rows"
        );
    }

    #[test]
    #[hardwon(
        "73413900c759: a private import of a name its target binds twice failed the provenance insert and aborted the crate's summary pass"
    )]
    fn private_import_of_a_twice_bound_name_publishes_both_traversed_bindings() {
        // `mod agent` reaches `select` through an explicit public re-export
        // and through a crate-visible glob that the explicit one shadows. Both
        // traversed bindings reach one declaration and one alias in `user`,
        // so the import route has two provenance rows.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"shadow\"]\nresolver = \"2\"\n",
            )
            .file(
                "shadow/Cargo.toml",
                "[package]\nname = \"shadow_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "shadow/src/lib.rs",
                "mod inner { pub fn select() -> u32 { 1 } }\n\
                 mod agent {\n\
                     pub(crate) use crate::inner::*;\n\
                     pub use crate::inner::select;\n\
                 }\n\
                 mod user {\n\
                     use crate::agent::select;\n\
                     pub fn run() -> u32 { select() }\n\
                 }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        let summary_id = summaries
            .get("shadow_unit")
            .expect("a double-bound private import must not abort the crate's summary pass")
            .0;
        let provenance = summary_provenance_projection(&workspace, summary_id);
        let mut rows_per_import = std::collections::BTreeMap::<i64, usize>::new();
        for row in &provenance {
            *rows_per_import.entry(row.0).or_default() += 1;
        }
        assert!(
            rows_per_import.values().any(|count| *count == 2),
            "the double-bound import keeps one provenance row per traversed binding: {provenance:?}"
        );
    }

    #[test]
    #[hardwon(
        "d04c9b381fde: a dev-dependency cycle ordered a consumer before its provider and left its trait endpoint unnamed"
    )]
    fn dev_dependency_cycle_does_not_leave_a_consumers_trait_endpoint_open() {
        // `cycle_a` depends on `cycle_b` and `cycle_b` dev-depends on `cycle_a`,
        // as Vector's vector-config and vector-config-macros do. Every chain
        // crate depends on the next one and the last on `cycle_a`, so the chain
        // consumes the cycle. A dev-dependency is an input of the test targets,
        // not of the library, so it must not order the library units; otherwise
        // the whole chain lands in the unordered remainder, and a crate can be
        // derived before the crate whose trait it implements.
        const CHAIN: usize = 8;
        let mut members = vec!["\"cycle_a\"".to_owned(), "\"cycle_b\"".to_owned()];
        members.extend((0..CHAIN).map(|index| format!("\"chain_{index}\"")));
        let mut fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                format!(
                    "[workspace]\nmembers = [{}]\nresolver = \"2\"\n",
                    members.join(", ")
                ),
            )
            .file(
                "cycle_a/Cargo.toml",
                "[package]\nname = \"cycle_a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\ncycle_b = { path = \"../cycle_b\" }\n",
            )
            .file("cycle_a/src/lib.rs", "pub fn a() {}\n")
            .file(
                "cycle_b/Cargo.toml",
                "[package]\nname = \"cycle_b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dev-dependencies]\ncycle_a = { path = \"../cycle_a\" }\n",
            )
            .file("cycle_b/src/lib.rs", "pub fn b() {}\n");
        for index in 0..CHAIN {
            let next = if index + 1 < CHAIN {
                format!("chain_{}", index + 1)
            } else {
                "cycle_a".to_owned()
            };
            let source = if index + 1 < CHAIN {
                format!(
                    "pub trait Tr{index} {{}}\npub struct S{index};\nimpl {next}::Tr{next_index} for S{index} {{}}\n",
                    next_index = index + 1
                )
            } else {
                format!("pub trait Tr{index} {{}}\n")
            };
            fixture = fixture
                .file(
                    format!("chain_{index}/Cargo.toml"),
                    format!(
                        "[package]\nname = \"chain_{index}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                         [dependencies]\n{next} = {{ path = \"../{next}\" }}\n"
                    ),
                )
                .file(format!("chain_{index}/src/lib.rs"), source);
        }
        let fixture = fixture.build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(
            summaries.len(),
            CHAIN + 2,
            "every unit publishes a summary: {:?}",
            summaries.keys().collect::<Vec<_>>()
        );
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let live_endpoints = |state: &str| -> Vec<(String, String)> {
            conn.prepare(
                "SELECT summaries.summary_id, endpoints.endpoint_role
                 FROM rust_resolution_unit_summary_trait_endpoints AS endpoints
                 JOIN resolution_unit_summary_versions AS versions
                   ON versions.summary_id = endpoints.summary_id AND versions.valid_until IS NULL
                 JOIN resolution_unit_summaries AS summaries
                   ON summaries.summary_id = versions.summary_id
                 WHERE endpoints.endpoint_state = ?1
                 ORDER BY summaries.summary_id, endpoints.endpoint_role",
            )
            .unwrap()
            .query_map([state], |row| {
                Ok((row.get::<_, i64>(0)?.to_string(), row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        };
        let resolved = live_endpoints("resolved");
        let unresolved = live_endpoints("unresolved");
        assert_eq!(
            resolved.len(),
            2 * (CHAIN - 1),
            "every chain impl names its subject and its trait: {resolved:?}"
        );
        assert!(
            unresolved.is_empty(),
            "no consumer was derived before its provider: {unresolved:?}"
        );
        let unavailable: Vec<(String, String)> = conn
            .prepare(
                "SELECT gaps.gap_kind, gaps.subject
                 FROM resolution_unit_summary_gaps AS gaps
                 JOIN resolution_unit_summary_versions AS versions
                   ON versions.summary_id = gaps.summary_id AND versions.valid_until IS NULL
                 WHERE gaps.gap_kind = 'unit_summary_unavailable'",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            unavailable.is_empty(),
            "a dev-dependency derived later is consumed once it exists: {unavailable:?}"
        );
    }

    #[test]
    #[ignore = "operator measurement: needs BIFROST_RUST_UNIT_SUMMARY_CORPUS, a writable Rust repository copy"]
    fn measure_rust_unit_summary_reconcile_on_a_corpus() {
        use std::sync::Arc;
        use std::time::Instant;

        use crate::analyzer::{Language, ProjectFile, TestProject};

        let root = std::path::PathBuf::from(
            std::env::var("BIFROST_RUST_UNIT_SUMMARY_CORPUS")
                .expect("BIFROST_RUST_UNIT_SUMMARY_CORPUS names a writable Rust repository copy"),
        )
        .canonicalize()
        .unwrap();
        let project: Arc<dyn crate::analyzer::Project> =
            Arc::new(TestProject::new(root.clone(), Language::Rust));
        let started = Instant::now();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("build the real Rust workspace");
        eprintln!("MEASURE Rust fresh build {:?}", started.elapsed());

        let report_rows = |label: &str, workspace: &WorkspaceAnalyzer| {
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            let mut statement = conn
                .prepare(
                    "SELECT topology.crate_name, summaries.summary_id,
                       2
                       + (SELECT count(*) FROM resolution_unit_summary_members AS members
                          WHERE members.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_dependencies AS dependencies
                          WHERE dependencies.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_reads AS reads
                          WHERE reads.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_exports AS exports
                          WHERE exports.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_imports AS imports
                          WHERE imports.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_gaps AS gaps
                          WHERE gaps.summary_id = summaries.summary_id)
                     FROM rust_crate_versions AS topology_versions
                     JOIN rust_crate_topologies AS topology USING(topology_id)
                     JOIN resolution_unit_summary_versions AS summary_versions
                       ON summary_versions.workspace_id = topology_versions.workspace_id
                      AND summary_versions.lang = topology_versions.lang
                      AND summary_versions.generation = topology_versions.generation
                      AND summary_versions.unit_key = topology_versions.crate_key
                      AND summary_versions.valid_until IS NULL
                     JOIN resolution_unit_summaries AS summaries
                       ON summaries.summary_id = summary_versions.summary_id
                     WHERE topology_versions.lang = 'rust'
                       AND topology_versions.valid_until IS NULL
                       AND topology.publication_state = 'complete'
                     ORDER BY topology.crate_name, topology.target_kind",
                )
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            eprintln!("MEASURE {label} summary rows per crate: {rows:?}");
            rows
        };

        let fresh = report_rows("fresh", &workspace);
        assert!(
            !fresh.is_empty(),
            "the Rust workspace published no summaries"
        );
        let store = workspace.store().unwrap();
        let member = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT rel_path FROM resolution_unit_summary_members
                 ORDER BY rel_path LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let path = root.join(&member);
        let mut source = std::fs::read_to_string(&path).unwrap();
        source.push_str("\n// Rust unit summary measurement edit\n");
        std::fs::write(&path, source).unwrap();
        let started = Instant::now();
        let updated = workspace.update(&BTreeSet::from([ProjectFile::new(
            root.clone(),
            std::path::PathBuf::from(&member),
        )]));
        eprintln!(
            "MEASURE Rust one-file edit/update {:?} ({member})",
            started.elapsed()
        );
        let after = report_rows("one-file-edit", &updated);
        let fresh_summary_ids = fresh
            .iter()
            .map(|(_, summary_id, _)| *summary_id)
            .collect::<BTreeSet<_>>();
        let derived = after
            .iter()
            .filter(|(_, summary_id, _)| !fresh_summary_ids.contains(summary_id))
            .map(|(crate_name, summary_id, rows)| (crate_name.clone(), *summary_id, *rows))
            .collect::<Vec<_>>();
        eprintln!("MEASURE Rust one-file edit derived crate summaries: {derived:?}");
        assert_eq!(
            derived.len(),
            1,
            "a body-only edit should derive its crate summary and no dependents"
        );
    }
}
