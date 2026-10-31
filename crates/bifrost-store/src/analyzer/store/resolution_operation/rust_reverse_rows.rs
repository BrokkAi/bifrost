//! Query-local reverse discovery from persisted crate and reference rows.

use super::super::resolution_prepare::resolution_rows::{
    gap_origin_code, namespace_code, site_kind_code,
};
use super::reverse_candidates::{
    ReverseCandidateKey, ReverseContextWitness, read_reverse_candidates,
};
use super::*;
use crate::analyzer::resolution::ResolutionCompletionAccumulator;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionGapKind, ResolutionMemberKind, ResolutionScopeId,
};
use rusqlite::{OptionalExtension, params};
use std::sync::OnceLock;

mod retained;
use super::reverse::{ReverseBlobControl, execute_reverse_blobs, execute_reverse_partitions};

/// The namespaces a Rust name can be looked up in. A reverse candidate is a
/// reference that looks the target's name up in any of them, and an export
/// half is a route from the crate root under one of them.
pub(super) const REVERSE_LOOKUP_NAMESPACES: [ResolutionNamespace; 6] = [
    ResolutionNamespace::Type,
    ResolutionNamespace::Value,
    ResolutionNamespace::Callable,
    ResolutionNamespace::Constructor,
    ResolutionNamespace::Constant,
    ResolutionNamespace::Macro,
];

pub(crate) const DEFINITION_SITE_SQL: &str = super::reverse_nomination::REVERSE_DEFINITION_SITE_SQL;
#[doc(hidden)]
pub const SAME_BLOB_TYPE_EXPORT_KEYS_SQL: &str = r#"
SELECT DISTINCT sites.semantic_key
FROM main.resolution_unit_summary_members AS candidate
  INDEXED BY resolution_unit_summary_members_blob
CROSS JOIN selected_rust_unit_summaries AS owner
  ON owner.summary_id=candidate.summary_id
CROSS JOIN main.rust_resolution_unit_summary_exports AS exports
  INDEXED BY rust_resolution_unit_summary_exports_declaration
  ON exports.summary_id=owner.summary_id
 AND exports.declaration_member_ordinal=candidate.member_ordinal
 AND exports.origin='declaration'
CROSS JOIN source_native_declaration_bridges AS export_bridge
  ON export_bridge.blob_id=candidate.blob_id
 AND export_bridge.source_site=exports.declaration_site
CROSS JOIN source_declaration_units AS export_unit
  ON export_unit.blob_id=export_bridge.blob_id
 AND export_unit.declaration_id=export_bridge.declaration_id
CROSS JOIN source_native_declaration_bridges AS target_bridge
  ON target_bridge.blob_id=candidate.blob_id AND target_bridge.source_site=?3
CROSS JOIN source_declaration_units AS target_unit
  ON target_unit.blob_id=target_bridge.blob_id
 AND target_unit.declaration_id=target_bridge.declaration_id
 AND target_unit.unit_key=export_unit.unit_key
CROSS JOIN resolution_semantic_sites AS sites
  ON sites.blob_id=candidate.blob_id
 AND sites.source_site=exports.declaration_site
 AND sites.semantic_role='definition'
WHERE candidate.blob_id=?1 AND exports.namespace='type' AND exports.name=?2
  AND exports.declaration_site<>?3
"#;
#[doc(hidden)]
pub const BASE_TARGET_ACTIVATION_SQL: &str = r#"
WITH target_unit AS (
  SELECT units.unit_key
  FROM source_native_declaration_bridges AS bridge
  CROSS JOIN source_declaration_units AS units
    ON units.blob_id=bridge.blob_id AND units.declaration_id=bridge.declaration_id
  WHERE bridge.blob_id=?1 AND bridge.source_site=?2
)
SELECT properties.cfg_condition, json(context.cfg_atoms), context.target_kind
FROM source_declaration_units AS units
CROSS JOIN target_unit ON target_unit.unit_key=units.unit_key
CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=units.blob_id AND bridge.declaration_id=units.declaration_id
CROSS JOIN resolution_semantic_sites AS site
  ON site.blob_id=bridge.blob_id AND site.source_site=bridge.source_site
 AND site.semantic_role='definition'
CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id=bridge.blob_id AND properties.declaration_id=bridge.declaration_id
CROSS JOIN main.resolution_unit_summary_members AS members
  INDEXED BY resolution_unit_summary_members_blob
  ON members.blob_id=site.blob_id
CROSS JOIN selected_rust_unit_summaries AS owner
  ON owner.summary_id=members.summary_id
CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id=owner.summary_id
WHERE units.blob_id=?1
"#;
pub(crate) const CONTRACT_OWNER_SQL: &str = "SELECT target_mount.persisted_relative_path, owner_site.source_site, owner.member_kind FROM temp.selected_resolution_mounts AS target_mount CROSS JOIN resolution_member_owner_properties AS owner ON owner.blob_id=target_mount.blob_id AND owner.definition_semantic_key=?2 CROSS JOIN resolution_semantic_sites AS owner_site ON owner_site.blob_id=owner.blob_id AND owner_site.semantic_key=owner.owner_definition_semantic_key AND owner_site.semantic_role='definition' WHERE target_mount.mount_ordinal=?1";
const MEMBER_OWNER_IS_TRAIT_SQL: &str = r#"
SELECT EXISTS (
  SELECT 1
  FROM temp.selected_resolution_mounts AS mount
  CROSS JOIN resolution_semantic_sites AS owner_site
    ON owner_site.blob_id=mount.blob_id
   AND owner_site.semantic_key=?2
   AND owner_site.semantic_role='definition'
  CROSS JOIN source_native_declaration_bridges AS bridge
    ON bridge.blob_id=owner_site.blob_id
   AND bridge.source_site=owner_site.source_site
  CROSS JOIN source_rust_declaration_properties AS properties
    ON properties.blob_id=bridge.blob_id
   AND properties.declaration_id=bridge.declaration_id
  WHERE mount.mount_ordinal=?1
    -- RustDeclarationKind::Trait is encoded as 3 in this source projection.
    AND properties.declaration_kind=3
)
"#;
/// Whether a qualified path root's external boundary is explained by a
/// workspace dependency that exists only on another target of this package.
/// The current placement rows identify the package through the manifest file
/// version, so this does not confuse identically named dependencies in other
/// workspace packages.
#[doc(hidden)]
pub const OTHER_TARGET_WORKSPACE_DEPENDENCY_SQL: &str = r#"
SELECT
 EXISTS(
   SELECT 1
   FROM temp.selected_rust_container_placements AS placement
   CROSS JOIN selected_rust_unit_summaries AS current
     ON current.topology_id=placement.topology_id
   CROSS JOIN main.rust_unit_summary_dependency_names AS dependency_name
     ON dependency_name.summary_id=current.summary_id
    AND dependency_name.extern_name=?2
   WHERE placement.mount_ordinal=?1
 ),
 EXISTS(
   SELECT 1
   FROM temp.selected_rust_container_placements AS placement
   CROSS JOIN selected_rust_unit_summaries AS current
     ON current.topology_id=placement.topology_id
   CROSS JOIN main.rust_resolution_unit_summary_versions AS sibling_version
     INDEXED BY rust_resolution_unit_summary_versions_manifest
     ON sibling_version.workspace_id=current.workspace_id
    AND sibling_version.generation=current.generation
    AND sibling_version.manifest_file_version_id=current.manifest_file_version_id
    AND sibling_version.unit_key<>current.unit_key
   CROSS JOIN selected_rust_unit_summaries AS sibling
     ON sibling.summary_id=sibling_version.summary_id
    AND sibling.workspace_id=current.workspace_id
    AND sibling.generation=current.generation
   CROSS JOIN main.rust_unit_summary_dependency_names AS dependency_name
     ON dependency_name.summary_id=sibling.summary_id
    AND dependency_name.extern_name=?2
   CROSS JOIN main.resolution_unit_summary_dependencies AS dependency
     ON dependency.summary_id=sibling.summary_id
    AND dependency.dependency_ordinal=dependency_name.dependency_ordinal
    AND dependency.boundary='workspace'
   WHERE placement.mount_ordinal=?1
     AND current.manifest_file_version_id IS NOT NULL
 )
"#;
const REFERENCE_ROOT_LOOKUP_SQL: &str = "SELECT root_identity.spelling
 FROM temp.selected_resolution_mounts AS mount
 CROSS JOIN resolution_reference_lookup_identities AS root_reference
  ON root_reference.blob_id=mount.blob_id AND root_reference.semantic_key=?2
 CROSS JOIN resolution_identities AS root_identity
  ON root_identity.id=root_reference.identity_id
 WHERE mount.mount_ordinal=?1 AND root_identity.spelling IS NOT NULL
 LIMIT 1";
/// The crate root of every Cargo target that compiles one candidate file.
///
/// A file declared by both a library and a binary target is compiled once per
/// target. Confirmation resolves once per distinct root while retaining every
/// selected placement/unit authority that contributes to that root. The
/// row is the owning target's own crate root, not the candidate file: a caller
/// path is how a confirmation names the crate context it resolves under, and
/// the candidate sites travel separately as locators. Returning the candidate
/// file collapsed every owning target into one request, in which `crate::error`
/// in a dual-owned module named the library's `error` and the binary's at once
/// and neither owner could claim the site.
#[doc(hidden)]
pub const CALLER_ROOTS_SQL: &str = r#"
WITH source(blob_id,persisted_relative_path) AS (
  SELECT blob_id,persisted_relative_path
  FROM temp.selected_resolution_mounts
  WHERE storage_language='rust' AND persisted_relative_path=?1
  UNION ALL
  SELECT blob.id,mask.persisted_relative_path
  FROM temp.selected_resolution_overlay_masks AS mask
  CROSS JOIN workspace_file_versions AS version
    ON version.file_version_id=mask.masked_file_version_id
  CROSS JOIN blobs AS blob
    ON blob.blob_oid=version.blob_oid AND blob.lang=version.lang AND blob.parse_variant=x''
   AND blob.generation=version.generation
  WHERE mask.storage_language='rust' AND mask.persisted_relative_path=?1
)
SELECT DISTINCT roots.rel_path, owner.workspace_id, owner.generation, owner.topology_id,
 owner.unit_key, owner.summary_id, authority.summary_digest, authority.output_digest,
 authority.producer_epoch, authority.derivation_version,
 source_placement.member_ordinal, source_placement.module_path,
 source_placement.source_kind, source_placement.scope_ordinal,
 root_placement.member_ordinal, root_placement.module_path,
 root_placement.source_kind, root_placement.scope_ordinal
FROM source
CROSS JOIN main.resolution_unit_summary_members AS source_members
  INDEXED BY resolution_unit_summary_members_blob
  ON source_members.blob_id=source.blob_id
 AND source_members.rel_path=source.persisted_relative_path
CROSS JOIN selected_rust_unit_summaries AS owner
  ON owner.summary_id=source_members.summary_id
CROSS JOIN main.rust_resolution_unit_summary_contexts AS owner_context
  ON owner_context.summary_id=owner.summary_id
CROSS JOIN main.rust_unit_summary_placements AS source_placement
  ON source_placement.summary_id=owner.summary_id
 AND source_placement.member_ordinal=source_members.member_ordinal
CROSS JOIN main.rust_unit_summary_placements AS root_placement
  ON root_placement.summary_id=owner.summary_id
 AND root_placement.module_path='crate'
 AND root_placement.source_kind='declared'
CROSS JOIN main.resolution_unit_summary_members AS roots
  ON roots.summary_id=root_placement.summary_id
 AND roots.member_ordinal=root_placement.member_ordinal
CROSS JOIN main.resolution_unit_summaries AS authority
  ON authority.summary_id=owner.summary_id
WHERE owner_context.target_kind<>'detached'
   OR NOT EXISTS (
     SELECT 1
     FROM main.resolution_unit_summary_members AS parent_member
       INDEXED BY resolution_unit_summary_members_blob
     CROSS JOIN selected_rust_unit_summaries AS container
       ON container.summary_id=parent_member.summary_id
     CROSS JOIN main.rust_resolution_unit_summary_contexts AS container_context
       ON container_context.summary_id=container.summary_id
      AND container_context.target_kind='detached'
     CROSS JOIN main.rust_unit_summary_placements AS parent_placement
       ON parent_placement.summary_id=parent_member.summary_id
      AND parent_placement.member_ordinal=parent_member.member_ordinal
      AND parent_placement.module_path<>'crate'
     WHERE parent_member.blob_id=roots.blob_id
       AND parent_member.rel_path=roots.rel_path
       AND container.unit_key<>owner.unit_key
   )
ORDER BY roots.rel_path, owner.unit_key, owner.summary_id,
 source_placement.member_ordinal, source_placement.module_path,
 source_placement.source_kind, source_placement.scope_ordinal,
 root_placement.member_ordinal, root_placement.scope_ordinal

"#;
/// The declaration site of the owner a member declaration belongs to, keyed by
/// the member's own blob and source site.
///
/// Both seeks are covering: `resolution_semantic_sites` is keyed by
/// `(blob_id, source_site)` and by `(blob_id, semantic_role, semantic_key)`,
/// and `resolution_member_owner_properties` by `(blob_id,
/// definition_semantic_key, ..)`. A member with no owner row answers nothing,
/// which is the ordinary case for a free item.
pub(crate) const MEMBER_OWNER_SITE_SQL: &str = "SELECT DISTINCT owner_site.source_site \
 FROM resolution_semantic_sites AS member_site \
 CROSS JOIN resolution_member_owner_properties AS owner \
  ON owner.blob_id=member_site.blob_id AND owner.definition_semantic_key=member_site.semantic_key \
 CROSS JOIN resolution_semantic_sites AS owner_site \
  ON owner_site.blob_id=owner.blob_id \
  AND owner_site.semantic_role='definition' \
  AND owner_site.semantic_key=owner.owner_definition_semantic_key \
 WHERE member_site.blob_id=?1 AND member_site.source_site=?2 \
  AND member_site.semantic_role='definition'";

pub use super::reverse_nomination::ReverseCandidateSet as RustReverseCandidateSet;
use super::reverse_nomination::{
    ReverseExposure, ReverseExposureSeeds, ReverseExposureStep, ReverseLookupSource,
    ReverseNominationHooks, ReverseSourceLookup, group_reverse_inputs, merged_locators,
    nominate_reverse_target,
};

pub(crate) const EXPORTS_SQL: &str = include_str!("../rust_reverse_exports.sql");
// A cfg-alternative definition can share one CodeUnit with its active sibling
// while only the sibling has a selected export row. Keep the sibling routes
// available to reverse discovery; forward confirmation checks each candidate.
#[doc(hidden)]
pub const SAME_BLOB_TYPE_EXPORTS_SQL: &str = r#"
SELECT owner.topology_id, owner.unit_key, exports.module_path, 'type',
       exports.name, exports.visibility, 0
FROM main.resolution_unit_summary_members AS candidate
  INDEXED BY resolution_unit_summary_members_blob
CROSS JOIN selected_rust_unit_summaries AS owner
  ON owner.summary_id=candidate.summary_id
CROSS JOIN main.rust_unit_summary_placements AS placement
  ON placement.summary_id=owner.summary_id
 AND placement.member_ordinal=candidate.member_ordinal
CROSS JOIN main.rust_resolution_unit_summary_exports AS exports
  INDEXED BY rust_resolution_unit_summary_exports_declaration
  ON exports.summary_id=owner.summary_id
 AND exports.declaration_member_ordinal=candidate.member_ordinal
 AND exports.module_path=placement.module_path
 AND exports.origin='declaration'
CROSS JOIN source_native_declaration_bridges AS export_bridge
  ON export_bridge.blob_id=candidate.blob_id
 AND export_bridge.source_site=exports.declaration_site
CROSS JOIN source_declaration_units AS export_unit
  ON export_unit.blob_id=export_bridge.blob_id
 AND export_unit.declaration_id=export_bridge.declaration_id
CROSS JOIN source_native_declaration_bridges AS target_bridge
  ON target_bridge.blob_id=candidate.blob_id AND target_bridge.source_site=?3
CROSS JOIN source_declaration_units AS target_unit
  ON target_unit.blob_id=target_bridge.blob_id
 AND target_unit.declaration_id=target_bridge.declaration_id
 AND target_unit.unit_key=export_unit.unit_key
WHERE candidate.blob_id=?1 AND candidate.rel_path=?4
  AND exports.namespace='type' AND exports.name=?2
  AND exports.declaration_site<>?3
"#;
#[doc(hidden)]
pub const IMPORTS_SQL: &str = "SELECT DISTINCT sources.blob_id, route.bound_name, CASE WHEN sources.blob_id=bound_member.blob_id THEN route.binder_scope END, owner.topology_id, owner.unit_key, route.module_path FROM main.rust_resolution_unit_summary_import_routes AS route INDEXED BY rust_resolution_unit_summary_import_routes_target_identity CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=route.summary_id CROSS JOIN main.resolution_unit_summary_members AS bound_member ON bound_member.summary_id=route.summary_id AND bound_member.member_ordinal=route.member_ordinal CROSS JOIN main.rust_unit_summary_placements AS placement ON placement.summary_id=route.summary_id AND placement.module_path=route.module_path CROSS JOIN main.resolution_unit_summary_members AS sources ON sources.summary_id=placement.summary_id AND sources.member_ordinal=placement.member_ordinal WHERE route.target_unit_key=?1 AND route.target_module_path=?2 AND route.target_name=?3";
#[doc(hidden)]
pub const GLOBS_SQL: &str = "SELECT DISTINCT sources.blob_id, CASE WHEN sources.blob_id=bound_member.blob_id THEN route.binder_scope END, owner.topology_id, owner.unit_key, route.module_path FROM main.rust_resolution_unit_summary_glob_imports AS route INDEXED BY rust_resolution_unit_summary_glob_imports_target_identity CROSS JOIN selected_rust_unit_summaries AS owner ON owner.summary_id=route.summary_id CROSS JOIN main.resolution_unit_summary_members AS bound_member ON bound_member.summary_id=route.summary_id AND bound_member.member_ordinal=route.member_ordinal CROSS JOIN main.rust_unit_summary_placements AS placement ON placement.summary_id=route.summary_id AND placement.module_path=route.module_path CROSS JOIN main.resolution_unit_summary_members AS sources ON sources.summary_id=placement.summary_id AND sources.member_ordinal=placement.member_ordinal WHERE route.target_unit_key=?1 AND route.target_module_path=?2";
#[doc(hidden)]
pub const MODULE_SOURCES_SQL: &str = r#"
SELECT members.blob_id
FROM selected_rust_unit_summaries AS owner
CROSS JOIN main.resolution_unit_summary_placements AS placement
  ON placement.summary_id=owner.summary_id AND placement.container_path=CASE ?2 WHEN 'crate' THEN '' ELSE ?2 END
CROSS JOIN selected_rust_unit_members AS members
  ON members.summary_id=placement.summary_id
 AND members.member_ordinal=placement.member_ordinal
WHERE owner.unit_key=?1
"#;
/// Every selected blob of every crate that compiles one blob.
///
/// A `macro_rules!` macro reaches the rest of its crate by textual scope:
/// `#[macro_use] mod definitions;` and a definition written above `mod child;`
/// both leave it visible in files that neither import nor export it, so no
/// import or export row names those files. The crate's own files are the
/// superset textual scope can reach; forward confirmation decides which
/// definition each invocation's textual scope holds.
#[doc(hidden)]
pub const TEXTUAL_MACRO_SOURCES_SQL: &str = r#"
SELECT DISTINCT members.blob_id
FROM main.resolution_unit_summary_members AS target
  INDEXED BY resolution_unit_summary_members_blob
CROSS JOIN selected_rust_unit_summaries AS owner
  ON owner.summary_id=target.summary_id
CROSS JOIN selected_rust_unit_members AS members
  ON members.summary_id=owner.summary_id
WHERE target.blob_id=?1
"#;
const TEXTUAL_MACRO_INVOCATION_RANGES_SQL: &str = "SELECT selected.persisted_relative_path, invocation.start_byte, invocation.macro_name FROM source_rust_macro_invocations AS invocation CROSS JOIN temp.selected_resolution_mounts AS selected ON selected.blob_id=invocation.blob_id WHERE invocation.blob_id=?1 AND invocation.macro_name=?2 AND selected.storage_language='rust'";
#[doc(hidden)]
pub const ROOT_REFERENCES_SQL: &str = r#"
SELECT members.blob_id, routes.reference_source_site
FROM main.rust_resolution_unit_summary_root_routes AS routes
  INDEXED BY rust_resolution_unit_summary_root_routes_target
CROSS JOIN main.resolution_unit_summary_members AS members
  ON members.summary_id=routes.summary_id AND members.member_ordinal=routes.member_ordinal
WHERE routes.target_unit_key=?1 AND routes.target_module_path=?2
  AND routes.target_name=?3
  AND EXISTS(SELECT 1 FROM selected_rust_unit_summary_route_owners AS owner
    WHERE owner.summary_id=routes.summary_id)
  AND EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS selected
    INDEXED BY selected_resolution_mounts_blob_ordinal
    WHERE selected.blob_id=members.blob_id AND selected.storage_language='rust'
      AND selected.persisted_relative_path=members.rel_path)
"#;
/// Which selected Rust blobs carry a reference that looks one shared identity
/// up. This is the tier-1 discovery half of every cross-blob reverse question:
/// the blobs it names then answer from their own interiors.
///
/// The caller holds the interned id a shared `SemanticId` carries, which is
/// what the rows hold, so the discovery is one covering seek on the integer
/// and `resolution_identities` is not joined at all.
pub(crate) const REFERENCE_LOOKUP_BLOBS_SQL: &str = "SELECT DISTINCT names.blob_id FROM resolution_reference_lookup_identities AS names INDEXED BY resolution_reference_lookup_identities_identity WHERE names.identity_id=?1 AND EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS selected INDEXED BY selected_resolution_mounts_blob_ordinal WHERE selected.blob_id=names.blob_id AND selected.storage_language='rust')";
pub(crate) const LOCATORS_SQL: &str = "SELECT mounts.persisted_relative_path FROM temp.selected_resolution_mounts AS mounts INDEXED BY selected_resolution_mounts_blob_ordinal WHERE mounts.blob_id = ?1 AND mounts.storage_language = 'rust'";

/// A target's candidate gap sites, one row per (host, blob, site), kept for the
/// two gap queries the target is asked. A reverse operation creates the table
/// when it starts, and a target deletes its own rows when it is done. The
/// forward point path never opens the table, so its pinned statement counts do
/// not include it.
#[doc(hidden)]
pub const GAP_CANDIDATE_SITES_SCHEMA_SQL: &str =
    "CREATE TEMP TABLE IF NOT EXISTS selected_rust_reverse_gap_sites(
  target_key INTEGER NOT NULL,
  host       INTEGER NOT NULL,
  blob_id    INTEGER NOT NULL,
  site       INTEGER NOT NULL,
  PRIMARY KEY(target_key, host, blob_id, site)
) WITHOUT ROWID, STRICT;";

pub(crate) const GAP_CANDIDATE_SITES_SQL: &str =
    include_str!("rust_reverse_gap_candidate_sites.sql");

const RELEASE_GAP_CANDIDATE_SITES_SQL: &str =
    "DELETE FROM temp.selected_rust_reverse_gap_sites WHERE target_key=?1";

/// Whatever an exit between a target's two gap queries left behind.
const CLEAR_GAP_CANDIDATE_SITES_SQL: &str = "DELETE FROM temp.selected_rust_reverse_gap_sites";

const TARGET_SCOPED_REFERENCE_INVENTORY_GAPS_SQL: &str =
    include_str!("rust_reverse_gap_candidates.sql");

fn target_scoped_reference_inventory_gap_predicates_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let sql = TARGET_SCOPED_REFERENCE_INVENTORY_GAPS_SQL.replace(
            "{effective_gap_remains}",
            super::super::resolution_stage::frontier_completion::effective_gap_remains_sql(),
        );
        sql.replace(":qualified_origin", "?3")
            .replace(":local_base", "?4")
    })
}

pub(crate) fn target_scoped_reference_inventory_gaps_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        target_scoped_reference_inventory_gap_predicates_sql().replace(
            "{projection}",
            r#"-- A qualified placeholder can nominate its authored reference even when the
-- route index cannot lower that path. Other gap origins remain obligations:
-- binder, macro/item and enumeration sites are not point-confirmation requests.
SELECT DISTINCT gap.reason_key,gap.host,
       CASE WHEN gap.origin=?3 AND EXISTS (
         SELECT 1 FROM main.resolution_sites AS reference_site
         WHERE reference_site.blob_id=gap.blob_id
           AND reference_site.site=gap.source_site
           AND reference_site.role=0
       ) THEN gap.source_site END AS source_site,
       gap.source_site,
       gap.origin
FROM effective_gaps AS gap"#,
        )
    })
}

/// Only qualified gaps owning an authored reference nominate point requests.
/// Keep the certificate's exclusions, but neither decode its reasons nor run
/// macro reason filtering: the full helper appends locators before that filter.
pub(crate) fn initial_reference_inventory_gap_locators_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        target_scoped_reference_inventory_gap_predicates_sql()
            .replace(
                "{projection}",
                "SELECT DISTINCT gap.host,gap.source_site
                 FROM effective_gaps AS gap
                 WHERE gap.origin=?3 AND EXISTS (
                   SELECT 1 FROM main.resolution_sites AS reference_site
                   WHERE reference_site.blob_id=gap.blob_id
                     AND reference_site.site=gap.source_site
                     AND reference_site.role=0
                 )",
            )
            .replace("?6", "'[]'")
            .replace("?9", "'[]'")
    })
}

/// A target's candidate gap sites. The rows live in
/// `temp.selected_rust_reverse_gap_sites`; this holds the key that names them
/// and the target names both gap queries bind.
struct GapCandidateSites {
    key: i64,
    names_json: String,
    /// The request admits no fragment, so there is no inventory to enumerate
    /// and no row was written.
    admits_nothing: bool,
}

/// Enumerate the sites a target's gap queries examine, once. They depend only
/// on the target and the request's admission, not on the references that
/// confirmation later accounts for, and the gap query is asked twice per
/// target. The caller releases them when the target is done.
fn materialize_gap_candidate_sites(
    selected: &SelectedResolutionOperation<'_, '_>,
    definition: SemanticId,
    target: &CodeUnit,
    target_names: &[(i64, String, String)],
    inventory_fragments: &[u32],
    admitted: bool,
    cancellation: &CancellationToken,
) -> Result<GapCandidateSites> {
    // A definition is unique to its target within the operation, so it names
    // the target's rows.
    let key = crate::analyzer::store::resolution_stage::codec::encode_semantic(definition);
    if admitted && inventory_fragments.is_empty() {
        return Ok(GapCandidateSites {
            key,
            names_json: String::new(),
            admits_nothing: true,
        });
    }

    let namespaces: &[&str] = match target.kind() {
        brokk_bifrost_core::analyzer::model::CodeUnitType::Class
        | brokk_bifrost_core::analyzer::model::CodeUnitType::Module => &["type"],
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function => &["callable"],
        brokk_bifrost_core::analyzer::model::CodeUnitType::Field => &["value", "constant"],
        brokk_bifrost_core::analyzer::model::CodeUnitType::Macro => &["macro"],
        brokk_bifrost_core::analyzer::model::CodeUnitType::FileScope => &[
            "type",
            "value",
            "callable",
            "constructor",
            "macro",
            "constant",
        ],
    };
    // Associated-method candidates are keyed by the method spelling. The
    // reverse locator set also carries owner type aliases so it can find
    // routed files, but those names cannot make a different method a
    // candidate for this answer (for example, `Tensor::from_slice` is not a
    // possible `Tensor::from_shape` reference).
    let mut names = namespaces
        .iter()
        .map(|namespace| serde_json::json!([target.identifier(), namespace]))
        .chain(
            target
                .owner_is_type_scope()
                .then(|| serde_json::json!([target.identifier(), "type"])),
        )
        .chain(
            (target.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Class)
                .then(|| serde_json::json!(["Self", "type"])),
        )
        .collect::<Vec<_>>();
    if !target.owner_is_type_scope() {
        names.extend(target_names.iter().flat_map(|(topology, module, name)| {
            namespaces
                .iter()
                .map(move |namespace| serde_json::json!([name, namespace, topology, module]))
        }));
    }
    names.sort_by_key(|name| name.to_string());
    names.dedup();
    let names_json = serde_json::to_string(&names).expect("target name keys serialize as JSON");
    let fragments_json = serde_json::to_string(inventory_fragments)
        .expect("target inventory fragments serialize as JSON");
    let member_reference = site_kind_code(ResolutionSiteKind::MemberReference);
    let callable_reference = site_kind_code(ResolutionSiteKind::CallableReference);
    let connection = selected.ready.inventory.connection();
    let result = super::super::resolution::with_resolution_read_progress_handler(
        connection,
        cancellation,
        |_| {
            // The retained selection survives only while every write to its
            // connection is accounted, so the target's rows are an owned write.
            selected
                .ready
                .inventory
                .with_owned_temp_write(|connection| {
                    // Rows left by an earlier execution for this target must not mix
                    // with this one.
                    connection
                        .prepare_cached(RELEASE_GAP_CANDIDATE_SITES_SQL)?
                        .execute([key])?;
                    connection
                        .prepare_cached(GAP_CANDIDATE_SITES_SQL)?
                        .execute(params![
                            definition.ordinal().map(i64::from),
                            names_json,
                            admitted,
                            fragments_json,
                            member_reference,
                            target.owner_is_type_scope(),
                            callable_reference,
                            gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::MacroArgument,
                                )
                            ),
                            gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnexpandedItemMacro,
                                )
                            ),
                            gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnexpandedImplMacro,
                                )
                            ),
                            gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnsupportedScopeOrBinder,
                                )
                            ),
                            gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnsupportedExpression,
                                )
                            ),
                            key,
                            gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::MalformedSyntax,
                                )
                            ),
                        ])?;
                    Ok(())
                })
        },
    );
    match result {
        // The query was cancelled; the caller sees the cancellation and
        // discards whatever the gap queries read from the partial rows.
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    Ok(GapCandidateSites {
        key,
        names_json,
        admits_nothing: false,
    })
}

/// Delete a target's candidate gap sites.
fn release_gap_candidate_sites(
    selected: &SelectedResolutionOperation<'_, '_>,
    sites: GapCandidateSites,
) -> Result<()> {
    if !sites.admits_nothing {
        selected
            .ready
            .inventory
            .with_owned_temp_write(|connection| {
                connection
                    .prepare_cached(RELEASE_GAP_CANDIDATE_SITES_SQL)?
                    .execute([sites.key])?;
                Ok(())
            })?;
    }
    Ok(())
}

/// Built-in macros whose expansion cannot invent an identifier. Their input
/// is already name-checked, so a frontier that does not spell a target name
/// cannot become a reference to it. This is the subset of the built-in list in
/// `rust_crate_item_macro_decisions.sql` whose expansion cannot capture an
/// identifier from a format string or included file.
const NON_SYNTHESIZING_BUILTIN_MACROS: &[&str] = &[
    "asm",
    "cfg",
    "column",
    "compile_error",
    "concat",
    "concat_bytes",
    "env",
    "file",
    "global_asm",
    "include_bytes",
    "include_str",
    "line",
    "log_syntax",
    "matches",
    "module_path",
    "naked_asm",
    "offset_of",
    "option_env",
    "stringify",
    "thread_local",
    "trace_macros",
    "vec",
];

/// Whether an unexpanded macro frontier is proven unable to synthesize any
/// name in the target's closure. A known local `macro_rules!` definition
/// bounds the names its transcriber can write; its input tokens bound the
/// names a metavariable can replay.
///
/// An expression-position macro that is not a known identifier synthesizer can
/// only reference a name it was handed: an input identifier, a format-string
/// capture, or a nested macro that produces one of those. A `mod` in its input
/// can mount a file whose names the input never spells, so it stays open. Item
/// and attribute position macros stay open because their expansion can
/// introduce items of its own. Identifier-synthesizing macros and a target
/// name present in the input or transcriber remain open.
fn macro_frontier_cannot_name_target(
    connection: &rusqlite::Connection,
    host: u32,
    source_site: u32,
    origin: i64,
    target_names_json: &str,
) -> Result<bool> {
    let expression_origin =
        gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            ResolutionGapKind::UnsupportedExpression,
        ));
    let macro_origins = [
        gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            ResolutionGapKind::MacroArgument,
        )),
        gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            ResolutionGapKind::UnexpandedItemMacro,
        )),
        gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            ResolutionGapKind::UnexpandedImplMacro,
        )),
        gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
            ResolutionGapKind::UnsupportedScopeOrBinder,
        )),
        expression_origin,
    ];
    if !macro_origins.contains(&origin) {
        return Ok(false);
    }
    let blob_id = connection
        .prepare_cached(
            "SELECT blob_id
             FROM temp.selected_resolution_mounts
             WHERE mount_ordinal=?1",
        )?
        .query_row([i64::from(host)], |row| row.get::<_, i64>(0))?;
    let Some((invocation, input_start, input_source, input_macro_name)) = connection
        .prepare_cached(
            "SELECT invocation_occurrence_id,start_byte,source,macro_name
             FROM source_rust_macro_inputs
             WHERE blob_id=?1 AND native_gap_site=?2",
        )?
        .query_row(params![blob_id, source_site], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .optional()?
    else {
        return Ok(false);
    };
    // Rows published before migration 0191 have no macro name of their own.
    // The item-macro table still names any unqualified invocation it owns.
    let macro_name = match input_macro_name {
        Some(name) => name,
        None => {
            let Some(name) = connection
                .prepare_cached(
                    "SELECT macro_name
                     FROM source_rust_macro_invocations
                     WHERE blob_id=?1 AND occurrence_id=?2",
                )?
                .query_row(params![blob_id, invocation], |row| row.get::<_, String>(0))
                .optional()?
            else {
                return Ok(false);
            };
            name
        }
    };
    let terminal = macro_name.rsplit("::").next().unwrap_or(&macro_name);
    if macro_import_synthesizes_identifiers(connection, blob_id, terminal)? {
        return Ok(false);
    }
    // The gap origin says how lowering classified the boundary, not where the
    // invocation sits. An expression-position invocation is bounded by its
    // input. An item-position invocation is bounded only when its written
    // path is qualified: an unqualified definitionless item macro may be a
    // textual-scope `macro_rules!` this store could not name, and an
    // unparseable input group there leaves reference enumeration open
    // (#5517). A qualified path whose definition this store cannot see names
    // an external macro, whose expansion receives no name it was not handed.
    // An unqualified name is that qualified path when it is proven to resolve
    // to one named import: no textual-scope macro can stand between them
    // (#6140).
    let expression_position: Option<i64> = connection
        .prepare_cached(
            "SELECT source_position
             FROM source_rust_item_macro_expansions
             WHERE blob_id=?1 AND invocation_occurrence_id=?2",
        )?
        .query_row(params![blob_id, invocation], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .optional()?
        .flatten();
    use crate::analyzer::store::source_facts::rust_items::{
        RUST_MACRO_CONTEXTS_VERSION, RUST_MACRO_FACTS_VERSION,
    };
    let bounds_by_input = origin == expression_origin
        && (expression_position == Some(2)
            || macro_name.contains("::")
            || connection
                .prepare_cached(MACRO_TEXTUAL_CLOSURE_SQL)?
                .query_row(
                    params![
                        blob_id,
                        invocation,
                        macro_name,
                        i64::from(host),
                        RUST_MACRO_FACTS_VERSION,
                        RUST_MACRO_CONTEXTS_VERSION,
                    ],
                    |row| row.get::<_, bool>(0),
                )?);
    let all_target_names = serde_json::from_str::<Vec<Vec<serde_json::Value>>>(target_names_json)
        .expect("target names JSON")
        .into_iter()
        .filter_map(|entry| {
            entry
                .first()
                .and_then(|name| name.as_str())
                .map(str::to_owned)
        })
        .filter(|name| *name != "*")
        .collect::<std::collections::BTreeSet<_>>();
    let non_self_names = all_target_names
        .iter()
        .filter(|name| name.as_str() != "Self")
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let non_self_names_json =
        serde_json::to_string(&non_self_names).expect("target names serialize");
    let self_is_target = connection
        .prepare_cached(
            "SELECT EXISTS (
               SELECT 1
               FROM source_rust_impl_items AS impl
               JOIN source_rust_types AS typ
                 ON typ.blob_id=impl.blob_id
                AND typ.occurrence_id=impl.target_type_occurrence_id
               JOIN source_rust_type_segments AS segment
                 ON segment.blob_id=typ.blob_id
                AND segment.type_occurrence_id=typ.occurrence_id
               WHERE impl.blob_id=?1
                 AND ?2>=impl.body_start_byte
                 AND ?2<impl.body_end_byte
                 AND segment.name IN (SELECT value FROM json_each(?3))
                 AND segment.ordinal=(
                   SELECT max(terminal.ordinal)
                   FROM source_rust_type_segments AS terminal
                   WHERE terminal.blob_id=segment.blob_id
                     AND terminal.type_occurrence_id=segment.type_occurrence_id
                 )
             )",
        )?
        .query_row(params![blob_id, input_start, non_self_names_json], |row| {
            row.get::<_, bool>(0)
        })?;
    let target_names = if self_is_target {
        all_target_names
    } else {
        non_self_names
    };
    let mut input_names = std::collections::BTreeSet::new();
    let mut literal_texts = Vec::new();
    let mut nested_name_producer = false;
    let mut mounts_module = false;
    let mut nested_decisions = std::collections::HashMap::new();
    let mut previous_token: Option<(String, usize, usize)> = None;
    {
        let mut statement = connection.prepare_cached(
            "SELECT syntax_kind,start_byte,end_byte
             FROM source_rust_macro_input_tokens
             WHERE blob_id=?1 AND invocation_occurrence_id=?2",
        )?;
        let mut tokens = statement.query(params![blob_id, invocation])?;
        while let Some(token) = tokens.next()? {
            let syntax_kind: String = token.get(0)?;
            let start: i64 = token.get(1)?;
            let end: i64 = token.get(2)?;
            let (Ok(start), Ok(end)) = (
                usize::try_from(start - input_start),
                usize::try_from(end - input_start),
            ) else {
                continue;
            };
            if syntax_kind == "!" {
                match previous_token.as_ref() {
                    Some((kind, start, end))
                        if matches!(
                            kind.as_str(),
                            "identifier" | "type_identifier" | "field_identifier"
                        ) =>
                    {
                        let terminal = input_source
                            .get(*start..*end)
                            .map(|spelling| {
                                brokk_bifrost_core::analyzer::symbol_path::
                                    strip_raw_identifier_prefix(spelling)
                            })
                            .unwrap_or_default();
                        let can_produce = match nested_decisions.get(terminal) {
                            Some(&decision) => decision,
                            None => {
                                let decision =
                                    nested_macro_can_produce_a_name(connection, blob_id, terminal)?;
                                nested_decisions.insert(terminal, decision);
                                decision
                            }
                        };
                        if can_produce {
                            nested_name_producer = true;
                        }
                    }
                    // A macro path this token stream does not spell as an
                    // identifier cannot be bounded here.
                    Some(_) | None => nested_name_producer = true,
                }
            }
            let Some(spelling) = input_source.get(start..end) else {
                continue;
            };
            match syntax_kind.as_str() {
                "identifier" | "type_identifier" | "field_identifier" | "primitive_type" => {
                    input_names.insert(
                        brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                            spelling,
                        )
                        .to_owned(),
                    );
                }
                "string_literal" | "raw_string_literal" => literal_texts.push(spelling),
                "mod" => mounts_module = true,
                _ => {}
            }
            previous_token = Some((syntax_kind, start, end));
        }
    }
    if target_names
        .iter()
        .any(|target| input_names.contains(target))
    {
        return Ok(false);
    }
    let mut definitions = Vec::new();
    if !macro_name.contains("::") {
        let mut statement = connection.prepare_cached(
            "SELECT definition.blob_id,definition.declaration_id,definition.exported
             FROM rust_item_macros AS definition
             WHERE definition.macro_name=?1",
        )?;
        let mut rows = statement.query([terminal])?;
        while let Some(row) = rows.next()? {
            definitions.push((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, bool>(2)?,
            ));
        }
    }
    if definitions.is_empty() {
        if bounds_by_input {
            // An expression macro can only reach a name it was given. A
            // format capture is text rather than an identifier token, so the
            // literal's decoded value decides whether it spells a target.
            // An escape form this decoder rejects keeps the frontier open.
            let literal_names_target = literal_texts.iter().any(|text| {
                rust_string_literal_value(text).is_none_or(|value| {
                    target_names
                        .iter()
                        .any(|target| value.contains(target.as_str()))
                })
            });
            return Ok(!(nested_name_producer || literal_names_target || mounts_module));
        }
        return Ok(NON_SYNTHESIZING_BUILTIN_MACROS.contains(&terminal));
    }
    let imported = connection
        .prepare_cached(
            "SELECT 1
             FROM source_rust_import_targets
             WHERE blob_id=?1 AND bound_name=?2
             LIMIT 1",
        )?
        .exists(params![blob_id, terminal])?;
    let mut checked_visible_definition = false;
    for (definition_blob, declaration_id, exported) in definitions {
        if definition_blob != blob_id && !exported && !imported {
            continue;
        }
        checked_visible_definition = true;
        let mut saw_arm = false;
        let mut statement = connection.prepare_cached(
            "SELECT transcriber_identifiers
             FROM source_rust_macro_arms
             WHERE blob_id=?1 AND declaration_id=?2",
        )?;
        let mut rows = statement.query(params![definition_blob, declaration_id])?;
        while let Some(row) = rows.next()? {
            saw_arm = true;
            let Some(identifiers) = row.get::<_, Option<String>>(0)? else {
                return Ok(false);
            };
            let identifiers = serde_json::from_str::<Vec<String>>(&identifiers)
                .expect("macro transcriber identifiers JSON");
            if identifiers
                .iter()
                .any(|name| matches!(name.as_str(), "paste" | "concat_idents" | "format_ident"))
            {
                return Ok(false);
            }
            if identifiers
                .iter()
                .any(|name| target_names.contains(name.as_str()))
            {
                return Ok(false);
            }
        }
        if !saw_arm {
            return Ok(false);
        }
    }
    Ok(checked_visible_definition)
}

/// Reviewed macros whose expansion can invent an identifier. `include!` can
/// import a file that names the target without naming it in the invocation.
///
/// A unique import may bind one of these spellings under another local name,
/// so `use paste::paste as p; p! { ... }` stays open as well.
fn macro_import_synthesizes_identifiers(
    connection: &rusqlite::Connection,
    blob_id: i64,
    terminal: &str,
) -> Result<bool> {
    const SYNTHESIZING: &[&str] = &["paste", "concat_idents", "format_ident", "include"];
    macro_name_is_in_reviewed_family(connection, blob_id, terminal, SYNTHESIZING)
}

/// A nested macro can feed a spelling to an outer expression macro without
/// writing it as one identifier. Besides identifier synthesizers, string
/// producers can compose a format string, so they stay open as well.
fn nested_macro_can_produce_a_name(
    connection: &rusqlite::Connection,
    blob_id: i64,
    terminal: &str,
) -> Result<bool> {
    const NAME_PRODUCERS: &[&str] = &[
        "paste",
        "concat_idents",
        "format_ident",
        "include",
        "concat",
        "stringify",
        "env",
        "option_env",
    ];
    macro_name_is_in_reviewed_family(connection, blob_id, terminal, NAME_PRODUCERS)
}

fn macro_name_is_in_reviewed_family(
    connection: &rusqlite::Connection,
    blob_id: i64,
    terminal: &str,
    family: &[&str],
) -> Result<bool> {
    if family.contains(&terminal) {
        return Ok(true);
    }
    let imported = connection
        .prepare_cached(
            "SELECT DISTINCT imported_name
             FROM source_rust_import_targets
             WHERE blob_id=?1 AND bound_name=?2 AND imported_name IS NOT NULL",
        )?
        .query_map(params![blob_id, terminal], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(imported.len() == 1 && family.contains(&imported[0].as_str()))
}

/// The value of one Rust string literal token, with its escapes decoded.
///
/// A macro input is inspected at the value level: `\x00` cannot become part of
/// an identifier, while `\x66inalize_message` spells one. Returns `None` for an
/// escape form this decoder does not understand, so the caller keeps the
/// frontier open rather than claiming a name is absent.
fn rust_string_literal_value(literal: &str) -> Option<String> {
    let literal = literal.trim();
    let raw = literal.starts_with('r') || literal.starts_with("br") || literal.starts_with("cr");
    let start = literal.find('"')? + 1;
    let end = literal.rfind('"')?;
    if start > end {
        return None;
    }
    let body = &literal[start..end];
    if raw {
        return Some(body.to_owned());
    }
    let mut value = Vec::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            let mut buffer = [0_u8; 4];
            value.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            continue;
        }
        match chars.next()? {
            '\\' => value.push(b'\\'),
            '"' => value.push(b'"'),
            '\'' => value.push(b'\''),
            '0' => value.push(0),
            'n' => value.push(b'\n'),
            'r' => value.push(b'\r'),
            't' => value.push(b'\t'),
            'x' => {
                let high = chars.next()?.to_digit(16)?;
                let low = chars.next()?.to_digit(16)?;
                value.push(u8::try_from(high * 16 + low).ok()?);
            }
            'u' => {
                if chars.next()? != '{' {
                    return None;
                }
                let mut hex = String::new();
                loop {
                    match chars.next()? {
                        '}' => break,
                        '_' => {}
                        ch if ch.is_ascii_hexdigit() => hex.push(ch),
                        _ => return None,
                    }
                }
                let scalar = u32::from_str_radix(&hex, 16).ok()?;
                let ch = char::from_u32(scalar)?;
                let mut buffer = [0_u8; 4];
                value.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
            }
            '\n' => {
                while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
                    chars.next();
                }
            }
            '\r' => {
                if chars.next()? != '\n' {
                    return None;
                }
                while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
                    chars.next();
                }
            }
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&value).into_owned())
}

/// Drop contract-completion reasons from macro frontiers that cannot name any
/// target name. Contract evaluation propagates an implementation's file-wide
/// macro gaps into the target's inventory even when the macro's input and
/// transcriber cannot produce the target.
fn filter_macro_frontier_completion(
    selected: &SelectedResolutionOperation<'_, '_>,
    completion: crate::analyzer::resolution::ResolutionCompletion,
    target_names_json: &str,
) -> Result<crate::analyzer::resolution::ResolutionCompletion> {
    use crate::analyzer::resolution::{ResolutionCompletion, ResolutionIncompleteReason};
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok(completion);
    };
    let connection = selected.ready.inventory.connection();
    let mut retained = Vec::new();
    for reason in reasons.iter() {
        let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
            retained.push(*reason);
            continue;
        };
        let (Some(host), Some(reason_key)) = (semantic.ordinal(), semantic.local_key()) else {
            retained.push(*reason);
            continue;
        };
        let Some(blob_id) = connection
            .prepare_cached(
                "SELECT blob_id
                 FROM temp.selected_resolution_mounts
                 WHERE mount_ordinal=?1",
            )?
            .query_row([i64::from(host)], |row| row.get::<_, i64>(0))
            .optional()?
        else {
            retained.push(*reason);
            continue;
        };
        let Some((site, origin)) = connection
            .prepare_cached(
                "SELECT site,origin
                 FROM resolution_gap_reasons
                 WHERE blob_id=?1 AND reason=?2",
            )?
            .query_row(params![blob_id, reason_key], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)?))
            })
            .optional()?
        else {
            retained.push(*reason);
            continue;
        };
        if macro_frontier_cannot_name_target(connection, host, site, origin, target_names_json)? {
            continue;
        }
        retained.push(*reason);
    }
    Ok(if retained.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(retained)
    })
}

fn initial_reference_inventory_gap_locators(
    selected: &SelectedResolutionOperation<'_, '_>,
    sites: &GapCandidateSites,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> Result<Vec<SelectedSemanticLocator>> {
    if sites.admits_nothing {
        return Ok(Vec::new());
    }
    let mut locators = Vec::new();
    let connection = selected.ready.inventory.connection();
    let result = super::super::resolution::with_resolution_read_progress_handler(
        connection,
        cancellation,
        |connection| {
            let mut statement =
                connection.prepare_cached(initial_reference_inventory_gap_locators_sql())?;
            let mut rows = statement.query(params![
                sites.key,
                sites.names_json,
                gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
                crate::analyzer::store::resolution_stage::codec::encode_semantic(
                    SemanticId::local(0, 0)
                ),
                site_kind_code(ResolutionSiteKind::MemberReference),
                "[]",
                target.owner_is_type_scope(),
                site_kind_code(ResolutionSiteKind::CallableReference),
                "[]",
                gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    ResolutionGapKind::GeneratedItemSurface,
                )),
                gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    ResolutionGapKind::UnsupportedCallApplicability,
                )),
            ])?;
            while let Some(row) = rows.next()? {
                let host = row.get::<_, u32>(0)?;
                let site = row.get::<_, u32>(1)?;
                let mount = selected
                    .mount_table()
                    .mount_by_ordinal(SelectedResolutionMountOrdinal::new(host))?;
                locators.push(SelectedSemanticLocator::new(
                    "rust",
                    mount.persisted_relative_path(),
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(site),
                    LoweredSemanticRole::Reference,
                ));
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            Ok(())
        },
    );
    match result {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    locators.sort();
    locators.dedup();
    Ok(locators)
}

/// The reference-inventory gaps of the target's candidate sites, as a
/// completion and the locators of the sites that nominate a reference.
fn target_scoped_reference_inventory_gaps(
    selected: &SelectedResolutionOperation<'_, '_>,
    sites: &GapCandidateSites,
    target: &CodeUnit,
    accounted_reference_sites: &[(u32, u32)],
    qualified_reference_sites: &[(u32, u32)],
    cancellation: &CancellationToken,
) -> Result<(ResolutionCompletion, Vec<SelectedSemanticLocator>)> {
    if sites.admits_nothing {
        return Ok((ResolutionCompletion::Complete, Vec::new()));
    }

    let accounted_reference_sites_json = serde_json::to_string(accounted_reference_sites)
        .expect("confirmed reverse reference sites serialize as JSON");
    let qualified_reference_sites_json = serde_json::to_string(qualified_reference_sites)
        .expect("closed reverse qualified routes serialize as JSON");
    let qualified_origin =
        gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference);
    let local_base =
        crate::analyzer::store::resolution_stage::codec::encode_semantic(SemanticId::local(0, 0));
    let member_reference = site_kind_code(ResolutionSiteKind::MemberReference);
    let callable_reference = site_kind_code(ResolutionSiteKind::CallableReference);
    let mut reasons = Vec::new();
    let mut locators = Vec::new();
    let connection = selected.ready.inventory.connection();
    let result = super::super::resolution::with_resolution_read_progress_handler(
        connection,
        cancellation,
        |connection| {
            let mut statement =
                connection.prepare_cached(target_scoped_reference_inventory_gaps_sql())?;
            let mut rows = statement.query(params![
                sites.key,
                sites.names_json,
                qualified_origin,
                local_base,
                member_reference,
                accounted_reference_sites_json,
                target.owner_is_type_scope(),
                callable_reference,
                qualified_reference_sites_json,
                gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    ResolutionGapKind::GeneratedItemSurface,
                )),
                gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    ResolutionGapKind::UnsupportedCallApplicability,
                )),
            ])?;
            while let Some(row) = rows.next()? {
                let host = row.get::<_, u32>(1)?;
                let site = row.get::<_, Option<u32>>(2)?;
                let raw_site = row.get::<_, u32>(3)?;
                let origin = row.get::<_, i64>(4)?;
                let mount = selected
                    .mount_table()
                    .mount_by_ordinal(SelectedResolutionMountOrdinal::new(host))?;
                if let Some(site) = site {
                    locators.push(SelectedSemanticLocator::new(
                        "rust",
                        mount.persisted_relative_path(),
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(site),
                        LoweredSemanticRole::Reference,
                    ));
                }
                let semantic =
                    crate::analyzer::store::resolution_stage::codec::decode_semantic(row.get(0)?);
                if macro_frontier_cannot_name_target(
                    connection,
                    host,
                    raw_site,
                    origin,
                    &sites.names_json,
                )? {
                    continue;
                }
                reasons.push(
                    crate::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(
                        semantic,
                    ),
                );
                if cancellation.is_cancelled() {
                    return Ok(());
                }
            }
            Ok(())
        },
    );
    match result {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {}
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    if cancellation.is_cancelled() {
        reasons.push(crate::analyzer::resolution::ResolutionIncompleteReason::Cancelled);
    }
    let completion = if reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(reasons)
    };
    locators.sort();
    locators.dedup();
    Ok((completion, locators))
}

pub(crate) const MASKED_BLOB_SQL: &str = "SELECT blob.id FROM temp.selected_resolution_overlay_masks AS mask CROSS JOIN workspace_file_versions AS version ON version.file_version_id=mask.masked_file_version_id CROSS JOIN blobs AS blob ON blob.blob_oid=version.blob_oid AND blob.lang=version.lang AND blob.parse_variant=x'' AND blob.generation=version.generation WHERE mask.storage_language='rust' AND mask.persisted_relative_path=?1";
pub(crate) const BLOB_DEFINITION_SITE_SQL: &str = "SELECT source_site FROM resolution_semantic_sites WHERE blob_id=?1 AND semantic_key=?2 AND semantic_role='definition'";

/// Read a field's source provenance without expanding its occurrence arena.
/// Only a primary source node in well-formed syntax excludes a method usage.
/// Embedded occurrences include guessed macro arguments: even a successful
/// field binding cannot prove what an unknown expansion will do with them.
pub(crate) const FIELD_REFERENCE_PROVENANCE_SQL: &str = "SELECT
         json_extract(arena.spans, '$[' || context.source_occurrence || '][4]')=?6,
         NOT EXISTS(
           SELECT 1 FROM resolution_gaps AS gap
           CROSS JOIN resolution_gap_reasons AS reason
             ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason
           WHERE gap.blob_id=site.blob_id AND gap.covers=1 AND gap.subject=0
             AND gap.lookup=0 AND reason.origin=?5
         )
       FROM temp.selected_resolution_mounts AS mount
       CROSS JOIN resolution_sites AS site
         ON site.blob_id=mount.blob_id AND site.site=?2
       CROSS JOIN resolution_rust_reference_contexts AS context
         ON context.blob_id=site.blob_id AND context.semantic_key=site.site
       CROSS JOIN source_occurrence_arenas AS arena ON arena.blob_id=site.blob_id
       WHERE mount.storage_language='rust' AND mount.persisted_relative_path=?1
         AND site.role=0 AND site.namespace=?3 AND site.site_kind=?4
         AND site.unqualified=0 AND context.source_site=site.site";

/// Read a reference site's persisted cfg condition: the condition of the
/// innermost declaration that encloses it.
pub(crate) const SITE_CFG_SQL: &str = "SELECT json(context.cfg_condition)
       FROM temp.selected_resolution_mounts AS mount
       CROSS JOIN resolution_rust_reference_contexts AS context
         ON context.blob_id=mount.blob_id AND context.semantic_key=?2
       WHERE mount.storage_language='rust' AND mount.persisted_relative_path=?1
         AND context.source_site=?2";

pub(crate) const MACRO_TEXTUAL_CLOSURE_SQL: &str =
    include_str!("rust_reverse_macro_textual_closure.sql");
pub(crate) const CALL_ARITY_SQL: &str = include_str!("rust_reverse_call_arity.sql");
pub(crate) const CALL_SHAPE_SQL: &str = include_str!("rust_reverse_call_shape.sql");

impl SelectedResolutionOperation<'_, '_> {
    fn reverse_target_activation(
        &self,
        definition: SemanticId,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<brokk_bifrost_rust::selected_context::RustSelectedActivation> {
        use brokk_bifrost_rust::selected_context::RustSelectedActivation;
        let lexical = self.ready.lexical_source();
        let Some(SelectedSemanticProvenance::FragmentLocal(local)) =
            lexical.semantic_provenance(definition, cancellation)?
        else {
            // Absent provenance and an interior this reader could not produce
            // both leave the activation undecided.
            return Ok(RustSelectedActivation::Unknown);
        };
        let conn = self.ready.inventory.connection();
        let mount = self
            .mount_table()
            .mount_by_ordinal(local.mount().ordinal())?;
        let Some((blob, site)) = (if self.is_overlay_mount(&mount) {
            let target = match self.project_rust_definitions(&[definition], cancellation)? {
                SelectedRustDefinitionProjection::Complete(mut units) => {
                    units.pop().expect("one overlay target")
                }
                _ => return Ok(RustSelectedActivation::Unknown),
            };
            self.persisted_reverse_target(&mount, &target, cancellation)?
        } else {
            Some(conn.prepare_cached(DEFINITION_SITE_SQL)?.query_row(
                params![local.mount().ordinal().get(), local.local_key().get()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )?)
        }) else {
            return Ok(RustSelectedActivation::Unknown);
        };
        let mut statement = conn.prepare_cached(BASE_TARGET_ACTIVATION_SQL)?;
        let mut activation = RustSelectedActivation::Inactive;
        let mut found = false;
        for row in statement.query_map(params![blob, site], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (condition, atoms, kind) = row?;
            let condition =
                brokk_bifrost_core::analyzer::rust_facts::decode_rust_cfg_condition(&condition)
                    .expect("persisted cfg condition");
            let atoms = serde_json::from_str(&atoms)
                .map_err(|error| StoreError::new(format!("selected crate cfg atoms: {error}")))?;
            found = true;
            // Reverse absence authority, so a detached root's absent feature
            // atoms stay unknown; see `detached_activation`.
            let selected = if kind == "detached" {
                brokk_bifrost_rust::cfg::detached_activation(&atoms, &condition)
            } else {
                brokk_bifrost_rust::cfg::crate_activation(&atoms, &condition)
            };
            match selected {
                RustSelectedActivation::Active => return Ok(selected),
                RustSelectedActivation::Unknown => activation = selected,
                RustSelectedActivation::Inactive => {}
            }
        }
        let activation = if found {
            activation
        } else {
            RustSelectedActivation::Unknown
        };
        if activation == RustSelectedActivation::Inactive
            && target.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Class
        {
            let alternatives = conn
                .prepare_cached(SAME_BLOB_TYPE_EXPORT_KEYS_SQL)?
                .query_map(params![blob, target.identifier(), site], |row| {
                    row.get::<_, i64>(0)
                })?
                .map(|row| {
                    let local_key = u32::try_from(row?)
                        .expect("a semantic site key fits the local identity payload");
                    Ok(SemanticId::local(local.mount().ordinal().get(), local_key))
                })
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if !alternatives.is_empty() {
                match self.project_rust_definitions(&alternatives, cancellation)? {
                    SelectedRustDefinitionProjection::Complete(units)
                        if units.iter().any(|unit| unit == target) =>
                    {
                        return Ok(RustSelectedActivation::Active);
                    }
                    SelectedRustDefinitionProjection::Complete(_) => {}
                    SelectedRustDefinitionProjection::Unavailable
                    | SelectedRustDefinitionProjection::Cancelled => {
                        return Ok(RustSelectedActivation::Unknown);
                    }
                }
            }
        }
        Ok(activation)
    }

    fn persisted_reverse_target(
        &self,
        mount: &SelectedResolutionOperationMount,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Option<(i64, i64)>> {
        let conn = self.ready.inventory.connection();
        let base = conn
            .prepare_cached(MASKED_BLOB_SQL)?
            .query_row([mount.persisted_relative_path()], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?;
        let mut coordinate = None;
        if let Some(blob) = base {
            let SelectedDefinitionSemanticReadOutcome::Ready(rows) = self
                .ready
                .inventory
                .definition_semantics_for_blob(blob, cancellation)?
            else {
                return Ok(None);
            };
            let units = RustMountUnits::new(&self.ready, mount)?;
            for (definition, row) in rows {
                if units.unit(&row)? == *target {
                    assert!(
                        coordinate.is_none(),
                        "one target has one persisted base declaration"
                    );
                    let site = conn
                        .prepare_cached(BLOB_DEFINITION_SITE_SQL)?
                        .query_row(params![blob, definition.get()], |row| row.get::<_, i64>(0))?;
                    coordinate = Some((blob, site));
                }
            }
        }
        Ok(coordinate)
    }

    #[doc(hidden)]
    pub fn rust_row_binding_candidates(
        &self,
        target: &SelectedRustBindingDefinition,
        extra_names: &[String],
        seeds: &[SelectedSemanticLocator],
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<(PathBuf, SelectedSemanticLocator)>>> {
        let unit = match target {
            SelectedRustBindingDefinition::Stable(semantic) => {
                match self.project_rust_definitions(&[*semantic], cancellation)? {
                    SelectedRustDefinitionProjection::Complete(mut units) => units.pop(),
                    _ => None,
                }
            }
        };
        let Some(unit) = unit else {
            return Ok(None);
        };
        let Some(candidate_set) =
            self.rust_reverse_candidate_set(&unit, extra_names, cancellation)?
        else {
            return Ok(None);
        };
        let locators = candidate_set.into_seeded_locators(seeds);
        let mut candidates = Vec::new();
        for locator in locators {
            let roots = self
                .ready
                .inventory
                .connection()
                .prepare_cached(CALLER_ROOTS_SQL)?
                .query_map([locator.relative_path()], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if roots.is_empty() {
                return Ok(None);
            }
            candidates.extend(
                roots
                    .into_iter()
                    .map(|root| (PathBuf::from(root), locator.clone())),
            );
        }
        Ok(Some(candidates))
    }

    fn overlay_reverse_locators(
        &self,
        mount: &SelectedResolutionOperationMount,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SelectedSemanticLocator>> {
        let conn = self.ready.inventory.connection();
        let blob: i64 = conn
            .prepare_cached(super::super::selected_definition::SELECTED_DEFINITION_BLOB_SQL)?
            .query_row([i64::from(mount.ordinal().get())], |row| row.get(0))?;
        // A dirty buffer's own references are candidates whether they look the
        // name up lexically or route to it through the crate root; the base
        // blob's rows cannot answer for the buffer's current text.
        let keys = self.rust_reverse_lookup_keys(blob, name)?;
        let Some(groups) = read_reverse_candidates(self, &keys, cancellation)? else {
            return Ok(Vec::new());
        };
        let mut locators = Vec::new();
        for site in groups
            .into_iter()
            .flatten()
            .map(|candidate| candidate.site)
            .chain(self.blob_root_demand_reference_sites(blob, name, cancellation)?)
        {
            locators.push(SelectedSemanticLocator::new(
                "rust",
                mount.persisted_relative_path(),
                site,
                LoweredSemanticRole::Reference,
            ));
        }
        Ok(locators)
    }

    /// Every reference in one blob whose own lookup names one spelling, in
    /// every namespace the reverse route admits.
    ///
    /// `binder_scope` narrows the answer to the scope chain a named import
    /// binds, which is what a bound name means in the importing file.
    fn scoped_reverse_lookup_sites(
        &self,
        blob: i64,
        name: &str,
        binder_scope: u32,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ResolutionSiteId>> {
        let lexical = self.ready.lexical_source();
        let binder_scope = Some(ResolutionScopeId::new(binder_scope));
        let mut sites = Vec::new();
        for namespace in REVERSE_LOOKUP_NAMESPACES {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let lookup = ResolutionLookupSemanticRecipe::new(Language::Rust, namespace, name)
                .semantic(&self.ready.shared_names());
            let Some(found) =
                lexical.lookup_reference_sites(blob, lookup, binder_scope, cancellation)?
            else {
                return Ok(Vec::new());
            };
            sites.extend(found);
        }
        Ok(sites)
    }

    fn rust_reverse_candidate_context(&self, blob: i64) -> Result<Option<ReverseContextWitness>> {
        let ordinal = self
            .ready
            .inventory
            .connection()
            .prepare_cached(super::super::resolution_lexical::SELECTED_MOUNT_OF_BLOB_SQL)?
            .query_row([blob], |row| row.get::<_, u32>(0))
            .optional()?;
        Ok(ordinal.map(|ordinal| ReverseContextWitness::new(self, ordinal, blob)))
    }

    fn rust_reverse_lookup_keys(&self, blob: i64, name: &str) -> Result<Vec<ReverseCandidateKey>> {
        let Some(context) = self.rust_reverse_candidate_context(blob)? else {
            return Ok(Vec::new());
        };
        Ok(REVERSE_LOOKUP_NAMESPACES
            .into_iter()
            .map(|namespace| ReverseCandidateKey {
                input_ordinal: 0,
                context: context.clone(),
                lookup: ResolutionLookupSemanticRecipe::new(Language::Rust, namespace, name)
                    .semantic(&self.ready.shared_names()),
                lexical: true,
                root: false,
                qualified: false,
            })
            .collect())
    }

    /// Every reference in one blob whose route to the crate root ends in one
    /// spelling, in every namespace the reverse route admits.
    fn blob_root_demand_reference_sites(
        &self,
        blob: i64,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ResolutionSiteId>> {
        let lexical = self.ready.lexical_source();
        let mut sites = Vec::new();
        for namespace in REVERSE_LOOKUP_NAMESPACES {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let lookup = ResolutionLookupSemanticRecipe::new(Language::Rust, namespace, name)
                .semantic(&self.ready.shared_names());
            let Some(found) = lexical.root_demand_reference_sites(blob, lookup, cancellation)?
            else {
                return Ok(Vec::new());
            };
            sites.extend(found);
        }
        Ok(sites)
    }

    /// Discovery is shared; existing forward confirmation remains authoritative.
    fn rust_reverse_candidate_set(
        &self,
        target: &CodeUnit,
        extra_names: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Option<RustReverseCandidateSet>> {
        #[cfg(any(test, feature = "test-support"))]
        CANDIDATE_SET_ENUMERATIONS.with(|count| count.set(count.get() + 1));
        nominate_reverse_target(
            self,
            &RustReverseNominationHooks(self),
            target,
            extra_names,
            cancellation,
        )
    }
}

struct RustReverseNominationHooks<'a, 'store, 'input>(
    &'a SelectedResolutionOperation<'store, 'input>,
);

impl ReverseNominationHooks for RustReverseNominationHooks<'_, '_, '_> {
    fn locate_reverse_definition(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        Ok(match self.0.locate_rust_definition(target, cancellation)? {
            SelectedRustDefinitionSemanticOutcome::Found(definition) => Some(definition),
            SelectedRustDefinitionSemanticOutcome::Missing
            | SelectedRustDefinitionSemanticOutcome::Cancelled => None,
        })
    }
    fn persisted_target(
        &self,
        mount: &SelectedResolutionOperationMount,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Option<(i64, i64)>> {
        self.0.persisted_reverse_target(mount, target, cancellation)
    }
    fn overlay_routes(
        &self,
        mount: &SelectedResolutionOperationMount,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SelectedSemanticLocator>> {
        self.0.overlay_reverse_locators(mount, name, cancellation)
    }
    fn exposure_seeds(
        &self,
        target: &CodeUnit,
        blob: i64,
        site: i64,
    ) -> Result<ReverseExposureSeeds> {
        let conn = self.0.ready.inventory.connection();
        // A member declaration has no export row of its own: a trait's
        // associated type is exported by nothing, while the trait that owns it
        // is exported and imported under every route Rust allows. A reference
        // to the member is nameable exactly where its owner is, so the
        // exposure closure runs on the owner's declaration site as well and
        // the blobs it names are then scanned for the member's own name below.
        // Candidates stay provisional: forward confirmation decides which
        // same-named trait each site meant.
        let owner_sites = conn
            .prepare_cached(MEMBER_OWNER_SITE_SQL)?
            .query_map(params![blob, site], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let member_of_an_owner = !owner_sites.is_empty();
        let mut exposures = conn.prepare_cached(EXPORTS_SQL)?;
        let mut exports = Vec::new();
        for exposed_site in std::iter::once(site).chain(owner_sites) {
            exports.extend(
                exposures
                    .query_map(
                        params![
                            blob,
                            exposed_site,
                            crate::path_utils::rel_path_string(target.source())
                        ],
                        ReverseExposure::from_row,
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        if target.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Class {
            exports.extend(
                conn.prepare_cached(SAME_BLOB_TYPE_EXPORTS_SQL)?
                    .query_map(
                        params![
                            blob,
                            target.identifier(),
                            site,
                            crate::path_utils::rel_path_string(target.source())
                        ],
                        ReverseExposure::from_row,
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        let mut sources = HashSet::from_iter([(blob, target.identifier().to_owned(), None)]);
        if target.is_macro() {
            for member in conn
                .prepare_cached(TEXTUAL_MACRO_SOURCES_SQL)?
                .query_map([blob], |row| row.get::<_, i64>(0))?
            {
                sources.insert((member?, target.identifier().to_owned(), None));
            }
        }
        Ok(ReverseExposureSeeds {
            exposures: exports,
            sources,
            unbound_spelling: member_of_an_owner.then(|| target.identifier().to_owned()),
        })
    }
    fn exposure_successors(
        &self,
        exposure: &ReverseExposure,
        extra_names: &[String],
    ) -> Result<ReverseExposureStep> {
        let conn = self.0.ready.inventory.connection();
        let ReverseExposure {
            key,
            module,
            name,
            depth,
            ..
        } = exposure;
        let mut candidates = Vec::new();
        let mut sources = Vec::new();
        let mut successors = Vec::new();
        // A blob that routes to the exposure by a qualified path also
        // binds the name it ends on when the path is a `use`, and the
        // blob's later lexical uses of that binding are references to the
        // same target. The route rows name the blob; the lexical half
        // below finds those uses. Forward confirmation proves each.
        for extra in extra_names {
            for row in conn
                .prepare_cached(ROOT_REFERENCES_SQL)?
                .query_map(params![key, module, extra], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?))
                })?
            {
                let (route_blob, site) = row?;
                candidates.push((route_blob, site));
                sources.push((route_blob, extra.clone(), None));
            }
        }
        for row in conn
            .prepare_cached(ROOT_REFERENCES_SQL)?
            .query_map(params![key, module, name], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?))
            })?
        {
            let (route_blob, site) = row?;
            candidates.push((route_blob, site));
            sources.push((route_blob, name.clone(), None));
        }
        for row in conn
            .prepare_cached(MODULE_SOURCES_SQL)?
            .query_map(params![key, module], |row| row.get::<_, i64>(0))?
        {
            sources.push((row?, name.clone(), None));
        }
        for row in
            conn.prepare_cached(IMPORTS_SQL)?
                .query_map(params![key, module, name], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<u32>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })?
        {
            let (source, bound, scope, topology, key, module) = row?;
            sources.push((source, bound.clone(), scope));
            successors.push(ReverseExposure {
                topology,
                key,
                module,
                name: bound,
                scope: None,
                depth: depth + 1,
            });
        }
        // A glob import binds every name its target exposes under the
        // importing module's own path, which is a further exposure for the
        // same reason a named import is: `use super::*;` in a child module
        // reaches the name only through the parent's own glob, and the
        // export fixpoint records neither, because a private `use` is not
        // an export row. Adding the importing blob as a scan source alone
        // stopped the chase after one hop, so a name two globs deep had no
        // candidate at all.
        for row in conn
            .prepare_cached(GLOBS_SQL)?
            .query_map(params![key, module], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<u32>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
        {
            let (blob, scope, glob_topology, glob_key, glob_module) = row?;
            sources.push((blob, name.clone(), scope));
            successors.push(ReverseExposure {
                topology: glob_topology,
                key: glob_key,
                module: glob_module,
                name: name.clone(),
                scope: None,
                depth: depth + 1,
            });
        }
        Ok(ReverseExposureStep {
            candidates,
            sources,
            successors,
        })
    }
    fn source_ranges(
        &self,
        target: &CodeUnit,
        sources: &HashSet<ReverseLookupSource>,
    ) -> Result<Vec<SelectedSemanticLocator>> {
        let conn = self.0.ready.inventory.connection();
        let mut macro_invocation_locators = Vec::new();
        if target.is_macro() {
            let mut invocations = conn.prepare_cached(TEXTUAL_MACRO_INVOCATION_RANGES_SQL)?;
            for (blob, name, _) in sources {
                for row in invocations.query_map(params![blob, name], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, usize>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })? {
                    let (path, start, spelling) = row?;
                    macro_invocation_locators.push(SelectedSemanticLocator::for_reference_range(
                        "rust",
                        path,
                        start,
                        start + spelling.len(),
                    ));
                }
            }
        }
        Ok(macro_invocation_locators)
    }
    fn source_lookup(
        &self,
        blob: i64,
        name: &str,
        scope: Option<u32>,
        cancellation: &CancellationToken,
    ) -> Result<ReverseSourceLookup> {
        let mut candidates = Vec::new();
        let mut lookup_keys = Vec::new();
        // A bound name is visible only inside the binder's own scope
        // chain; an unbound one is visible to every lookup in the blob.
        if let Some(scope) = scope {
            for site in self
                .0
                .scoped_reverse_lookup_sites(blob, name, scope, cancellation)?
            {
                candidates.push((blob, site.get()));
            }
        } else {
            lookup_keys.extend(self.0.rust_reverse_lookup_keys(blob, name)?);
        }
        Ok(ReverseSourceLookup {
            candidates,
            keys: lookup_keys,
        })
    }
    fn root_lookup(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<ReverseSourceLookup>> {
        let conn = self.0.ready.inventory.connection();
        let lexical = self.0.ready.lexical_source();
        let mut candidates = Vec::new();
        let mut root_keys = Vec::new();
        for namespace in REVERSE_LOOKUP_NAMESPACES {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let symbol = ResolutionLookupSemanticRecipe::new(Language::Rust, namespace, name)
                .semantic(&self.0.ready.shared_names());
            for blob in conn.prepare_cached(REFERENCE_LOOKUP_BLOBS_SQL)?.query_map(
                [i64::from(
                    symbol
                        .shared_name_id()
                        .expect("a reverse lookup symbol is a shared name")
                        .get(),
                )],
                |row| row.get::<_, i64>(0),
            )? {
                let blob = blob?;
                let Some(imported) =
                    lexical.imported_root_demand_reference_sites(blob, symbol, cancellation)?
                else {
                    return Ok(None);
                };
                if let Some(context) = self.0.rust_reverse_candidate_context(blob)? {
                    root_keys.push(ReverseCandidateKey {
                        input_ordinal: 0,
                        context,
                        lookup: symbol,
                        lexical: false,
                        root: true,
                        qualified: true,
                    });
                }
                for site in imported {
                    candidates.push((blob, site.get()));
                }
            }
        }
        Ok(Some(ReverseSourceLookup {
            candidates,
            keys: root_keys,
        }))
    }
    fn observation_sites(
        &self,
        blob: i64,
        site: u32,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<ResolutionSiteId>>> {
        self.0
            .ready
            .lexical_source()
            .type_identity_observation_sites(blob, ResolutionSiteId::new(site), cancellation)
    }
    fn site_locators(&self, blob: i64, site: u32) -> Result<Vec<SelectedSemanticLocator>> {
        super::reverse_nomination::selected_site_locators(
            self.0.ready.inventory.connection(),
            LOCATORS_SQL,
            "rust",
            blob,
            site,
        )
    }
}

/// Authority carried by one selected source/root placement, never a path hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "test-support"), derive(serde::Serialize))]
struct RustReverseOwner {
    workspace_id: String,
    generation: i64,
    topology_id: i64,
    unit_key: [u8; 32],
    summary_id: i64,
    summary_digest: [u8; 32],
    output_digest: [u8; 32],
    producer_epoch: String,
    derivation_version: i64,
    source_member: i64,
    source_module: String,
    source_kind: String,
    source_scope: Option<i64>,
    root_member: i64,
    root_module: String,
    root_kind: String,
    root_scope: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
// Native summaries still collapse test/non-test profiles (#6029). Owners are
// authority for the existing caller-root view, not additional solve sessions.
#[cfg_attr(any(test, feature = "test-support"), derive(serde::Serialize))]
struct RustReverseView {
    caller: PathBuf,
    owners: Vec<RustReverseOwner>,
}

type RustRequiredContext = reverse::ReverseContextId<RustReverseView>;
type RustConfirmedContextBatch =
    reverse::ReverseContextBatch<RustRequiredContext, SelectedRustReferenceAnswer>;

/// One identity arena and file-domain index for the enclosing target query.
struct RustReverseDomains {
    proof: reverse::ReverseProofBatch<RustReverseView>,
    files: HashMap<String, Vec<usize>>,
}
impl RustReverseDomains {
    fn new(target: SemanticId) -> Self {
        Self {
            proof: reverse::ReverseProofBatch::new(target, Vec::new()),
            files: HashMap::default(),
        }
    }
    fn admit(&mut self, selected: &SelectedResolutionOperation<'_, '_>, path: &str) -> Result<()> {
        if !self.files.contains_key(path) {
            let indices = self
                .proof
                .extend_contexts(required_reverse_domain(selected, path)?);
            self.files.insert(path.to_owned(), indices);
        }
        Ok(())
    }
    fn contexts(
        &self,
        selected: &SelectedResolutionOperation<'_, '_>,
        path: &str,
    ) -> Result<Vec<RustRequiredContext>> {
        let mount = selected
            .ready
            .inventory
            .mount_record_for_path("rust", path)?
            .expect("an admitted reverse file has a selected mount");
        let witness = ReverseContextWitness::new(selected, mount.ordinal().get(), mount.blob_id());
        Ok(self
            .files
            .get(path)
            .expect("file domain precedes nomination filtering")
            .iter()
            .map(|&index| reverse::ReverseContextId {
                selected: witness.clone(),
                view: self.proof.required[index].view.clone(),
            })
            .collect())
    }
}

fn required_reverse_domain(
    selected: &SelectedResolutionOperation<'_, '_>,
    path: &str,
) -> Result<Vec<RustRequiredContext>> {
    let Some(mount) = selected
        .ready
        .inventory
        .mount_record_for_path("rust", path)?
    else {
        return Ok(Vec::new());
    };
    let witness = ReverseContextWitness::new(selected, mount.ordinal().get(), mount.blob_id());
    let mut statement = selected
        .ready
        .inventory
        .connection()
        .prepare_cached(CALLER_ROOTS_SQL)?;
    let mut rows = statement.query([path])?;
    let mut contexts = Vec::<RustRequiredContext>::new();
    while let Some(row) = rows.next()? {
        let root = row.get::<_, String>(0)?;
        let owner = RustReverseOwner {
            workspace_id: row.get(1)?,
            generation: row.get(2)?,
            topology_id: row.get(3)?,
            unit_key: row.get(4)?,
            summary_id: row.get(5)?,
            summary_digest: row.get(6)?,
            output_digest: row.get(7)?,
            producer_epoch: row.get(8)?,
            derivation_version: row.get(9)?,
            source_member: row.get(10)?,
            source_module: row.get(11)?,
            source_kind: row.get(12)?,
            source_scope: row.get(13)?,
            root_member: row.get(14)?,
            root_module: row.get(15)?,
            root_kind: row.get(16)?,
            root_scope: row.get(17)?,
        };
        if let Some(context) = contexts
            .last_mut()
            .filter(|context| context.view.caller == Path::new(&root))
        {
            context.view.owners.push(owner);
        } else {
            contexts.push(reverse::ReverseContextId {
                selected: witness.clone(),
                view: RustReverseView {
                    caller: PathBuf::from(root),
                    owners: vec![owner],
                },
            });
        }
    }
    Ok(contexts)
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug)]
enum RustCheapExclusion {
    CallShapeOrArity,
    AuthoredField,
    InactiveCfg,
}

fn record_cheap_exclusion(locator: &SelectedSemanticLocator, domains: &mut RustReverseDomains) {
    reverse::exclude_reverse_site(
        &mut domains.proof,
        locator,
        domains
            .files
            .get(locator.relative_path())
            .expect("admitted file domain"),
        ResolutionCompletion::Complete,
    );
}

/// A diagnostic sink belongs to one target request, including its zero-hit domain.
#[cfg(any(test, feature = "test-support"))]
struct RustReverseObserver {
    output: Option<PathBuf>,
    rows: Vec<serde_json::Value>,
}
#[cfg(any(test, feature = "test-support"))]
impl RustReverseObserver {
    fn new() -> Self {
        Self {
            output: std::env::var_os("BIFROST_REVERSE_OBSERVER").map(PathBuf::from),
            rows: Vec::new(),
        }
    }
    fn domain(
        &mut self,
        path: &str,
        domain: &[usize],
        arena: &reverse::ReverseProofBatch<RustReverseView>,
        activation: &str,
    ) {
        if self.output.is_none() {
            return;
        }
        self.rows.push(
            serde_json::json!({"stage":"domain","path":path,"activation":activation,
            "contexts":domain.iter().map(|&index| { let row = &arena.required[index]; serde_json::json!({
                "selected":format!("{:?}",row.selected),"view":row.view }) }).collect::<Vec<_>>() }),
        );
    }
    fn cheap_exclusion(&mut self, locator: &SelectedSemanticLocator, proof: RustCheapExclusion) {
        if self.output.is_some() {
            self.rows.push(serde_json::json!({"stage":"cheap_exclusion","locator":format!("{locator:?}"),"proof":format!("{proof:?}")}));
        }
    }
    fn finish(
        self,
        selected: &SelectedResolutionOperation<'_, '_>,
        target: &CodeUnit,
        proof: Option<&reverse::ReverseProofBatch<RustReverseView>>,
        completion: &ResolutionCompletion,
    ) -> Result<()> {
        let Some(output) = self.output else {
            return Ok(());
        };
        let proof = proof
            .map(|proof| {
                reverse::observe_reverse_proof(
                    proof,
                    |view| serde_json::json!(view),
                    |completion| {
                        Ok(serde_json::json!(named_reason_details(
                            &selected.ready,
                            completion
                        )?))
                    },
                )
            })
            .transpose()?;
        let value = serde_json::json!({"root":selected.ready.project.root(),"target":target.fq_name().as_str(),
            "rows":self.rows,"proof":proof,"completion":format!("{completion:?}")});
        let mut bytes = serde_json::to_vec(&value).expect("JSON observation values serialize");
        bytes.push(b'\n');
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(output)?
            .write_all(&bytes)?;
        Ok(())
    }
}

#[derive(Clone)]
struct RustReverseClosure {
    qualified: bool,
    concrete_prefix: bool,
    local_type_prefix: bool,
}
impl reverse::ReverseClosure for RustReverseClosure {
    fn meet(&mut self, other: Self) {
        self.qualified &= other.qualified;
        self.concrete_prefix &= other.concrete_prefix;
        self.local_type_prefix &= other.local_type_prefix;
    }
}

struct RustClassifiedAnswer {
    binding: Option<crate::analyzer::resolution::FactReverseReferenceBinding>,
    targets: BTreeSet<SemanticId>,
    binding_completion: ResolutionCompletion,
    rejection: ResolutionCompletion,
    contract_inventory: ResolutionCompletion,
}

#[doc(hidden)]
pub fn confirm_rust_reverse_references(
    operation: &mut SelectedResolutionOperation<'_, '_>,
    root: &std::path::Path,
    locators: &[&crate::analyzer::resolution::SelectedSemanticLocator],
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::store::resolution_operation::RustReverseConfirmation> {
    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
    let _timing = crate::profiling::scope("rust_selected::reverse_confirm_blob");
    #[cfg(any(test, feature = "test-support"))]
    operation.attach_active_reverse_sql_work_trace();
    let budget =
        brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default();
    let answer = operation.confirm_rust_references_for_caller_bounded(
        root,
        locators,
        budget,
        cancellation,
        &mut SelectedResolutionContextMetrics,
        &mut crate::analyzer::resolution::ResolutionBatchMetrics::default(),
    );
    let answer = answer?;
    #[cfg(any(test, feature = "test-support"))]
    if let Some(output) = std::env::var_os("BIFROST_REVERSE_OBSERVER") {
        // Observe the existing bounded result without finishing or polling the
        // session again. Stopped blobs still leave a charge/outcome receipt.
        let outcome = match &answer {
            BoundedResolution::Complete { .. } => "complete",
            BoundedResolution::Exceeded { .. } => "bounded",
            BoundedResolution::Cancelled { .. } => "cancelled",
        };
        let value = serde_json::json!({"stage":"session","root":operation.ready.project.root(),
            "caller":root,"locators":format!("{locators:?}"),"outcome":outcome,"work":format!("{:?}",answer.work())});
        let mut bytes = serde_json::to_vec(&value).expect("JSON observation values serialize");
        bytes.push(b'\n');
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(output)?
            .write_all(&bytes)?;
    }
    let outcome = match answer {
        BoundedResolution::Cancelled { .. } => reverse::ReverseBatch::Cancelled {
            stage: reverse::ReverseCancellationStage::Context,
            completion: cancelled_completion(),
        },
        BoundedResolution::Exceeded { limit, .. } => reverse::ReverseBatch::Bounded(limit),
        BoundedResolution::Complete { value, .. } => value.map_limit(|limit| match limit {}),
    };
    // Keep the existing consumer mapping; internal lifecycle outcomes stay typed.
    if let reverse::ReverseBatch::Ready(reports) = &outcome
        && reports
            .iter()
            .any(|report| matches!(report, reverse::ReverseSessionReport::Missing { .. }))
    {
        return Err(StoreError::new(
            "reverse candidate has no forward reference",
        ));
    }
    Ok(outcome)
}

fn rust_reverse_preparation_error<T, L>(outcome: reverse::ReverseBatch<T, L>) -> StoreError {
    match outcome {
        reverse::ReverseBatch::Stale(reason) => {
            StoreError::new(format!("reverse confirmation stale: {reason:?}"))
        }
        reverse::ReverseBatch::Unavailable(reason) => {
            StoreError::new(format!("reverse confirmation unavailable: {reason:?}"))
        }
        reverse::ReverseBatch::UnsupportedContext => {
            StoreError::new("reverse confirmation caller profile unavailable")
        }
        _ => unreachable!("only a preparation failure reaches its Rust consumer mapping"),
    }
}

/// F consumes plural shared session reports directly; point adapters stay outside F.
#[doc(hidden)]
pub type RustReverseConfirmation = reverse::ReverseBatch<
    Vec<reverse::ReverseSessionReport<SelectedRustReferenceAnswer>>,
    brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit,
>;

enum RustContractCompletion {
    Confirmed(Option<ResolutionCompletion>),
    Incomplete(ResolutionCompletion),
    Cancelled,
    TimeBudgetExceeded,
}

/// Confirm every named site of one caller file in one request. The sites of a
/// candidate blob share everything a point request prepares, so the reverse
/// asks about all of them at once.
type ConfirmReferences<'a> = dyn for<'store, 'input> Fn(
        &mut SelectedResolutionOperation<'store, 'input>,
        &Path,
        &[&SelectedSemanticLocator],
    ) -> Result<RustReverseConfirmation>
    + Sync
    + 'a;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static REVERSE_SQL_WORK: RefCell<Option<(usize, usize)>> = const { RefCell::new(None) };
    /// Candidate sets enumerated on this thread.
    static CANDIDATE_SET_ENUMERATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reset_candidate_set_enumerations_for_test() {
    CANDIDATE_SET_ENUMERATIONS.with(|count| count.set(0));
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn candidate_set_enumerations_for_test() -> usize {
    CANDIDATE_SET_ENUMERATIONS.with(std::cell::Cell::get)
}

#[cfg(any(test, feature = "test-support"))]
unsafe extern "C" fn record_reverse_sql_work(
    event: std::ffi::c_uint,
    _context: *mut std::ffi::c_void,
    statement: *mut std::ffi::c_void,
    _sql: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    REVERSE_SQL_WORK.with(|work| {
        let mut work = work.borrow_mut();
        let sql = unsafe {
            let raw = rusqlite::ffi::sqlite3_sql(statement.cast());
            (!raw.is_null()).then(|| std::ffi::CStr::from_ptr(raw).to_string_lossy())
        };
        // Point resolution has separate exact-work pins for persisted interior
        // reads. This trace measures the reverse crate/import/reference row
        // frontier that replaced workspace root-half reconstruction.
        if sql
            .as_deref()
            .is_some_and(|sql| sql.contains("resolution_fragment_interiors"))
        {
            return;
        }
        if let Some(work) = work.as_mut() {
            match event {
                rusqlite::ffi::SQLITE_TRACE_STMT => work.0 += 1,
                rusqlite::ffi::SQLITE_TRACE_ROW => work.1 += 1,
                _ => {}
            }
        }
    });
    0
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn reverse_sql_work_trace_active() -> bool {
    REVERSE_SQL_WORK.with(|work| work.borrow().is_some())
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn attach_reverse_sql_work_trace(connection: &rusqlite::Connection) {
    // SAFETY: every attached connection is used on this thread, where the
    // trace destination lives, and is detached before the reader is returned.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(
            connection.handle(),
            rusqlite::ffi::SQLITE_TRACE_STMT | rusqlite::ffi::SQLITE_TRACE_ROW,
            Some(record_reverse_sql_work),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn detach_reverse_sql_work_trace(connection: &rusqlite::Connection) {
    // SAFETY: this removes the callback installed on this same connection.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(connection.handle(), 0, None, std::ptr::null_mut())
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
}

fn retain_owned_reverse_rejection(
    selected: &SelectedResolutionOperation<'_, '_>,
    completion: ResolutionCompletion,
) -> ResolutionCompletion {
    let ResolutionCompletion::Incomplete(reasons) = &completion else {
        return completion;
    };
    let rebaser = selected.ready.inventory.mount_rebaser().borrow();
    let unowned = reasons
        .iter()
        .copied()
        .filter(|reason| {
            matches!(
                reason,
                ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                    if !rebaser.issued_semantic(*semantic)
                        || matches!(
                            rebaser.registered_semantic_provenance(*semantic),
                            Some(crate::analyzer::resolution::SelectedSemanticProvenance::Shared(identity))
                                if identity
                                    .shared_name()
                                    .is_some_and(|name| !name.is_interned())
                        )
            )
        })
        .collect::<Vec<_>>();
    if unowned.is_empty() {
        return completion;
    }
    reasons.without_reasons(unowned).map_or(
        ResolutionCompletion::Complete,
        ResolutionCompletion::Incomplete,
    )
}

/// Whether a rejected site's unresolved Type path root is a Cargo dependency
/// alias unavailable to this target. Cargo target kinds have different
/// dependency sets: a `build.rs` may name a normal dependency that exists on
/// the package's library target, and a library may name a build dependency.
/// The manifest-file version ties sibling targets to the package without
/// confusing identically named dependencies in other workspace packages.
fn wrong_target_workspace_dependency(
    selected: &SelectedResolutionOperation<'_, '_>,
    locator: &SelectedSemanticLocator,
    reference: SemanticId,
    resolution: &FactResolutionAnswer,
    cancellation: &CancellationToken,
) -> Result<bool> {
    if !resolution.binding().targets().is_empty() {
        return Ok(false);
    }
    let ResolutionCompletion::Incomplete(reasons) = resolution.binding().completion() else {
        return Ok(false);
    };
    let root_semantics = reasons
        .iter()
        .map(|reason| match reason {
            ResolutionIncompleteReason::OpenBoundary {
                semantic,
                status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
            } => Some(*semantic),
            _ => None,
        })
        .collect::<Option<BTreeSet<_>>>();
    let Some(root_semantics) = root_semantics.filter(|roots| roots.len() == 1) else {
        return Ok(false);
    };
    let root_semantic = *root_semantics.iter().next().expect("one root semantic");
    let Some(ordinal) = reference.ordinal() else {
        return Ok(false);
    };
    if root_semantic.ordinal() != Some(ordinal) {
        return Ok(false);
    }
    let mount = SelectedResolutionMountOrdinal::new(ordinal);
    assert_eq!(
        selected
            .mount_table()
            .mount_by_ordinal(mount)?
            .persisted_relative_path(),
        locator.relative_path(),
        "reverse candidate reference belongs to its locator mount"
    );
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    let spelling = selected
        .ready
        .inventory
        .connection()
        .prepare_cached(REFERENCE_ROOT_LOOKUP_SQL)?
        .query_row(
            params![
                i64::from(ordinal),
                i64::from(
                    reference
                        .local_key()
                        .expect("a rejected route names a local qualified reference")
                )
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(spelling) = spelling else {
        return Ok(false);
    };
    let (current_has_alias, sibling_has_workspace_alias): (bool, bool) = selected
        .ready
        .inventory
        .connection()
        .prepare_cached(OTHER_TARGET_WORKSPACE_DEPENDENCY_SQL)?
        .query_row(params![i64::from(ordinal), spelling], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    Ok(!current_has_alias && sibling_has_workspace_alias)
}

/// Whether a trait member target's owner is not nameable at a rejected site.
///
/// A rejected `Foo::f()` whose lookup found no `f` keeps the open member
/// surface (`open_callable_member_surfaces`: an unindexed trait, a blanket
/// impl or a `Deref` chain could supply `f`). None of them can make the site
/// the member of a trait that is not in scope there: rustc looks a method or
/// associated function up only in inherent impls and in the traits in scope
/// (E0599), and a blanket impl or `Deref` step still needs the trait in
/// scope. A member-owner row can also describe a field or another non-trait
/// owner, where that rule does not exclude the target and the open surface
/// must remain.
fn member_owner_unnameable_at(
    selected: &SelectedResolutionOperation<'_, '_>,
    definition: SemanticId,
    reference: SemanticId,
    cancellation: &CancellationToken,
) -> Result<bool> {
    use crate::analyzer::resolution::{
        FactPageVisitor, LoweredMemberOwnerProperty, RustImplementedTraits,
        SelectedTypedFactSource, SelectedTypedRow, TypedFactRequest,
    };
    let typed = selected.ready.typed_source();
    let mut owners = Vec::new();
    let mut collect = |rows: &[SelectedTypedRow<LoweredMemberOwnerProperty>]| {
        owners.extend(rows.iter().map(|row| row.row().owner_definition()));
        Ok(!cancellation.is_cancelled())
    };
    let outcome = typed.visit_member_owner_pages_for_definitions(
        TypedFactRequest::new(&[definition]),
        cancellation,
        &mut FactPageVisitor::new(&mut collect),
    )?;
    if outcome.is_cancelled() {
        return Ok(false);
    }
    if let [owner] = owners.as_slice() {
        let (Some(owner_mount), Some(owner_key)) = (owner.ordinal(), owner.local_key()) else {
            return Ok(false);
        };
        let owner_is_trait = selected
            .ready
            .inventory
            .connection()
            .prepare_cached(MEMBER_OWNER_IS_TRAIT_SQL)?
            .query_row(
                params![i64::from(owner_mount), i64::from(owner_key)],
                |row| row.get::<_, bool>(0),
            )?;
        if !owner_is_trait {
            return Ok(false);
        }
        return Ok(matches!(
            typed.rust_trait_nameable_at(*owner, reference, cancellation)?,
            RustImplementedTraits::Traits(traits) if traits.is_empty()
        ));
    }
    if !owners.is_empty() {
        return Ok(false);
    }
    // A dependency's local trait can close its associated-member surface at
    // this boundary even when its private impl trait was not exported. Query
    // impl-item traits only when the indexed owner rows have no answer.
    let RustImplementedTraits::Traits(traits) =
        typed.rust_impl_item_traits(definition, cancellation)?
    else {
        return Ok(false);
    };
    if traits.is_empty() {
        return Ok(false);
    }
    for trait_definition in traits {
        match typed.rust_trait_nameable_at(trait_definition, reference, cancellation)? {
            RustImplementedTraits::Traits(nameable) if nameable.is_empty() => {}
            RustImplementedTraits::Traits(_) | RustImplementedTraits::Unplaced => {
                return Ok(false);
            }
            RustImplementedTraits::Cancelled => return Ok(false),
        }
    }
    Ok(true)
}

/// A complete empty point answer closes a target's qualified route only when
/// the canonical access policy independently excludes that exact endpoint.
fn target_access_denied_at(
    selected: &SelectedResolutionOperation<'_, '_>,
    locator: &SelectedSemanticLocator,
    definition: SemanticId,
    reference: SemanticId,
    cancellation: &CancellationToken,
) -> Result<bool> {
    use crate::analyzer::resolution::{
        DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow, FactPageVisitor,
        SelectedDeclarationAccessSource, TypedFactRequest,
    };
    let keys =
        selected.rust_crate_keys_for_file(Path::new(locator.relative_path()), cancellation)?;
    if keys.is_empty() || cancellation.is_cancelled() {
        return Ok(false);
    }
    let policy = selected.crate_set_access_policy(keys)?;
    let request = DeclarationAccessRequest {
        reference,
        definition,
    };
    let mut decision = None;
    let mut collect = |rows: &[DeclarationAccessRow]| {
        for row in rows {
            assert_eq!(row.request, request);
            assert!(decision.replace(row.decision).is_none());
        }
        Ok(!cancellation.is_cancelled())
    };
    let outcome = policy.visit_access_pages(
        &selected.ready.typed_source(),
        TypedFactRequest::new(&[request]),
        cancellation,
        &mut FactPageVisitor::new(&mut collect),
    )?;
    if super::rust_privacy::complete_access_source_read(
        outcome,
        cancellation,
        "Rust inverse endpoint exclusion",
    )?
    .is_some()
    {
        return Ok(false);
    }
    Ok(decision == Some(DeclarationAccessDecision::Denied))
}

struct RustReverseQueries<'a, 'store, 'input> {
    selected: &'a mut SelectedResolutionOperation<'store, 'input>,
    cancellation: &'a CancellationToken,
    admitted: Option<&'a HashSet<ProjectFile>>,
    confirm: &'a ConfirmReferences<'a>,
    unavailable: Option<SelectedResolutionUnavailable>,
    stale: Option<SelectedResolutionStale>,
    #[cfg(any(test, feature = "test-support"))]
    definition_mounts: HashSet<SelectedResolutionMountOrdinal>,
}

impl RustReverseQueries<'_, '_, '_> {
    /// Answer on the operation's own connection, taking it back from the
    /// callback first and lending it again afterwards. `stopped` is the
    /// answer when the wait for the connection is cancelled, or when another
    /// store user changed the selection's rows while the callback had the
    /// connection, which makes the operation stale.
    fn on_own_connection<T>(
        &mut self,
        stopped: T,
        answer: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        match self
            .selected
            .ready
            .inventory
            .reclaim_writer(self.cancellation)?
        {
            SelectedResolutionRevalidationOutcome::Current => {}
            SelectedResolutionRevalidationOutcome::Cancelled => return Ok(stopped),
            SelectedResolutionRevalidationOutcome::Stale(reason) => {
                self.stale = Some(reason);
                return Ok(stopped);
            }
        }
        let answer = answer(self)?;
        self.selected.ready.inventory.lend_writer()?;
        Ok(answer)
    }

    /// Record why a target has no selected definition, and return it. The
    /// enclosing operation reports it as its outcome.
    fn missing_definition_unit(&mut self, target: &CodeUnit) -> SelectedResolutionUnavailable {
        let reason = SelectedResolutionUnavailable::MissingDefinitionUnit {
            storage_language: "rust".into(),
            persisted_relative_path: crate::path_utils::rel_path_string(target.source()),
        };
        self.unavailable = Some(reason.clone());
        reason
    }

    /// Confirm every candidate site of one file. The sites share the file's
    /// crate roots, so the whole group is one point request per root instead
    /// of one per site.
    fn confirm_locators(
        selected: &mut SelectedResolutionOperation<'_, '_>,
        cancellation: &CancellationToken,
        confirm: &ConfirmReferences<'_>,
        locators: &[&SelectedSemanticLocator],
        auxiliary_locators: &HashSet<&SelectedSemanticLocator>,
        evaluations: &mut usize,
        domain: Vec<RustRequiredContext>,
    ) -> Result<
        reverse::ReverseBatch<
            RustConfirmedContextBatch,
            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit,
        >,
    > {
        use reverse::ReverseBatch;
        let Some(first) = locators.first() else {
            return Ok(ReverseBatch::Ready(reverse::ReverseContextBatch {
                required: Vec::new(),
                sites: Vec::new(),
            }));
        };
        assert!(
            locators
                .iter()
                .all(|locator| locator.relative_path() == first.relative_path()),
            "one confirmation group is one candidate blob: {locators:?}"
        );
        if domain.is_empty() {
            return Err(StoreError::new(format!(
                "reverse reference has no selected crate root: {first:?}"
            )));
        }
        let answers =
            match reverse::confirm_reverse_contexts(domain, locators, cancellation, |context| {
                context.selected.assert_selected(selected);
                *evaluations += 1;
                confirm(selected, &context.view.caller, locators)
            })? {
                ReverseBatch::Ready(answers) => answers,
                other => return Ok(other),
            };
        // Published candidates need source units in this reader before their
        // targets can support implementation/trait-contract discovery. An
        // auxiliary prefix is only a proof input: its normal point answer may
        // name a staged macro owner that this reverse reader did not stage.
        // Its own certificate can block terminal closure, but its owner does
        // not become an independent reverse target or operational rejection.
        let units = answers
            .sites
            .iter()
            .zip(locators)
            .filter(|(_, locator)| !auxiliary_locators.contains(*locator))
            .flat_map(|(site, _)| {
                site.reports
                    .iter()
                    .flat_map(|(_, answers)| answers)
                    .map(|answer| &answer.answer)
            })
            .flat_map(|answer| &answer.definitions)
            .collect::<HashSet<_>>();
        if !selected.all_rust_definitions_located(&units, cancellation)? {
            if cancellation.is_cancelled() {
                return Ok(ReverseBatch::Cancelled {
                    stage: reverse::ReverseCancellationStage::Projection,
                    completion: cancelled_completion(),
                });
            }
            return Err(StoreError::new(format!(
                "confirmed reverse targets have no selected definitions: {units:?}"
            )));
        }
        Ok(ReverseBatch::Ready(answers))
    }

    /// A concrete implementation is an inverse usage of its trait contract.
    /// Confirm the implementation's declared trait reference through the same
    /// point entry; a matching spelling alone cannot establish this relation.
    fn contract_completion(
        selected: &mut SelectedResolutionOperation<'_, '_>,
        cancellation: &CancellationToken,
        confirm: &ConfirmReferences<'_>,
        definition: SemanticId,
        implementation: SemanticId,
        evaluations: &mut usize,
    ) -> Result<RustContractCompletion> {
        // The owner half is a declaration property, persisted per blob; the
        // relation that carries the trait reference is interior detail of the
        // implementing blob.
        let (owners, member_mount, member_path) = {
            let lexical = selected.ready.lexical_source();
            let (
                Some(SelectedSemanticProvenance::FragmentLocal(target)),
                Some(SelectedSemanticProvenance::FragmentLocal(member)),
            ) = (
                lexical.semantic_provenance(definition, cancellation)?,
                lexical.semantic_provenance(implementation, cancellation)?,
            )
            else {
                // Either the pair is not both fragment-local or an interior
                // could not be produced; neither states a contract owner.
                return Ok(RustContractCompletion::Confirmed(None));
            };
            let member_mount = member.mount().ordinal();
            let member_path = selected
                .mount_table()
                .mount_by_ordinal(member_mount)?
                .persisted_relative_path()
                .to_owned();
            let connection = selected.ready.inventory.connection();
            let owners = connection
                .prepare_cached(CONTRACT_OWNER_SQL)?
                .query_map(
                    params![target.mount().ordinal().get(), target.local_key().get()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, u32>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            (owners, member_mount, member_path)
        };
        let mut rows = Vec::new();
        for (owner_path, owner_site, member_kind) in owners {
            let member_kind = ResolutionMemberKind::from_label(&member_kind)
                .expect("a persisted member owner property names a member kind");
            let Some(references) = selected.ready.lexical_source().contract_reference_sites(
                member_mount,
                implementation,
                member_kind,
                cancellation,
            )?
            else {
                return Ok(RustContractCompletion::Confirmed(None));
            };
            for reference_site in references {
                rows.push((
                    owner_path.clone(),
                    owner_site,
                    member_path.clone(),
                    reference_site,
                ));
            }
        }
        for (owner_path, owner_site, reference_path, reference_site) in rows {
            let lexical = selected.ready.lexical_source();
            let owner = SelectedSemanticLocator::new(
                "rust",
                owner_path,
                ResolutionSiteId::new(owner_site),
                LoweredSemanticRole::Definition,
            );
            let LocatedSemantic::Found(owner) =
                selected
                    .ready
                    .lookup_locator(&lexical, &owner, cancellation)?
            else {
                return Ok(RustContractCompletion::Confirmed(None));
            };
            let reference = SelectedSemanticLocator::new(
                "rust",
                reference_path,
                reference_site,
                LoweredSemanticRole::Reference,
            );
            // A receiver-analysis budget still means no contract provenance.
            // The request time budget is different: the caller must retain an
            // explicit inventory gap instead of treating the missing proof as
            // a negative contract answer.
            let domain = required_reverse_domain(selected, reference.relative_path())?;
            let confirmation = Self::confirm_locators(
                selected,
                cancellation,
                confirm,
                &[&reference],
                &HashSet::default(),
                evaluations,
                domain,
            )?;
            let mut answers = match confirmation {
                reverse::ReverseBatch::Ready(answers) => answers,
                reverse::ReverseBatch::TimeStopped => {
                    return Ok(RustContractCompletion::TimeBudgetExceeded);
                }
                reverse::ReverseBatch::Cancelled { .. } => {
                    return Ok(RustContractCompletion::Cancelled);
                }
                reverse::ReverseBatch::Bounded(_) => {
                    return Ok(RustContractCompletion::Incomplete(
                        ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::ReceiverBudgetExhausted(definition),
                        ]),
                    ));
                }
                other @ (reverse::ReverseBatch::Stale(_)
                | reverse::ReverseBatch::Unavailable(_)
                | reverse::ReverseBatch::UnsupportedContext) => {
                    return Err(rust_reverse_preparation_error(other));
                }
            };
            for answer in answers
                .sites
                .remove(0)
                .reports
                .into_iter()
                .flat_map(|(_, answers)| answers)
            {
                let answer = answer.answer.resolution;
                if answer.binding().targets().contains(&owner) {
                    let mut completion = answer.binding().completion().clone();
                    if answer.binding().targets().len() != 1 {
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(definition),
                        ]));
                    }
                    return Ok(RustContractCompletion::Confirmed(Some(completion)));
                }
            }
        }
        Ok(RustContractCompletion::Confirmed(None))
    }
}

/// Evidence retained by one candidate partition after all reader-dependent
/// checks. Nothing in this value outlives the enclosing reverse query.
#[derive(Default)]
struct RustReverseRetained {
    proof: Option<reverse::ReverseProofBatch<RustReverseView>>,
    references: Vec<SemanticId>,
    witnesses: Vec<crate::analyzer::resolution::ResolutionWitness>,
    bindings: Vec<crate::analyzer::resolution::FactReverseReferenceBinding>,
    accounted_references: Vec<SemanticId>,
    qualified_references: Vec<SemanticId>,
    inventory: ResolutionCompletionAccumulator,
    confirmed_enumeration: HashMap<ProjectFile, ResolutionCompletionAccumulator>,
    evaluated_type_terminals: Vec<SemanticId>,
    type_terminal_rejections: Vec<(SemanticId, ResolutionCompletion)>,
    proven_prefixes: HashSet<SemanticId>,
    proven_local_type_prefixes: HashSet<SemanticId>,
    local_prefix_reasons: HashMap<SemanticId, HashSet<ResolutionIncompleteReason>>,
    time_budget_exceeded: bool,
    evaluation_count: usize,
}

/// Target and structured prefix evidence that one partition must check.
struct RustReverseRetentionInput<'a> {
    target: &'a CodeUnit,
    definition: SemanticId,
    type_terminal_references: &'a HashSet<SemanticId>,
    type_prefix_references: &'a HashSet<SemanticId>,
    auxiliary_type_prefix_references: &'a HashSet<SemanticId>,
    domains: &'a RustReverseDomains,
}

/// Confirm and retain one fixed group of candidate blobs on its own reader.
/// The reader is opened, validated, and dropped on this worker thread.
fn prepare_reference_partition(
    selected: &mut SelectedResolutionOperation<'_, '_>,
    cancellation: &CancellationToken,
    confirm: &ConfirmReferences<'_>,
    retention: &RustReverseRetentionInput<'_>,
    parent_sites: &[(&SelectedSemanticLocator, SemanticId)],
    range: std::ops::Range<usize>,
) -> Result<SelectedResolutionOperationOutcome<retained::RetainedPartition>> {
    let definition = match selected.locate_rust_definition(retention.target, cancellation)? {
        SelectedRustDefinitionSemanticOutcome::Found(definition) => definition,
        SelectedRustDefinitionSemanticOutcome::Missing => {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingDefinitionUnit {
                    storage_language: "rust".to_owned(),
                    persisted_relative_path: crate::path_utils::rel_path_string(
                        retention.target.source(),
                    ),
                },
            ));
        }
        SelectedRustDefinitionSemanticOutcome::Cancelled => {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
    };
    let mut sites = Vec::with_capacity(range.len());
    let mut admitted = Vec::with_capacity(range.len());
    let mut type_terminals = HashSet::default();
    let mut type_prefixes = HashSet::default();
    let mut auxiliary_prefixes = HashSet::default();
    for index in range {
        let (locator, parent_reference) = parent_sites[index];
        let reference = match selected.ready.lookup_locator(
            &selected.ready.lexical_source(),
            locator,
            cancellation,
        )? {
            LocatedSemantic::Found(reference) => reference,
            LocatedSemantic::Missing => {
                return Err(StoreError::new(format!(
                    "worker has no selected source locator: {locator:?}"
                )));
            }
            LocatedSemantic::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        if retention
            .type_terminal_references
            .contains(&parent_reference)
        {
            type_terminals.insert(reference);
        }
        if retention.type_prefix_references.contains(&parent_reference) {
            type_prefixes.insert(reference);
        }
        if retention
            .auxiliary_type_prefix_references
            .contains(&parent_reference)
        {
            auxiliary_prefixes.insert(reference);
        }
        sites.push((index, reference));
        admitted.push((locator, reference));
    }
    let outcome = run_reference_files(
        selected,
        cancellation,
        confirm,
        &RustReverseRetentionInput {
            target: retention.target,
            definition,
            type_terminal_references: &type_terminals,
            type_prefix_references: &type_prefixes,
            auxiliary_type_prefix_references: &auxiliary_prefixes,
            domains: retention.domains,
        },
        &admitted,
    )?;
    Ok(match outcome {
        SelectedResolutionOperationOutcome::Native(mut partition) => {
            partition.sites = sites;
            SelectedResolutionOperationOutcome::Native(partition)
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            SelectedResolutionOperationOutcome::Unavailable(reason)
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            SelectedResolutionOperationOutcome::Stale(reason)
        }
        SelectedResolutionOperationOutcome::Cancelled(completion) => {
            SelectedResolutionOperationOutcome::Cancelled(completion)
        }
    })
}

struct RustReferenceFiles<'a, 'store, 'input, 'request> {
    selected: &'a mut SelectedResolutionOperation<'store, 'input>,
    cancellation: &'a CancellationToken,
    confirm: &'a ConfirmReferences<'a>,
    retention: &'a RustReverseRetentionInput<'request>,
    admitted: &'a [(&'a SelectedSemanticLocator, SemanticId)],
    retained: RustReverseRetained,
}

impl reverse::ReverseFileHooks<()> for RustReferenceFiles<'_, '_, '_, '_> {
    type Session = RustConfirmedContextBatch;
    type Limit = brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    fn cancellation(&self) -> &CancellationToken {
        self.cancellation
    }
    fn confirm(
        &mut self,
        file: &mut reverse::ReverseFile<()>,
    ) -> Result<reverse::ReverseBatch<Self::Session, Self::Limit>> {
        let admitted = &self.admitted[file.range.clone()];
        let group = admitted
            .iter()
            .map(|&(locator, _)| locator)
            .collect::<Vec<_>>();
        let auxiliary = admitted
            .iter()
            .filter(|(_, reference)| {
                self.retention
                    .auxiliary_type_prefix_references
                    .contains(reference)
            })
            .map(|&(locator, _)| locator)
            .collect::<HashSet<_>>();
        let domain = self
            .retention
            .domains
            .contexts(self.selected, group[0].relative_path())?;
        RustReverseQueries::confirm_locators(
            self.selected,
            self.cancellation,
            self.confirm,
            &group,
            &auxiliary,
            &mut self.retained.evaluation_count,
            domain,
        )
    }
    fn commit(
        &mut self,
        file: reverse::ReverseFile<()>,
        answers: Self::Session,
    ) -> Result<ReverseBlobControl> {
        let Some(retained) = RustReverseQueries::retain_confirmed_sites(
            self.selected,
            self.cancellation,
            self.confirm,
            RustReverseRetentionInput {
                target: self.retention.target,
                definition: self.retention.definition,
                type_terminal_references: self.retention.type_terminal_references,
                type_prefix_references: self.retention.type_prefix_references,
                auxiliary_type_prefix_references: self.retention.auxiliary_type_prefix_references,
                domains: self.retention.domains,
            },
            self.admitted[file.range].to_vec(),
            answers,
            std::mem::take(&mut self.retained),
        )?
        else {
            return Ok(ReverseBlobControl::Cancelled);
        };
        self.retained = retained;
        Ok(ReverseBlobControl::Continue)
    }
    fn stopped(
        &mut self,
        _file: reverse::ReverseFile<()>,
        outcome: reverse::ReverseBatch<std::convert::Infallible, Self::Limit>,
    ) -> Result<ReverseBlobControl> {
        use reverse::ReverseBatch;
        match outcome {
            ReverseBatch::Ready(never) => match never {},
            ReverseBatch::Bounded(_) => {
                self.retained
                    .inventory
                    .include(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::ReceiverBudgetExhausted(
                            self.retention.definition,
                        ),
                    ]));
                Ok(ReverseBlobControl::Continue)
            }
            ReverseBatch::Cancelled { .. } => Ok(ReverseBlobControl::Cancelled),
            ReverseBatch::TimeStopped => Ok(ReverseBlobControl::TimeBudgetExceeded),
            other @ (ReverseBatch::Stale(_)
            | ReverseBatch::Unavailable(_)
            | ReverseBatch::UnsupportedContext) => Err(rust_reverse_preparation_error(other)),
        }
    }
}

fn run_reference_files(
    selected: &mut SelectedResolutionOperation<'_, '_>,
    cancellation: &CancellationToken,
    confirm: &ConfirmReferences<'_>,
    retention: &RustReverseRetentionInput<'_>,
    admitted: &[(&SelectedSemanticLocator, SemanticId)],
) -> Result<SelectedResolutionOperationOutcome<retained::RetainedPartition>> {
    let mut hooks = RustReferenceFiles {
        selected,
        cancellation,
        confirm,
        retention,
        admitted,
        retained: RustReverseRetained::default(),
    };
    let progress = execute_reverse_blobs(admitted, 0..admitted.len(), &mut hooks)?;
    let mut retained = hooks.retained;
    match progress.stopped {
        ReverseBlobControl::Continue => {}
        ReverseBlobControl::Cancelled => {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        ReverseBlobControl::TimeBudgetExceeded => {
            retained
                .inventory
                .include(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::TimeBudgetExceeded(retention.definition),
                ]));
            retained.time_budget_exceeded = true;
        }
    }
    let mut unattempted_blobs = admitted[progress.next..]
        .iter()
        .map(|(locator, _)| PathBuf::from(locator.relative_path()))
        .collect::<Vec<_>>();
    unattempted_blobs.dedup();
    Ok(SelectedResolutionOperationOutcome::Native(
        retained::RetainedPartition {
            retained,
            definition: retention.definition,
            sites: Vec::new(),
            unattempted_blobs,
        },
    ))
}
/// Forward evidence for the rich incoming projection, with parent source anchors.
struct RecheckedPartition {
    answers: Vec<(usize, SemanticId, ReferenceResolution)>,
}

impl crate::analyzer::resolution::worker_transport::WorkerAnswer for RecheckedPartition {
    fn translate(
        self,
        translation: &impl crate::analyzer::resolution::ResolutionIdentityTranslation,
    ) -> Self {
        Self {
            answers: self
                .answers
                .into_iter()
                .map(|(index, reference, answer)| {
                    let answer = match answer {
                        ReferenceResolution::Answered(answers) => ReferenceResolution::Answered(
                            answers
                                .into_iter()
                                .map(|answer| answer.translate(translation))
                                .collect(),
                        ),
                        ReferenceResolution::Omitted(reason) => {
                            ReferenceResolution::Omitted(reason)
                        }
                    };
                    (index, translation.semantic(reference), answer)
                })
                .collect(),
        }
    }
}

struct RustRecheckFiles<'a, 'store, 'input> {
    selected: &'a mut SelectedResolutionOperation<'store, 'input>,
    cancellation: &'a CancellationToken,
    confirm: &'a ConfirmReferences<'a>,
    admitted: &'a [(&'a SelectedSemanticLocator, SemanticId)],
    domains: HashMap<String, Vec<RustRequiredContext>>,
    answers: Vec<(usize, SemanticId, ReferenceResolution)>,
    evaluations: usize,
}

impl RustRecheckFiles<'_, '_, '_> {
    /// Source-anchor projection is Rust policy, independent of file scheduling.
    fn append_answers(
        &mut self,
        range: std::ops::Range<usize>,
        answers: Vec<ReferenceResolution>,
    ) -> Result<ReverseBlobControl> {
        assert_eq!(answers.len(), range.len());
        for (index, answer) in range.zip(answers) {
            let reference = match self.selected.ready.lookup_locator(
                &self.selected.ready.lexical_source(),
                self.admitted[index].0,
                self.cancellation,
            )? {
                LocatedSemantic::Found(reference) => reference,
                LocatedSemantic::Missing => {
                    return Err(StoreError::new(format!(
                        "recheck has no selected source locator: {:?}",
                        self.admitted[index].0
                    )));
                }
                LocatedSemantic::Cancelled => return Ok(ReverseBlobControl::Cancelled),
            };
            self.answers.push((index, reference, answer));
        }
        Ok(ReverseBlobControl::Continue)
    }
}

impl reverse::ReverseFileHooks<()> for RustRecheckFiles<'_, '_, '_> {
    type Session = RustConfirmedContextBatch;
    type Limit = brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    fn cancellation(&self) -> &CancellationToken {
        self.cancellation
    }
    fn confirm(
        &mut self,
        file: &mut reverse::ReverseFile<()>,
    ) -> Result<reverse::ReverseBatch<Self::Session, Self::Limit>> {
        let locators = self.admitted[file.range.clone()]
            .iter()
            .map(|&(locator, _)| locator)
            .collect::<Vec<_>>();
        let domain = self
            .domains
            .remove(locators[0].relative_path())
            .expect("recheck domain precedes file confirmation");
        RustReverseQueries::confirm_locators(
            self.selected,
            self.cancellation,
            self.confirm,
            &locators,
            &HashSet::default(),
            &mut self.evaluations,
            domain,
        )
    }
    fn commit(
        &mut self,
        file: reverse::ReverseFile<()>,
        batch: Self::Session,
    ) -> Result<ReverseBlobControl> {
        let required = (0..batch.required.len()).collect::<Vec<_>>();
        let answers = batch
            .sites
            .into_iter()
            .map(|site| {
                let reduced = reverse::project_reverse_context_site(&required, site, |answer| {
                    answer.resolution
                });
                ReferenceResolution::Answered(reduced.undecided)
            })
            .collect();
        self.append_answers(file.range, answers)
    }
    fn stopped(
        &mut self,
        file: reverse::ReverseFile<()>,
        outcome: reverse::ReverseBatch<std::convert::Infallible, Self::Limit>,
    ) -> Result<ReverseBlobControl> {
        use reverse::ReverseBatch;
        match outcome {
            ReverseBatch::Ready(never) => match never {},
            ReverseBatch::Bounded(limit) => {
                let answers = std::iter::repeat_with(|| {
                    ReferenceResolution::Omitted(ReferenceOmission::ReceiverBudget(limit))
                })
                .take(file.range.len())
                .collect();
                self.append_answers(file.range, answers)
            }
            ReverseBatch::Cancelled { .. } => Ok(ReverseBlobControl::Cancelled),
            ReverseBatch::TimeStopped => Ok(ReverseBlobControl::TimeBudgetExceeded),
            other @ (ReverseBatch::Stale(_)
            | ReverseBatch::Unavailable(_)
            | ReverseBatch::UnsupportedContext) => Err(rust_reverse_preparation_error(other)),
        }
    }
}

fn project_recheck_files(
    selected: &mut SelectedResolutionOperation<'_, '_>,
    cancellation: &CancellationToken,
    confirm: &ConfirmReferences<'_>,
    admitted: &[(&SelectedSemanticLocator, SemanticId)],
    range: std::ops::Range<usize>,
) -> Result<Option<RecheckedPartition>> {
    let _timing = crate::profiling::scope("rust_selected::incoming_recheck_partition");
    let mut domains = HashMap::default();
    for (locator, _) in &admitted[range.clone()] {
        if !domains.contains_key(locator.relative_path()) {
            domains.insert(
                locator.relative_path().to_owned(),
                required_reverse_domain(selected, locator.relative_path())?,
            );
        }
    }
    let mut hooks = RustRecheckFiles {
        selected,
        cancellation,
        confirm,
        admitted,
        domains,
        answers: Vec::with_capacity(range.len()),
        evaluations: 0,
    };
    let progress = execute_reverse_blobs(admitted, range, &mut hooks)?;
    if matches!(progress.stopped, ReverseBlobControl::Cancelled) {
        return Ok(None);
    }
    Ok(Some(RecheckedPartition {
        answers: hooks.answers,
    }))
}

impl RustReverseQueries<'_, '_, '_> {
    fn project_reference_partitions(
        &mut self,
        admitted: &[(&SelectedSemanticLocator, SemanticId)],
        retention: RustReverseRetentionInput<'_>,
    ) -> Result<Option<RustReverseRetained>> {
        let cancellation = self.cancellation;
        let confirm = self.confirm;
        let results = execute_reverse_partitions(
            self.selected,
            admitted,
            cancellation,
            |selected, range| {
                prepare_reference_partition(
                    selected,
                    cancellation,
                    confirm,
                    &retention,
                    admitted,
                    range,
                )
            },
            |selected| run_reference_files(selected, cancellation, confirm, &retention, admitted),
            |answer| {
                std::iter::once((answer.definition.into(), retention.definition.into()))
                    .chain(
                        answer.sites.iter().map(|&(index, reference)| {
                            (reference.into(), admitted[index].1.into())
                        }),
                    )
                    .collect()
            },
        )?;
        let outcome = reverse::fold_reverse_partitions(
            results,
            RustReverseRetained::default(),
            |retained, partition| retained.append(partition.merge()),
            |retained, range| {
                retained
                    .inventory
                    .include(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::TimeBudgetExceeded(retention.definition),
                    ]));
                retained.time_budget_exceeded = true;
                let mut unattempted_blobs = admitted[range]
                    .iter()
                    .map(|(locator, _)| locator.relative_path())
                    .collect::<Vec<_>>();
                unattempted_blobs.dedup();
                brokk_bifrost_core::profiling::note_with(|| {
                    format!("rust reverse undispatched blobs: {unattempted_blobs:?}")
                });
            },
        );
        match outcome {
            SelectedResolutionOperationOutcome::Native(retained) => Ok(Some(retained)),
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                self.unavailable = Some(reason);
                Ok(None)
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                self.stale = Some(reason);
                Ok(None)
            }
            SelectedResolutionOperationOutcome::Cancelled(_) => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn classify_confirmed_answer(
        selected: &mut SelectedResolutionOperation<'_, '_>,
        cancellation: &CancellationToken,
        confirm: &ConfirmReferences<'_>,
        input: &RustReverseRetentionInput<'_>,
        locator: &SelectedSemanticLocator,
        reference: SemanticId,
        answer: SelectedRustReferenceAnswer,
        retained: &mut RustReverseRetained,
        contract_time_budget_exceeded: &mut bool,
    ) -> Result<Option<reverse::ReverseViewVerdict<RustClassifiedAnswer, RustReverseClosure>>> {
        use crate::analyzer::resolution::FactReverseReferenceBinding;
        let target = input.target;
        let definition = input.definition;
        let type_prefix_references = input.type_prefix_references;
        let auxiliary_type_prefix_references = input.auxiliary_type_prefix_references;
        let mut binding = None;
        let mut site_contract_inventory = ResolutionCompletionAccumulator::default();
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "rust reverse confirmation: locator={locator:?}, definitions={:?}, binding={:?}, enumeration={:?}, inventory_details={:?}",
                answer.definitions,
                answer.resolution.binding(),
                answer.enumeration,
                answer.inventory_details
            )
        });
        // Source-fragment enumeration must be complete. The exact
        // target-linked binder gaps are the only binding reasons
        // this Cargo view may discharge; activation stays intact.
        let local_type_prefix = type_prefix_references.contains(&reference)
            && locator.role() == LoweredSemanticRole::Reference
            && answer.resolution.site_metadata().is_some_and(|metadata| {
                metadata.namespace() == ResolutionNamespace::Type
                    && metadata.site_kind() == ResolutionSiteKind::TypeReference
            })
            && answer
                .enumeration
                .as_ref()
                .is_some_and(|(_, completion)| *completion == ResolutionCompletion::Complete)
            && super::rust_crate_context::block_local_type_prefix_binding_is_decided(
                &selected.ready,
                answer.resolution.binding().targets(),
                answer.resolution.binding().completion(),
            )?;
        if local_type_prefix
            && let ResolutionCompletion::Incomplete(reasons) =
                answer.resolution.binding().completion()
        {
            retained
                .local_prefix_reasons
                .entry(reference)
                .or_default()
                .extend(reasons.iter().copied());
        }
        if let Some((file, completion)) = answer.enumeration {
            retained
                .confirmed_enumeration
                .entry(file)
                .or_default()
                .include(&completion);
        }
        if auxiliary_type_prefix_references.contains(&reference) {
            return Ok(Some(reverse::ReverseViewVerdict {
                relation: reverse::ReverseTargetRelation::Undecided,
                closes_site: false,
                closure: RustReverseClosure {
                    qualified: false,
                    concrete_prefix: false,
                    local_type_prefix,
                },
                answer: RustClassifiedAnswer {
                    binding: None,
                    targets: BTreeSet::new(),
                    binding_completion: ResolutionCompletion::Complete,
                    rejection: ResolutionCompletion::Complete,
                    contract_inventory: ResolutionCompletion::Complete,
                },
            }));
        }
        // Alternatives are published to a caller that speaks
        // `CodeUnit`s, so targets that project to the one unit this
        // scan is about are not alternatives to it. Two `pub fn
        // value` in one `impl`, or one item declared under two
        // `cfg`s, are one overload set and every use of the name
        // would otherwise be ambiguous against itself. `names`
        // keeps a row per target, so the two counts agreeing is
        // what says every target projected to a unit rather than
        // one of them having no `CodeUnit` at all.
        let every_target_is_this_unit = answer.definitions.as_slice()
            == std::slice::from_ref(target)
            && answer.lexical_definitions.is_empty()
            && (answer.definition_names.len() == answer.resolution.binding().targets().len()
                || (answer.resolution.binding().targets().is_empty()
                    && !answer.definition_names.is_empty()
                    && answer
                        .definition_names
                        .iter()
                        .all(|(_, name)| name == target.fq_name().as_str())));
        // Cfg alternatives of one declaration project to one
        // CodeUnit. The selected target may be one alternative
        // while this site's active binding names its sibling.
        // Macro-use lookup can project an exact target without
        // listing it in the binding's target set. Its retained.witnesses
        // still control whether that candidate closes retained.inventory.
        let binds_target_unit = every_target_is_this_unit;
        // A site that reached a block-local item names that item,
        // which is never this target: it has no `CodeUnit`.
        let block_local = super::rust_block_local_binding_is_decided(
            &answer.definitions,
            &answer.lexical_definitions,
            answer.resolution.binding().completion(),
        );
        let answer = answer.resolution;
        // One answer is one Cargo target's view of this site. Its
        // alternatives and its completion belong to that view:
        // another target's answer is a different compilation of the
        // same file, not an alternative reading of this one. They
        // are merged below, and only the views that bound the
        // definition are published with it.
        let mut answer_targets = BTreeSet::new();
        let mut answer_completion = ResolutionCompletionAccumulator::default();
        let mut answer_bound = false;
        if every_target_is_this_unit {
            answer_targets.insert(definition);
        } else {
            answer_targets.extend(answer.binding().targets().iter().copied());
        }
        answer_completion.include(
            if (block_local && !type_prefix_references.contains(&reference)) || local_type_prefix {
                &ResolutionCompletion::Complete
            } else {
                answer.binding().completion()
            },
        );
        retained.witnesses.extend(
            answer
                .binding()
                .witnesses()
                .iter()
                .filter(|witness| witness.target() == definition)
                .cloned(),
        );
        let candidate_binding = FactReverseReferenceBinding::from_forward(reference, &answer);
        if answer.binding().targets().contains(&definition) || binds_target_unit {
            answer_bound = true;
            binding = Some(candidate_binding);
        } else if crate::analyzer::resolution::undecided_callable_receiver(&answer) {
            let completion =
                candidate_binding
                    .completion()
                    .combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(definition),
                    ]));
            answer_completion.include(&completion);
            retained
                .witnesses
                .push(crate::analyzer::resolution::ResolutionWitness::new(
                    reference,
                    definition,
                    Vec::new(),
                    completion,
                ));
            answer_bound = true;
            binding = Some(candidate_binding);
        } else {
            for &implementation in answer.binding().targets() {
                if *contract_time_budget_exceeded {
                    continue;
                }
                match Self::contract_completion(
                    selected,
                    cancellation,
                    confirm,
                    definition,
                    implementation,
                    &mut retained.evaluation_count,
                )? {
                    RustContractCompletion::TimeBudgetExceeded => {
                        *contract_time_budget_exceeded = true;
                        retained.time_budget_exceeded = true;
                        retained
                            .inventory
                            .include(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::TimeBudgetExceeded(definition),
                            ]));
                    }
                    RustContractCompletion::Incomplete(completion) => {
                        site_contract_inventory.include(&completion);
                    }
                    RustContractCompletion::Cancelled => {
                        return Ok(None);
                    }
                    RustContractCompletion::Confirmed(Some(provenance)) => {
                        answer_completion.include(&provenance);
                        for witness in answer
                            .binding()
                            .witnesses()
                            .iter()
                            .filter(|witness| witness.target() == implementation)
                        {
                            let source = witness.reference();
                            let completion = witness.completion();
                            let mut steps = witness.steps().to_vec();
                            steps.push(crate::analyzer::resolution::WitnessStep::Candidate {
                                semantic: definition,
                                outcome: crate::analyzer::structural::CandidateOutcome::Selected,
                            });
                            retained.witnesses.push(
                                crate::analyzer::resolution::ResolutionWitness::new(
                                    source,
                                    definition,
                                    steps,
                                    completion.combine(&provenance),
                                ),
                            );
                        }
                        answer_bound = true;
                        binding = Some(candidate_binding.clone());
                    }
                    RustContractCompletion::Confirmed(None) => {}
                }
            }
        }
        // A retained binding accounts for this view's source site
        // even when its receiver remains unproven. Other views
        // must independently bind or prove exclusion; publishing
        // one view never discards another root's unresolved route.
        let answer_completion = answer_completion.finish();
        // Point evaluation can emit an operation-local reason
        // while rejecting a concrete unrelated member. It is not
        // a source retained.inventory gap in this selected reader. Apply
        // the same ownership check before per-root closure, while
        // keeping the original binding evidence for retained hits.
        let proven_other_binding = !answer_bound
            && !answer.binding().targets().is_empty()
            && answer.binding().targets().iter().all(|target| {
                answer.binding().witnesses().iter().any(|witness| {
                    witness.reference() == reference
                        && witness.target() == *target
                        && *witness.completion() == ResolutionCompletion::Complete
                })
            });
        let mut completion = if proven_other_binding {
            retain_owned_reverse_rejection(selected, answer_completion.clone())
        } else {
            answer_completion.clone()
        };
        let wrong_target_dependency =
            wrong_target_workspace_dependency(selected, locator, reference, &answer, cancellation)?;
        let target_inaccessible = !answer_bound
            && answer_targets.is_empty()
            && completion == ResolutionCompletion::Complete
            && target_access_denied_at(selected, locator, definition, reference, cancellation)?;
        let open_surface = ResolutionIncompleteReason::OpenBoundary {
            semantic: reference,
            status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
        };
        let mut owner_excluded = false;
        if !answer_bound
            && let ResolutionCompletion::Incomplete(reasons) = &completion
            && reasons.contains(&open_surface)
            && member_owner_unnameable_at(selected, definition, reference, cancellation)?
        {
            completion = reasons.without_reasons([open_surface]).map_or(
                ResolutionCompletion::Complete,
                ResolutionCompletion::Incomplete,
            );
            // This exact trait cannot supply the call even though
            // another unindexed trait may. Its absence is scoped
            // to this target and leaves point uncertainty intact.
            owner_excluded = completion == ResolutionCompletion::Complete;
        }
        if wrong_target_dependency {
            completion = ResolutionCompletion::Complete;
        }
        let concrete_prefix = (wrong_target_dependency || !answer_targets.is_empty())
            && completion == ResolutionCompletion::Complete;
        // A complete empty binding can close local applicability,
        // but does not prove an unresolved qualified route absent.
        // Require evidence in every root before closing that
        // independent retained.inventory placeholder.
        let qualified = answer_bound
            || !answer_targets.is_empty()
            || wrong_target_dependency
            || target_inaccessible
            || owner_excluded;
        // Inventory completion tracks whether this source site
        // was accounted for. The retained binding carries its
        // own forward uncertainty and does not make the scan
        // incomplete.
        Ok(Some(reverse::ReverseViewVerdict {
            relation: if answer_bound {
                reverse::ReverseTargetRelation::Matches
            } else {
                reverse::ReverseTargetRelation::Excluded
            },
            closes_site: answer_bound || completion == ResolutionCompletion::Complete,
            closure: RustReverseClosure {
                qualified,
                concrete_prefix,
                local_type_prefix,
            },
            answer: RustClassifiedAnswer {
                binding,
                targets: answer_targets,
                binding_completion: answer_completion,
                rejection: completion,
                contract_inventory: site_contract_inventory.finish(),
            },
        }))
    }

    fn retain_confirmed_sites(
        selected: &mut SelectedResolutionOperation<'_, '_>,
        cancellation: &CancellationToken,
        confirm: &ConfirmReferences<'_>,
        input: RustReverseRetentionInput<'_>,
        admitted_sites: Vec<(&SelectedSemanticLocator, SemanticId)>,
        confirmed: RustConfirmedContextBatch,
        mut retained: RustReverseRetained,
    ) -> Result<Option<RustReverseRetained>> {
        let mut proof = reverse::ReverseProofBatch::new(input.definition, confirmed.required);
        let required = (0..proof.required.len()).collect::<Vec<_>>();
        for context in &proof.required {
            context.selected.assert_selected(selected);
        }
        let mut contract_time_budget_exceeded = retained.time_budget_exceeded;
        for ((locator, reference), site) in admitted_sites.into_iter().zip(confirmed.sites) {
            if !site.reports.is_empty() && input.type_terminal_references.contains(&reference) {
                retained.evaluated_type_terminals.push(reference);
            }
            let Some(reduced) = reverse::classify_reverse_context_site(
                &mut proof,
                locator,
                &required,
                site,
                |answer| {
                    let Some(verdict) = Self::classify_confirmed_answer(
                        selected,
                        cancellation,
                        confirm,
                        &input,
                        locator,
                        reference,
                        answer,
                        &mut retained,
                        &mut contract_time_budget_exceeded,
                    )?
                    else {
                        return Ok(None);
                    };
                    let applicability = if verdict.closes_site {
                        ResolutionCompletion::Complete
                    } else {
                        verdict.answer.rejection.clone()
                    };
                    let binding = verdict.answer.binding_completion.clone();
                    Ok(Some(reverse::ReverseClassifiedView {
                        verdict,
                        applicability,
                        binding,
                    }))
                },
            )?
            else {
                return Ok(None);
            };
            let closure = reduced.closure;
            if input.auxiliary_type_prefix_references.contains(&reference) {
                if closure
                    .as_ref()
                    .is_some_and(|closure| closure.local_type_prefix)
                {
                    retained.proven_prefixes.insert(reference);
                    retained.proven_local_type_prefixes.insert(reference);
                }
                continue;
            }
            if reduced.every_context_closed {
                retained.accounted_references.push(reference);
                if closure.as_ref().is_some_and(|closure| closure.qualified) {
                    retained.qualified_references.push(reference);
                }
            }
            if closure
                .as_ref()
                .is_some_and(|closure| closure.concrete_prefix)
            {
                retained.proven_prefixes.insert(reference);
            }
            if closure
                .as_ref()
                .is_some_and(|closure| closure.local_type_prefix)
            {
                retained.proven_local_type_prefixes.insert(reference);
            }
            if reduced.binding.is_empty() {
                let mut contracts = ResolutionCompletionAccumulator::default();
                let mut rejections = ResolutionCompletionAccumulator::default();
                for answer in reduced.rejecting.into_iter().chain(reduced.undecided) {
                    contracts.include(&answer.contract_inventory);
                    rejections.include(&answer.rejection);
                }
                retained.inventory.include(&contracts.finish());
                let mut rejected = retain_owned_reverse_rejection(selected, rejections.finish());
                if input.type_terminal_references.contains(&reference) {
                    retained
                        .type_terminal_rejections
                        .push((reference, rejected));
                    continue;
                }
                let open_surface = ResolutionIncompleteReason::OpenBoundary {
                    semantic: reference,
                    status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                };
                if let ResolutionCompletion::Incomplete(reasons) = &rejected
                    && reasons.contains(&open_surface)
                    && member_owner_unnameable_at(
                        selected,
                        input.definition,
                        reference,
                        cancellation,
                    )?
                {
                    rejected = reasons.without_reasons([open_surface]).map_or(
                        ResolutionCompletion::Complete,
                        ResolutionCompletion::Incomplete,
                    );
                }
                retained.inventory.include(&rejected);
                continue;
            }
            let mut targets = BTreeSet::new();
            let mut completion = ResolutionCompletionAccumulator::default();
            let mut binding = None;
            for answer in reduced.binding {
                targets.extend(answer.targets);
                completion.include(&answer.binding_completion);
                if answer.binding.is_some() {
                    binding = answer.binding;
                }
            }
            if let Some(binding) = binding {
                retained.bindings.push(
                    binding.with_alternatives(targets.into_iter().collect(), completion.finish()),
                );
                retained.references.push(reference);
            }
        }
        match retained.proof.as_mut() {
            Some(into) => reverse::append_reverse_proof(into, proof),
            None => retained.proof = Some(proof),
        }
        Ok(Some(retained))
    }
}

/// The answers, on the operation's own connection. The callback reaches them
/// through the trait implementation below.
impl RustReverseQueries<'_, '_, '_> {
    fn held_candidate_sets(
        &mut self,
        targets: &[CodeUnit],
    ) -> Result<Option<Vec<RustReverseCandidateSet>>> {
        match group_reverse_inputs(targets, |target| {
            self.selected
                .rust_reverse_candidate_set(target, &[], self.cancellation)
        })? {
            std::ops::ControlFlow::Continue(sets) => Ok(Some(sets)),
            std::ops::ControlFlow::Break(ordinal) => {
                if !self.cancellation.is_cancelled() {
                    self.missing_definition_unit(&targets[ordinal]);
                }
                Ok(None)
            }
        }
    }
    fn held_references_to(
        &mut self,
        targets: &[CodeUnit],
        candidates: &[RustReverseCandidateSet],
        request: RustReverseRequest,
    ) -> Result<SelectedRustReverseBatchOutcome> {
        use crate::analyzer::resolution::MAX_REVERSE_TARGETS_PER_BATCH;
        assert!(targets.len() <= MAX_REVERSE_TARGETS_PER_BATCH);
        assert_eq!(
            targets.len(),
            candidates.len(),
            "every reverse target arrives with its candidate set: {targets:?}"
        );
        assert_eq!(
            targets.iter().collect::<HashSet<_>>().len(),
            targets.len(),
            "reverse targets must be unique: {targets:?}"
        );
        if self.cancellation.is_cancelled() {
            return Ok(SelectedRustReverseBatchOutcome::Cancelled);
        }
        if let Some(reason) = &self.unavailable {
            return Ok(SelectedRustReverseBatchOutcome::Unavailable(reason.clone()));
        }
        let mut results = Vec::with_capacity(targets.len());
        for (target, candidate_set) in targets.iter().zip(candidates) {
            let target_names = candidate_set.names.as_slice();
            // The set may have been enumerated by an earlier selected
            // operation; this operation's own selection decides whether the
            // target still has a definition here.
            let definition = match self
                .selected
                .locate_rust_definition(target, self.cancellation)?
            {
                SelectedRustDefinitionSemanticOutcome::Found(definition) => definition,
                SelectedRustDefinitionSemanticOutcome::Cancelled => {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                }
                SelectedRustDefinitionSemanticOutcome::Missing => {
                    return Ok(SelectedRustReverseBatchOutcome::Unavailable(
                        self.missing_definition_unit(target),
                    ));
                }
            };
            #[cfg(any(test, feature = "test-support"))]
            self.definition_mounts.insert(
                self.selected
                    .rust_definition_mount_for_target(target)?
                    .expect("located target has a mount"),
            );
            // The inventory's completeness is relative to the files this
            // request may list a site from. A file the admission excludes
            // cannot hide a site from this answer, so its enumeration gap is
            // not this answer's gap. Without an admission the target's own
            // file is in scope even when no locator nominated it, because a
            // gap there can hide a self-reference the answer would list.
            let inventory_files = match self.admitted {
                Some(admitted) => admitted.clone(),
                None => candidate_set
                    .files(self.selected.ready.project.root(), target)
                    .collect::<HashSet<_>>(),
            };
            let mut domain_paths = inventory_files
                .iter()
                .map(crate::path_utils::rel_path_string)
                .collect::<Vec<_>>();
            domain_paths.sort();
            let mut domains = RustReverseDomains::new(definition);
            for path in domain_paths {
                domains.admit(self.selected, &path)?;
            }
            #[cfg(any(test, feature = "test-support"))]
            let mut observer = RustReverseObserver::new();
            let lexical = self.selected.ready.lexical_source();
            let mut inventory = ResolutionCompletionAccumulator::default();
            let target_activation =
                self.selected
                    .reverse_target_activation(definition, target, self.cancellation)?;
            // An inactive or unknown target nominates no site; the prepared
            // set is borrowed either way, never edited.
            let nominated: &[SelectedSemanticLocator] = match target_activation {
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Active => {
                    &candidate_set.locators
                }
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Inactive => &[],
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Unknown => {
                    inventory.include(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(definition),
                    ]));
                    &[]
                }
            };

            let mut inventory_fragments = Vec::new();
            for file in &inventory_files {
                let relative_path = crate::path_utils::rel_path_string(file);
                if let Some(mount) = self
                    .selected
                    .mount_table()
                    .mount_for_path("rust", &relative_path)?
                {
                    inventory_fragments.push(mount.fragment().ordinal());
                }
            }
            inventory_fragments.sort_unstable();
            inventory_fragments.dedup();
            // An active or unknown target uses the shared gap predicates here to
            // nominate sites, and after confirmation to report what is left.
            // The sites it examines do not depend on the confirmation, so they
            // are enumerated once and both executions read them.
            let (gap_sites, gap_locators) = match target_activation {
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Inactive => {
                    (None, Vec::new())
                }
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Unknown => (
                    Some(materialize_gap_candidate_sites(
                        self.selected,
                        definition,
                        target,
                        target_names,
                        &inventory_fragments,
                        self.admitted.is_some(),
                        self.cancellation,
                    )?),
                    Vec::new(),
                ),
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Active => {
                    let sites = materialize_gap_candidate_sites(
                        self.selected,
                        definition,
                        target,
                        target_names,
                        &inventory_fragments,
                        self.admitted.is_some(),
                        self.cancellation,
                    )?;
                    // Exact route discovery and gap discovery are separate
                    // indexes. Confirm every named gap candidate too: a
                    // same-spelled decoy must be excluded by its own binding,
                    // not left unexamined.
                    let locators = initial_reference_inventory_gap_locators(
                        self.selected,
                        &sites,
                        target,
                        self.cancellation,
                    )?;
                    (Some(sites), locators)
                }
            };
            let mut locators = merged_locators([nominated, &gap_locators, &[]]);
            let mut prefix_locators = Vec::new();

            let mut type_terminal_prefixes = HashMap::default();
            let mut local_type_terminal_prefixes = HashMap::default();
            let mut auxiliary_type_prefix_references = HashSet::default();
            if matches!(
                target.kind(),
                brokk_bifrost_core::analyzer::model::CodeUnitType::Class
                    | brokk_bifrost_core::analyzer::model::CodeUnitType::Module
            ) {
                // A type-prefix use also nominates its own qualified terminal.
                // A call's member can be unindexed while its authored type
                // prefix is exact. Retain the structured connection so a type
                // question can close that terminal's inventory placeholder
                // from the prefix, independently of method applicability.
                let mut prefixes = HashSet::default();
                let mut type_reference_nodes = HashSet::default();
                let mut paths = HashSet::default();
                for &locator in &locators {
                    if self.cancellation.is_cancelled() {
                        return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                    }
                    let file = ProjectFile::new(
                        self.selected.ready.project.root(),
                        locator.relative_path(),
                    );
                    if self.admitted.is_some_and(|files| !files.contains(&file)) {
                        continue;
                    }
                    match lexical.lookup_semantic_sites(
                        locator,
                        self.cancellation,
                        &ResolutionSession::unbounded(),
                    )? {
                        SelectedSemanticLookupOutcome::Found(sites) => {
                            for site in sites
                                .into_iter()
                                .filter(|site| site.namespace() == ResolutionNamespace::Type)
                            {
                                prefixes.insert(site.semantic());
                                if locator.role() == LoweredSemanticRole::Reference {
                                    type_reference_nodes.insert(site.node());
                                }
                            }
                            paths.insert(locator.relative_path());
                        }
                        SelectedSemanticLookupOutcome::Missing => {}
                        SelectedSemanticLookupOutcome::Cancelled => {
                            return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                        }
                    }
                }
                let mounts = paths
                    .into_iter()
                    .map(|path| {
                        self.selected
                            .mount_table()
                            .mount_for_path("rust", path)
                            .map(|mount| mount.expect("a selected candidate has a mount"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let scope = RustRootHalfScope::new(
                    mounts.iter(),
                    std::iter::empty::<&SelectedResolutionOperationMount>(),
                );
                let Some((halves, _)) =
                    self.selected
                        .rust_root_halves(&scope, self.cancellation, None)?
                else {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                };
                let terminal_nodes = halves
                    .into_iter()
                    .filter_map(|half| match half {
                        SelectedRootPathHalf::Reference {
                            source_reference,
                            prefix_reference: Some(prefix),
                            anchor,
                            ..
                        } if prefixes.contains(&prefix)
                            || (anchor == ResolutionRootImportAnchor::Lexical
                                && type_reference_nodes.contains(&source_reference)) =>
                        {
                            Some((source_reference, prefix))
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let nodes = terminal_nodes
                    .iter()
                    .map(|(node, _)| *node)
                    .collect::<Vec<_>>();
                let terminal_references = lexical
                    .classify_endpoint_nodes(&nodes, self.cancellation)?
                    .into_iter()
                    .filter_map(|endpoint| Some((endpoint.node(), endpoint.reference()?)))
                    .collect::<HashMap<_, _>>();
                let mut source_references = Vec::new();
                for (node, prefix) in terminal_nodes {
                    if let Some(&reference) = terminal_references.get(&node) {
                        type_terminal_prefixes
                            .entry(reference)
                            .or_insert_with(Vec::new)
                            .push(prefix);
                        if !prefixes.contains(&prefix) {
                            // Terminal-directed discovery may not close a
                            // module's unresolved export. Its new root must
                            // prove the narrow local-type certificate in
                            // every required view.
                            local_type_terminal_prefixes
                                .entry(reference)
                                .or_insert_with(Vec::new)
                                .push(prefix);
                            auxiliary_type_prefix_references.insert(prefix);
                        }
                        // A target-name query may nominate the terminal of
                        // `local_type::Target` without its differently named
                        // root. Confirm both authored references in every
                        // normal Cargo view before using prefix closure.
                        source_references.extend([reference, prefix]);
                    }
                }
                source_references.sort_unstable();
                source_references.dedup();
                let Some(sites) = selected_reference_source_sites(
                    &lexical,
                    self.selected.mount_table(),
                    self.selected.ready.project.root(),
                    &source_references,
                    self.cancellation,
                )?
                else {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                };
                for site in &sites {
                    if let Some(metadata) = site.metadata() {
                        prefix_locators.push(SelectedSemanticLocator::new(
                            "rust",
                            crate::path_utils::rel_path_string(site.file()),
                            metadata.site(),
                            LoweredSemanticRole::Reference,
                        ));
                    }
                }
                locators = merged_locators([nominated, &gap_locators, &prefix_locators]);
            }

            let type_prefix_references = type_terminal_prefixes
                .values()
                .flatten()
                .copied()
                .collect::<HashSet<_>>();
            let mut examined = HashSet::default();
            let nominated_site_count = locators.len();
            let mut candidate_count = 0;
            // Admit and locate every candidate site first, then confirm them
            // one blob at a time. A site's confirmation is a point request on
            // its own file, and every site of a file asks for the same
            // preparation; grouping them is what makes the reverse pay for a
            // candidate blob once instead of once per site.
            let mut admitted_sites = Vec::new();
            let mut field_provenance = self
                .selected
                .ready
                .inventory
                .connection()
                .prepare_cached(FIELD_REFERENCE_PROVENANCE_SQL)?;
            let connection = self.selected.ready.inventory.connection();
            let mut site_cfg = connection.prepare_cached(SITE_CFG_SQL)?;
            let mut call_shape = (request == RustReverseRequest::CallSites)
                .then(|| connection.prepare_cached(CALL_SHAPE_SQL))
                .transpose()?;
            let mut excluded_sites = Vec::new();
            let formal_arities = if request == RustReverseRequest::CallSites {
                let arities = connection
                    .prepare_cached(CALL_ARITY_SQL)?
                    .query_map(
                        params![
                            definition.ordinal().map(i64::from),
                            definition.local_key().map(i64::from)
                        ],
                        |row| Ok((row.get::<_, Option<usize>>(0)?, row.get::<_, bool>(1)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                if arities.is_empty() || arities.iter().any(|(arity, _)| arity.is_none()) {
                    None
                } else {
                    Some(
                        serde_json::to_string(
                            &arities
                                .iter()
                                .map(|(arity, receiver)| {
                                    (
                                        arity.expect("known formal inventory"),
                                        usize::from(*receiver),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        )
                        .expect("arity pairs serialize as JSON"),
                    )
                }
            } else {
                None
            };
            for locator in locators {
                if self.cancellation.is_cancelled() {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                }
                let file =
                    ProjectFile::new(self.selected.ready.project.root(), locator.relative_path());
                if self.admitted.is_some_and(|files| !files.contains(&file)) {
                    continue;
                }
                domains.admit(self.selected, locator.relative_path())?;
                // A site whose cfg every Cargo view of its file refutes is not
                // compiled, so it names nothing. The usage projection already
                // drops such a site when it binds; its unbound forward doubt
                // must not hold the inventory open either. The exclusion
                // closes this exact site's gap rows like a call-shape
                // rejection; other gaps of its file stay obligations.
                if let Some(site) = locator.source_site()
                    && let Some(condition) = site_cfg
                        .query_row(params![locator.relative_path(), site.get()], |row| {
                            row.get::<_, String>(0)
                        })
                        .optional()?
                {
                    let condition =
                        super::super::resolution_prepare::rust_authority::decode_cfg(&condition);
                    if condition
                        != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always
                    {
                        match self.selected.rust_cfg_activation_for_caller_under_site_cfg(
                            std::path::Path::new(locator.relative_path()),
                            &condition,
                            self.cancellation,
                        )? {
                            None => return Ok(SelectedRustReverseBatchOutcome::Cancelled),
                            Some((
                                brokk_bifrost_rust::selected_context::RustSelectedActivation::Inactive,
                                _,
                            )) => {
                                let mount = self
                                    .selected
                                    .mount_table()
                                    .mount_for_path("rust", locator.relative_path())?
                                    .expect("a selected candidate has a mount");
                                excluded_sites.push((mount.ordinal().get(), site.get()));
                                record_cheap_exclusion(locator, &mut domains);
                                #[cfg(any(test, feature = "test-support"))]
                                observer.cheap_exclusion(locator, RustCheapExclusion::InactiveCfg);
                                continue;
                            }
                            Some(_) => {}
                        }
                    }
                }
                if request == RustReverseRequest::CallSites
                    && target.is_callable()
                    && let Some(site) = locator.source_site()
                    && call_shape.as_mut().expect("call-site request has its statement").query_row(params![
                        locator.relative_path(), site.get(), formal_arities,
                        site_kind_code(ResolutionSiteKind::CallableReference),
                        site_kind_code(ResolutionSiteKind::MemberReference),
                        namespace_code(ResolutionNamespace::Callable),
                        super::super::resolution_prepare::resolution_rows::code(
                            brokk_bifrost_core::analyzer::resolution_facts::ALL_RESOLUTION_ENGINE_RULE_KINDS,
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionEngineRuleKind::ArgumentCoercionFilter,
                        ),
                        super::super::source_facts::provenance_code(
                            brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::PrimaryNode,
                        ),
                        gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
                        gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedCallApplicability,
                        )),
                    ], |row| row.get::<_, bool>(0)).optional()? == Some(false)
                {
                    // This structural rejection closes only the exact site's
                    // coarse lookup/applicability placeholders for this target.
                    // Macro, binder and enumeration gaps stay independent.
                    let mount = self.selected.mount_table()
                        .mount_for_path("rust", locator.relative_path())?
                        .expect("a selected candidate has a mount");
                    excluded_sites.push((mount.ordinal().get(), site.get()));
                    record_cheap_exclusion(locator, &mut domains);
                    #[cfg(any(test, feature = "test-support"))]
                    observer.cheap_exclusion(locator, RustCheapExclusion::CallShapeOrArity);
                    continue;
                }
                // Keep inventory_files from before this exclusion: a file
                // with no remaining candidate can still hide a reference in
                // an unexpanded macro or another enumeration gap. Only the
                // irrelevant field's binding doubt is discharged here.
                let mut speculative_field = false;
                if target.is_function()
                    && let Some(site) = locator.source_site()
                    && let Some((primary, well_formed)) = field_provenance.query_row(
                        params![
                            locator.relative_path(),
                            i64::from(site.get()),
                            namespace_code(ResolutionNamespace::Value),
                            site_kind_code(ResolutionSiteKind::MemberReference),
                            gap_origin_code(
                                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::MalformedSyntax,
                                ),
                            ),
                            super::super::source_facts::provenance_code(
                                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::PrimaryNode,
                            ),
                        ],
                        |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
                    ).optional()?
                {
                    if primary && well_formed {
                        record_cheap_exclusion(locator, &mut domains);
                        #[cfg(any(test, feature = "test-support"))]
                        observer.cheap_exclusion(locator, RustCheapExclusion::AuthoredField);
                        continue;
                    }
                    speculative_field = !primary;
                }
                let reference = match self.selected.ready.lookup_locator(
                    &lexical,
                    locator,
                    self.cancellation,
                )? {
                    LocatedSemantic::Found(reference) => reference,
                    LocatedSemantic::Missing => {
                        return Err(StoreError::new(format!(
                            "selected reverse candidate has no canonical source site: {locator:?}"
                        )));
                    }
                    LocatedSemantic::Cancelled => {
                        return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                    }
                };
                if speculative_field {
                    // Confirmation resolves the guessed field expression,
                    // not the unrepresented macro expansion. Keep that source
                    // uncertainty even when the guess binds a real field.
                    inventory.include(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(reference),
                    ]));
                }
                if !examined.insert(reference) {
                    continue;
                }
                candidate_count += 1;
                admitted_sites.push((locator, reference));
            }
            drop(field_provenance);
            drop(site_cfg);
            drop(call_shape);
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "rust reverse nominations: target={}, request={request:?}, nominated_sites={nominated_site_count}, confirmed_sites={candidate_count}, confirmed_blobs={}",
                    target.fq_name(),
                    admitted_sites
                        .iter()
                        .map(|(locator, _)| locator.relative_path())
                        .collect::<HashSet<_>>()
                        .len(),
                )
            });
            admitted_sites.sort_unstable_by_key(|(locator, _)| *locator);
            #[cfg(any(test, feature = "test-support"))]
            let domain_rows = {
                let mut sink = RustReverseObserver {
                    output: observer.output.clone(),
                    rows: Vec::new(),
                };
                let activation = match target_activation {
                    brokk_bifrost_rust::selected_context::RustSelectedActivation::Active => {
                        "active"
                    }
                    brokk_bifrost_rust::selected_context::RustSelectedActivation::Inactive => {
                        "inactive"
                    }
                    brokk_bifrost_rust::selected_context::RustSelectedActivation::Unknown => {
                        "unknown"
                    }
                };
                let mut files = domains.files.iter().collect::<Vec<_>>();
                files.sort_by_key(|(path, _)| *path);
                for (path, domain) in files {
                    sink.domain(path, domain, &domains.proof, activation);
                }
                sink.rows
            };
            let Some(retained) = self.project_reference_partitions(
                &admitted_sites,
                RustReverseRetentionInput {
                    target,
                    definition,
                    type_terminal_references: &type_terminal_prefixes.keys().copied().collect(),
                    type_prefix_references: &type_prefix_references,
                    auxiliary_type_prefix_references: &auxiliary_type_prefix_references,
                    domains: &domains,
                },
            )?
            else {
                return Ok(SelectedRustReverseBatchOutcome::Cancelled);
            };
            let RustReverseRetained {
                mut proof,
                references,
                witnesses,
                bindings,
                accounted_references,
                qualified_references,
                inventory: retained_inventory,
                mut confirmed_enumeration,
                evaluated_type_terminals,
                type_terminal_rejections,
                proven_prefixes,
                proven_local_type_prefixes,
                local_prefix_reasons,
                time_budget_exceeded,
                evaluation_count,
            } = retained;
            {
                let cheap = domains.proof;
                match proof.as_mut() {
                    Some(into) => reverse::append_reverse_proof(into, cheap),
                    None => proof = Some(cheap),
                }
            }
            if let Some(proof) = &proof {
                for site in &proof.sites {
                    proof.required[site.context]
                        .selected
                        .assert_selected(self.selected);
                }
            }
            let retained_inventory = retained_inventory.finish();
            let retained_inventory = if let Some(sites) = &gap_sites {
                filter_macro_frontier_completion(
                    self.selected,
                    retained_inventory,
                    &sites.names_json,
                )?
            } else {
                retained_inventory
            };
            inventory.include(&retained_inventory);
            let mut accounted_references = accounted_references.into_iter().collect::<HashSet<_>>();
            let mut qualified_references = qualified_references.into_iter().collect::<HashSet<_>>();
            let mut dependency_evidence = reverse::ReverseEvidence::new(definition);
            let dependencies = evaluated_type_terminals
                .into_iter()
                .map(|terminal| {
                    let mut handles = Vec::new();
                    for (_, rejection) in type_terminal_rejections
                        .iter()
                        .filter(|(key, _)| *key == terminal)
                    {
                        if let ResolutionCompletion::Incomplete(reasons) = rejection {
                            for reason in reasons.iter().copied() {
                                let handle = dependency_evidence.enumeration.record(
                                    reverse::ReverseSubject::Target(definition),
                                    reverse::ReverseEvidenceOrigin::Binding,
                                    ResolutionCompletion::incomplete([reason]),
                                );
                                handles.push((reason, handle));
                            }
                        }
                    }
                    reverse::ReverseDependency {
                        dependent: terminal,
                        prerequisites: type_terminal_prefixes[&terminal].clone(),
                        proof: handles,
                    }
                })
                .collect::<Vec<_>>();
            let proven_type_terminals = reverse::close_reverse_dependencies(
                &dependencies,
                &proven_prefixes,
                &mut dependency_evidence,
                |dependency| {
                    if !local_type_terminal_prefixes
                        .get(&dependency.dependent)
                        .into_iter()
                        .flatten()
                        .all(|prefix| proven_local_type_prefixes.contains(prefix))
                    {
                        return Ok(None);
                    }
                    let open_surface = ResolutionIncompleteReason::OpenBoundary {
                        semantic: dependency.dependent,
                        status:
                            crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                    };
                    let local_reasons = dependency
                        .prerequisites
                        .iter()
                        .flat_map(|prefix| local_prefix_reasons.get(prefix).into_iter().flatten())
                        .copied()
                        .collect::<HashSet<_>>();
                    Ok(Some(
                        dependency
                            .proof
                            .iter()
                            .filter(|(reason, _)| {
                                *reason == open_surface || local_reasons.contains(reason)
                            })
                            .map(|(_, handle)| handle.clone())
                            .collect(),
                    ))
                },
            )?;
            accounted_references.extend(proven_type_terminals.iter().copied());
            qualified_references.extend(proven_type_terminals.iter().copied());
            for (terminal, original_rejection) in type_terminal_rejections {
                let dependency = dependencies
                    .iter()
                    .find(|dependency| dependency.dependent == terminal)
                    .expect("an evaluated terminal retains its dependency obligations");
                let handles = dependency
                    .proof
                    .iter()
                    .map(|(_, handle)| handle.clone())
                    .collect::<Vec<_>>();
                let Some(rejected) = reverse::reverse_completion_for_obligations(
                    &dependency_evidence,
                    &handles,
                    &mut || self.cancellation.is_cancelled(),
                ) else {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                };
                debug_assert!(
                    original_rejection == ResolutionCompletion::Complete || !handles.is_empty()
                );
                let rejected = if let Some(sites) = &gap_sites {
                    filter_macro_frontier_completion(self.selected, rejected, &sites.names_json)?
                } else {
                    rejected
                };
                inventory.include(&rejected);
            }
            let _dependency_handles = reverse::append_reverse_evidence(
                &mut proof
                    .as_mut()
                    .expect("a target retains its independent file domain")
                    .evidence,
                dependency_evidence,
            );
            #[cfg(any(test, feature = "test-support"))]
            if observer.output.is_some() {
                for dependency in &dependencies {
                    let links = dependency.proof.iter().map(|(reason, handle)| {
                        let handle = if _dependency_handles.is_empty() { handle } else {
                            _dependency_handles.get(handle)
                                .expect("dependency link was imported with its obligation")
                        };
                        serde_json::json!({"reason":format!("{reason:?}"),"obligation":format!("{handle:?}")})
                    }).collect::<Vec<_>>();
                    observer.rows.push(serde_json::json!({"stage":"dependency","terminal":format!("{:?}",dependency.dependent),
                        "prerequisites":format!("{:?}",dependency.prerequisites),"links":links}));
                }
            }
            let mut observed_references = references
                .iter()
                .copied()
                .chain(accounted_references.iter().copied())
                .collect::<Vec<_>>();
            observed_references.sort_unstable();
            observed_references.dedup();
            let source_sites = {
                let lexical = self.selected.ready.lexical_source();
                let observed_lexical = SeamProfiled::observing(&lexical);
                selected_reference_source_sites(
                    &observed_lexical,
                    self.selected.mount_table(),
                    self.selected.ready.project.root(),
                    &observed_references,
                    self.cancellation,
                )?
            };
            let Some(mut source_sites) = source_sites else {
                return Ok(SelectedRustReverseBatchOutcome::Cancelled);
            };
            let mut accounted_reference_sites = source_sites
                .iter()
                .filter(|site| accounted_references.contains(&site.reference()))
                .filter_map(|source_site| {
                    Some((
                        source_site.reference().ordinal()?,
                        source_site.metadata()?.site().get(),
                    ))
                })
                .collect::<Vec<_>>();
            accounted_reference_sites.extend(excluded_sites.iter().copied());
            let mut qualified_reference_sites = source_sites
                .iter()
                .filter(|site| qualified_references.contains(&site.reference()))
                .filter_map(|source_site| {
                    Some((
                        source_site.reference().ordinal()?,
                        source_site.metadata()?.site().get(),
                    ))
                })
                .collect::<Vec<_>>();
            qualified_reference_sites.extend(excluded_sites);
            let published_references = references.iter().copied().collect::<HashSet<_>>();
            source_sites = source_sites
                .into_vec()
                .into_iter()
                .filter(|site| published_references.contains(&site.reference()))
                .collect();
            if time_budget_exceeded {
                // The already confirmed blobs may have supplied useful
                // enumeration completions. Keep those facts while skipping
                // the per-file completion reads that remain after the stop.
                for completion in confirmed_enumeration.into_values() {
                    let completion = completion.finish();
                    let completion = if let Some(sites) = &gap_sites {
                        filter_macro_frontier_completion(
                            self.selected,
                            completion,
                            &sites.names_json,
                        )?
                    } else {
                        completion
                    };
                    inventory.include(&completion);
                }
            } else if let Some(sites) = &gap_sites {
                // The scoped SQL rereads the persisted gap rows it names so a
                // qualified route can be dismissed only after an exact
                // complete forward answer or a proven external root. Per-file
                // completion
                // would reintroduce unrelated names from those same blobs.
                confirmed_enumeration.clear();
                let (scoped_gaps, _gap_locators) = target_scoped_reference_inventory_gaps(
                    self.selected,
                    sites,
                    target,
                    &accounted_reference_sites,
                    &qualified_reference_sites,
                    self.cancellation,
                )?;
                inventory.include(&scoped_gaps);
            }
            if let Some(sites) = gap_sites {
                release_gap_candidate_sites(self.selected, sites)?;
            }
            let inventory_completion = inventory.finish();
            let inventory_completion = crate::analyzer::resolution::FactResolutionOperation::refine_reference_inventory_from_sources(
                &self.selected.ready.lexical_source(),
                &self.selected.ready.typed_source(),
                definition,
                &inventory_completion,
                self.cancellation,
            )?;
            if inventory_completion.contains_reason(ResolutionIncompleteReason::Cancelled) {
                return Ok(SelectedRustReverseBatchOutcome::Cancelled);
            }
            #[cfg(any(test, feature = "test-support"))]
            {
                observer.rows.extend(domain_rows);
                observer.finish(self.selected, target, proof.as_ref(), &inventory_completion)?;
            }
            let answer = ReferenceSearchAnswer::new(references, witnesses, inventory_completion);
            match project_rust_reference_owners(
                &self.selected.ready,
                self.selected.mount_table(),
                &mut source_sites,
                self.cancellation,
            )? {
                SelectedRustReferenceOwnerProjection::Complete => {}
                SelectedRustReferenceOwnerProjection::Cancelled => {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                }
                SelectedRustReferenceOwnerProjection::Unavailable => {
                    // Every owner that the `CodeUnit` model simply has no node
                    // for is projected as "no enclosing unit", so reaching here
                    // means a persisted owner semantic has no source row at
                    // all: a store inconsistency, not a shape of the language.
                    return Err(StoreError::new(format!(
                        "reverse reference owner is unavailable for target {:?} among sites {:?}",
                        target,
                        source_sites
                            .iter()
                            .map(SelectedReferenceSourceSite::reference)
                            .collect::<Vec<_>>()
                    )));
                }
            }
            results.push(SelectedRustTargetReferences {
                target: target.clone(),
                metrics: FactReverseResolutionMetrics::for_row_candidates(
                    candidate_count,
                    evaluation_count,
                    source_sites.len(),
                ),
                search: SelectedReferenceSearchAnswer {
                    answer,
                    source_sites,
                },
                bindings: bindings.into_boxed_slice(),
            });
        }
        Ok(SelectedRustReverseBatchOutcome::Ready(results))
    }

    fn held_resolve_references(
        &mut self,
        references: &[SemanticId],
    ) -> Result<Option<Vec<ReferenceResolution>>> {
        let _timing = crate::profiling::scope("rust_selected::incoming_recheck");
        let lexical = self.selected.ready.lexical_source();
        let observed_lexical = SeamProfiled::observing(&lexical);
        let Some(sites) = selected_reference_source_sites(
            &observed_lexical,
            self.selected.mount_table(),
            self.selected.ready.project.root(),
            references,
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        let reference_indices = references
            .iter()
            .enumerate()
            .map(|(index, &reference)| (reference, index))
            .collect::<HashMap<_, _>>();
        assert_eq!(reference_indices.len(), references.len());
        let mut locators_by_file =
            HashMap::<ProjectFile, Vec<(usize, SelectedSemanticLocator)>>::default();
        for site in sites {
            let metadata = site
                .metadata
                .ok_or_else(|| StoreError::new("reverse reference metadata is unavailable"))?;
            let index = *reference_indices
                .get(&site.reference())
                .expect("selected source projection preserves each requested reference");
            let locator = SelectedSemanticLocator::new(
                "rust",
                crate::path_utils::rel_path_string(&site.file),
                metadata.site(),
                LoweredSemanticRole::Reference,
            );
            locators_by_file
                .entry(site.file.clone())
                .or_default()
                .push((index, locator));
        }
        let mut file_locators = locators_by_file.into_values().flatten().collect::<Vec<_>>();
        file_locators.sort_unstable_by(|(_, left), (_, right)| left.cmp(right));
        let admitted = file_locators
            .iter()
            .map(|(index, locator)| (locator, references[*index]))
            .collect::<Vec<_>>();
        let answers_by_reference = std::iter::repeat_with(|| {
            ReferenceResolution::Omitted(ReferenceOmission::TimeBudgetExceeded)
        })
        .take(references.len())
        .collect::<Vec<_>>();
        let cancellation = self.cancellation;
        let confirm = self.confirm;
        let evaluate = |selected: &mut SelectedResolutionOperation<'_, '_>, range| {
            match project_recheck_files(selected, cancellation, confirm, &admitted, range)? {
                Some(answer) => Ok(SelectedResolutionOperationOutcome::Native(answer)),
                None => Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                )),
            }
        };
        let results = execute_reverse_partitions(
            self.selected,
            &admitted,
            cancellation,
            evaluate,
            |selected| evaluate(selected, 0..admitted.len()),
            |answer| {
                answer
                    .answers
                    .iter()
                    .map(|(index, reference, _)| ((*reference).into(), admitted[*index].1.into()))
                    .collect()
            },
        )?;
        let outcome = reverse::fold_reverse_partitions(
            results,
            answers_by_reference,
            |answers, partition| {
                for (index, _, answer) in partition.answers {
                    answers[file_locators[index].0] = answer;
                }
            },
            |_, _| {},
        );
        match outcome {
            SelectedResolutionOperationOutcome::Native(answers) => Ok(Some(answers)),
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                self.unavailable = Some(reason);
                Ok(None)
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                self.stale = Some(reason);
                Ok(None)
            }
            SelectedResolutionOperationOutcome::Cancelled(_) => Ok(None),
        }
    }
}

/// The callback's view of the operation. On the in-memory fallback the
/// operation's reader is the store's only connection, and the callback reads
/// the store between queries: its projection asks the analyzer for parents,
/// sources and structural facts. So the operation lends that connection to
/// the callback, and takes it back only while it answers (#6018).
impl SelectedRustReverseQueries for RustReverseQueries<'_, '_, '_> {
    fn analysis_generation(&self) -> u64 {
        self.selected.ready.analysis_generation
    }

    fn candidate_sets(
        &mut self,
        targets: &[CodeUnit],
    ) -> Result<Option<Vec<RustReverseCandidateSet>>> {
        self.on_own_connection(None, |queries| queries.held_candidate_sets(targets))
    }

    fn rust_cfg_activation_for_caller_under_site_cfg(
        &mut self,
        caller: &std::path::Path,
        condition: &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition,
        cancellation: &CancellationToken,
    ) -> Result<
        Option<(
            brokk_bifrost_rust::selected_context::RustSelectedActivation,
            bool,
        )>,
    > {
        self.on_own_connection(None, |queries| {
            queries
                .selected
                .rust_cfg_activation_for_caller_under_site_cfg(caller, condition, cancellation)
        })
    }

    fn references_to(
        &mut self,
        targets: &[CodeUnit],
        candidates: &[RustReverseCandidateSet],
        request: RustReverseRequest,
    ) -> Result<SelectedRustReverseBatchOutcome> {
        self.on_own_connection(SelectedRustReverseBatchOutcome::Cancelled, |queries| {
            queries.held_references_to(targets, candidates, request)
        })
    }

    fn resolve_references(
        &mut self,
        references: &[SemanticId],
    ) -> Result<Option<Vec<ReferenceResolution>>> {
        self.on_own_connection(None, |queries| queries.held_resolve_references(references))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn definition_mount_read_count(&self) -> usize {
        self.definition_mounts.len()
    }

    #[cfg(any(test, feature = "test-support"))]
    fn begin_sql_work_trace(&self) {
        REVERSE_SQL_WORK.with(|work| {
            assert!(work.borrow().is_none(), "reverse SQL trace cannot nest");
            work.replace(Some((0, 0)));
        });
        attach_reverse_sql_work_trace(self.selected.ready.inventory.connection());
    }

    #[cfg(any(test, feature = "test-support"))]
    fn finish_sql_work_trace(&self) -> (usize, usize) {
        detach_reverse_sql_work_trace(self.selected.ready.inventory.connection());
        REVERSE_SQL_WORK.with(|work| {
            work.borrow_mut()
                .take()
                .expect("reverse SQL trace must be active")
        })
    }
}

impl<'store, 'input> SelectedResolutionOperation<'store, 'input> {
    #[doc(hidden)]
    pub fn with_rust_row_reverse_queries<'a, T>(
        mut self,
        admitted: Option<&'a HashSet<ProjectFile>>,
        cancellation: &'a CancellationToken,
        confirm: impl for<'confirm_store, 'confirm_input> Fn(
            &mut SelectedResolutionOperation<'confirm_store, 'confirm_input>,
            &Path,
            &[&SelectedSemanticLocator],
        ) -> Result<RustReverseConfirmation>
        + Sync,
        run: impl FnOnce(&mut dyn SelectedRustReverseQueries) -> Result<T>,
    ) -> Result<SelectedResolutionOperationOutcome<T>> {
        self.ready
            .inventory
            .connection()
            .execute_batch(GAP_CANDIDATE_SITES_SCHEMA_SQL)?;
        let mut queries = RustReverseQueries {
            selected: &mut self,
            cancellation,
            admitted,
            confirm: &confirm,
            unavailable: None,
            stale: None,
            #[cfg(any(test, feature = "test-support"))]
            definition_mounts: HashSet::default(),
        };
        queries.selected.ready.inventory.lend_writer()?;
        let result = run(&mut queries)?;
        let unavailable = queries.unavailable.take();
        let stale = queries.stale.take();
        drop(queries);
        self.ready.inventory.end_writer_loan()?;
        self.ready.inventory.with_owned_temp_write(|connection| {
            connection.execute(CLEAR_GAP_CANDIDATE_SITES_SQL, [])?;
            Ok(())
        })?;
        drop(self.ready.rust_caller_context.get_mut().take());
        drop(self.ready.rust_caller_demand.get_mut().take());
        debug_assert!(
            self.ready.rust_caller_context.borrow().is_none()
                && self.ready.rust_caller_demand.borrow().is_none(),
            "row discovery must not construct or retain a profile context"
        );
        if let Some(reason) = unavailable {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
        }
        if let Some(reason) = stale {
            return Ok(SelectedResolutionOperationOutcome::Stale(reason));
        }
        self.ready
            .finish(result, &ResolutionCompletion::Complete, cancellation)
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_shared_reverse_domain_for_test(operation: &SelectedResolutionOperation<'_, '_>) {
    let cancellation = CancellationToken::new();
    assert!(
        operation
            .ensure_selected_rust_inputs(&cancellation)
            .unwrap()
    );
    let domain = required_reverse_domain(operation, "src/unused.rs").unwrap();
    assert_eq!(domain.len(), 1, "one evaluation per existing caller root");
    assert_eq!(domain[0].view.caller, Path::new("src/shared.rs"));
    let units = domain[0]
        .view
        .owners
        .iter()
        .map(|owner| owner.unit_key)
        .collect::<HashSet<_>>();
    assert_eq!(
        units.len(),
        2,
        "both selected Cargo authorities survive with no nominated hits"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::analyzer::store::planner_statistics::pinned_plans::{
        explain_pin, pinned, prepare_pin_context,
    };

    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#5142: reverse name closure walked all hosts once per queued name")]
    fn target_scoped_inventory_query_uses_candidate_and_route_indexes() {
        let store = crate::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let connection = store.conn.lock().unwrap();
        store
            .select_writer_workspace_snapshots(&connection, &HashMap::default())
            .unwrap();
        prepare_pin_context(&connection);
        let sites_query = pinned("rust_reverse_gap_candidate_sites");
        let gaps_query = pinned("rust_reverse_target_scoped_inventory_gaps");
        for state in PlannerStatisticsState::BOTH {
            state.install(&connection);

            // The candidate sites are enumerated once per target.
            let plan = explain_pin(&connection, &sites_query);
            assert!(
                plan.iter()
                    .any(|line| line.contains("resolution_rust_reverse_gap_candidates_name")),
                "{state:?}: target completeness must seek named gap rows: {plan:?}"
            );
            assert!(
                plan.iter().any(|line| {
                    line.contains(
                        "SEARCH terminal USING COVERING INDEX source_rust_type_segments_name (name=? AND blob_id=?)",
                    )
                }),
                "{state:?}: type-alias closure must seek segments by target name and host blob: {plan:?}"
            );
            assert!(
                plan.iter().any(|line| {
                    line.contains("SEARCH alias_unit USING PRIMARY KEY (blob_id=? AND unit_key=?)")
                }),
                "{state:?}: type-alias closure must seek declarations by blob and unit key: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|line| line.contains("resolution_unit_summary_dependencies_unit")),
                "{state:?}: reverse dependency closure must seek live child summaries by unit key: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|line| { line.contains("SEARCH a USING PRIMARY KEY (mount_ordinal=?)") }),
                "{state:?}: selected module placements must seek materialized rows by mount: {plan:?}"
            );
            assert!(
                plan.iter().any(|line| {
                    line.contains("rust_resolution_unit_summary_import_routes_site")
                }),
                "{state:?}: alias closure must seek routes by source import identity: {plan:?}"
            );
            assert!(
                plan.iter().any(|line| {
                    line.contains("resolution_unit_summary_dependency_names_name")
                        || line.contains("resolution_unit_summary_dependency_names_owner_name")
                }),
                "{state:?}: external-route classification must seek the Rust dependency alias: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|line| { line.contains("SCAN gap USING INDEX resolution_gaps_identity") }),
                "{state:?}: candidate completeness must not scan every gap: {plan:?}"
            );
            // Each name-keyed candidate branch seeks the name index per name. The
            // wildcard branches seek their constant key. None may scan the index.
            let candidate_seeks = plan
                .iter()
                .filter(|line| {
                    line.contains(
                        "SEARCH candidate USING COVERING INDEX resolution_rust_reverse_gap_candidates_name (candidate_name=?",
                    )
                })
                .count();
            assert!(
                candidate_seeks >= 5,
                "{state:?}: every candidate branch must seek the name index: {candidate_seeks} seeks in {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| {
                    line.contains("SCAN candidate USING COVERING INDEX resolution_rust_reverse_gap_candidates_name")
                }),
                "{state:?}: no candidate branch may scan the name index: {plan:?}"
            );
            assert!(
                plan.iter().any(|line| {
                    line.contains("idx_source_imports_identifier (identifier=? AND blob_id=?)")
                }),
                "{state:?}: bound import aliases must seek source imports by name and host blob: {plan:?}"
            );
            assert!(
                plan.iter().any(|line| {
                    line.contains(
                        "idx_rust_import_targets_imported_name (imported_name=? AND blob_id=?",
                    )
                }),
                "{state:?}: unresolved import aliases must seek by name and host blob: {plan:?}"
            );
            // The unresolved-source alias arm is the third recursive arm. Its
            // current name row must drive the host and import lookups, so each
            // queued name seeks only its matching host before reading imports.
            let recursive_name = plan
                .iter()
                .enumerate()
                .filter(|(_, line)| line.as_str() == "SCAN names")
                .nth(2)
                .map(|(index, _)| index)
                .unwrap_or_else(|| {
                    panic!("{state:?}: third recursive name scan missing: {plan:?}")
                });
            let host = plan
                .iter()
                .enumerate()
                .skip(recursive_name + 1)
                .find(|(_, line)| line.contains("SEARCH host USING"))
                .map(|(index, _)| index)
                .unwrap_or_else(|| {
                    panic!("{state:?}: recursive name must seek its host: {plan:?}")
                });
            let unresolved = plan
                .iter()
                .enumerate()
                .skip(host + 1)
                .find(|(_, line)| line.contains("SEARCH unresolved USING"))
                .map(|(index, _)| index)
                .unwrap_or_else(|| {
                    panic!("{state:?}: host must drive unresolved imports: {plan:?}")
                });
            let imported = plan
                .iter()
                .enumerate()
                .skip(unresolved + 1)
                .find(|(_, line)| line.contains("SEARCH imported USING"))
                .map(|(index, _)| index)
                .unwrap_or_else(|| {
                    panic!("{state:?}: unresolved imports must drive aliases: {plan:?}")
                });
            assert!(
                recursive_name < host && host < unresolved && unresolved < imported,
                "{state:?}: unresolved alias closure must read the recursive name, matching host, and import tables in that order: {plan:?}"
            );
            assert!(
                !plan[unresolved..=imported]
                    .iter()
                    .any(|line| line.contains("AUTOMATIC")),
                "{state:?}: unresolved source and alias imports must not need automatic indexes: {plan:?}"
            );

            // The gap query, asked twice per target, reads those sites by key
            // and runs none of the closure.
            let plan = explain_pin(&connection, &gaps_query);
            assert!(
                plan.iter()
                    .any(|line| line.contains("resolution_root_route_segments_reference")),
                "{state:?}: qualified gaps must seek routes by source site: {plan:?}"
            );
            assert!(
                plan.iter().any(|line| {
                    line.contains("SEARCH candidate USING PRIMARY KEY (target_key=?")
                }),
                "{state:?}: the target's candidate sites must be read by their key: {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| line.starts_with("SCAN candidate")),
                "{state:?}: the candidate sites must not be scanned: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|line| line.contains("source_rust_type_segments_name")
                        || line.contains("idx_source_imports_identifier")
                        || line.contains("idx_rust_import_targets_unresolved_source_alias")),
                "{state:?}: the gap query must not rerun the name closure: {plan:?}"
            );
            // The raw_gaps reason and gap joins are driven by the candidate sites.
            // Each site seeks its reasons, and each reason seeks its gap rows.
            assert!(
                plan.iter().any(|line| {
                    line.contains(
                        "SEARCH reason USING COVERING INDEX resolution_gap_reasons_site (blob_id=? AND site=?",
                    )
                }),
                "{state:?}: gap reasons must seek by candidate site: {plan:?}"
            );
            assert!(
                plan.iter().any(|line| {
                    line.contains(
                        "SEARCH gap USING COVERING INDEX resolution_gaps_reason_covers (blob_id=? AND reason=? AND covers=?)",
                    )
                }),
                "{state:?}: gap rows must seek by reason and covers: {plan:?}"
            );
            assert!(
                !plan.iter().any(|line| {
                    line.contains("SCAN reason USING COVERING INDEX resolution_gap_reasons_site")
                }),
                "{state:?}: no gap reason may scan the reason index: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|line| { line.contains("SCAN gap USING INDEX resolution_gaps_identity") }),
                "{state:?}: candidate completeness must not scan every gap: {plan:?}"
            );
        }
    }

    #[test]
    fn macro_textual_closure_seeks_one_file_and_its_enclosing_contexts() {
        let store = crate::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let connection = store.conn.lock().unwrap();
        store
            .select_writer_workspace_snapshots(&connection, &HashMap::default())
            .unwrap();
        prepare_pin_context(&connection);
        let query = pinned("rust_reverse_macro_textual_closure");
        for state in PlannerStatisticsState::BOTH {
            state.install(&connection);
            let plan = explain_pin(&connection, &query);
            for required in [
                "SEARCH context USING PRIMARY KEY (blob_id=? AND occurrence_id=?)",
                "source_rust_item_macro_expansions_fk_context_occurrence_id (context_occurrence_id=? AND blob_id=?)",
                "source_rust_macro_definitions_fk_context_occurrence_id (context_occurrence_id=? AND blob_id=?)",
                "SEARCH member USING INDEX resolution_unit_summary_members_blob",
            ] {
                assert!(
                    plan.iter().any(|line| line.contains(required)),
                    "{state:?}: the closure requires {required}: {plan:?}"
                );
            }
            assert!(
                !plan.iter().any(|line| line.contains("AUTOMATIC")),
                "{state:?}: the closure must use owned indexes: {plan:?}"
            );
            for table in [
                "expansion",
                "context",
                "earlier",
                "definition",
                "declaration",
                "named",
                "import_context",
                "member",
                "attribute",
                "manifest",
                "syntax",
            ] {
                assert!(
                    !plan
                        .iter()
                        .any(|line| line.contains(&format!("SCAN {table} "))
                            || line.ends_with(&format!("SCAN {table}"))),
                    "{state:?}: the closure must not scan {table}: {plan:?}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#6048: gap CTE probes re-ran per raw gap and read every reference site; 10s per Rust target"
    )]
    fn target_scoped_inventory_gap_ctes_run_once_from_the_raw_gaps() {
        let store = crate::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let connection = store.conn.lock().unwrap();
        store
            .select_writer_workspace_snapshots(&connection, &HashMap::default())
            .unwrap();
        prepare_pin_context(&connection);
        let gaps_query = pinned("rust_reverse_target_scoped_inventory_gaps");
        for state in PlannerStatisticsState::BOTH {
            state.install(&connection);
            let plan = explain_pin(&connection, &gaps_query);
            for cte in [
                "qualified_routes",
                "external_roots",
                "out_of_scope_local_alias_roots",
            ] {
                assert!(
                    plan.iter()
                        .any(|line| line == &format!("MATERIALIZE {cte}")),
                    "{state:?}: {cte} must be computed once per execution: {plan:?}"
                );
                assert!(
                    !plan.iter().any(|line| line == &format!("CO-ROUTINE {cte}")),
                    "{state:?}: {cte} must not rerun for every raw gap: {plan:?}"
                );
            }
            assert!(
                !plan
                    .iter()
                    .any(|line| line.contains("SEARCH reference_site USING AUTOMATIC")),
                "{state:?}: reference sites must be sought by the raw gap's site: {plan:?}"
            );
        }
    }

    #[test]
    fn rust_reverse_call_shape_queries_seek_candidate_and_signature_keys() {
        let store = crate::analyzer::store::AnalyzerStore::open_ephemeral().unwrap();
        let connection = store.conn.lock().unwrap();
        store
            .select_writer_workspace_snapshots(&connection, &HashMap::default())
            .unwrap();
        prepare_pin_context(&connection);
        for state in PlannerStatisticsState::BOTH {
            state.install(&connection);
            for (name, required) in [
                (
                    "rust_reverse_call_arity",
                    &[
                        "SEARCH alternative USING COVERING INDEX source_declaration_units_unit (blob_id=? AND unit_key=?)",
                        "SEARCH signature USING PRIMARY KEY (blob_id=? AND definition=?)",
                        "SEARCH parameter USING PRIMARY KEY (blob_id=? AND declaration_id=?)",
                        "SEARCH receiver USING PRIMARY KEY (blob_id=? AND declaration_id=?)",
                    ][..],
                ),
                (
                    "rust_reverse_call_shape",
                    &[
                        "SEARCH site USING PRIMARY KEY (blob_id=? AND site=?)",
                        "SEARCH obligation USING PRIMARY KEY (blob_id=? AND callee_reference=?)",
                        "SEARCH gap USING PRIMARY KEY (blob_id=? AND site=?)",
                    ][..],
                ),
            ] {
                let plan = explain_pin(&connection, &pinned(name));
                for required in required {
                    assert!(
                        plan.iter().any(|line| line.contains(required)),
                        "{state:?}: {name} requires {required}: {plan:?}"
                    );
                }
                assert!(
                    !plan.iter().any(|line| line.contains("AUTOMATIC")),
                    "{state:?}: {name} must use owned indexes: {plan:?}"
                );
                for table in [
                    "site",
                    "signature",
                    "parameter",
                    "receiver",
                    "obligation",
                    "gap",
                    "alternative",
                ] {
                    assert!(
                        !plan
                            .iter()
                            .any(|line| line.contains(&format!("SCAN {table} "))
                                || line.ends_with(&format!("SCAN {table}"))),
                        "{state:?}: {name} must not scan {table}: {plan:?}"
                    );
                }
            }
        }
    }
}
