//! Query-local reverse discovery from persisted crate and reference rows.

use super::super::resolution_prepare::resolution_rows::{
    gap_origin_code, namespace_code, site_kind_code,
};
use super::*;
use crate::analyzer::resolution::ResolutionCompletionAccumulator;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionGapKind, ResolutionMemberKind, ResolutionScopeId,
};
use rusqlite::{OptionalExtension, params};

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

pub(crate) const DEFINITION_SITE_SQL: &str = "SELECT sites.blob_id, sites.source_site FROM temp.selected_resolution_mounts AS mounts CROSS JOIN resolution_semantic_sites AS sites ON sites.blob_id = mounts.blob_id AND sites.semantic_key = ?2 AND sites.semantic_role = 'definition' WHERE mounts.mount_ordinal = ?1";
pub(crate) const TARGET_ACTIVATION_SQL: &str = "SELECT properties.cfg_condition, json(owner.cfg_atoms), owner.target_kind FROM temp.selected_resolution_mounts AS mount CROSS JOIN resolution_semantic_sites AS site ON site.blob_id=mount.blob_id AND site.semantic_key=?2 AND site.semantic_role='definition' CROSS JOIN source_native_declaration_bridges AS bridge ON bridge.blob_id=site.blob_id AND bridge.source_site=site.source_site CROSS JOIN source_rust_declaration_properties AS properties ON properties.blob_id=bridge.blob_id AND properties.declaration_id=bridge.declaration_id CROSS JOIN rust_crate_container_sources AS sources INDEXED BY rust_crate_containers_blob ON sources.blob_id=site.blob_id CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=sources.topology_id WHERE mount.mount_ordinal=?1";
pub(crate) const SAME_BLOB_TYPE_EXPORT_KEYS_SQL: &str = "SELECT DISTINCT sites.semantic_key FROM rust_crate_exports AS exports INDEXED BY rust_crate_exports_declaration CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=exports.topology_id CROSS JOIN source_native_declaration_bridges AS export_bridge ON export_bridge.blob_id=exports.declaration_blob_id AND export_bridge.source_site=exports.declaration_site CROSS JOIN source_declaration_units AS export_unit ON export_unit.blob_id=export_bridge.blob_id AND export_unit.declaration_id=export_bridge.declaration_id CROSS JOIN source_native_declaration_bridges AS target_bridge ON target_bridge.blob_id=exports.declaration_blob_id AND target_bridge.source_site=?3 CROSS JOIN source_declaration_units AS target_unit ON target_unit.blob_id=target_bridge.blob_id AND target_unit.declaration_id=target_bridge.declaration_id AND target_unit.unit_key=export_unit.unit_key CROSS JOIN resolution_semantic_sites AS sites ON sites.blob_id=exports.declaration_blob_id AND sites.source_site=exports.declaration_site AND sites.semantic_role='definition' WHERE exports.declaration_blob_id=?1 AND exports.namespace='type' AND exports.name=?2 AND exports.declaration_site<>?3";
pub(crate) const BASE_TARGET_ACTIVATION_SQL: &str = "SELECT properties.cfg_condition, json(owner.cfg_atoms), owner.target_kind FROM resolution_semantic_sites AS site CROSS JOIN source_native_declaration_bridges AS bridge ON bridge.blob_id=site.blob_id AND bridge.source_site=site.source_site CROSS JOIN source_rust_declaration_properties AS properties ON properties.blob_id=bridge.blob_id AND properties.declaration_id=bridge.declaration_id CROSS JOIN rust_crate_container_sources AS sources INDEXED BY rust_crate_containers_blob ON sources.blob_id=site.blob_id CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=sources.topology_id WHERE site.blob_id=?1 AND site.source_site=?2 AND site.semantic_role='definition'";
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
const OTHER_TARGET_WORKSPACE_DEPENDENCY_SQL: &str = r#"
SELECT
 EXISTS(
   SELECT 1
   FROM selected_rust_module_placements AS placement
   JOIN rust_crate_dependencies AS dependency USING(topology_id)
   WHERE placement.mount_ordinal=?1 AND dependency.extern_name=?2
 ),
 EXISTS(
   SELECT 1
   FROM selected_rust_module_placements AS placement
   JOIN rust_crate_versions AS current_version
     ON current_version.topology_id=placement.topology_id
    AND current_version.valid_until IS NULL
    AND current_version.manifest_file_version_id IS NOT NULL
   JOIN selected_rust_crates AS sibling
     ON sibling.topology_id<>current_version.topology_id
   JOIN rust_crate_versions AS sibling_version
     ON sibling_version.topology_id=sibling.topology_id
    AND sibling_version.workspace_id=current_version.workspace_id
    AND sibling_version.lang=current_version.lang
    AND sibling_version.generation=current_version.generation
    AND sibling_version.manifest_file_version_id=current_version.manifest_file_version_id
    AND sibling_version.valid_until IS NULL
   JOIN rust_crate_dependencies AS sibling_dependency
     ON sibling_dependency.topology_id=sibling_version.topology_id
    AND sibling_dependency.extern_name=?2
    AND sibling_dependency.boundary='workspace'
   WHERE placement.mount_ordinal=?1
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
/// target, and `confirm_locators` resolves it once per row this returns. The
/// row is the owning target's own crate root, not the candidate file: a caller
/// path is how a confirmation names the crate context it resolves under, and
/// the candidate sites travel separately as locators. Returning the candidate
/// file collapsed every owning target into one request, in which `crate::error`
/// in a dual-owned module named the library's `error` and the binary's at once
/// and neither owner could claim the site.
pub(crate) const CALLER_ROOTS_SQL: &str = "WITH source(blob_id,persisted_relative_path) AS (SELECT blob_id,persisted_relative_path FROM temp.selected_resolution_mounts WHERE storage_language='rust' AND persisted_relative_path=?1 UNION ALL SELECT blob.id,mask.persisted_relative_path FROM temp.selected_resolution_overlay_masks AS mask CROSS JOIN workspace_file_versions AS version ON version.file_version_id=mask.masked_file_version_id CROSS JOIN blobs AS blob ON blob.blob_oid=version.blob_oid AND blob.lang=version.lang AND blob.generation=version.generation WHERE mask.storage_language='rust' AND mask.persisted_relative_path=?1) SELECT DISTINCT roots.rel_path FROM source CROSS JOIN rust_crate_container_sources AS placement INDEXED BY rust_crate_containers_blob ON placement.blob_id=source.blob_id AND placement.rel_path=source.persisted_relative_path CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=placement.topology_id CROSS JOIN rust_crate_container_sources AS roots ON roots.topology_id=owner.topology_id AND roots.container_path='crate' WHERE roots.source_kind='declared' AND (owner.target_kind<>'detached' OR NOT EXISTS(SELECT 1 FROM rust_crate_container_sources AS parent INDEXED BY rust_crate_containers_blob CROSS JOIN selected_rust_crates AS container ON container.topology_id=parent.topology_id WHERE parent.blob_id=roots.blob_id AND parent.rel_path=roots.rel_path AND parent.topology_id<>owner.topology_id AND parent.container_path<>'crate' AND container.target_kind='detached'))";
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
pub(crate) const EXPORTS_SQL: &str = include_str!("../rust_reverse_exports.sql");
// A cfg-alternative definition can share one CodeUnit with its active sibling
// while only the sibling has a selected export row. Keep the sibling routes
// available to reverse discovery; forward confirmation checks each candidate.
pub(crate) const SAME_BLOB_TYPE_EXPORTS_SQL: &str = "SELECT exports.topology_id, owner.crate_key, exports.module_path, 'type', exports.name, exports.visibility, 0 FROM rust_crate_exports AS exports INDEXED BY rust_crate_exports_declaration CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=exports.topology_id CROSS JOIN source_native_declaration_bridges AS export_bridge ON export_bridge.blob_id=exports.declaration_blob_id AND export_bridge.source_site=exports.declaration_site CROSS JOIN source_declaration_units AS export_unit ON export_unit.blob_id=export_bridge.blob_id AND export_unit.declaration_id=export_bridge.declaration_id CROSS JOIN source_native_declaration_bridges AS target_bridge ON target_bridge.blob_id=exports.declaration_blob_id AND target_bridge.source_site=?3 CROSS JOIN source_declaration_units AS target_unit ON target_unit.blob_id=target_bridge.blob_id AND target_unit.declaration_id=target_bridge.declaration_id AND target_unit.unit_key=export_unit.unit_key WHERE exports.declaration_blob_id=?1 AND exports.namespace='type' AND exports.name=?2 AND exports.declaration_site<>?3";
pub(crate) const IMPORTS_SQL: &str = "SELECT sources.blob_id, imports.bound_name, CASE WHEN sources.blob_id=imports.blob_id THEN imports.binder_scope END, imports.topology_id, owner.crate_key, imports.module_path FROM rust_crate_imports AS imports INDEXED BY rust_crate_imports_target CROSS JOIN selected_rust_crates AS owner ON owner.topology_id = imports.topology_id CROSS JOIN rust_crate_container_sources AS sources ON sources.topology_id=imports.topology_id AND sources.container_path=imports.module_path WHERE imports.target_crate_key = ?1 AND imports.target_module_path = ?2 AND imports.target_name = ?3";
pub(crate) const GLOBS_SQL: &str = "SELECT sources.blob_id, CASE WHEN sources.blob_id=imports.blob_id THEN imports.binder_scope END, imports.topology_id, owner.crate_key, imports.module_path FROM rust_crate_glob_imports AS imports INDEXED BY rust_crate_glob_imports_target CROSS JOIN selected_rust_crates AS owner ON owner.topology_id = imports.topology_id CROSS JOIN rust_crate_container_sources AS sources ON sources.topology_id=imports.topology_id AND sources.container_path=imports.module_path WHERE imports.target_crate_key = ?1 AND imports.target_module_path = ?2";
pub(crate) const MODULE_SOURCES_SQL: &str = "SELECT candidate.blob_id FROM rust_crate_container_sources AS candidate CROSS JOIN selected_rust_crate_containers AS selected ON selected.topology_id=candidate.topology_id AND selected.container_path=candidate.container_path AND selected.rel_path=candidate.rel_path AND selected.blob_id=candidate.blob_id WHERE candidate.topology_id=?1 AND candidate.container_path=?2";
/// Every selected blob of every crate that compiles one blob.
///
/// A `macro_rules!` macro reaches the rest of its crate by textual scope:
/// `#[macro_use] mod definitions;` and a definition written above `mod child;`
/// both leave it visible in files that neither import nor export it, so no
/// import or export row names those files. The crate's own files are the
/// superset textual scope can reach; forward confirmation decides which
/// definition each invocation's textual scope holds.
pub(crate) const TEXTUAL_MACRO_SOURCES_SQL: &str = "SELECT member.blob_id FROM rust_crate_container_sources AS placement INDEXED BY rust_crate_containers_blob CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=placement.topology_id CROSS JOIN rust_crate_container_sources AS member INDEXED BY rust_crate_containers_path ON member.topology_id=placement.topology_id WHERE placement.blob_id=?1 AND EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS selected INDEXED BY selected_resolution_mounts_blob_ordinal WHERE selected.blob_id=member.blob_id AND selected.storage_language='rust' AND selected.persisted_relative_path=member.rel_path)";
pub(crate) const ROOT_REFERENCES_SQL: &str = "SELECT routes.blob_id, routes.reference_source_site FROM rust_crate_root_references AS routes INDEXED BY rust_crate_root_references_target CROSS JOIN rust_crate_container_sources AS placement ON placement.topology_id=routes.topology_id AND placement.container_path=routes.module_path AND placement.blob_id=routes.blob_id WHERE EXISTS(SELECT 1 FROM selected_rust_crates AS owner WHERE owner.topology_id=routes.topology_id) AND routes.target_crate_key=?1 AND routes.target_module_path=?2 AND routes.target_name=?3 AND EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS selected INDEXED BY selected_resolution_mounts_blob_ordinal WHERE selected.blob_id=routes.blob_id AND selected.storage_language='rust' AND selected.persisted_relative_path=placement.rel_path)";
/// Which selected Rust blobs carry a reference that looks one shared identity
/// up. This is the tier-1 discovery half of every cross-blob reverse question:
/// the blobs it names then answer from their own interiors.
///
/// The caller holds the interned id a shared `SemanticId` carries, which is
/// what the rows hold, so the discovery is one covering seek on the integer
/// and `resolution_identities` is not joined at all.
pub(crate) const REFERENCE_LOOKUP_BLOBS_SQL: &str = "SELECT DISTINCT names.blob_id FROM resolution_reference_lookup_identities AS names INDEXED BY resolution_reference_lookup_identities_identity WHERE names.identity_id=?1 AND EXISTS(SELECT 1 FROM temp.selected_resolution_mounts AS selected INDEXED BY selected_resolution_mounts_blob_ordinal WHERE selected.blob_id=names.blob_id AND selected.storage_language='rust')";
pub(crate) const LOCATORS_SQL: &str = "SELECT mounts.persisted_relative_path FROM temp.selected_resolution_mounts AS mounts INDEXED BY selected_resolution_mounts_blob_ordinal WHERE mounts.blob_id = ?1 AND mounts.storage_language = 'rust'";

pub(crate) const MASKED_BLOB_SQL: &str = "SELECT blob.id FROM temp.selected_resolution_overlay_masks AS mask CROSS JOIN workspace_file_versions AS version ON version.file_version_id=mask.masked_file_version_id CROSS JOIN blobs AS blob ON blob.blob_oid=version.blob_oid AND blob.lang=version.lang AND blob.generation=version.generation WHERE mask.storage_language='rust' AND mask.persisted_relative_path=?1";
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
        let (sql, first, second) = if self.is_overlay_mount(&mount) {
            let target = match self.project_rust_definitions(&[definition], cancellation)? {
                SelectedRustDefinitionProjection::Complete(mut units) => {
                    units.pop().expect("one overlay target")
                }
                _ => return Ok(RustSelectedActivation::Unknown),
            };
            let Some((blob, site)) =
                self.persisted_reverse_target(&mount, &target, cancellation)?
            else {
                return Ok(RustSelectedActivation::Unknown);
            };
            (BASE_TARGET_ACTIVATION_SQL, blob, site)
        } else {
            (
                TARGET_ACTIVATION_SQL,
                i64::from(local.mount().ordinal().get()),
                local.local_key().get(),
            )
        };
        let mut statement = conn.prepare_cached(sql)?;
        let mut activation = RustSelectedActivation::Inactive;
        let mut found = false;
        for row in statement.query_map(params![first, second], |row| {
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
            let Some((blob, target_site)) = (if self.is_overlay_mount(&mount) {
                self.persisted_reverse_target(&mount, target, cancellation)?
            } else {
                Some(conn.prepare_cached(DEFINITION_SITE_SQL)?.query_row(
                    params![local.mount().ordinal().get(), local.local_key().get()],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )?)
            }) else {
                return Ok(RustSelectedActivation::Unknown);
            };
            let alternatives = conn
                .prepare_cached(SAME_BLOB_TYPE_EXPORT_KEYS_SQL)?
                .query_map(params![blob, target.identifier(), target_site], |row| {
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

    pub(crate) fn rust_row_binding_candidates(
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
        let Some(mut locators) =
            self.rust_reverse_candidate_locators_with_names(&unit, extra_names, cancellation)?
        else {
            return Ok(None);
        };
        locators.extend(seeds.iter().cloned());
        locators.sort();
        locators.dedup();
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

    fn is_overlay_mount(&self, mount: &SelectedResolutionOperationMount) -> bool {
        self.ready
            .content_mounts
            .iter()
            .any(|request| request.persisted_relative_path() == mount.persisted_relative_path())
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
        let mut locators = Vec::new();
        for site in self
            .blob_lookup_reference_sites(blob, name, None, cancellation)?
            .into_iter()
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
    fn blob_lookup_reference_sites(
        &self,
        blob: i64,
        name: &str,
        binder_scope: Option<u32>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<ResolutionSiteId>> {
        let lexical = self.ready.lexical_source();
        let binder_scope = binder_scope.map(ResolutionScopeId::new);
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

    /// Candidates are provisional. The caller must forward-confirm each site
    /// and perform the selected operation's final authority check.
    pub(crate) fn rust_reverse_candidate_locators(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedSemanticLocator>>> {
        self.rust_reverse_candidate_locators_with_names(target, &[], cancellation)
    }

    pub(crate) fn rust_reverse_candidate_locators_with_names(
        &self,
        target: &CodeUnit,
        extra_names: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedSemanticLocator>>> {
        let definition = match self.locate_rust_definition(target, cancellation)? {
            SelectedRustDefinitionSemanticOutcome::Found(definition) => definition,
            SelectedRustDefinitionSemanticOutcome::Missing
            | SelectedRustDefinitionSemanticOutcome::Cancelled => return Ok(None),
        };
        let lexical = self.ready.lexical_source();
        let Some(provenance) = lexical.semantic_provenance(definition, cancellation)? else {
            return Ok(None);
        };
        let SelectedSemanticProvenance::FragmentLocal(local) = provenance else {
            return Err(StoreError::new(
                "source definition must have local provenance",
            ));
        };
        let mount = self
            .mount_table()
            .mount_by_ordinal(local.mount().ordinal())?;
        let conn = self.ready.inventory.connection();
        let mut overlay_locators = Vec::new();
        let coordinate = if self.is_overlay_mount(&mount) {
            overlay_locators.extend(self.overlay_reverse_locators(
                &mount,
                target.identifier(),
                cancellation,
            )?);
            self.persisted_reverse_target(&mount, target, cancellation)?
        } else {
            Some(conn.prepare_cached(DEFINITION_SITE_SQL)?.query_row(
                params![local.mount().ordinal().get(), local.local_key().get()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )?)
        };
        let Some((blob, site)) = coordinate else {
            return Ok(Some(overlay_locators));
        };
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
                    .query_map(params![blob, exposed_site], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(6)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        if target.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Class {
            exports.extend(
                conn.prepare_cached(SAME_BLOB_TYPE_EXPORTS_SQL)?
                    .query_map(params![blob, target.identifier(), site], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(6)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        let mut candidates = HashSet::default();
        let mut sources = HashSet::from_iter([(blob, target.identifier().to_owned(), None)]);
        if target.is_macro() {
            for member in conn
                .prepare_cached(TEXTUAL_MACRO_SOURCES_SQL)?
                .query_map([blob], |row| row.get::<_, i64>(0))?
            {
                sources.insert((member?, target.identifier().to_owned(), None));
            }
        }
        let mut names = HashSet::from_iter([target.identifier().to_owned()]);
        // A named import binds the exposure it reaches under a new route: the
        // importing module's own path and the bound name. Descendant modules
        // name the target through that route and nothing else, so the walk
        // treats every import binding as a further exposure and repeats. The
        // export half alone stops at `pub use` chains and misses a private
        // `use` a parent module owns, which is a real Rust route.
        let mut pending = exports;
        let mut reached = pending
            .iter()
            .map(|(_, key, module, name, _)| (key.clone(), module.clone(), name.clone()))
            .collect::<HashSet<_>>();
        while let Some((topology, key, module, name, depth)) = pending.pop() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if depth == 64 {
                return Err(StoreError::new("reverse export route reached depth 64"));
            }
            names.insert(name.clone());
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
                    candidates.insert((route_blob, site));
                    sources.insert((route_blob, extra.clone(), None));
                }
            }
            for row in conn
                .prepare_cached(ROOT_REFERENCES_SQL)?
                .query_map(params![key, module, name], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?))
                })?
            {
                let (route_blob, site) = row?;
                candidates.insert((route_blob, site));
                sources.insert((route_blob, name.clone(), None));
            }
            for row in conn
                .prepare_cached(MODULE_SOURCES_SQL)?
                .query_map(params![topology, module], |row| row.get::<_, i64>(0))?
            {
                sources.insert((row?, name.clone(), None));
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
                sources.insert((source, bound.clone(), scope));
                if reached.insert((key.clone(), module.clone(), bound.clone())) {
                    pending.push((topology, key, module, bound, depth + 1));
                }
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
                sources.insert((blob, name.clone(), scope));
                if reached.insert((glob_key.clone(), glob_module.clone(), name.clone())) {
                    pending.push((
                        glob_topology,
                        glob_key,
                        glob_module,
                        name.clone(),
                        depth + 1,
                    ));
                }
            }
        }
        let additional_sources = sources
            .iter()
            .flat_map(|(blob, _, scope)| {
                extra_names
                    .iter()
                    .map(move |name| (*blob, name.clone(), *scope))
            })
            .collect::<Vec<_>>();
        sources.extend(additional_sources);
        // The owner's exposures above named blobs under the owner's bound
        // names. A member is written under its own name inside those blobs, so
        // each one is scanned for it, unbound: `A: WriterFactory<'a, Writer =
        // String>` spells `Writer` with no binder of its own anywhere.
        if member_of_an_owner {
            let member_sources = sources
                .iter()
                .map(|(blob, _, _)| (*blob, target.identifier().to_owned(), None))
                .collect::<Vec<_>>();
            sources.extend(member_sources);
        }
        names.extend(extra_names.iter().cloned());
        for (blob, name, scope) in sources {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            // A bound name is visible only inside the binder's own scope
            // chain; an unbound one is visible to every lookup in the blob.
            for site in self.blob_lookup_reference_sites(blob, &name, scope, cancellation)? {
                candidates.insert((blob, site.get()));
            }
        }
        // A typed receiver may arrive through a factory, with no owner-type
        // import in its file. Its structured qualified lookup is a separate
        // indexed candidate source; forward confirmation proves its owner.
        let lexical = self.ready.lexical_source();
        for name in &names {
            for namespace in REVERSE_LOOKUP_NAMESPACES {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let symbol = ResolutionLookupSemanticRecipe::new(Language::Rust, namespace, name)
                    .semantic(&self.ready.shared_names());
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
                    let (Some(prefixed), Some(imported), Some(qualified)) = (
                        lexical.prefixed_root_demand_reference_sites(blob, symbol, cancellation)?,
                        lexical.imported_root_demand_reference_sites(blob, symbol, cancellation)?,
                        lexical.qualified_route_reference_sites(blob, symbol, cancellation)?,
                    ) else {
                        return Ok(None);
                    };
                    for site in prefixed.into_iter().chain(imported).chain(qualified) {
                        candidates.insert((blob, site.get()));
                    }
                }
            }
        }
        // Dirty fragments are request inputs, not workspace inventory. Their
        // current references may name a different persisted target even when
        // the base blob had no route to that target at all.
        for request in &self.ready.content_mounts {
            let mount = self
                .mount_table()
                .mount_for_path(
                    request.storage_language(),
                    request.persisted_relative_path(),
                )?
                .expect("selected content mount");
            for name in &names {
                overlay_locators.extend(self.overlay_reverse_locators(
                    &mount,
                    name,
                    cancellation,
                )?);
            }
        }
        let mut observations = Vec::new();
        for &(blob, site) in &candidates {
            let Some(observed) = lexical.type_identity_observation_sites(
                blob,
                ResolutionSiteId::new(site),
                cancellation,
            )?
            else {
                return Ok(None);
            };
            observations.extend(observed.into_iter().map(|site| (blob, site.get())));
        }
        candidates.extend(observations);
        let mut locators = overlay_locators;
        for (blob, site) in candidates {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            for path in conn
                .prepare_cached(LOCATORS_SQL)?
                .query_map([blob], |row| row.get::<_, String>(0))?
            {
                locators.push(SelectedSemanticLocator::new(
                    "rust",
                    path?,
                    ResolutionSiteId::new(site),
                    LoweredSemanticRole::Reference,
                ));
            }
        }
        locators.sort();
        locators.dedup();
        Ok(Some(locators))
    }
}

/// What confirming one candidate blob produced.
pub(crate) enum RustReverseConfirmation {
    /// One answer list per site the confirmation was asked about.
    Confirmed(Vec<Vec<SelectedRustReferenceAnswer>>),
    /// The operation was cancelled.
    Cancelled,
    /// The declared receiver-analysis budget stopped this blob's confirmation
    /// before it reached an answer.
    ///
    /// This is an incompleteness and not a failure: the sites of this blob stay
    /// unproven and are reported as such, and the target's other candidate
    /// blobs keep the answers they already proved. Raising it as an error
    /// discarded 137 other candidate blobs of one tract target and reported an
    /// analysis budget as an internal store error.
    Bounded,
    /// The request's soft time budget stopped confirmation before this blob
    /// could be confirmed across every selected root.
    TimeBudgetExceeded,
}

enum RustContractCompletion {
    Confirmed(Option<ResolutionCompletion>),
    TimeBudgetExceeded,
}

/// Confirm every named site of one caller file in one request. The sites of a
/// candidate blob share everything a point request prepares, so the reverse
/// asks about all of them at once.
type ConfirmReferences<'a> =
    dyn FnMut(&Path, &[&SelectedSemanticLocator]) -> Result<RustReverseConfirmation> + 'a;

#[cfg(test)]
thread_local! {
    static REVERSE_SQL_WORK: RefCell<Option<(usize, usize)>> = const { RefCell::new(None) };
}

#[cfg(test)]
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

#[cfg(test)]
pub(super) fn reverse_sql_work_trace_active() -> bool {
    REVERSE_SQL_WORK.with(|work| work.borrow().is_some())
}

#[cfg(test)]
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

#[cfg(test)]
pub(super) fn detach_reverse_sql_work_trace(connection: &rusqlite::Connection) {
    // SAFETY: this removes the callback installed on this same connection.
    let status = unsafe {
        rusqlite::ffi::sqlite3_trace_v2(connection.handle(), 0, None, std::ptr::null_mut())
    };
    assert_eq!(status, rusqlite::ffi::SQLITE_OK);
}

/// Whether a callable reference's forward confirmation failed to decide what
/// the call names, rather than deciding against the reverse target.
///
/// An empty forward target set disproves a candidate site only when the
/// forward answer is complete. A receiver the route could not type -- a bare
/// generic parameter, an inference failure -- is *more* uncertain than a
/// receiver whose named type simply lacks the member, so its structurally
/// matching site must stay unproven instead of being dropped as a complete
/// negative; dropping it published a false "dead" for the target.
///
/// The receiver origin is what keeps this narrow. Crate-root rows nominate
/// every structured component of a qualified route, and forward confirmation
/// rejects the prefix components with an unowned gap that
/// [`retain_owned_reverse_rejection`] exists to discard. Those components
/// carry no callable receiver origin, so they stay disproved; only a site
/// whose source syntax supplied a receiver -- and whose receiver the route
/// could not resolve -- is retained.
fn undecided_callable_receiver(answer: &FactResolutionAnswer) -> bool {
    answer.callable_receiver_origin().is_some()
        && answer.binding().completion() != &ResolutionCompletion::Complete
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

struct RustReverseQueries<'a, 'store, 'input> {
    selected: &'a SelectedResolutionOperation<'store, 'input>,
    cancellation: &'a CancellationToken,
    admitted: Option<&'a HashSet<ProjectFile>>,
    confirm: &'a mut ConfirmReferences<'a>,
    unavailable: Option<SelectedResolutionUnavailable>,
    #[cfg(test)]
    definition_mounts: HashSet<SelectedResolutionMountOrdinal>,
}

impl RustReverseQueries<'_, '_, '_> {
    /// Close the false external-member boundary on a qualified type path when
    /// its lexical Type prefix is a proven local binding. The prefix proof
    /// must identify that exact binding and its known gaps; unrelated boundary
    /// and gap reasons remain in the reverse inventory.
    fn close_local_type_root_shadow(
        selected: &SelectedResolutionOperation<'_, '_>,
        cancellation: &CancellationToken,
        locator: &SelectedSemanticLocator,
        reference: SemanticId,
        rejected: &ResolutionCompletion,
    ) -> Result<Option<ResolutionCompletion>> {
        let open_surface = ResolutionIncompleteReason::OpenBoundary {
            semantic: reference,
            status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
        };
        let ResolutionCompletion::Incomplete(reasons) = rejected else {
            return Ok(None);
        };
        if !reasons.contains(&open_surface) {
            return Ok(None);
        }
        let Some(ordinal) = reference.ordinal() else {
            return Ok(None);
        };
        let Some(mount) = selected
            .mount_table()
            .mount_for_path(locator.storage_language(), locator.relative_path())?
        else {
            return Ok(None);
        };
        if mount.ordinal().get() != ordinal {
            return Ok(None);
        }
        let source_reference = match selected.ready.lexical_source().lookup_semantic_sites(
            locator,
            cancellation,
            &ResolutionSession::unbounded(),
        )? {
            SelectedSemanticLookupOutcome::Found(sites) => sites
                .into_iter()
                .find(|site| site.semantic() == reference)
                .map(|site| site.node()),
            SelectedSemanticLookupOutcome::Missing | SelectedSemanticLookupOutcome::Cancelled => {
                None
            }
        };
        let Some(source_reference) = source_reference else {
            return Ok(None);
        };
        let scope = RustRootHalfScope::new(
            std::iter::once(&mount),
            std::iter::empty::<&SelectedResolutionOperationMount>(),
        );
        let Some((halves, _)) = selected.rust_root_halves(&scope, cancellation, None)? else {
            return Ok(None);
        };
        let mut matching_halves = Vec::new();
        let mut prefix = None;
        for half in &halves {
            let SelectedRootPathHalf::Reference {
                source_reference: candidate,
                prefix_reference: Some(candidate_prefix),
                anchor: ResolutionRootImportAnchor::Lexical,
                ..
            } = half
            else {
                continue;
            };
            if *candidate != source_reference {
                continue;
            }
            if prefix.is_some_and(|prefix| prefix != *candidate_prefix) {
                return Ok(None);
            }
            prefix = Some(*candidate_prefix);
            matching_halves.push(half.clone());
        }
        let Some(prefix) = prefix else {
            return Ok(None);
        };
        let contexts = selected.empty_contexts(&ResolutionCompletion::Complete)?;
        let Some(resolutions) =
            selected.resolve_rust_prefixes_preliminary(contexts, &matching_halves, cancellation)?
        else {
            return Ok(None);
        };
        let Some((_, resolved)) = resolutions
            .iter()
            .find(|(reference, _)| *reference == prefix)
        else {
            return Ok(None);
        };
        let decided = super::rust_crate_context::block_local_type_prefix_binding_is_decided(
            &selected.ready,
            &resolved.targets,
            &resolved.completion,
        )?;
        if !decided {
            return Ok(None);
        }
        let ResolutionCompletion::Incomplete(prefix_reasons) = &resolved.completion else {
            return Ok(None);
        };
        let removals = std::iter::once(open_surface)
            .chain(
                prefix_reasons
                    .iter()
                    .filter(|reason| reasons.contains(reason))
                    .copied(),
            )
            .collect::<Vec<_>>();
        Ok(Some(reasons.without_reasons(removals).map_or(
            ResolutionCompletion::Complete,
            ResolutionCompletion::Incomplete,
        )))
    }

    /// Confirm every candidate site of one file. The sites share the file's
    /// crate roots, so the whole group is one point request per root instead
    /// of one per site.
    fn confirm_locators(
        selected: &SelectedResolutionOperation<'_, '_>,
        cancellation: &CancellationToken,
        confirm: &mut ConfirmReferences<'_>,
        locators: &[&SelectedSemanticLocator],
        evaluations: &mut usize,
    ) -> Result<RustReverseConfirmation> {
        let Some(first) = locators.first() else {
            return Ok(RustReverseConfirmation::Confirmed(Vec::new()));
        };
        assert!(
            locators
                .iter()
                .all(|locator| locator.relative_path() == first.relative_path()),
            "one confirmation group is one candidate blob: {locators:?}"
        );
        let roots = selected
            .ready
            .inventory
            .connection()
            .prepare_cached(CALLER_ROOTS_SQL)?
            .query_map([first.relative_path()], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if roots.is_empty() {
            return Err(StoreError::new(format!(
                "reverse reference has no selected crate root: {first:?}"
            )));
        }
        let mut answers = std::iter::repeat_with(Vec::new)
            .take(locators.len())
            .collect::<Vec<Vec<SelectedRustReferenceAnswer>>>();
        for root in roots {
            if cancellation.is_cancelled() {
                return Ok(RustReverseConfirmation::Cancelled);
            }
            if cancellation.soft_deadline_passed() {
                return Ok(RustReverseConfirmation::TimeBudgetExceeded);
            }
            *evaluations += 1;
            let found = match confirm(Path::new(&root), locators)? {
                RustReverseConfirmation::Confirmed(found) => found,
                outcome @ (RustReverseConfirmation::Cancelled
                | RustReverseConfirmation::Bounded
                | RustReverseConfirmation::TimeBudgetExceeded) => return Ok(outcome),
            };
            assert_eq!(
                found.len(),
                locators.len(),
                "a confirmation answers every site it was asked about"
            );
            for (site, found) in answers.iter_mut().zip(found) {
                site.extend(found);
            }
        }
        // The point projection supplies exact source units. Every one must
        // locate in this reader before cross-reader target evidence is used
        // for implementation/trait-contract discovery. The sites of one blob
        // name few distinct units, usually in one file, so they are located
        // together: one crosswalk read per mount rather than one per site.
        let units = answers
            .iter()
            .flatten()
            .flat_map(|answer| &answer.definitions)
            .collect::<HashSet<_>>();
        if !selected.all_rust_definitions_located(&units, cancellation)? {
            return Ok(RustReverseConfirmation::Cancelled);
        }
        Ok(RustReverseConfirmation::Confirmed(answers))
    }

    /// A concrete implementation is an inverse usage of its trait contract.
    /// Confirm the implementation's declared trait reference through the same
    /// point entry; a matching spelling alone cannot establish this relation.
    fn contract_completion(
        selected: &SelectedResolutionOperation<'_, '_>,
        cancellation: &CancellationToken,
        confirm: &mut ConfirmReferences<'_>,
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
            let confirmation = Self::confirm_locators(
                selected,
                cancellation,
                confirm,
                &[&reference],
                evaluations,
            )?;
            let mut answers = match confirmation {
                RustReverseConfirmation::Confirmed(answers) => answers,
                RustReverseConfirmation::TimeBudgetExceeded => {
                    return Ok(RustContractCompletion::TimeBudgetExceeded);
                }
                RustReverseConfirmation::Cancelled | RustReverseConfirmation::Bounded => {
                    return Ok(RustContractCompletion::Confirmed(None));
                }
            };
            for answer in answers.remove(0) {
                let answer = answer.resolution;
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

impl SelectedRustReverseQueries for RustReverseQueries<'_, '_, '_> {
    fn candidate_files(&mut self, targets: &[CodeUnit]) -> Result<Option<HashSet<ProjectFile>>> {
        let mut files = HashSet::default();
        for target in targets {
            let Some(locators) = self
                .selected
                .rust_reverse_candidate_locators(target, self.cancellation)?
            else {
                return Ok(None);
            };
            // The defining blob can carry an enumeration gap even when it
            // has no reference sites (for example a missing include source).
            files.insert(target.source().clone());
            for locator in locators {
                files.insert(ProjectFile::new(
                    self.selected.ready.project.root(),
                    locator.relative_path(),
                ));
            }
        }
        Ok(Some(files))
    }
    fn references_to(&mut self, targets: &[CodeUnit]) -> Result<SelectedRustReverseBatchOutcome> {
        use crate::analyzer::resolution::{
            FactReverseReferenceBinding, MAX_REVERSE_TARGETS_PER_BATCH,
        };
        assert!(targets.len() <= MAX_REVERSE_TARGETS_PER_BATCH);
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
        for target in targets {
            let Some(mut locators) = self
                .selected
                .rust_reverse_candidate_locators(target, self.cancellation)?
            else {
                if self.cancellation.is_cancelled() {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                }
                let reason = SelectedResolutionUnavailable::MissingDefinitionUnit {
                    storage_language: "rust".into(),
                    persisted_relative_path: crate::path_utils::rel_path_string(target.source()),
                };
                self.unavailable = Some(reason.clone());
                return Ok(SelectedRustReverseBatchOutcome::Unavailable(reason));
            };
            let SelectedRustDefinitionSemanticOutcome::Found(definition) = self
                .selected
                .locate_rust_definition(target, self.cancellation)?
            else {
                return Ok(SelectedRustReverseBatchOutcome::Cancelled);
            };
            #[cfg(test)]
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
                None => {
                    let mut files = locators
                        .iter()
                        .map(|locator| {
                            ProjectFile::new(
                                self.selected.ready.project.root(),
                                locator.relative_path(),
                            )
                        })
                        .collect::<HashSet<_>>();
                    files.insert(target.source().clone());
                    files
                }
            };
            let lexical = self.selected.ready.lexical_source();
            let mut references = Vec::new();
            let mut witnesses = Vec::new();
            let mut bindings = Vec::new();
            let mut inventory = ResolutionCompletionAccumulator::default();
            let mut confirmed_enumeration = HashMap::default();
            match self
                .selected
                .reverse_target_activation(definition, target, self.cancellation)?
            {
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Active => {}
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Inactive => {
                    locators.clear()
                }
                brokk_bifrost_rust::selected_context::RustSelectedActivation::Unknown => {
                    locators.clear();
                    inventory.include(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(definition),
                    ]));
                }
            }

            let mut examined = HashSet::default();
            let mut candidate_count = 0;
            let mut evaluation_count = 0;
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
            for locator in locators {
                if self.cancellation.is_cancelled() {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                }
                let file =
                    ProjectFile::new(self.selected.ready.project.root(), locator.relative_path());
                if self.admitted.is_some_and(|files| !files.contains(&file)) {
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
                        continue;
                    }
                    speculative_field = !primary;
                }
                let LocatedSemantic::Found(reference) =
                    self.selected
                        .ready
                        .lookup_locator(&lexical, &locator, self.cancellation)?
                else {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
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
            let mut confirmed = Vec::with_capacity(admitted_sites.len());
            let mut confirmed_site_count = 0;
            let mut time_budget_exceeded = false;
            let mut blob_start = 0;
            while blob_start < admitted_sites.len() {
                if self.cancellation.is_cancelled() {
                    return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                }
                if self.cancellation.soft_deadline_passed() {
                    inventory.include(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::TimeBudgetExceeded(definition),
                    ]));
                    time_budget_exceeded = true;
                    break;
                }
                let path = admitted_sites[blob_start].0.relative_path().to_owned();
                let mut blob_end = blob_start;
                while blob_end < admitted_sites.len()
                    && admitted_sites[blob_end].0.relative_path() == path
                {
                    blob_end += 1;
                }
                let group = admitted_sites[blob_start..blob_end]
                    .iter()
                    .map(|(locator, _)| locator)
                    .collect::<Vec<_>>();
                match Self::confirm_locators(
                    self.selected,
                    self.cancellation,
                    self.confirm,
                    &group,
                    &mut evaluation_count,
                )? {
                    RustReverseConfirmation::Confirmed(answers) => {
                        confirmed_site_count += answers.len();
                        confirmed.extend(answers);
                    }
                    RustReverseConfirmation::Cancelled => {
                        return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                    }
                    // The declared budget stopped this blob. Its sites stay
                    // unproven and say so; the target keeps every other blob's
                    // proved answers instead of losing the whole scan.
                    RustReverseConfirmation::Bounded => {
                        inventory.include(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::ReceiverBudgetExhausted(definition),
                        ]));
                        confirmed_site_count += group.len();
                        confirmed.extend(std::iter::repeat_with(Vec::new).take(group.len()));
                    }
                    RustReverseConfirmation::TimeBudgetExceeded => {
                        inventory.include(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::TimeBudgetExceeded(definition),
                        ]));
                        time_budget_exceeded = true;
                        break;
                    }
                }
                blob_start = blob_end;
            }
            assert_eq!(confirmed.len(), confirmed_site_count);
            assert!(confirmed_site_count <= admitted_sites.len());
            let mut contract_time_budget_exceeded = time_budget_exceeded;
            for ((locator, reference), answers) in admitted_sites
                .into_iter()
                .zip(confirmed)
                .take(confirmed_site_count)
            {
                let mut forward_targets = BTreeSet::new();
                let mut forward_completion = ResolutionCompletionAccumulator::default();
                let mut rejected_completion = ResolutionCompletionAccumulator::default();
                let mut bound = false;
                let mut binding = None;
                for answer in answers {
                    brokk_bifrost_core::profiling::note_with(|| {
                        format!(
                            "rust reverse confirmation: locator={locator:?}, definitions={:?}, binding={:?}, enumeration={:?}, inventory_details={:?}",
                            answer.definitions,
                            answer.resolution.binding(),
                            answer.enumeration,
                            answer.inventory_details
                        )
                    });
                    if let Some((file, completion)) = answer.enumeration {
                        confirmed_enumeration
                            .entry(file)
                            .or_insert_with(ResolutionCompletionAccumulator::default)
                            .include(&completion);
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
                        && answer.definition_names.len()
                            == answer.resolution.binding().targets().len();
                    // Two cfg alternatives of one type alias are one CodeUnit,
                    // so a site bound to the active sibling binds the target.
                    let binds_target_type_unit = every_target_is_this_unit
                        && target.kind()
                            == brokk_bifrost_core::analyzer::model::CodeUnitType::Class;
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
                    answer_completion.include(if block_local {
                        &ResolutionCompletion::Complete
                    } else {
                        answer.binding().completion()
                    });
                    witnesses.extend(
                        answer
                            .binding()
                            .witnesses()
                            .iter()
                            .filter(|witness| witness.target() == definition)
                            .cloned(),
                    );
                    let candidate_binding =
                        FactReverseReferenceBinding::from_forward(reference, &answer);
                    if answer.binding().targets().contains(&definition) || binds_target_type_unit {
                        answer_bound = true;
                        binding = Some(candidate_binding);
                    } else if answer.binding().targets().is_empty()
                        && (candidate_binding.type_bound_receiver()
                            || undecided_callable_receiver(&answer))
                    {
                        let completion = candidate_binding.completion().combine(
                            &ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(definition),
                            ]),
                        );
                        answer_completion.include(&completion);
                        witnesses.push(crate::analyzer::resolution::ResolutionWitness::new(
                            reference,
                            definition,
                            Vec::new(),
                            completion,
                        ));
                        answer_bound = true;
                        binding = Some(candidate_binding);
                    } else {
                        for &implementation in answer.binding().targets() {
                            if contract_time_budget_exceeded {
                                continue;
                            }
                            match Self::contract_completion(
                                self.selected,
                                self.cancellation,
                                self.confirm,
                                definition,
                                implementation,
                                &mut evaluation_count,
                            )? {
                                RustContractCompletion::TimeBudgetExceeded => {
                                    contract_time_budget_exceeded = true;
                                    time_budget_exceeded = true;
                                    inventory.include(&ResolutionCompletion::incomplete([
                                        ResolutionIncompleteReason::TimeBudgetExceeded(definition),
                                    ]));
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
                                        steps
                                        .push(crate::analyzer::resolution::WitnessStep::Candidate {
                                        semantic: definition,
                                        outcome:
                                            crate::analyzer::structural::CandidateOutcome::Selected,
                                    });
                                        witnesses.push(
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
                    // Publish the evidence of the views that bound the
                    // definition, and only those. A view that did not bind it
                    // is another Cargo target's compilation of the same file;
                    // its targets are not alternatives to this one and its
                    // doubt is not doubt about this one. The first binding view
                    // discards whatever earlier non-binding views accumulated.
                    if answer_bound {
                        if !bound {
                            bound = true;
                            forward_targets.clear();
                            forward_completion = ResolutionCompletionAccumulator::default();
                        }
                        forward_targets.extend(answer_targets);
                        forward_completion.include(&answer_completion.finish());
                    } else if !bound {
                        let mut completion = answer_completion.finish();
                        if wrong_target_workspace_dependency(
                            self.selected,
                            &locator,
                            reference,
                            &answer,
                            self.cancellation,
                        )? {
                            completion = ResolutionCompletion::Complete;
                        }
                        forward_targets.extend(answer_targets);
                        forward_completion.include(&completion);
                        rejected_completion.include(&completion);
                    }
                }
                if binding.is_none() {
                    // Crate-root rows nominate every structured component of a
                    // qualified route. Forward confirmation rejects prefix
                    // components. An unowned gap from that negative point has
                    // no producer row capable of weakening the complete
                    // target-index relation; retain only source-owned gaps.
                    let mut rejected =
                        retain_owned_reverse_rejection(self.selected, rejected_completion.finish());
                    if let Some(closed) = Self::close_local_type_root_shadow(
                        self.selected,
                        self.cancellation,
                        &locator,
                        reference,
                        &rejected,
                    )? {
                        rejected = closed;
                    } else if self.cancellation.is_cancelled() {
                        return Ok(SelectedRustReverseBatchOutcome::Cancelled);
                    }
                    let open_surface = ResolutionIncompleteReason::OpenBoundary {
                        semantic: reference,
                        status:
                            crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                    };
                    if let ResolutionCompletion::Incomplete(reasons) = &rejected
                        && reasons.contains(&open_surface)
                        && member_owner_unnameable_at(
                            self.selected,
                            definition,
                            reference,
                            self.cancellation,
                        )?
                    {
                        rejected = reasons.without_reasons([open_surface]).map_or(
                            ResolutionCompletion::Complete,
                            ResolutionCompletion::Incomplete,
                        );
                    }
                    inventory.include(&rejected);
                    continue;
                }
                if let Some(binding) = binding {
                    // Preserve alternate forward targets and their completion;
                    // querying one overload must never erase ambiguity.
                    bindings.push(binding.with_alternatives(
                        forward_targets.into_iter().collect(),
                        forward_completion.finish(),
                    ));
                    references.push(reference);
                }
            }
            if time_budget_exceeded {
                // The already confirmed blobs may have supplied useful
                // enumeration completions. Keep those facts while skipping
                // the per-file completion reads that remain after the stop.
                for completion in confirmed_enumeration.into_values() {
                    inventory.include(&completion.finish());
                }
            } else {
                for file in &inventory_files {
                    if let Some(completion) = confirmed_enumeration.remove(file) {
                        inventory.include(&completion.finish());
                        continue;
                    }
                    let relative_path = crate::path_utils::rel_path_string(file);
                    if let Some(mount) = self
                        .selected
                        .mount_table()
                        .mount_for_path("rust", &relative_path)?
                    {
                        let completion = lexical.reference_inventory_completion(
                            mount.fragment(),
                            self.cancellation,
                            &ResolutionSession::unbounded(),
                        )?;
                        let completion =
                            match lexical.close_completion(&completion, self.cancellation)? {
                                Some(completion) => completion,
                                None => completion.combine(&cancelled_completion()),
                            };
                        inventory.include(&completion);
                    }
                }
            }
            let answer = ReferenceSearchAnswer::new(references, witnesses, inventory.finish());
            let observed_lexical = SeamProfiled::observing(&lexical);
            let Some(mut source_sites) = selected_reference_source_sites(
                &observed_lexical,
                self.selected.mount_table(),
                self.selected.ready.project.root(),
                &answer,
                self.cancellation,
            )?
            else {
                return Ok(SelectedRustReverseBatchOutcome::Cancelled);
            };
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

    fn resolve_references(
        &mut self,
        references: &[SemanticId],
    ) -> Result<Option<Vec<FactResolutionAnswer>>> {
        let lexical = self.selected.ready.lexical_source();
        let search = ReferenceSearchAnswer::new(
            references.to_vec(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let observed_lexical = SeamProfiled::observing(&lexical);
        let Some(sites) = selected_reference_source_sites(
            &observed_lexical,
            self.selected.mount_table(),
            self.selected.ready.project.root(),
            &search,
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        let mut answers = Vec::new();
        for site in sites {
            let metadata = site
                .metadata
                .ok_or_else(|| StoreError::new("reverse reference metadata is unavailable"))?;
            let locator = SelectedSemanticLocator::new(
                "rust",
                crate::path_utils::rel_path_string(&site.file),
                metadata.site(),
                LoweredSemanticRole::Reference,
            );
            let RustReverseConfirmation::Confirmed(mut confirmed) = Self::confirm_locators(
                self.selected,
                self.cancellation,
                self.confirm,
                &[&locator],
                &mut 0,
            )?
            else {
                return Ok(None);
            };
            answers.extend(
                confirmed
                    .remove(0)
                    .into_iter()
                    .map(|answer| answer.resolution),
            );
        }
        Ok(Some(answers))
    }

    #[cfg(test)]
    fn definition_mount_read_count(&self) -> usize {
        self.definition_mounts.len()
    }

    #[cfg(test)]
    fn begin_sql_work_trace(&self) {
        REVERSE_SQL_WORK.with(|work| {
            assert!(work.borrow().is_none(), "reverse SQL trace cannot nest");
            work.replace(Some((0, 0)));
        });
        attach_reverse_sql_work_trace(self.selected.ready.inventory.connection());
    }

    #[cfg(test)]
    fn finish_sql_work_trace(&self) -> (usize, usize) {
        detach_reverse_sql_work_trace(self.selected.ready.inventory.connection());
        REVERSE_SQL_WORK.with(|work| {
            work.borrow_mut()
                .take()
                .expect("reverse SQL trace must be active")
        })
    }
}

impl SelectedResolutionOperation<'_, '_> {
    pub(crate) fn with_rust_row_reverse_queries<'a, T>(
        mut self,
        admitted: Option<&'a HashSet<ProjectFile>>,
        cancellation: &'a CancellationToken,
        mut confirm: impl FnMut(&Path, &[&SelectedSemanticLocator]) -> Result<RustReverseConfirmation>,
        run: impl FnOnce(&mut dyn SelectedRustReverseQueries) -> Result<T>,
    ) -> Result<SelectedResolutionOperationOutcome<T>> {
        let mut queries = RustReverseQueries {
            selected: &self,
            cancellation,
            admitted,
            confirm: &mut confirm,
            unavailable: None,
            #[cfg(test)]
            definition_mounts: HashSet::default(),
        };
        let result = run(&mut queries)?;
        debug_assert!(
            self.ready.rust_caller_context.borrow().is_none()
                && self.ready.rust_caller_demand.borrow().is_none(),
            "row discovery must not construct or retain a profile context"
        );
        if let Some(reason) = queries.unavailable {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
        }
        self.ready
            .finish(result, &ResolutionCompletion::Complete, cancellation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnalyzerConfig;
    use crate::analyzer::store::planner_statistics::pinned_plans::{
        explain_pin, pinned, prepare_pin_context,
    };
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::types::Value;

    #[test]
    fn reverse_detached_root_confirms_named_import_calls() {
        use crate::analyzer::CodeUnitIndex;
        use crate::analyzer::rust::RustAnalyzer;
        use crate::analyzer::rust::selected_reverse::{
            RustSelectedReverseOutcome, with_rust_selected_reverse_queries,
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub mod target; pub mod caller;")
            .file("src/target.rs", "pub fn collect_it() -> i32 { 1 }")
            .file(
                "src/caller.rs",
                "use crate::target::collect_it; pub fn call_it() -> i32 { collect_it() }",
            )
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let rust = crate::analyzer::resolve_analyzer::<RustAnalyzer>(analyzer.analyzer()).unwrap();
        let target = rust
            .declarations(&fixture.file("src/target.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "collect_it")
            .unwrap();
        let result =
            with_rust_selected_reverse_queries(rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[target])
            });
        assert!(
            matches!(result, RustSelectedReverseOutcome::Ready(Some(ref rows)) if rows[0].edges.len()==2),
            "{result:?}"
        );
    }

    #[test]
    fn reverse_import_binder_scope_reaches_plain_value_reads() {
        use crate::analyzer::CodeUnitIndex;
        use crate::analyzer::rust::RustAnalyzer;
        use crate::analyzer::rust::selected_reverse::{
            RustSelectedReverseOutcome, with_rust_selected_reverse_queries,
        };
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname='demo'\nversion='0.1.0'\n")
            .file(
                "src/lib.rs",
                "pub mod outer { #[path=\"mapped.rs\"] pub mod mapped; pub mod consumer; }",
            )
            .file("src/outer/mapped.rs", "pub const VALUE: usize = 1;")
            .file(
                "src/outer/consumer.rs",
                "use super::mapped::VALUE; fn valid() { let _ = VALUE; }",
            )
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let rust = crate::analyzer::resolve_analyzer::<RustAnalyzer>(analyzer.analyzer()).unwrap();
        let target = rust
            .declarations(&fixture.file("src/outer/mapped.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "VALUE")
            .unwrap();
        let result =
            with_rust_selected_reverse_queries(rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[target])
            });
        assert!(
            matches!(result,RustSelectedReverseOutcome::Ready(Some(ref rows)) if rows[0].edges.len()==2),
            "{result:?}"
        );
    }

    #[test]
    fn reverse_root_candidates_ignore_unrelated_same_named_references() {
        let mut measurements = Vec::new();
        for unrelated in [0, 32] {
            let mut builder = InlineTestProject::new().file(
                "Cargo.toml",
                "[package]\nname='root_reference_pin'\nversion='0.1.0'\nedition='2021'\n",
            );
            // Keep a fixed later key in the same root/name index range so both
            // fixtures execute a range boundary check rather than one ending
            // at B-tree EOF (which omits two VM instructions).
            let mut source = "pub fn target() {} pub fn z_after() {} pub fn caller() { crate::target(); crate::z_after(); }\n".to_owned();
            for index in 0..unrelated {
                source.push_str(&format!("pub mod decoy{index};\n"));
                builder = builder.file(
                    format!("src/decoy{index}.rs"),
                    format!(
                        "pub fn target() {{}} pub fn caller() {{ crate::decoy{index}::target(); }}"
                    ),
                ).file(format!("isolated/decoy{index}.rs"), "pub fn target() {} pub fn caller() { crate::target(); }");
            }
            let fixture = builder.file("src/lib.rs", source).build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.conn.lock().unwrap();
            crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
            conn.execute("DELETE FROM selected_workspace_revisions", [])
                .unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            prepare_pin_context(&conn);
            conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) SELECT row_number() OVER(),blob_id,'rust',rel_path FROM (SELECT DISTINCT blob_id,rel_path FROM rust_crate_container_sources)", []).unwrap();
            for state in PlannerStatisticsState::BOTH {
                state.install(&conn);
                let key: Vec<u8> = conn
                    .query_row(
                        "SELECT crate_key FROM selected_rust_crates WHERE target_kind='lib'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let mut statement = conn.prepare(ROOT_REFERENCES_SQL).unwrap();
                let rows = statement
                    .query_map(params![key, "crate", "target"], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    rows.len(),
                    1,
                    "only the selected crate route can name this definition: {rows:?}"
                );
                measurements.push((
                    unrelated,
                    state,
                    rows.len(),
                    statement.get_status(rusqlite::StatementStatus::VmStep),
                ));
            }
        }
        eprintln!("same-name different-route candidate reads: {measurements:?}");
        for index in 0..2 {
            assert_eq!(
                measurements[index].2,
                measurements[index + 2].2,
                "different module routes cannot grow this definition's candidates: {measurements:?}"
            );
            assert_eq!(
                measurements[index].3,
                measurements[index + 2].3,
                "different module routes cannot grow this definition's query work: {measurements:?}"
            );
        }
    }

    #[test]
    fn reverse_root_name_work_ignores_unrelated_same_named_definitions() {
        let mut measurements = Vec::new();
        for unrelated in [0, 32] {
            let mut builder = InlineTestProject::new().file(
                "Cargo.toml",
                "[package]\nname='root_pin'\nversion='0.1.0'\nedition='2021'\n",
            );
            let mut source = "pub fn target() {} pub fn caller() { crate::target(); }\n".to_owned();
            for index in 0..unrelated {
                source.push_str(&format!("pub mod decoy{index};\n"));
                builder = builder.file(
                    format!("src/decoy{index}.rs"),
                    format!("pub fn target() {{}} // {index}"),
                );
            }
            let fixture = builder.file("src/lib.rs", source).build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.conn.lock().unwrap();
            crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
            conn.execute("DELETE FROM selected_workspace_revisions", [])
                .unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            prepare_pin_context(&conn);
            conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) SELECT row_number() OVER(),blob_id,'rust',rel_path FROM (SELECT DISTINCT blob_id,rel_path FROM rust_crate_container_sources)", []).unwrap();
            for state in PlannerStatisticsState::BOTH {
                state.install(&conn);
                let key: Vec<u8> = conn
                    .query_row(
                        "SELECT crate_key FROM selected_rust_crates WHERE target_kind='lib'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let mut statement = conn.prepare(ROOT_REFERENCES_SQL).unwrap();
                let rows = statement
                    .query_map(params![key, "crate", "target"], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    rows.len(),
                    1,
                    "one rooted call, no decoy references: {rows:?}"
                );
                measurements.push((
                    unrelated,
                    state,
                    statement.get_status(rusqlite::StatementStatus::VmStep),
                ));
            }
        }
        eprintln!("root candidate name VM steps: {measurements:?}");
        for index in 0..2 {
            assert_eq!(
                measurements[index].2,
                measurements[index + 2].2,
                "unrelated declarations are not candidate reads: {measurements:?}"
            );
        }
    }

    /// The tier-1 root-route family is what build-time crate derivation reads
    /// instead of joining path bodies, reference sites and recipes across the
    /// member blobs of a crate. What it must hold is that each route is one
    /// contiguous run of segment rows closed by exactly one terminal row, that
    /// the terminal row names a reference site of the same blob, and that the
    /// whole family follows the fragment out of the store.
    #[test]
    fn root_route_rows_describe_their_routes_and_follow_fragment_deletion() {
        let source = "pub mod api { pub fn target() {} } pub fn caller() { crate::api::target(); } fn typed(_: external::Shared) {}";
        let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        let root_start = source.find("external::Shared").unwrap() + "external::".len();
        let root_end = root_start + "Shared".len();
        let published_reference_identity: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1
                   FROM rust_crate_container_sources AS source
                   JOIN resolution_sites AS site ON site.blob_id=source.blob_id
                   JOIN resolution_semantic_sites AS site_semantic
                     ON site_semantic.blob_id=site.blob_id AND site_semantic.source_site=site.site
                    AND site_semantic.semantic_role='reference'
                   JOIN resolution_reference_lookup_identities AS reference
                     ON reference.blob_id=site_semantic.blob_id
                    AND reference.semantic_key=site_semantic.semantic_key
                   JOIN resolution_identities AS identity ON identity.id=reference.identity_id
                   WHERE source.rel_path='src/lib.rs' AND site.role=0
                     AND site.start_byte=?1 AND site.end_byte=?2
                     AND identity.spelling='external'
                 )",
                params![
                    i64::try_from(root_start).unwrap(),
                    i64::try_from(root_end).unwrap()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            published_reference_identity,
            "a qualified terminal reference has its first route segment's lookup identity"
        );
        let blob: i64 = conn
            .query_row(
                "SELECT blob_id FROM resolution_root_route_segments LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let malformed: Vec<(i64, i64, i64, i64, i64)> = conn
            .prepare(
                "SELECT blob_id, path_key, COUNT(*),
                        SUM(terminal_spelling IS NOT NULL), MAX(position)
                 FROM resolution_root_route_segments
                 GROUP BY blob_id, path_key
                 HAVING SUM(terminal_spelling IS NOT NULL) <> 1
                     OR MAX(position) <> COUNT(*) - 1
                     OR SUM(CASE WHEN terminal_spelling IS NOT NULL THEN position END)
                        <> COUNT(*) - 1",
            )
            .unwrap()
            .query_map([], |row| {
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
            .unwrap();
        assert!(
            malformed.is_empty(),
            "each root route is a contiguous run closed by one terminal row: {malformed:?}"
        );
        let unsited: Vec<(i64, i64)> = conn
            .prepare(
                "SELECT route.blob_id, route.path_key
                 FROM resolution_root_route_segments AS route
                 WHERE route.terminal_spelling IS NOT NULL
                   AND NOT EXISTS(
                       SELECT 1 FROM resolution_semantic_sites AS site
                       WHERE site.blob_id = route.blob_id
                         AND site.source_site = route.reference_source_site
                         AND site.semantic_role = 'reference')",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            unsited.is_empty(),
            "every root route names a reference site of its own blob: {unsited:?}"
        );
        conn.execute_batch("SAVEPOINT root_routes").unwrap();
        conn.execute(
            "DELETE FROM resolution_fragment_interiors WHERE blob_id=?1",
            [blob],
        )
        .unwrap();
        for table in [
            "resolution_root_route_segments",
            "resolution_reference_lookup_identities",
        ] {
            assert_eq!(
                conn.query_row(
                    &format!("SELECT count(*) FROM {table} WHERE blob_id=?1"),
                    [blob],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                0,
                "{table} must follow its fragment out of the store"
            );
        }
        conn.execute_batch("ROLLBACK TO root_routes; RELEASE root_routes")
            .unwrap();
    }

    #[test]
    fn reverse_rows_export_and_import_work_is_independent_of_unrelated_inventory() {
        let mut measurements = Vec::new();
        for unrelated in [0, 32] {
            let mut builder = InlineTestProject::new()
                .file("Cargo.toml", "[workspace]\nmembers=['api','barrel','client']\nresolver='2'\n")
                .file("api/Cargo.toml", "[package]\nname='api'\nversion='0.1.0'\nedition='2021'\n")
                .file("barrel/Cargo.toml", "[package]\nname='barrel'\nversion='0.1.0'\nedition='2021'\n[dependencies]\napi={path='../api'}\n")
                .file("client/Cargo.toml", "[package]\nname='client'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nbarrel={path='../barrel'}\n")
                .file("barrel/src/lib.rs", "pub use api::target as renamed; pub use api::*;\n")
                .file("client/src/lib.rs", "use barrel::renamed as local; pub fn caller() { local(); }\n");
            let mut api = "pub fn target() {}\n".to_owned();
            for index in 0..unrelated {
                api.push_str(&format!("pub mod decoy{index};\n"));
                builder = builder.file(
                    format!("api/src/decoy{index}.rs"),
                    format!("pub fn other{index}() {{}}\n"),
                );
            }
            let fixture = builder.file("api/src/lib.rs", api).build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.conn.lock().unwrap();
            crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
            conn.execute("DELETE FROM selected_workspace_revisions", [])
                .unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            prepare_pin_context(&conn);
            conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,producer_epoch,interior_digest,persisted_relative_path) SELECT row_number() OVER(), member.blob_id, 'rust', interior.semantic_language, interior.producer_epoch, interior.interior_digest, member.rel_path FROM (SELECT DISTINCT blob_id,rel_path FROM selected_rust_crate_containers) AS member JOIN resolution_fragment_interiors AS interior USING(blob_id)", []).unwrap();

            let (blob, site): (i64, i64) = conn.query_row("SELECT declaration_blob_id,declaration_site FROM rust_crate_exports e JOIN rust_crate_topologies t USING(topology_id) WHERE t.crate_name='api' AND e.name='target'", [], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
            let (topology, key): (i64, Vec<u8>) = conn.query_row("SELECT topology_id,crate_key FROM selected_rust_crates WHERE crate_name='barrel'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
            let client_blob: i64 = conn.query_row("SELECT blob_id FROM selected_rust_crate_containers WHERE rel_path='client/src/lib.rs'", [], |row| row.get(0)).unwrap();
            let oracle = conn.prepare("SELECT topology_id,module_path,namespace,name FROM rust_crate_exports_reachable WHERE declaration_blob_id=?1 AND declaration_site=?2 ORDER BY 1,2,3,4").unwrap().query_map(params![blob, site], |row| Ok((row.get::<_, i64>(0)?,row.get::<_, String>(1)?,row.get::<_, String>(2)?,row.get::<_, String>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(oracle.len(), 3, "{oracle:?}");
            for state in PlannerStatisticsState::BOTH {
                state.install(&conn);
                let mut export_pin = pinned("rust_reverse_exports");
                export_pin.params = vec![Value::Integer(blob), Value::Integer(site)];
                let mut statement = conn.prepare(&export_pin.sql).unwrap();
                let mut rows = statement
                    .query_map(params![blob, site], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                rows.sort();
                rows.dedup();
                assert_eq!(rows, oracle, "{state:?}");
                let export_work = statement.get_status(rusqlite::StatementStatus::VmStep);
                let mut import_pin = pinned("rust_reverse_imports");
                import_pin.params = vec![
                    Value::Blob(key.clone()),
                    Value::Text("crate".into()),
                    Value::Text("renamed".into()),
                ];
                let mut imports = conn.prepare(&import_pin.sql).unwrap();
                let bindings = imports
                    .query_map(params![key, "crate", "renamed"], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(bindings, [(client_blob, "local".into())]);
                let import_work = imports.get_status(rusqlite::StatementStatus::VmStep);
                measurements.push((unrelated, state, export_work, import_work));
                let cases = [
                    (
                        {
                            let mut p = pinned("rust_reverse_definition_blob");
                            p.params = vec![Value::Integer(0)];
                            p
                        },
                        "SEARCH mount USING PRIMARY KEY",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_definition_semantics");
                            p.params = vec![Value::Integer(blob)];
                            p
                        },
                        "SEARCH crosswalk USING",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_masked_blob");
                            p.params = vec![Value::Text("client/src/lib.rs".into())];
                            p
                        },
                        "SEARCH mask USING PRIMARY KEY",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_blob_definition_site");
                            p.params = vec![Value::Integer(blob), Value::Integer(0)];
                            p
                        },
                        "SEARCH resolution_semantic_sites USING",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_base_target_activation");
                            p.params = vec![Value::Integer(blob), Value::Integer(site)];
                            p
                        },
                        "rust_crate_containers_blob",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_definition_site");
                            p.params = vec![Value::Integer(0), Value::Integer(0)];
                            p
                        },
                        "SEARCH mounts USING PRIMARY KEY",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_root_references");
                            p.params = vec![
                                Value::Blob(key.clone()),
                                Value::Text("crate".into()),
                                Value::Text("renamed".into()),
                            ];
                            p
                        },
                        "rust_crate_root_references_target",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_target_activation");
                            p.params = vec![Value::Integer(0), Value::Integer(0)];
                            p
                        },
                        "rust_crate_containers_blob",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_contract_owner");
                            p.params = vec![Value::Integer(0), Value::Integer(0)];
                            p
                        },
                        "SEARCH owner USING",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_reference_lookup_blobs");
                            p.params = vec![Value::Blob(
                                ResolutionLookupSemanticRecipe::new(
                                    Language::Rust,
                                    ResolutionNamespace::Callable,
                                    "target",
                                )
                                .semantic(crate::analyzer::resolution::test_shared_names())
                                .as_bytes()
                                .to_vec(),
                            )];
                            p
                        },
                        "resolution_reference_lookup_identities_identity",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_caller_roots");
                            p.params = vec![Value::Text("client/src/lib.rs".into())];
                            p
                        },
                        "rust_crate_containers_blob",
                    ),
                    (pinned("rust_graph_definitions"), "SEARCH site USING"),
                    (export_pin, "rust_crate_exports_declaration"),
                    (import_pin, "rust_crate_imports_target"),
                    (
                        {
                            let mut p = pinned("rust_reverse_globs");
                            p.params = vec![Value::Blob(key.clone()), Value::Text("crate".into())];
                            p
                        },
                        "rust_crate_glob_imports_target",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_module_sources");
                            p.params = vec![Value::Integer(topology), Value::Text("crate".into())];
                            p
                        },
                        "SEARCH candidate USING PRIMARY KEY",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_locators");
                            p.params = vec![Value::Integer(client_blob)];
                            p
                        },
                        "selected_resolution_mounts_blob_ordinal",
                    ),
                ];
                for (pin, index) in cases {
                    let plan = explain_pin(&conn, &pin);
                    assert!(
                        plan.iter().any(|row| row.contains(index)),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    for table in [
                        "exports", "routes", "imports", "paths", "sites", "names", "sources",
                    ] {
                        assert!(
                            !plan
                                .iter()
                                .any(|row| row.starts_with(&format!("SCAN {table}"))),
                            "{state:?} {}: {plan:?}",
                            pin.name
                        );
                    }
                }
            }
        }
        eprintln!("reverse rows VM steps: {measurements:?}");
        for index in 0..2 {
            assert_eq!(
                (measurements[index].2, measurements[index].3),
                (measurements[index + 2].2, measurements[index + 2].3),
                "unrelated export inventory must not add candidate reads: {measurements:?}"
            );
        }
    }
}
