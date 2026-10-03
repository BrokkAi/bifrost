//! Demand-local Go dot-import composition over immutable package publications.
//!
//! This is one caller's query. Package membership stays in SQLite; the source
//! halves, candidate export halves and compiled bridges die with the query.

use super::*;
use crate::analyzer::resolution::{
    FactPageVisitor, SelectedResolutionMountContext, SelectedRootPathHalf,
    visit_selected_root_export_half_pages, visit_selected_root_import_half_pages,
};

/// Unsaved Go replacements that keep their predecessor's package placement.
/// The Go tool placed the predecessor from its bytes through the imports; an
/// equal membership digest proves the same build constraints, package name,
/// cgo use and import spellings. NULL digests never compare equal. The masks
/// are the request's overlays, so this view stays small, and every join seeks
/// an index. A replacement absent here has no selected placement.
pub(in crate::analyzer::store) const GO_TRANSIENT_PLACEMENTS_SQL: &str = r#"
CREATE INDEX IF NOT EXISTS temp.selected_resolution_overlay_masks_version
  ON selected_resolution_overlay_masks(masked_file_version_id);
CREATE TEMP VIEW IF NOT EXISTS selected_go_transient_placements(mount_ordinal, file_version_id) AS
SELECT mounted.mount_ordinal, mask.masked_file_version_id
FROM temp.selected_resolution_overlay_masks AS mask
JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.storage_language = mask.storage_language
 AND mounted.persisted_relative_path = mask.persisted_relative_path
JOIN main.source_go_manifests AS replacement ON replacement.blob_id = mounted.blob_id
JOIN main.blobs AS predecessor_blob
  ON predecessor_blob.lang = 'go' AND predecessor_blob.generation = mounted.generation
 AND predecessor_blob.blob_oid = mask.masked_blob_oid
JOIN main.source_go_manifests AS predecessor ON predecessor.blob_id = predecessor_blob.id
WHERE mask.storage_language = 'go' AND mounted.file_version_id IS NULL
  AND replacement.membership_digest = predecessor.membership_digest;
"#;

const TRANSIENT_PLACEMENT: &str =
    "SELECT file_version_id FROM temp.selected_go_transient_placements WHERE mount_ordinal = ?1";

// A transient Go source without a proven placement may belong to any package
// the Go tool would assign it, so no package's member set is complete.
const UNPLACED_TRANSIENT_SOURCE: &str = r#"
SELECT EXISTS(
  SELECT 1 FROM temp.selected_resolution_mounts AS mounted
  WHERE mounted.storage_language = 'go' AND mounted.file_version_id IS NULL
    AND NOT EXISTS(SELECT 1 FROM temp.selected_go_transient_placements AS placed
                   WHERE placed.mount_ordinal = mounted.mount_ordinal))
"#;

/// The selected file version whose package placement this mount uses: its
/// own, or the predecessor an unsaved replacement provably keeps.
pub(in crate::analyzer::store) fn go_placement_file_version(
    connection: &rusqlite::Connection,
    record: &crate::analyzer::store::resolution_selection::SelectedResolutionMountRecord,
) -> Result<Option<i64>> {
    if let Some(version) = record.file_version_id() {
        return Ok(Some(version));
    }
    Ok(connection
        .prepare_cached(TRANSIENT_PLACEMENT)?
        .query_row([record.ordinal().get()], |row| row.get(0))
        .optional()?)
}

// A context is usable only for the exact revision selected by this operation.
// The head is checked again before a caller may publish its answer.
const CONTEXT_SELECTION: &str = r#"
SELECT c.complete, json(c.gaps), c.selection_id, c.publication_digest
FROM main.go_context_publications AS c
JOIN main.go_context_selections AS s ON s.selection_id = c.selection_id
JOIN main.go_context_heads AS h ON h.selection_id = s.selection_id AND h.context_id = c.context_id
JOIN temp.selected_workspace_revisions AS selected
  ON selected.workspace_id = s.workspace_id AND selected.lang = s.lang
 AND selected.generation = s.generation AND selected.revision = s.revision
WHERE c.context_id = ?1 AND s.derivation_version = ?2
"#;

// Exact file placement and import mapping, then only the selected provider's
// admitted Go files. No package-name or path-suffix lookup is authority here.
pub(crate) const DOT_IMPORT_TARGET_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal
FROM main.go_context_source_files AS caller
JOIN main.go_package_instances AS package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
 AND ((?3='go' AND package.for_test='')
   OR (?3 IN ('test','xtest') AND package.for_test<>'')
   OR (?3 IN ('test','xtest') AND package.provider_provenance='source_inventory'))
JOIN main.go_package_imports AS imports
  ON imports.context_id = caller.context_id
 AND imports.importer_package_id = caller.package_id
 AND imports.import_role = ?3 AND imports.source_spelling = ?4
JOIN main.go_context_source_files AS provider
  ON provider.context_id = caller.context_id
 AND provider.package_id = imports.target_package_id
JOIN main.go_package_instances AS target_package
  ON target_package.context_id=provider.context_id AND target_package.package_id=provider.package_id
 AND (provider.source_role='go' OR (provider.source_role='test' AND target_package.for_test<>''))
JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.file_version_id = provider.file_version_id
WHERE caller.context_id = ?1 AND caller.file_version_id = ?2
  AND caller.source_role = ?3
UNION ALL
SELECT placed.mount_ordinal
FROM main.go_context_source_files AS caller
JOIN main.go_package_instances AS package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
 AND ((?3='go' AND package.for_test='')
   OR (?3 IN ('test','xtest') AND package.for_test<>'')
   OR (?3 IN ('test','xtest') AND package.provider_provenance='source_inventory'))
JOIN main.go_package_imports AS imports
  ON imports.context_id = caller.context_id
 AND imports.importer_package_id = caller.package_id
 AND imports.import_role = ?3 AND imports.source_spelling = ?4
JOIN main.go_context_source_files AS provider
  ON provider.context_id = caller.context_id
 AND provider.package_id = imports.target_package_id
JOIN main.go_package_instances AS target_package
  ON target_package.context_id=provider.context_id AND target_package.package_id=provider.package_id
 AND (provider.source_role='go' OR (provider.source_role='test' AND target_package.for_test<>''))
JOIN temp.selected_go_transient_placements AS placed
  ON placed.file_version_id = provider.file_version_id
WHERE caller.context_id = ?1 AND caller.file_version_id = ?2
  AND caller.source_role = ?3
"#;

pub(crate) enum GoDotImportContext {
    Ready(SelectedResolutionContextSet),
    Unavailable,
    Cancelled,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Compose only source-owned dot-import demands for one selected file.
    /// Named qualifiers and same-package continuation have separate binding
    /// rules and are not claimed by this operation.
    pub(crate) fn go_dot_import_context(
        &self,
        context_id: i64,
        caller_path: &str,
        source_role: &str,
        cancellation: &CancellationToken,
    ) -> Result<GoDotImportContext> {
        assert!(matches!(source_role, "go" | "test" | "xtest"));
        if cancellation.is_cancelled() {
            return Ok(GoDotImportContext::Cancelled);
        }
        let connection = self.ready.inventory.connection();
        let selected = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row(
                [
                    context_id,
                    super::super::go_package_context::DERIVATION_VERSION,
                ],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((complete, evidence, selection_id, digest)) = selected else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let publication = super::super::GoContextIdentity {
            selection_id,
            context_id,
            publication_digest: digest
                .try_into()
                .map_err(|_| StoreError::corrupt("Go publication digest must have 32 bytes"))?,
        };
        if let Some(previous) = self.ready.go_publication.replace(Some(publication.clone())) {
            assert_eq!(
                previous, publication,
                "one query uses one selected Go publication"
            );
        }
        let Some(source) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let source_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        // An unsaved replacement whose membership inputs changed has no
        // selected placement; its disk predecessor cannot authorize it.
        let Some(file_version) = go_placement_file_version(connection, &source_record)? else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let identities = self.ready.context_identities.clone();
        let mut reasons = Vec::new();
        if !complete {
            let mut hash = CanonicalHasher::new(b"bifrost-go-context-incomplete:v1");
            hash.field("context", &context_id.to_le_bytes());
            hash.field("evidence", evidence.as_bytes());
            reasons.push(identities.named_semantic(
                hash.finish(),
                "go-context-incomplete",
                &evidence,
            ));
        }
        let unplaced: bool =
            connection.query_row(UNPLACED_TRANSIENT_SOURCE, [], |row| row.get(0))?;
        if unplaced {
            let evidence =
                "an unsaved Go source changed the inputs the Go tool uses to place it in a package";
            let mut hash = CanonicalHasher::new(b"bifrost-go-transient-placement-unproven:v1");
            hash.field("context", &context_id.to_le_bytes());
            reasons.push(identities.named_semantic(
                hash.finish(),
                "go-transient-placement-unproven",
                evidence,
            ));
        }
        let completion = if reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete(
                reasons
                    .iter()
                    .map(|&reason| ResolutionIncompleteReason::UnsupportedSemantic(reason)),
            )
        };
        let lexical = self.ready.lexical_source();
        let mut imports = Vec::new();
        let outcome = visit_selected_root_import_half_pages(
            &identities,
            &lexical,
            &lexical,
            Some(&[source.ordinal()]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                imports.extend_from_slice(page);
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(GoDotImportContext::Cancelled);
        }
        let mut bridges = Vec::new();
        for import in imports {
            let SelectedRootPathHalf::Import {
                route,
                token,
                anchor,
                anchor_semantic,
                demand,
                ..
            } = import
            else {
                continue;
            };
            let mut semantics = route.into_vec();
            semantics.push(demand);
            let mut recipes = Vec::with_capacity(semantics.len());
            for page in semantics.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
                let requests = page
                    .iter()
                    .map(|&semantic| SelectedLookupRecipeRequest {
                        fragment: source.fragment(),
                        semantic,
                    })
                    .collect::<Vec<_>>();
                let SelectedLookupRecipeReadOutcome::Ready(rows) =
                    lexical.lookup_semantic_recipes(&requests, cancellation, None)?
                else {
                    return Ok(GoDotImportContext::Cancelled);
                };
                for recipe in rows {
                    recipes.push(recipe.ok_or_else(|| {
                        StoreError::corrupt("selected Go root lookup has no shared recipe")
                    })?);
                }
            }
            let demand_recipe = recipes.pop().expect("one import demand");
            let spelling = recipes
                .iter()
                .map(ResolutionLookupSemanticRecipe::spelling)
                .collect::<Vec<_>>()
                .join("/");
            let mut statement = connection.prepare_cached(DOT_IMPORT_TARGET_MOUNTS)?;
            let rows = statement.query_map(
                rusqlite::params![context_id, file_version, source_role, spelling],
                |row| row.get::<_, u32>(0),
            )?;
            let targets = rows.collect::<rusqlite::Result<BTreeSet<_>>>()?;
            for target in targets {
                if cancellation.is_cancelled() {
                    return Ok(GoDotImportContext::Cancelled);
                }
                let ordinal = SelectedResolutionMountOrdinal::new(target);
                let mut exports = Vec::new();
                let outcome = visit_selected_root_export_half_pages(
                    &identities,
                    &lexical,
                    &lexical,
                    Some(&[ordinal]),
                    cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        exports.extend_from_slice(page);
                        Ok(true)
                    }),
                )?;
                if outcome.is_cancelled() {
                    return Ok(GoDotImportContext::Cancelled);
                }
                for export in exports {
                    let SelectedRootPathHalf::Export {
                        identity,
                        token: export_token,
                        demand: export_demand,
                        ..
                    } = &export
                    else {
                        unreachable!("export-only visitor")
                    };
                    if *export_demand != demand {
                        continue;
                    }
                    bridges.push(
                        SelectedRootBridgeDescriptor::from_selected_path_tokens(
                            source.fragment(),
                            Language::Go,
                            token,
                            anchor,
                            anchor_semantic,
                            identity.fragment(),
                            Language::Go,
                            *export_token,
                            recipes.clone(),
                            demand_recipe.clone(),
                            demand_recipe.clone(),
                            completion.clone(),
                        )
                        .with_selected_export(&self.ready.shared_names(), &export),
                    );
                }
            }
        }
        let mount = SelectedResolutionMountContext::new(
            source.ordinal(),
            source.fragment(),
            Language::Go,
            bridges,
            completion,
        )?;
        let mounts = self.mount_table();
        let context = SelectedResolutionContextSet::new(
            identities,
            vec![mount],
            mounts.mount_count(),
            &|fragment| {
                Ok(mounts
                    .mount_for_fragment(fragment)?
                    .map(|mount| (mount.ordinal(), mount.semantic_language())))
            },
        )?;
        Ok(GoDotImportContext::Ready(reasons.into_iter().fold(
            context,
            SelectedResolutionContextSet::with_context_owned_inventory_reason,
        )))
    }
}
