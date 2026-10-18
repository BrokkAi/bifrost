//! Demand-local Go dot-import composition over immutable package publications.
//!
//! This is one caller's query. Package membership stays in SQLite; the source
//! halves, candidate export halves and compiled bridges die with the query.

use super::*;
use crate::analyzer::resolution::{
    FactPageVisitor, ResolutionLookupSemanticRecipe, SelectedResolutionMountContext,
    SelectedRootPathHalf, SharedNameId, SharedNameInterner, visit_selected_root_export_half_pages,
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

// A transient Go source without a proven placement leaves only its containing
// Go package's inventory open. Go package files share a directory.
const UNPLACED_TRANSIENT_SOURCES: &str = r#"
SELECT mounted.persisted_relative_path
FROM temp.selected_resolution_mounts AS mounted
WHERE mounted.storage_language = 'go' AND mounted.file_version_id IS NULL
  AND NOT EXISTS(SELECT 1 FROM temp.selected_go_transient_placements AS placed
                 WHERE placed.mount_ordinal = mounted.mount_ordinal)
ORDER BY mounted.persisted_relative_path
"#;

// Go root-import paths have LexicalBinding tier code 0 and ordinal 0. Go root
// reference paths use PackageOrModule, so this selects only import demands.
const GO_ROOT_IMPORT_TERMINAL_TARGETS: &str = r#"
SELECT DISTINCT root_terminal
FROM main.resolution_paths INDEXED BY resolution_paths_root_terminal
WHERE blob_id=?1 AND end_node=-1 AND root_terminal IS NOT NULL
  AND json_extract(body, '$[8][0][0]')=0
  AND json_extract(body, '$[8][0][1]')=0
ORDER BY root_terminal
"#;

const PACKAGE_SOURCE_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal
FROM main.go_context_source_files AS source
JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.file_version_id=source.file_version_id
WHERE source.context_id=?1 AND source.package_id=?2 AND source.source_role<>'ignored'
UNION
SELECT placed.mount_ordinal
FROM main.go_context_source_files AS source
JOIN temp.selected_go_transient_placements AS placed
  ON placed.file_version_id=source.file_version_id
WHERE source.context_id=?1 AND source.package_id=?2 AND source.source_role<>'ignored'
ORDER BY 1
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
SELECT json(c.gaps),
       (SELECT COUNT(*)
        FROM json_each(c.gaps) AS gap
        WHERE COALESCE(json_extract(gap.value, '$.code'), '') NOT IN (
          'build_selection_unavailable',
          'source_cgo_build_selection_unavailable',
          'conflicting_source_package_names',
          'source_import_provider_unavailable'
        ) OR (
          COALESCE(json_extract(gap.value, '$.code'), '') = 'build_selection_unavailable'
          AND ?3 = 'xtest'
        )),
       c.selection_id, c.publication_digest
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

#[derive(Clone, Default)]
pub(crate) struct GoPackageInventoryState {
    pub(crate) complete: bool,
    pub(crate) fragments: HashMap<BindingFragmentId, bool>,
}

impl GoPackageInventoryState {
    pub(crate) fn merge(&mut self, other: Self) {
        self.complete |= other.complete;
        for (fragment, is_complete) in other.fragments {
            *self.fragments.entry(fragment).or_insert(true) &= is_complete;
        }
    }
}

#[derive(Clone)]
pub(crate) struct GoContextSelection {
    pub(crate) identity: super::super::GoContextIdentity,
    evidence: String,
    global_gap_count: i64,
}

// A transient return value: the ready payload is moved out immediately, so
// boxing it would add an allocation to every context read.
#[allow(clippy::large_enum_variant)]
pub(crate) enum GoDotImportContext {
    Ready {
        context: SelectedResolutionContextSet,
        inventory: GoPackageInventoryState,
    },
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
        let Some(selection) = self.go_context_selection(context_id, source_role)? else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let outcome = self.go_dot_import_context_for_selection(
            context_id,
            caller_path,
            source_role,
            &selection,
            cancellation,
        )?;
        if let GoDotImportContext::Ready { inventory, .. } = &outcome {
            self.record_go_package_inventory_state(inventory);
        }
        Ok(outcome)
    }

    pub(super) fn go_context_selection(
        &self,
        context_id: i64,
        source_role: &str,
    ) -> Result<Option<GoContextSelection>> {
        // The selection is a constant of this operation (its workspace
        // revision and the Go head are fixed for the request) but reading it
        // scans the publication's whole gap list, so a request that prepares
        // hundreds of files must not repeat it per file.
        let memo_key = (context_id, source_role.to_owned());
        if let Some(selection) = self.go_context_selections.borrow().get(&memo_key) {
            return Ok(selection.clone());
        }
        let selection = self.read_go_context_selection(context_id, source_role)?;
        self.go_context_selections
            .borrow_mut()
            .insert(memo_key, selection.clone());
        Ok(selection)
    }

    fn read_go_context_selection(
        &self,
        context_id: i64,
        source_role: &str,
    ) -> Result<Option<GoContextSelection>> {
        let connection = self.ready.inventory.connection();
        let selected = connection
            .prepare_cached(CONTEXT_SELECTION)?
            .query_row(
                rusqlite::params![
                    context_id,
                    super::super::go_package_context::DERIVATION_VERSION,
                    source_role,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((evidence, global_gap_count, selection_id, digest)) = selected else {
            return Ok(None);
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
        Ok(Some(GoContextSelection {
            identity: publication,
            evidence,
            global_gap_count,
        }))
    }

    pub(super) fn go_dot_import_context_for_selection(
        &self,
        context_id: i64,
        caller_path: &str,
        source_role: &str,
        selection: &GoContextSelection,
        cancellation: &CancellationToken,
    ) -> Result<GoDotImportContext> {
        if cancellation.is_cancelled() {
            return Ok(GoDotImportContext::Cancelled);
        }
        let connection = self.ready.inventory.connection();
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
        let package_id: Option<i64> = connection
            .prepare_cached(super::go_same_package::CALLER_PACKAGE)?
            .query_row(
                rusqlite::params![context_id, file_version, source_role],
                |row| row.get(0),
            )
            .optional()?;
        let Some(package_id) = package_id else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let (package_complete, package_evidence): (bool, String) = connection
            .query_row(
                "SELECT complete, json(gaps) FROM main.go_package_instances
                 WHERE context_id=?1 AND package_id=?2",
                rusqlite::params![context_id, package_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| StoreError::corrupt("selected Go caller package disappeared"))?;
        let identities = self.ready.context_identities.clone();
        let mut reasons = Vec::new();
        if selection.global_gap_count != 0 {
            let mut hash = CanonicalHasher::new(b"bifrost-go-context-incomplete:v1");
            hash.field("context", &context_id.to_le_bytes());
            hash.field("evidence", selection.evidence.as_bytes());
            reasons.push(identities.named_semantic(
                hash.finish(),
                "go-context-incomplete",
                &selection.evidence,
            ));
        }
        if !package_complete {
            let mut hash = CanonicalHasher::new(b"bifrost-go-package-incomplete:v1");
            hash.field("context", &context_id.to_le_bytes());
            hash.field("package", &package_id.to_le_bytes());
            hash.field("evidence", package_evidence.as_bytes());
            reasons.push(identities.named_semantic(
                hash.finish(),
                "go-package-incomplete",
                &package_evidence,
            ));
        }
        let caller_directory =
            std::path::Path::new(source_record.persisted_relative_path()).parent();
        let mut unplaced_sources = connection.prepare_cached(UNPLACED_TRANSIENT_SOURCES)?;
        let mut rows = unplaced_sources.query([])?;
        let mut unplaced_source = None;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
            let path: String = row.get(0)?;
            if std::path::Path::new(&path).parent() == caller_directory {
                unplaced_source = Some(path);
                break;
            }
        }
        drop(rows);
        drop(unplaced_sources);
        let package_inventory_complete = package_complete && unplaced_source.is_none();
        let mut package_fragments = vec![source.fragment()];
        let mut statement = connection.prepare_cached(PACKAGE_SOURCE_MOUNTS)?;
        let mut rows = statement.query(rusqlite::params![context_id, package_id])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
            let ordinal = SelectedResolutionMountOrdinal::new(row.get(0)?);
            package_fragments.push(self.mount_table().mount_by_ordinal(ordinal)?.fragment());
        }
        drop(rows);
        drop(statement);
        package_fragments.sort_unstable();
        package_fragments.dedup();
        let inventory = GoPackageInventoryState {
            complete: package_inventory_complete,
            fragments: package_fragments
                .into_iter()
                .map(|fragment| (fragment, package_inventory_complete))
                .collect(),
        };
        if let Some(path) = unplaced_source {
            let evidence = format!(
                "unsaved Go source {path:?} has no proven placement in the caller package directory"
            );
            let mut hash = CanonicalHasher::new(b"bifrost-go-transient-placement-unproven:v2");
            hash.field("context", &context_id.to_le_bytes());
            hash.field("package", &package_id.to_le_bytes());
            hash.field("evidence", evidence.as_bytes());
            reasons.push(identities.named_semantic(
                hash.finish(),
                "go-transient-placement-unproven",
                &evidence,
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
        if !self.go_import_inputs_loaded(source.ordinal())
            && !self.load_go_import_inputs(
                context_id,
                &[(source.ordinal(), file_version, source_role)],
                cancellation,
            )?
        {
            return Ok(GoDotImportContext::Cancelled);
        }
        // Only dot imports publish root import paths, and this reader uses
        // import halves alone, so a file without a dot import skips the
        // inventory of every root path it owns.
        let mut imports = Vec::new();
        if self.go_mount_has_dot_import(source.ordinal()) {
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
            let Some(import_completion) = self.go_import_completion(
                context_id,
                source.ordinal(),
                file_version,
                source_role,
                &spelling,
                &completion,
                cancellation,
            )?
            else {
                return Ok(GoDotImportContext::Cancelled);
            };
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
                            import_completion.clone(),
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
        Ok(GoDotImportContext::Ready {
            context: reasons.into_iter().fold(
                context,
                SelectedResolutionContextSet::with_context_owned_inventory_reason,
            ),
            inventory,
        })
    }

    fn go_root_import_terminal_targets(
        &self,
        blob_id: i64,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SharedNameId>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let connection = self.ready.inventory.connection();
        let names = self.ready.shared_names();
        let mut targets = Vec::new();
        let mut statement = connection.prepare_cached(GO_ROOT_IMPORT_TERMINAL_TARGETS)?;
        let mut rows = statement.query([blob_id])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let persisted = SharedNameId::interned(row.get(0)?);
            targets.push(names.from_persisted(persisted));
        }
        Ok(Some(targets))
    }

    pub(super) fn record_go_package_inventory_state(&self, inventory: &GoPackageInventoryState) {
        let mut complete = self.ready.go_package_inventory_complete.borrow_mut();
        *complete = Some(complete.unwrap_or(false) || inventory.complete);
        drop(complete);
        let mut fragments = self.ready.go_package_inventory_fragments.borrow_mut();
        for (&fragment, &is_complete) in &inventory.fragments {
            *fragments.entry(fragment).or_insert(true) &= is_complete;
        }
    }

    /// Completion of one Go import spelling of a mounted file, from the file's
    /// selected import rows. Loads them as a one-element batch when no
    /// prefetch has; `None` means cancelled.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn go_import_completion(
        &self,
        context_id: i64,
        mount: SelectedResolutionMountOrdinal,
        file_version: i64,
        source_role: &str,
        spelling: &str,
        base_completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> Result<Option<ResolutionCompletion>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if !self.go_import_inputs_loaded(mount)
            && !self.load_go_import_inputs(
                context_id,
                &[(mount, file_version, source_role)],
                cancellation,
            )?
        {
            return Ok(None);
        }
        let row = self.go_import_row(mount, spelling);
        Ok(Some(self.go_import_completion_for(
            context_id,
            file_version,
            source_role,
            spelling,
            row.as_ref(),
            base_completion,
        )))
    }

    /// The completion a selected import row states; a spelling without a row
    /// is incomplete.
    pub(super) fn go_import_completion_for(
        &self,
        context_id: i64,
        file_version: i64,
        source_role: &str,
        spelling: &str,
        selected: Option<&super::go_named::GoFileImportRow>,
        base_completion: &ResolutionCompletion,
    ) -> ResolutionCompletion {
        if selected.is_some_and(|row| row.complete) {
            return base_completion.clone();
        }
        let evidence = selected.map_or_else(
            || format!("missing selected Go import row for {source_role}:{spelling}"),
            |row| row.gaps.clone(),
        );
        let mut hash = CanonicalHasher::new(b"bifrost-go-import-incomplete:v1");
        hash.field("context", &context_id.to_le_bytes());
        hash.field("file-version", &file_version.to_le_bytes());
        hash.field("role", source_role.as_bytes());
        hash.field("spelling", spelling.as_bytes());
        hash.field("evidence", evidence.as_bytes());
        let reason = self.ready.context_identities.named_semantic(
            hash.finish(),
            "go-import-incomplete",
            &evidence,
        );
        base_completion.combine(&ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(reason),
        ]))
    }
}
