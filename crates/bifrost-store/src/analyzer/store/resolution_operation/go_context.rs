//! Demand-local Go dot-import composition over immutable package publications.
//!
//! This is one caller's query. Package membership stays in SQLite; the source
//! halves, candidate export halves and compiled bridges die with the query.

use super::file_context::RootHalfRequest;
use super::root_bridges::{RootBridgePair, RootBridgeRules, assemble_root_bridges};
use super::*;
use crate::analyzer::resolution::{
    ResolutionLookupSemanticRecipe, SelectedResolutionMountContext, SelectedRootPathHalf,
    SharedNameId, SharedNameInterner,
};

// The go_context_source_files view's semantics in version-led order for
// file-keyed probes. The view keeps context-led order for plan stability.
// `probe` supplies the selected revision; the caller constrains the version.
pub(in crate::analyzer::store) const GO_CONTEXT_SOURCE_FILE_BY_VERSION_JOIN: &str = r#"
CROSS JOIN main.workspace_file_versions versions
  ON versions.input_kind='source'
 AND versions.valid_from<=probe.revision
 AND (versions.valid_until IS NULL OR probe.revision<versions.valid_until)
CROSS JOIN main.go_package_files source ON source.rel_path=versions.rel_path
CROSS JOIN main.go_package_instances package
  ON package.package_id=source.package_id
CROSS JOIN main.go_context_publications publication
  ON publication.context_id=package.context_id
 AND versions.workspace_id=publication.workspace_id AND versions.lang=publication.lang
 AND versions.generation=publication.generation
 AND publication.valid_from<=probe.revision
 AND (publication.valid_until IS NULL OR probe.revision<publication.valid_until)
"#;

// File-keyed users of the selected view use this equivalent derived table.
// Outer file predicates push into `versions` before package membership is read.
pub(super) static GO_SELECTED_SOURCE_FILE_BY_VERSION: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
SELECT package.context_id, package.package_id, source.source_role,
       versions.file_version_id, versions.rel_path, versions.blob_oid,
       versions.projection_digest, versions.valid_from, versions.valid_until,
       publication.valid_from AS publication_valid_from,
       publication.valid_until AS publication_valid_until,
       versions.workspace_id, versions.lang, versions.generation
FROM temp.selected_workspace_revisions probe
{}
WHERE probe.lang='go' AND versions.workspace_id=probe.workspace_id AND versions.lang=probe.lang
  AND versions.generation=probe.generation
"#,
            GO_CONTEXT_SOURCE_FILE_BY_VERSION_JOIN
        )
    });

/// Unsaved Go replacements that keep their predecessor's package placement.
/// The Go tool placed the predecessor from its bytes through the imports; an
/// equal membership digest proves the same build constraints, package name,
/// cgo use and import spellings. NULL digests never compare equal. The masks
/// are the request's overlays, so this view stays small, and every join seeks
/// an index. A replacement absent here has no selected placement.
pub(in crate::analyzer::store) const GO_TRANSIENT_PLACEMENTS_SQL: &str = r#"
CREATE TEMP VIEW IF NOT EXISTS selected_go_context_source_files AS
SELECT source.*
FROM main.go_context_source_files source
JOIN temp.selected_workspace_revisions selected
  ON selected.workspace_id=source.workspace_id AND selected.lang=source.lang AND selected.generation=source.generation
WHERE source.valid_from<=selected.revision AND (source.valid_until IS NULL OR selected.revision<source.valid_until)
  AND source.publication_valid_from<=selected.revision
  AND (source.publication_valid_until IS NULL OR selected.revision<source.publication_valid_until);
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

pub(crate) const PACKAGE_SOURCE_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal
FROM temp.selected_go_context_source_files AS source
JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.file_version_id=source.file_version_id
WHERE source.context_id=?1 AND source.package_id=?2 AND source.source_role<>'ignored'
UNION
SELECT placed.mount_ordinal
FROM temp.selected_go_context_source_files AS source
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
          'domain_discovery_failed',
          'source_cgo_build_selection_unavailable',
          'conflicting_source_package_names',
          'source_import_provider_unavailable'
        ) OR (
          COALESCE(json_extract(gap.value, '$.code'), '') IN ('build_selection_unavailable','domain_discovery_failed')
          AND ?3 = 'xtest'
        )),
       c.selection_id, c.publication_digest, selected.revision
FROM main.go_context_publications AS c
JOIN main.go_context_selections AS s ON s.selection_id = c.selection_id
JOIN temp.selected_workspace_revisions AS selected
  ON selected.workspace_id = s.workspace_id AND selected.lang = s.lang
 AND selected.generation = s.generation
 AND c.valid_from<=selected.revision AND (c.valid_until IS NULL OR selected.revision<c.valid_until)
WHERE c.context_id = ?1 AND s.derivation_version = ?2
"#;

// Exact file placement and import mapping, then only the selected provider's
// admitted Go files. No package-name or path-suffix lookup is authority here.
pub(crate) static DOT_IMPORT_TARGET_MOUNTS: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
SELECT mounted.mount_ordinal
FROM ({}) AS caller
JOIN main.go_package_instances AS package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
 AND ((?3='go' AND package.for_test='')
   OR (?3 IN ('test','xtest') AND package.for_test<>'')
   OR (?3 IN ('test','xtest') AND package.provider_provenance='source_inventory'))
JOIN main.go_package_imports AS imports
  ON imports.context_id = caller.context_id
 AND imports.importer_package_id = caller.package_id
 AND imports.import_role = ?3 AND imports.source_spelling = ?4
JOIN temp.selected_go_context_source_files AS provider
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
FROM ({}) AS caller
JOIN main.go_package_instances AS package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
 AND ((?3='go' AND package.for_test='')
   OR (?3 IN ('test','xtest') AND package.for_test<>'')
   OR (?3 IN ('test','xtest') AND package.provider_provenance='source_inventory'))
JOIN main.go_package_imports AS imports
  ON imports.context_id = caller.context_id
 AND imports.importer_package_id = caller.package_id
 AND imports.import_role = ?3 AND imports.source_spelling = ?4
JOIN temp.selected_go_context_source_files AS provider
  ON provider.context_id = caller.context_id
 AND provider.package_id = imports.target_package_id
JOIN main.go_package_instances AS target_package
  ON target_package.context_id=provider.context_id AND target_package.package_id=provider.package_id
 AND (provider.source_role='go' OR (provider.source_role='test' AND target_package.for_test<>''))
JOIN temp.selected_go_transient_placements AS placed
  ON placed.file_version_id = provider.file_version_id
WHERE caller.context_id = ?1 AND caller.file_version_id = ?2
  AND caller.source_role = ?3
"#,
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str(),
            super::go_context::GO_SELECTED_SOURCE_FILE_BY_VERSION.as_str()
        )
    });

#[derive(Clone, Default)]
#[doc(hidden)]
pub struct GoPackageInventoryState {
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

pub(super) struct GoSelectedPackageInventory {
    package_complete: bool,
    package_evidence: String,
    pub(super) inventory: GoPackageInventoryState,
    unplaced_source: Option<String>,
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
#[doc(hidden)]
pub enum GoDotImportContext {
    Ready {
        context: SelectedResolutionContextSet,
        inventory: GoPackageInventoryState,
    },
    Unavailable,
    Cancelled,
}

/// A file-to-context lookup at one snapshot, in the provider or the owner role.
type GoContextsForFileLookup = fn(
    &rusqlite::Connection,
    &crate::analyzer::store::WorkspaceSnapshotId,
    &[u8; 32],
    &str,
) -> Result<Vec<(super::super::GoContextIdentity, [u8; 32])>>;

impl SelectedResolutionOperation<'_, '_> {
    /// Failure metadata is independent of whether package membership admits a file.
    #[doc(hidden)]
    pub fn go_domain_discovery_failure(
        &self,
        context_id: i64,
    ) -> Result<Option<super::graph_stage::GraphDomainDiscoveryFailure>> {
        self.ready
            .inventory
            .connection()
            .query_row(DOMAIN_DISCOVERY_FAILURE_SQL, [context_id], |row| {
                Ok(super::graph_stage::GraphDomainDiscoveryFailure {
                    domain_dir: row.get(0)?,
                    gowork_path: row.get(1)?,
                    discovery_error: row.get(2)?,
                })
            })
            .optional()
            .map_err(Into::into)
    }

    /// Select the publication(s) containing this workspace source at R.
    /// Results and bound identities live only for this request.
    #[doc(hidden)]
    pub fn go_contexts_for_file(
        &self,
        base: &[u8; 32],
        path: &str,
    ) -> Result<Vec<(super::super::GoContextIdentity, [u8; 32])>> {
        self.bound_go_contexts_for_file(
            base,
            path,
            super::super::go_package_context::go_contexts_for_file_on,
        )
    }

    /// The one context that owns this workspace source: its package belongs
    /// to one of the context's main modules.
    #[doc(hidden)]
    pub fn go_context_for_file(
        &self,
        base: &[u8; 32],
        path: &str,
    ) -> Result<Option<super::super::GoContextIdentity>> {
        let mut contexts = self.bound_go_contexts_for_file(
            base,
            path,
            super::super::go_package_context::go_owner_context_for_file_on,
        )?;
        assert!(
            contexts.len() <= 1,
            "one workspace source belongs to one discovery domain: {contexts:?}"
        );
        Ok(contexts.pop().map(|(context, _)| context))
    }

    /// Select the immutable Go profile on this operation, including worker readers.
    pub fn initialize_go_base_profile(&self, base: &[u8; 32]) {
        if let Some(previous) = self.ready.go_base_profile.get() {
            assert_eq!(previous, *base, "one request uses one Go base profile");
        } else {
            self.ready.go_base_profile.set(Some(*base));
        }
    }

    /// Run one file-to-context lookup at the request's snapshot and bind every
    /// returned publication for this request.
    fn bound_go_contexts_for_file(
        &self,
        base: &[u8; 32],
        path: &str,
        lookup: GoContextsForFileLookup,
    ) -> Result<Vec<(super::super::GoContextIdentity, [u8; 32])>> {
        let Some(snapshot) = self.captured_input.snapshots.get("go") else {
            return Ok(Vec::new());
        };
        self.initialize_go_base_profile(base);
        let contexts = lookup(self.ready.inventory.connection(), snapshot, base, path)?;
        for (context, _) in &contexts {
            self.bind_go_context_publication(context.clone());
        }
        Ok(contexts)
    }

    /// Compose only source-owned dot-import demands for one selected file.
    /// Named qualifiers and same-package continuation have separate binding
    /// rules and are not claimed by this operation.
    #[doc(hidden)]
    pub fn go_dot_import_context(
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
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((evidence, global_gap_count, selection_id, digest, revision)) = selected else {
            return Ok(None);
        };
        let publication = super::super::GoContextIdentity {
            revision,
            selection_id,
            context_id,
            publication_digest: digest
                .try_into()
                .map_err(|_| StoreError::corrupt("Go publication digest must have 32 bytes"))?,
        };
        self.bind_go_context_publication(publication.clone());
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
            .prepare_cached(&super::go_same_package::CALLER_PACKAGE)?
            .query_row(
                rusqlite::params![context_id, file_version, source_role],
                |row| row.get(0),
            )
            .optional()?;
        let Some(package_id) = package_id else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let Some(GoSelectedPackageInventory {
            package_complete,
            package_evidence,
            inventory,
            unplaced_source,
        }) = self.go_package_inventory_for_selected_package(
            context_id,
            package_id,
            &source_record,
            cancellation,
        )?
        else {
            return Ok(GoDotImportContext::Cancelled);
        };
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
        let authority = super::go_named::GoImportAuthority::new(
            source.ordinal(),
            context_id,
            file_version,
            source_role,
        );
        if !self.go_import_inputs_loaded(&authority)
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
            let (halves, outcome) = self
                .read_root_inventory(RootHalfRequest::Imports(&[source.ordinal()]), cancellation)?;
            imports = halves;
            if outcome.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
        }
        let mut bridges = Vec::new();
        for import in imports {
            let SelectedRootPathHalf::Import { route, demand, .. } = &import else {
                continue;
            };
            let mut semantics = route.to_vec();
            semantics.push(*demand);
            let requests = semantics
                .iter()
                .map(|&semantic| SelectedLookupRecipeRequest {
                    fragment: source.fragment(),
                    semantic,
                })
                .collect::<Vec<_>>();
            let Some(rows) =
                self.read_context_recipes(&lexical, &requests, cancellation, |_| {})?
            else {
                return Ok(GoDotImportContext::Cancelled);
            };
            let mut recipes = rows
                .into_iter()
                .map(|row| {
                    row.ok_or_else(|| {
                        StoreError::corrupt("selected Go root lookup has no shared recipe")
                    })
                })
                .collect::<Result<Vec<_>>>()?;
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
            let mut statement = connection.prepare_cached(&DOT_IMPORT_TARGET_MOUNTS)?;
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
                let (exports, outcome) =
                    self.read_root_inventory(RootHalfRequest::Exports(&[ordinal]), cancellation)?;
                if outcome.is_cancelled() {
                    return Ok(GoDotImportContext::Cancelled);
                }
                let names = self.ready.shared_names();
                let assembly = assemble_root_bridges(
                    &self.ready,
                    exports.iter().map(|export_half| RootBridgePair {
                        import_half: &import,
                        export_half,
                        extra: (),
                    }),
                    &GoDotRootBridgeRules {
                        names: &names,
                        target: ordinal,
                        route: &recipes,
                        demand: &demand_recipe,
                        completion: &import_completion,
                    },
                    cancellation,
                )?;
                if assembly
                    .completion
                    .contains_reason(ResolutionIncompleteReason::Cancelled)
                {
                    return Ok(GoDotImportContext::Cancelled);
                }
                bridges.extend(assembly.descriptors);
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
            &selected_mount_lookup(mounts),
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

    /// Read the exact selected package, including a ForTest instance whose
    /// ordinary Go files also occur in the normal package. Source role alone
    /// cannot choose the inventory of an imported package.
    pub(super) fn go_package_inventory_for_selected_package(
        &self,
        context_id: i64,
        package_id: i64,
        source_record: &crate::analyzer::store::resolution_selection::SelectedResolutionMountRecord,
        cancellation: &CancellationToken,
    ) -> Result<Option<GoSelectedPackageInventory>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let connection = self.ready.inventory.connection();
        let (package_complete, package_evidence): (bool, String) = connection
            .query_row(
                "SELECT complete, json(gaps) FROM main.go_package_instances
                 WHERE context_id=?1 AND package_id=?2",
                rusqlite::params![context_id, package_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| StoreError::corrupt("selected Go caller package disappeared"))?;
        let caller_directory =
            std::path::Path::new(source_record.persisted_relative_path()).parent();
        let mut unplaced_sources = connection.prepare_cached(UNPLACED_TRANSIENT_SOURCES)?;
        let mut rows = unplaced_sources.query([])?;
        let mut unplaced_source = None;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
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
        let mut package_fragments = vec![source_record.fragment_id()];
        let mut statement = connection.prepare_cached(PACKAGE_SOURCE_MOUNTS)?;
        let mut rows = statement.query(rusqlite::params![context_id, package_id])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
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
        Ok(Some(GoSelectedPackageInventory {
            package_complete,
            package_evidence,
            inventory,
            unplaced_source,
        }))
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
        let authority =
            super::go_named::GoImportAuthority::new(mount, context_id, file_version, source_role);
        if !self.go_import_inputs_loaded(&authority)
            && !self.load_go_import_inputs(
                context_id,
                &[(mount, file_version, source_role)],
                cancellation,
            )?
        {
            return Ok(None);
        }
        let row = self.go_import_row(&authority, spelling);
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

pub(crate) const DOMAIN_DISCOVERY_FAILURE_SQL: &str = r#"
SELECT s.domain_dir, s.gowork_path, json_extract(gap.value, '$.evidence')
FROM go_context_publications c JOIN go_context_selections s ON s.selection_id=c.selection_id,
     json_each(c.gaps) gap
WHERE c.context_id=?1 AND c.complete=0
  AND json_extract(gap.value, '$.code')='domain_discovery_failed'
  AND EXISTS(SELECT 1 FROM go_package_instances p WHERE p.context_id=c.context_id
             AND p.provider_provenance='source_inventory')
LIMIT 1
"#;

/// Exact context reads owned by ReadySelectedResolution, never by its retained
/// selection. Scope and stage changes replace the ordinal-indexed answers.
#[derive(Clone, Copy, PartialEq, Eq)]
struct GoDefinitionContextAuthority {
    scope: [u8; 32],
    stage: (u64, u64),
    base_profile: [u8; 32],
}

#[derive(Default)]
pub(super) struct GoDefinitionContextMemo {
    authority: Option<GoDefinitionContextAuthority>,
    contexts: Vec<Option<Option<super::super::GoContextIdentity>>>,
}

impl super::super::resolution_typed::GoDefinitionContextBinder
    for super::ReadySelectedResolution<'_, '_>
{
    // The caller has already selected this request's base profile. Candidate
    // declarations can belong to other domains under that same profile.
    fn bind_context(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
        path: &str,
        candidates: &[SemanticId],
    ) -> Result<Option<super::super::GoContextIdentity>> {
        let Some(snapshot) = &self.go_snapshot else {
            return Ok(None);
        };
        let base = self.go_base_profile.get().unwrap_or_else(|| {
            panic!("Go candidate participation requires a base profile: file={path}, candidates={candidates:?}")
        });
        let authority = GoDefinitionContextAuthority {
            scope: self.inventory.scope_identity(),
            stage: self.inventory.staged_read_epoch(),
            base_profile: base,
        };
        {
            let mut memo = self.go_definition_contexts.borrow_mut();
            if memo.authority != Some(authority) {
                memo.authority = Some(authority);
                memo.contexts = vec![None; self.inventory.persisted_mount_count()];
            }
            if let Some(context) = &memo.contexts[ordinal.get() as usize] {
                return Ok(context.clone());
            }
        }
        let mut contexts =
            super::super::go_package_context::go_owner_context_for_definition_file_on(
                self.inventory.connection(),
                snapshot,
                &base,
                path,
            )?;
        assert!(
            contexts.len() <= 1,
            "one workspace source belongs to one discovery domain: {contexts:?}"
        );
        let context = contexts.pop().map(|(context, _)| context);
        if let Some(context) = &context {
            self.bind_go_context_publication(context.clone());
        }
        self.go_definition_contexts.borrow_mut().contexts[ordinal.get() as usize] =
            Some(context.clone());
        Ok(context)
    }
}

/// The target inventory has already proved exact package and source-role
/// authority. Admission compares the canonical import and export lookups.
struct GoDotRootBridgeRules<'a> {
    names: &'a dyn SharedNameInterner,
    target: SelectedResolutionMountOrdinal,
    route: &'a [ResolutionLookupSemanticRecipe],
    demand: &'a ResolutionLookupSemanticRecipe,
    completion: &'a ResolutionCompletion,
}

impl RootBridgeRules for GoDotRootBridgeRules<'_> {
    type Extra = ();
    type Admission = ();

    fn admit(
        &self,
        _operation: &ReadySelectedResolution<'_, '_>,
        pair: &RootBridgePair<'_, Self::Extra>,
        _cancellation: &CancellationToken,
    ) -> Result<Option<Self::Admission>> {
        let () = pair.extra;
        let SelectedRootPathHalf::Import { demand, .. } = pair.import_half else {
            unreachable!("dot imports use import halves")
        };
        let SelectedRootPathHalf::Export {
            identity,
            demand: export_demand,
            ..
        } = pair.export_half
        else {
            unreachable!("export-only visitor")
        };
        debug_assert_eq!(identity.fragment().ordinal(), self.target.get());
        Ok((export_demand == demand).then_some(()))
    }

    fn descriptor(
        &self,
        pair: &RootBridgePair<'_, Self::Extra>,
        (): Self::Admission,
    ) -> SelectedRootBridgeDescriptor {
        let SelectedRootPathHalf::Import {
            identity: source,
            token,
            anchor,
            anchor_semantic,
            ..
        } = pair.import_half
        else {
            unreachable!("dot imports use import halves")
        };
        let SelectedRootPathHalf::Export {
            identity,
            token: export_token,
            ..
        } = pair.export_half
        else {
            unreachable!("export-only visitor")
        };
        SelectedRootBridgeDescriptor::from_selected_path_tokens(
            source.fragment(),
            Language::Go,
            *token,
            *anchor,
            *anchor_semantic,
            identity.fragment(),
            Language::Go,
            *export_token,
            self.route.to_vec(),
            self.demand.clone(),
            self.demand.clone(),
            self.completion.clone(),
        )
        .with_selected_export(self.names, pair.export_half)
    }

    fn fold_completion(
        &self,
        _completion: &mut ResolutionCompletion,
        _descriptor: &SelectedRootBridgeDescriptor,
    ) {
        // Import evidence remains on its bridge, as before assembly.
    }
}
