//! File-local Go import bindings from selected source and package authority.

use super::go_context::GoDotImportContext;
use super::*;
use crate::analyzer::resolution::{LoweredGoPackageImport, SelectedGoImportBindingDescriptor};
use crate::analyzer::store::resolution_stage::codec;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionGoPackageImportKind, ResolutionNamespace, ResolutionSiteId,
};

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GoExternalPackageProvenance {
    GoTool {
        provider_kind: String,
        module_path: Option<String>,
        module_version: Option<String>,
    },
    SemanticModel {
        symbol_id: String,
        pack_id: String,
        pack_digest: String,
        record_id: String,
    },
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GoSelectedExternalImport {
    pub(crate) source_spelling: String,
    pub(crate) import_path: String,
    pub(crate) package_name: String,
    pub(crate) provenance: GoExternalPackageProvenance,
}

#[cfg(any(test, feature = "test-support"))]
impl GoSelectedExternalImport {
    pub(crate) fn has_authoritative_provenance(&self) -> bool {
        match &self.provenance {
            GoExternalPackageProvenance::GoTool { provider_kind, .. } => {
                matches!(provider_kind.as_str(), "standard" | "module")
            }
            GoExternalPackageProvenance::SemanticModel {
                symbol_id,
                pack_id,
                pack_digest,
                record_id,
            } => {
                !symbol_id.is_empty()
                    && !pack_id.is_empty()
                    && !pack_digest.is_empty()
                    && !record_id.is_empty()
            }
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
const SELECTED_EXTERNAL_IMPORTS: &str = r#"
SELECT imports.source_spelling,target.tool_import_path,target.package_name,
       target.provider_kind,target.provider_module_path,target.provider_module_version
FROM main.go_context_source_files caller
JOIN main.go_package_instances importer
  ON importer.context_id=caller.context_id AND importer.package_id=caller.package_id
 AND ((caller.source_role='go' AND importer.for_test='')
   OR (caller.source_role IN ('test','xtest') AND importer.for_test<>'')
   OR (caller.source_role IN ('test','xtest') AND importer.provider_provenance='source_inventory'))
JOIN main.go_package_imports imports
  ON imports.context_id=caller.context_id
 AND imports.importer_package_id=caller.package_id
 AND imports.import_role=caller.source_role
JOIN main.go_package_instances target
  ON target.context_id=imports.context_id AND target.package_id=imports.target_package_id
WHERE caller.context_id=?1 AND caller.file_version_id=?2
  AND imports.complete=1 AND target.complete=1
  AND target.provider_kind IN ('standard','module')
  AND NOT EXISTS (SELECT 1 FROM main.go_package_files files
                  WHERE files.package_id=target.package_id)
ORDER BY imports.source_spelling,target.tool_import_path
"#;

#[cfg(any(test, feature = "test-support"))]
const SELECTED_UNRESOLVED_IMPORTS: &str = r#"
SELECT DISTINCT imports.source_spelling
FROM main.go_context_source_files caller
JOIN main.go_package_instances importer
  ON importer.context_id=caller.context_id AND importer.package_id=caller.package_id
 AND ((caller.source_role='go' AND importer.for_test='')
   OR (caller.source_role IN ('test','xtest') AND importer.for_test<>'')
   OR (caller.source_role IN ('test','xtest') AND importer.provider_provenance='source_inventory'))
JOIN main.go_package_imports imports
  ON imports.context_id=caller.context_id
 AND imports.importer_package_id=caller.package_id
 AND imports.import_role=caller.source_role
WHERE caller.context_id=?1 AND caller.file_version_id=?2
  AND imports.target_package_id IS NULL AND imports.complete=0
  AND NOT EXISTS (
    SELECT 1 FROM main.go_package_instances exact
    WHERE exact.context_id=caller.context_id
      AND exact.tool_import_path=imports.source_spelling
  )
ORDER BY imports.source_spelling
"#;

const SELECTED_IMPORT_CONTEXT_FILES: &str = r#"
WITH RECURSIVE reachable(package_id) AS (
  SELECT caller.package_id
  FROM main.go_context_source_files caller
  WHERE caller.context_id=?1 AND caller.file_version_id=?2
  UNION
  SELECT imports.target_package_id
  FROM reachable
  JOIN main.go_package_imports imports
    ON imports.context_id=?1 AND imports.importer_package_id=reachable.package_id
  WHERE imports.complete=1 AND imports.target_package_id IS NOT NULL
), source_files(file_version_id, rel_path, source_role) AS (
  SELECT DISTINCT source.file_version_id, files.rel_path, source.source_role
  FROM reachable
  JOIN main.go_context_source_files source
    ON source.context_id=?1 AND source.package_id=reachable.package_id
  JOIN main.go_package_instances package
    ON package.context_id=source.context_id AND package.package_id=source.package_id
  JOIN main.workspace_file_versions files
    ON files.file_version_id=source.file_version_id
  WHERE source.file_version_id=?2 OR source.source_role='go'
     OR (source.source_role='test' AND package.for_test<>'')
)
SELECT rel_path, source_role FROM (
  SELECT source_files.rel_path, source_files.source_role
  FROM source_files
  JOIN temp.selected_resolution_mounts mounted
    ON mounted.file_version_id=source_files.file_version_id
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=mounted.mount_ordinal
  UNION
  SELECT source_files.rel_path, source_files.source_role
  FROM source_files
  JOIN temp.selected_go_transient_placements placed
    ON placed.file_version_id=source_files.file_version_id
  JOIN temp.selected_resolution_scope_mounts selected
    ON selected.mount_ordinal=placed.mount_ordinal
)
ORDER BY rel_path, source_role
"#;

pub(in crate::analyzer::store) const CALLER_SOURCE_ROLE: &str = r#"
SELECT caller.source_role
FROM main.go_context_source_files caller
JOIN main.go_package_instances package
  ON package.context_id=caller.context_id AND package.package_id=caller.package_id
WHERE caller.context_id=?1 AND caller.file_version_id=?2
 AND ((caller.source_role='go' AND package.for_test='')
   OR (caller.source_role IN ('test','xtest') AND package.for_test<>'')
   OR (caller.source_role='test' AND package.for_test='' AND package.complete=0
       AND NOT EXISTS(
         SELECT 1
         FROM main.go_context_source_files selected_test
         JOIN main.go_package_instances selected_package
           ON selected_package.context_id=selected_test.context_id
          AND selected_package.package_id=selected_test.package_id
         WHERE selected_test.context_id=caller.context_id
           AND selected_test.file_version_id=caller.file_version_id
           AND selected_test.source_role='test'
           AND selected_package.for_test<>''
       ))
   OR (caller.source_role IN ('test','xtest') AND package.provider_provenance='source_inventory'))
"#;

pub(in crate::analyzer::store) const ORDINARY_IMPORT_BINDINGS: &str = r#"
SELECT p.definition_key,p.source_site,p.file_scope_key,p.spelling_choice_key,
       p.start_byte,p.end_byte,p.kind,i.import_id
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN main.resolution_go_package_imports p ON p.blob_id=mounted.blob_id
LEFT JOIN main.source_imports i ON i.blob_id=p.blob_id
 AND i.declaration_start_byte=p.start_byte AND i.declaration_end_byte=p.end_byte
WHERE selected.mount_ordinal=?1
"#;

pub(in crate::analyzer::store) const STAGED_IMPORT_BINDINGS: &str = r#"
SELECT p.definition_key,p.source_site,p.file_scope_key,p.spelling_choice_key,
       p.start_byte,p.end_byte,p.kind,i.import_id
FROM temp.selected_resolution_scope_mounts selected
JOIN temp.selected_resolution_mounts mounted ON mounted.mount_ordinal=selected.mount_ordinal
JOIN temp.selected_resolution_stage_go_package_imports p ON p.host_ordinal=selected.mount_ordinal
LEFT JOIN main.source_imports i ON i.blob_id=mounted.blob_id
 AND i.declaration_start_byte=p.start_byte AND i.declaration_end_byte=p.end_byte
WHERE selected.mount_ordinal=?1
"#;

pub(in crate::analyzer::store) const IMPORT_PACKAGE_NAME: &str = r#"
SELECT target.package_name,target.package_id
FROM main.go_package_imports imports
JOIN main.go_package_instances target
 ON target.context_id=imports.context_id AND target.package_id=imports.target_package_id
WHERE imports.context_id=?1 AND imports.importer_package_id=?2
 AND imports.import_role=?3 AND imports.source_spelling=?4
"#;

#[derive(Clone, Copy, PartialEq, Eq)]
struct GoImportBindingRow {
    metadata: LoweredGoPackageImport,
    source_import: usize,
}

impl GoImportBindingRow {
    fn source(
        row: &rusqlite::Row<'_>,
        definition: SemanticId,
        file_scope: BindingNodeId,
        spelling_choice: SemanticId,
    ) -> Result<Self> {
        Ok(Self {
            metadata: LoweredGoPackageImport {
                definition,
                source_site: ResolutionSiteId::new(row.get(1)?),
                file_scope,
                spelling_choice,
                start_byte: row.get(4)?,
                end_byte: row.get(5)?,
                kind: ResolutionGoPackageImportKind::from_label(&row.get::<_, String>(6)?)
                    .ok_or_else(|| StoreError::corrupt("invalid Go import kind"))?,
            },
            source_import: row.get::<_, Option<usize>>(7)?.ok_or_else(|| {
                StoreError::corrupt("Go import metadata lacks exact sealed source import span")
            })?,
        })
    }

    fn ordinary(row: &rusqlite::Row<'_>, ordinal: u32) -> Result<Self> {
        Self::source(
            row,
            SemanticId::local(ordinal, row.get(0)?),
            BindingNodeId::local(ordinal, row.get(2)?),
            SemanticId::local(ordinal, row.get(3)?),
        )
    }

    fn staged(row: &rusqlite::Row<'_>) -> Result<Self> {
        Self::source(
            row,
            codec::decode_semantic(row.get(0)?),
            codec::decode_node(row.get(2)?),
            codec::decode_semantic(row.get(3)?),
        )
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Return this caller's complete, source-less standard/dependency import
    /// targets. The vector is request-owned and bounded by this file's imports.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn go_selected_external_imports(
        &self,
        context_id: i64,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<GoSelectedExternalImport>> {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let Some(source) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(Vec::new());
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let Some(version) = super::go_context::go_placement_file_version(
            self.ready.inventory.connection(),
            &record,
        )?
        else {
            return Ok(Vec::new());
        };
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(SELECTED_EXTERNAL_IMPORTS)?;
        let mut rows = statement.query(rusqlite::params![context_id, version])?;
        let mut imports = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            imports.push(GoSelectedExternalImport {
                source_spelling: row.get(0)?,
                import_path: row.get(1)?,
                package_name: row.get(2)?,
                provenance: GoExternalPackageProvenance::GoTool {
                    provider_kind: row.get(3)?,
                    module_path: row.get(4)?,
                    module_version: row.get(5)?,
                },
            });
        }
        Ok(imports)
    }

    /// Return only exact unresolved import spellings from this selected
    /// source file. A caller may match these to a semantic model by exact
    /// import path; no path-derived package name is supplied here.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn go_selected_unresolved_imports(
        &self,
        context_id: i64,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Vec<String>> {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let Some(source) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(Vec::new());
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let Some(version) = super::go_context::go_placement_file_version(
            self.ready.inventory.connection(),
            &record,
        )?
        else {
            return Ok(Vec::new());
        };
        let connection = self.ready.inventory.connection();
        let mut statement = connection.prepare_cached(SELECTED_UNRESOLVED_IMPORTS)?;
        let mut rows = statement.query(rusqlite::params![context_id, version])?;
        let mut imports = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            imports.push(row.get(0)?);
        }
        Ok(imports)
    }

    /// Choose the caller role from its exact selected package membership.
    /// Filename spelling cannot authorize an ordinary or test-package query,
    /// and an unsaved replacement uses its predecessor's membership only when
    /// the membership digests prove the Go tool would place it identically.
    pub(crate) fn go_selected_import_context(
        &self,
        context_id: i64,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<GoDotImportContext> {
        if cancellation.is_cancelled() {
            return Ok(GoDotImportContext::Cancelled);
        }
        let Some(source) = self.mount_table().mount_for_path("go", caller_path)? else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let connection = self.ready.inventory.connection();
        let Some(version) = super::go_context::go_placement_file_version(connection, &record)?
        else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let mut statement = connection.prepare_cached(CALLER_SOURCE_ROLE)?;
        let mut rows = statement.query(rusqlite::params![context_id, version])?;
        let mut source_role = None;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
            let role: String = row.get(0)?;
            if source_role
                .as_ref()
                .is_some_and(|previous| previous != &role)
            {
                return Ok(GoDotImportContext::Unavailable);
            }
            source_role = Some(role);
        }
        drop(rows);
        drop(statement);
        let Some(_source_role) = source_role else {
            return Ok(GoDotImportContext::Unavailable);
        };
        let mut statement = connection.prepare_cached(SELECTED_IMPORT_CONTEXT_FILES)?;
        let mut rows = statement.query(rusqlite::params![context_id, version])?;
        let mut files = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
            files.push((row.get::<_, String>(0)?, row.get::<_, String>(1)?));
        }
        drop(rows);
        drop(statement);
        let mut context: Option<SelectedResolutionContextSet> = None;
        for (path, role) in files {
            if cancellation.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
            let next =
                match self.go_import_binding_context(context_id, &path, &role, cancellation)? {
                    GoDotImportContext::Ready(context) => context,
                    GoDotImportContext::Unavailable => return Ok(GoDotImportContext::Unavailable),
                    GoDotImportContext::Cancelled => return Ok(GoDotImportContext::Cancelled),
                };
            context = Some(if let Some(context) = context {
                let mounts = self.mount_table();
                let Some(context) = context.merge(next, cancellation, &|fragment| {
                    Ok(mounts
                        .mount_for_fragment(fragment)?
                        .map(|mount| (mount.ordinal(), mount.semantic_language())))
                })?
                else {
                    return Ok(GoDotImportContext::Cancelled);
                };
                context
            } else {
                next
            });
        }
        Ok(context.map_or(GoDotImportContext::Unavailable, GoDotImportContext::Ready))
    }

    /// Bind explicit aliases and selected canonical package names in this file.
    /// Then resolve positioned prefixes and admit only their exact package
    /// exports. Package bindings never establish a nominal receiver type.
    pub(crate) fn go_import_binding_context(
        &self,
        context_id: i64,
        caller_path: &str,
        source_role: &str,
        cancellation: &CancellationToken,
    ) -> Result<GoDotImportContext> {
        let context =
            match self.go_package_context(context_id, caller_path, source_role, cancellation)? {
                GoDotImportContext::Ready(context) => context,
                other => return Ok(other),
            };
        let source = self
            .mount_table()
            .mount_for_path("go", caller_path)?
            .expect("package context validated its caller mount");
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let connection = self.ready.inventory.connection();
        let version = super::go_context::go_placement_file_version(connection, &record)?
            .expect("package context requires a selected placement");
        let package: i64 = connection
            .prepare_cached(super::go_same_package::CALLER_PACKAGE)?
            .query_row(rusqlite::params![context_id, version, source_role], |row| {
                row.get(0)
            })?;
        let Some(imports) =
            super::super::source_facts::read_source_imports(connection, record.blob_id(), &|| {
                !cancellation.is_cancelled()
            })?
        else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let mut metadata = BTreeMap::new();
        let mut statement = connection.prepare_cached(STAGED_IMPORT_BINDINGS)?;
        let mut rows = statement.query([source.ordinal().get()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
            let fact = GoImportBindingRow::staged(row)?;
            if metadata
                .insert(fact.metadata.definition, fact)
                .is_some_and(|prior| prior != fact)
            {
                return Err(StoreError::corrupt(
                    "contradictory staged Go import binding metadata",
                ));
            }
        }
        drop(rows);
        let mut statement = connection.prepare_cached(ORDINARY_IMPORT_BINDINGS)?;
        let mut rows = statement.query([source.ordinal().get()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
            let fact = GoImportBindingRow::ordinary(row, source.ordinal().get())?;
            metadata.entry(fact.metadata.definition).or_insert(fact);
        }
        drop(rows);
        let names = self.ready.shared_names();
        let lexical = self.ready.lexical_source();
        let completion = context.inventory_completion().clone();
        let mut bindings = Vec::new();
        let mut providers = HashMap::default();
        for row in metadata.into_values() {
            if cancellation.is_cancelled() {
                return Ok(GoDotImportContext::Cancelled);
            }
            if row.metadata.kind == ResolutionGoPackageImportKind::Blank {
                continue;
            }
            let import = imports.get(row.source_import).ok_or_else(|| {
                StoreError::corrupt("Go import metadata names absent source import")
            })?;
            let Some(path) = &import.path else {
                return Err(StoreError::corrupt(
                    "Go package import has no structured source path",
                ));
            };
            let spelling = path.segments.join("/");
            let package_target: Option<(String, i64)> = connection
                .prepare_cached(IMPORT_PACKAGE_NAME)?
                .query_row(
                    rusqlite::params![context_id, package, source_role, spelling],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some(name) = import
                .alias
                .as_deref()
                .or(package_target.as_ref().map(|(name, _)| name.as_str()))
            else {
                // Canonical publication keeps a missing provider explicitly
                // incomplete; no path basename may invent the default name.
                assert!(
                    !matches!(completion, ResolutionCompletion::Complete),
                    "missing canonical import name requires incomplete publication"
                );
                continue;
            };
            let Some(definition_node) =
                lexical.lookup_definition_node(row.metadata.definition, cancellation)?
            else {
                if cancellation.is_cancelled() {
                    return Ok(GoDotImportContext::Cancelled);
                }
                return Err(StoreError::corrupt(
                    "Go import metadata has no selected definition node",
                ));
            };
            if let Some((_, package)) = &package_target {
                providers.insert(row.metadata.definition, *package);
            }
            bindings.push(SelectedGoImportBindingDescriptor::new(
                source.fragment(),
                &row.metadata,
                definition_node,
                ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Package,
                    name,
                )
                .semantic(&names),
                completion.clone(),
            ));
        }
        let mounts = self.mount_table();
        let Some(context) =
            context.extend_go_import_bindings(bindings, cancellation, &|fragment| {
                Ok(mounts
                    .mount_for_fragment(fragment)?
                    .map(|mount| (mount.ordinal(), mount.semantic_language())))
            })?
        else {
            return Ok(GoDotImportContext::Cancelled);
        };
        self.go_qualified_import_context(
            context,
            source.ordinal(),
            context_id,
            &providers,
            cancellation,
        )
    }

    /// Authorize package exports only through definitions actually reached by
    /// the positioned lexical prefix. Local values and types remain blockers.
    fn go_qualified_import_context(
        &self,
        context: SelectedResolutionContextSet,
        source: SelectedResolutionMountOrdinal,
        context_id: i64,
        providers: &HashMap<SemanticId, i64>,
        cancellation: &CancellationToken,
    ) -> Result<GoDotImportContext> {
        let lexical = self.ready.lexical_source();
        let identities = self.ready.context_identities.clone();
        let mut halves = Vec::new();
        let outcome = visit_selected_root_import_half_pages(
            &identities,
            &lexical,
            &lexical,
            Some(&[source]),
            cancellation,
            &mut FactPageVisitor::new(&mut |page| {
                halves.extend(
                    page.iter()
                        .filter(|half| {
                            matches!(
                                half,
                                SelectedRootPathHalf::Reference {
                                    prefix_reference: Some(_),
                                    ..
                                }
                            )
                        })
                        .cloned(),
                );
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(GoDotImportContext::Cancelled);
        }
        if halves.is_empty() {
            return Ok(GoDotImportContext::Ready(context));
        }
        let mut references = halves
            .iter()
            .map(|half| match half {
                SelectedRootPathHalf::Reference {
                    prefix_reference: Some(reference),
                    route,
                    ..
                } => {
                    assert!(
                        route.is_empty(),
                        "Go package qualifier has exactly one prefix segment"
                    );
                    *reference
                }
                _ => unreachable!("qualified reference filter"),
            })
            .collect::<Vec<_>>();
        references.sort_unstable();
        references.dedup();
        let Some(blueprint) = self.prepare_prefix_blueprint(context.clone(), cancellation)? else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let typed = self.ready.typed_source();
        let resolutions = blueprint.with_forward_operation_in_session(
            &lexical,
            &lexical,
            &typed,
            cancellation,
            &ResolutionSession::unbounded(),
            |operation| {
                let mut resolutions = HashMap::default();
                for references in references.chunks(MAX_REFERENCE_SEEDS_PER_BATCH) {
                    let batch = operation.resolve_references_with_metrics(
                        references,
                        &mut ResolutionBatchMetrics::default(),
                    )?;
                    if cancellation.is_cancelled()
                        || batch
                            .completion()
                            .contains_reason(ResolutionIncompleteReason::Cancelled)
                    {
                        return Ok(None);
                    }
                    for answer in batch.answers() {
                        let binding = answer.answer().binding();
                        assert_eq!(
                            answer
                                .answer()
                                .site_metadata()
                                .expect("positioned Go prefix metadata")
                                .namespace(),
                            ResolutionNamespace::TypeOrValue
                        );
                        resolutions.insert(
                            answer.reference(),
                            (binding.targets().to_vec(), binding.completion().clone()),
                        );
                    }
                }
                Ok(Some(resolutions))
            },
        )?;
        let Some(resolutions) = resolutions else {
            return Ok(GoDotImportContext::Cancelled);
        };
        let mut bridges = Vec::new();
        for half in halves {
            let SelectedRootPathHalf::Reference {
                identity,
                prefix_reference: Some(prefix),
                token,
                anchor,
                anchor_semantic,
                demand,
                ..
            } = half
            else {
                unreachable!("qualified reference filter")
            };
            let (targets, completion) = resolutions
                .get(&prefix)
                .expect("every requested prefix has an answer");
            let SelectedLookupRecipeReadOutcome::Ready(recipes) = lexical.lookup_semantic_recipes(
                &[SelectedLookupRecipeRequest {
                    fragment: identity.fragment(),
                    semantic: demand,
                }],
                cancellation,
                None,
            )?
            else {
                return Ok(GoDotImportContext::Cancelled);
            };
            let recipe =
                recipes.into_iter().next().flatten().ok_or_else(|| {
                    StoreError::corrupt("Go qualified demand lacks lookup recipe")
                })?;
            for target in targets {
                let Some(package) = providers.get(target) else {
                    continue;
                };
                let connection = self.ready.inventory.connection();
                let mut statement = connection.prepare_cached(NAMED_IMPORT_TARGET_MOUNTS)?;
                let mut rows = statement.query(rusqlite::params![context_id, package])?;
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(GoDotImportContext::Cancelled);
                    }
                    let ordinal = SelectedResolutionMountOrdinal::new(row.get(0)?);
                    let outcome = visit_selected_root_export_half_pages(
                        &identities,
                        &lexical,
                        &lexical,
                        Some(&[ordinal]),
                        cancellation,
                        &mut FactPageVisitor::new(&mut |page| {
                            for export in page {
                                let SelectedRootPathHalf::Export {
                                    identity: target,
                                    token: export_token,
                                    demand: export_demand,
                                    ..
                                } = export
                                else {
                                    unreachable!("export-only visitor")
                                };
                                if *export_demand == demand {
                                    bridges.push(SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
                                        identity.fragment(), Language::Go, token, anchor, anchor_semantic,
                                        target.fragment(), Language::Go, *export_token, prefix,
                                        Vec::new(), recipe.clone(), recipe.clone(),
                                        completion.combine(context.inventory_completion()),
                                    ).with_selected_export(&self.ready.shared_names(), export));
                                }
                            }
                            Ok(true)
                        }),
                    )?;
                    if outcome.is_cancelled() {
                        return Ok(GoDotImportContext::Cancelled);
                    }
                }
            }
        }
        let mounts = self.mount_table();
        Ok(
            match context.extend_root_bridges(bridges, cancellation, None, &|fragment| {
                Ok(mounts
                    .mount_for_fragment(fragment)?
                    .map(|mount| (mount.ordinal(), mount.semantic_language())))
            })? {
                Some(context) => GoDotImportContext::Ready(context),
                None => GoDotImportContext::Cancelled,
            },
        )
    }
}

pub(in crate::analyzer::store) const NAMED_IMPORT_TARGET_MOUNTS: &str = r#"
SELECT mounted.mount_ordinal
FROM main.go_context_source_files provider
JOIN main.go_package_instances package ON package.context_id=provider.context_id AND package.package_id=provider.package_id
JOIN temp.selected_resolution_mounts mounted ON mounted.file_version_id=provider.file_version_id
JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=mounted.mount_ordinal
WHERE provider.context_id=?1 AND provider.package_id=?2
 AND (provider.source_role='go' OR (provider.source_role='test' AND package.for_test<>''))
 AND mounted.storage_language='go'
UNION ALL
SELECT placed.mount_ordinal
FROM main.go_context_source_files provider
JOIN main.go_package_instances package ON package.context_id=provider.context_id AND package.package_id=provider.package_id
JOIN temp.selected_go_transient_placements placed ON placed.file_version_id=provider.file_version_id
JOIN temp.selected_resolution_scope_mounts selected ON selected.mount_ordinal=placed.mount_ordinal
WHERE provider.context_id=?1 AND provider.package_id=?2
 AND (provider.source_role='go' OR (provider.source_role='test' AND package.for_test<>''))
"#;
