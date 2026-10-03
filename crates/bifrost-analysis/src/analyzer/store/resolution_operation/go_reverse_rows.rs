//! Query-local Go reverse candidates from selected package rows and shared
//! reference lookup identities. Every row is provisional until the selected
//! Go forward operation confirms it.

use super::*;
use crate::analyzer::resolution::{
    LoweredSemanticRole, ResolutionLookupSemanticRecipe, SelectedSemanticLocator,
};
use crate::analyzer::store::resolution_operation::native_units;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ALL_RESOLUTION_NAMESPACES, ResolutionNamespace,
};
use brokk_bifrost_go::declarations::go_identifier_is_exported;
use rusqlite::{OptionalExtension, params};

#[cfg(test)]
thread_local! {
    static LAST_GO_REVERSE_CANDIDATE_PLAN: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static LAST_GO_REVERSE_CANDIDATE_PATHS: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static LAST_GO_REVERSE_DEFINITION_PLAN: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

pub(crate) const GO_REVERSE_CANDIDATE_SITES_SQL: &str = r#"
WITH RECURSIVE target_package(package_id, tool_import_path, package_name) AS (
  SELECT source.package_id, package.tool_import_path, package.package_name
  FROM main.go_context_source_files AS source
  JOIN main.go_package_instances AS package
    ON package.context_id=source.context_id AND package.package_id=source.package_id
  WHERE source.context_id=?1 AND source.file_version_id=?2
), visible_packages(package_id) AS (
  SELECT package_id FROM target_package
  UNION
  SELECT test_package.package_id
  FROM main.go_package_instances AS test_package
  JOIN target_package AS target ON test_package.for_test=target.tool_import_path
  WHERE test_package.context_id=?1 AND test_package.for_test<>''
    AND (?4=1 OR test_package.package_name=target.package_name)
  UNION
  SELECT imports.importer_package_id
  FROM main.go_package_imports AS imports INDEXED BY idx_go_package_imports_target
  JOIN visible_packages AS visible ON visible.package_id=imports.target_package_id
  WHERE imports.context_id=?1 AND ?4=1
), candidate_files(file_version_id, source_role) AS (
  SELECT source.file_version_id, source.source_role
  FROM main.go_context_source_files AS source
  JOIN visible_packages AS visible ON visible.package_id=source.package_id
  WHERE source.context_id=?1
), candidate_mounts(mount_ordinal, source_role) AS (
  SELECT mounted.mount_ordinal, candidate.source_role
  FROM candidate_files AS candidate
  JOIN temp.selected_resolution_mounts AS mounted
    ON mounted.file_version_id=candidate.file_version_id
  WHERE mounted.storage_language='go'
  UNION
  SELECT placed.mount_ordinal, candidate.source_role
  FROM candidate_files AS candidate
  JOIN temp.selected_go_transient_placements AS placed
    ON placed.file_version_id=candidate.file_version_id
  JOIN temp.selected_resolution_mounts AS mounted
    ON mounted.mount_ordinal=placed.mount_ordinal
  WHERE mounted.storage_language='go'
)
SELECT mounted.mount_ordinal, mounted.persisted_relative_path,
       candidate.source_role, mounted.blob_id,
       EXISTS(
         SELECT 1 FROM main.resolution_qualified_routes AS qualified
           INDEXED BY resolution_qualified_routes_source_lookup
         WHERE qualified.blob_id=mounted.blob_id AND qualified.source_lookup=?3
       ) AS has_qualified_route,
       EXISTS(
         SELECT 1 FROM main.resolution_paths AS root
           INDEXED BY resolution_paths_root_terminal
         WHERE root.blob_id=mounted.blob_id AND root.root_terminal=?3
           AND root.end_node=-1
       ) AS has_root_demand
FROM candidate_mounts AS candidate
JOIN temp.selected_resolution_mounts AS mounted
  ON mounted.mount_ordinal=candidate.mount_ordinal
WHERE mounted.storage_language='go'
  AND (
    EXISTS(
      SELECT 1 FROM main.resolution_reference_lookup_identities AS names
        INDEXED BY resolution_reference_lookup_identities_identity
      WHERE names.blob_id=mounted.blob_id AND names.identity_id=?3
    )
    OR EXISTS(
      SELECT 1 FROM main.resolution_qualified_routes AS qualified
        INDEXED BY resolution_qualified_routes_source_lookup
      WHERE qualified.blob_id=mounted.blob_id AND qualified.source_lookup=?3
    )
    OR EXISTS(
      SELECT 1 FROM main.resolution_paths AS root
        INDEXED BY resolution_paths_root_terminal
      WHERE root.blob_id=mounted.blob_id AND root.root_terminal=?3
        AND root.end_node=-1
    )
  )
"#;

const GO_REVERSE_DEFINITION_LEXICAL_LOCATION_SQL: &str = r#"
SELECT mounted.persisted_relative_path,
       declaration.name_start_byte, declaration.name_end_byte,
       declaration.name_start_line, declaration.name_end_line
FROM temp.selected_resolution_mounts AS mounted
JOIN main.resolution_semantic_sites AS semantic
  ON semantic.blob_id=mounted.blob_id AND semantic.semantic_role='definition'
 AND semantic.semantic_key=?2
JOIN main.source_fact_manifests AS source
  ON source.blob_id=mounted.blob_id AND source.publication_state='complete'
JOIN main.source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
JOIN main.source_declarations AS declaration
  ON declaration.blob_id=bridge.blob_id
 AND declaration.declaration_id=bridge.declaration_id
WHERE mounted.mount_ordinal=?1 AND mounted.storage_language='go'
  AND declaration.name_occurrence_id IS NOT NULL
"#;

pub(crate) static GO_TARGET_DEFINITION_SEMANTICS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
SELECT DISTINCT semantic.semantic_key
FROM temp.selected_resolution_mounts AS mount
JOIN main.resolution_fragment_interiors AS interior
  ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
 AND interior.semantic_language=mount.semantic_language
 AND interior.producer_epoch=mount.producer_epoch
 AND interior.interior_digest=mount.interior_digest
 AND interior.publication_state='complete'
JOIN main.source_fact_manifests AS source
  ON source.blob_id=interior.blob_id AND source.publication_state='complete'
JOIN main.resolution_semantic_sites AS semantic
  ON semantic.blob_id=interior.blob_id AND semantic.semantic_role='definition'
JOIN main.source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
JOIN main.source_declaration_units AS link
  ON link.blob_id=bridge.blob_id AND link.declaration_id=bridge.declaration_id
JOIN main.code_units AS units
  ON units.blob_id=link.blob_id AND units.unit_key=link.unit_key
JOIN main.blobs AS keys ON keys.id=units.blob_id
JOIN main.blob_meta AS meta ON meta.blob_id=units.blob_id
WHERE mount.mount_ordinal=?1 AND units.in_declarations=1
  AND {complete}
ORDER BY semantic.semantic_key
"#,
            complete = super::super::PARSED_BLOB_COMPLETE_CONDITION,
        )
    });

const GO_REVERSE_INVENTORY_COMPLETE_SQL: &str = r#"
SELECT publication.complete
   AND NOT EXISTS(
     SELECT 1 FROM main.go_package_instances AS package
     WHERE package.context_id=publication.context_id AND package.complete=0)
   AND NOT EXISTS(
     SELECT 1 FROM main.go_package_imports AS imports
     WHERE imports.context_id=publication.context_id AND imports.complete=0)
FROM main.go_context_publications AS publication
WHERE publication.context_id=?1
"#;

#[derive(Clone)]
pub(crate) struct GoReverseCandidate {
    pub(crate) locator: SelectedSemanticLocator,
    pub(crate) source_role: String,
}

pub(crate) struct GoReverseCandidateSet {
    pub(crate) target: SemanticId,
    pub(crate) candidates: Vec<GoReverseCandidate>,
    pub(crate) completion: ResolutionCompletion,
}

pub(crate) enum GoReverseCandidateOutcome {
    Ready(GoReverseCandidateSet),
    Unavailable(String),
    Cancelled,
}

pub(crate) struct GoReverseConfirmedReference {
    pub(crate) locator: SelectedSemanticLocator,
    pub(crate) answer: FactResolutionAnswer,
    pub(crate) owner: Option<CodeUnit>,
    pub(crate) binding_targets: Vec<GoReverseBindingTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoReverseBindingTarget {
    Unit(CodeUnit),
    Lexical {
        source_file: ProjectFile,
        name_range: crate::analyzer::Range,
    },
}

pub(crate) struct GoReverseConfirmed {
    pub(crate) target: SemanticId,
    pub(crate) references: Vec<GoReverseConfirmedReference>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) candidate_inventory_complete: bool,
}

pub(crate) enum GoReverseConfirmationOutcome {
    Ready(GoReverseConfirmed),
    Unavailable(String),
    Stale(String),
    Cancelled,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Select all structured same-package and importing-package sites whose
    /// shared lookup identity could name `target`. The caller still has to
    /// resolve each site in its own file-scoped Go context.
    pub(crate) fn go_reverse_candidate_sites(
        &self,
        target: &CodeUnit,
        context_id: i64,
        cancellation: &CancellationToken,
    ) -> Result<GoReverseCandidateOutcome> {
        if cancellation.is_cancelled() {
            return Ok(GoReverseCandidateOutcome::Cancelled);
        }
        let relative_path = crate::path_utils::rel_path_string(target.source());
        let Some(mount) = self.mount_table().mount_for_path("go", &relative_path)? else {
            return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                "Go target is outside the selected source mounts: {relative_path}"
            )));
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        let connection = self.ready.inventory.connection();
        let Some(file_version) = super::go_context::go_placement_file_version(connection, &record)?
        else {
            return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                "Go target has no proven selected package placement: {relative_path}"
            )));
        };

        let mut statement =
            connection.prepare_cached(GO_TARGET_DEFINITION_SEMANTICS_SQL.as_str())?;
        let semantics = statement
            .query_map([i64::from(mount.ordinal().get())], |row| {
                row.get::<_, i64>(0)
            })?
            .map(|key| {
                key.map(|key| {
                    SemanticId::local(
                        mount.ordinal().get(),
                        u32::try_from(key).expect("Go definition catalog key fits u32"),
                    )
                })
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let projected = match native_units::project_native_definition_units(
            &self.ready,
            &semantics,
            cancellation,
            &ResolutionSession::unbounded(),
        )? {
            SelectedNativeDefinitions::Ready(projected) => projected,
            SelectedNativeDefinitions::Unavailable => {
                return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                    "Go target definitions are not projectable: {relative_path}"
                )));
            }
            SelectedNativeDefinitions::Cancelled => {
                return Ok(GoReverseCandidateOutcome::Cancelled);
            }
        };
        let Some((target_semantic, _)) = projected.into_iter().find(|(_, definition)| {
            matches!(definition, SelectedNativeDefinition::Unit(unit) if unit == target)
        }) else {
            return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                "Go target has no selected definition identity: {target:?}"
            )));
        };

        let target_context =
            match self.go_selected_import_context(context_id, &relative_path, cancellation)? {
                GoDotImportContext::Ready(context) => context,
                GoDotImportContext::Unavailable => {
                    return Ok(GoReverseCandidateOutcome::Unavailable(format!(
                        "Go target import context is unavailable: {relative_path}"
                    )));
                }
                GoDotImportContext::Cancelled => {
                    return Ok(GoReverseCandidateOutcome::Cancelled);
                }
            };

        let inventory_complete: bool = connection
            .prepare_cached(GO_REVERSE_INVENTORY_COMPLETE_SQL)?
            .query_row([context_id], |row| row.get(0))
            .optional()?
            .unwrap_or(false);
        let mut completion = target_context.inventory_completion().clone();
        if !inventory_complete {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
            ]));
        }

        let target_exported = go_identifier_is_exported(target.terminal_name());
        let mut candidates = HashMap::<(String, String), HashSet<ResolutionSiteId>>::default();
        let mut candidate_mounts = HashSet::<u32>::default();
        let lexical = self.ready.lexical_source();
        for namespace in ALL_RESOLUTION_NAMESPACES
            .iter()
            .filter(|namespace| **namespace != ResolutionNamespace::TypeOrValue)
        {
            if cancellation.is_cancelled() {
                return Ok(GoReverseCandidateOutcome::Cancelled);
            }
            let lookup =
                ResolutionLookupSemanticRecipe::new(Language::Go, *namespace, target.identifier())
                    .semantic(&self.ready.shared_names());
            let identity = lookup
                .shared_name_id()
                .map(|identity| i64::from(identity.get()));
            #[cfg(test)]
            if let Some(identity) = identity {
                LAST_GO_REVERSE_CANDIDATE_PLAN.with(|last| {
                    *last.borrow_mut() = explain_go_reverse_candidate_plan(
                        connection,
                        context_id,
                        file_version,
                        identity,
                        target_exported,
                    )
                    .expect("explain populated Go reverse candidate query");
                });
            }
            let mut statement = connection.prepare_cached(GO_REVERSE_CANDIDATE_SITES_SQL)?;
            for row in statement.query_map(
                params![context_id, file_version, identity, target_exported],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, bool>(5)?,
                    ))
                },
            )? {
                let (mount_ordinal, path, source_role, blob_id, has_qualified, has_root) = row?;
                candidate_mounts.insert(mount_ordinal);
                let Some(mut sites) =
                    lexical.lookup_reference_sites(blob_id, lookup, None, cancellation)?
                else {
                    return Ok(GoReverseCandidateOutcome::Cancelled);
                };
                if has_root {
                    let Some(prefixed) = lexical.prefixed_root_demand_reference_sites(
                        blob_id,
                        lookup,
                        cancellation,
                    )?
                    else {
                        return Ok(GoReverseCandidateOutcome::Cancelled);
                    };
                    sites.extend(prefixed);
                }
                if has_qualified {
                    let Some(qualified) =
                        lexical.qualified_route_reference_sites(blob_id, lookup, cancellation)?
                    else {
                        return Ok(GoReverseCandidateOutcome::Cancelled);
                    };
                    sites.extend(qualified);
                }
                for site in sites {
                    candidates
                        .entry((path.clone(), source_role.clone()))
                        .or_default()
                        .insert(site);
                }
            }
        }

        let session = ResolutionSession::unbounded();
        let mut candidate_mounts = candidate_mounts.into_iter().collect::<Vec<_>>();
        candidate_mounts.sort_unstable();
        for &ordinal in &candidate_mounts {
            if cancellation.is_cancelled() {
                return Ok(GoReverseCandidateOutcome::Cancelled);
            }
            let mount = self
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            let enumeration = lexical.reference_inventory_completion(
                mount.fragment_id(),
                cancellation,
                &session,
            )?;
            let Some(enumeration) = lexical.close_completion(&enumeration, cancellation)? else {
                return Ok(GoReverseCandidateOutcome::Cancelled);
            };
            completion = completion.combine(&enumeration);
        }

        let mut candidates = candidates
            .into_iter()
            .flat_map(|((path, source_role), sites)| {
                sites.into_iter().map(move |site| GoReverseCandidate {
                    locator: SelectedSemanticLocator::new(
                        "go",
                        path.clone(),
                        site,
                        LoweredSemanticRole::Reference,
                    ),
                    source_role: source_role.clone(),
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.locator
                .relative_path()
                .cmp(right.locator.relative_path())
                .then_with(|| left.source_role.cmp(&right.source_role))
                .then_with(|| left.locator.cmp(&right.locator))
        });
        #[cfg(test)]
        LAST_GO_REVERSE_CANDIDATE_PATHS.with(|last| {
            *last.borrow_mut() = candidates
                .iter()
                .map(|candidate| candidate.locator.relative_path().to_owned())
                .collect();
        });
        Ok(GoReverseCandidateOutcome::Ready(GoReverseCandidateSet {
            target: target_semantic,
            candidates,
            completion,
        }))
    }

    /// Forward-confirm candidates in batches that share one caller file and
    /// its selected Go package/import context.
    pub(crate) fn confirm_go_reverse_candidates(
        mut self,
        context_id: i64,
        candidates: GoReverseCandidateSet,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<GoReverseConfirmed>> {
        let mut groups = HashMap::<(String, String), Vec<GoReverseCandidate>>::default();
        for candidate in candidates.candidates {
            groups
                .entry((
                    candidate.locator.relative_path().to_owned(),
                    candidate.source_role.clone(),
                ))
                .or_default()
                .push(candidate);
        }
        let candidate_inventory_complete =
            matches!(candidates.completion, ResolutionCompletion::Complete);
        let target_semantic = candidates.target;
        let mut references = Vec::new();
        let mut completion = candidates.completion;
        for ((path, source_role), mut candidates) in groups {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            candidates.sort_by(|left, right| left.locator.cmp(&right.locator));
            let context = match self.go_import_binding_context(
                context_id,
                &path,
                &source_role,
                cancellation,
            )? {
                GoDotImportContext::Ready(context) => context,
                GoDotImportContext::Unavailable => {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                    ]));
                    continue;
                }
                GoDotImportContext::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            let context = match self.prepare_context(context, cancellation, context_metrics)? {
                SelectedResolutionContextValidationOutcome::Ready(context) => context,
                SelectedResolutionContextValidationOutcome::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            let ready = &self.ready;
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint = match ready.collect_blueprint(context, cancellation)? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    ..
                } => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancellation_completion,
                    ));
                }
            };
            if matches!(
                ready.register_context(&blueprint, cancellation)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let mut located = Vec::with_capacity(candidates.len());
            for candidate in candidates {
                match ready.lookup_locator(&persisted_lexical, &candidate.locator, cancellation)? {
                    LocatedSemantic::Found(reference) => located.push((candidate, reference)),
                    LocatedSemantic::Missing => {
                        return Err(StoreError::corrupt(format!(
                            "Go reverse candidate locator is absent from selected source: {:?}",
                            candidate.locator
                        )));
                    }
                    LocatedSemantic::Cancelled => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancelled_completion(),
                        ));
                    }
                }
            }
            let (answers, forward_completion) = blueprint.with_forward_operation_in_session(
                &observed_lexical,
                &persisted_lexical,
                &observed_typed,
                cancellation,
                &ResolutionSession::unbounded(),
                |operation| {
                    let mut answers = Vec::with_capacity(located.len());
                    for (candidate, reference) in located {
                        if cancellation.is_cancelled() {
                            return Ok((Vec::new(), cancelled_completion()));
                        }
                        let mut metrics = ResolutionBatchMetrics::default();
                        let answer =
                            operation.resolve_reference_with_metrics(reference, &mut metrics)?;
                        answers.push((candidate, answer));
                    }
                    let completion = answers
                        .iter()
                        .fold(ResolutionCompletion::Complete, |completion, (_, answer)| {
                            completion.combine(answer.completion())
                        });
                    Ok((answers, completion))
                },
            )?;
            completion = completion.combine(&forward_completion);
            let mut definition_semantics = Vec::new();
            for (_, answer) in &answers {
                if let Some(Some(owner)) = answer.reference_owner() {
                    definition_semantics.push(owner);
                }
                definition_semantics.extend(answer.binding().targets().iter().copied());
            }
            definition_semantics.sort_unstable();
            definition_semantics.dedup();
            let definitions = match native_units::project_native_definition_units(
                &self.ready,
                &definition_semantics,
                cancellation,
                &ResolutionSession::unbounded(),
            )? {
                SelectedNativeDefinitions::Ready(rows) => rows,
                SelectedNativeDefinitions::Unavailable => {
                    let mut projected = Vec::new();
                    for semantic in &definition_semantics {
                        match native_units::project_native_definition_units(
                            &self.ready,
                            std::slice::from_ref(semantic),
                            cancellation,
                            &ResolutionSession::unbounded(),
                        )? {
                            SelectedNativeDefinitions::Ready(mut rows) => {
                                projected.append(&mut rows);
                            }
                            SelectedNativeDefinitions::Unavailable => {
                                completion =
                                    completion.combine(&ResolutionCompletion::incomplete([
                                        ResolutionIncompleteReason::UnsupportedSemantic(*semantic),
                                    ]));
                            }
                            SelectedNativeDefinitions::Cancelled => {
                                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                                    cancelled_completion(),
                                ));
                            }
                        }
                    }
                    projected
                }
                SelectedNativeDefinitions::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            let mut owner_units = HashMap::default();
            let mut lexical_definition_locations = HashMap::default();
            for (semantic, definition) in definitions {
                match definition {
                    SelectedNativeDefinition::Unit(unit) => {
                        owner_units.insert(semantic, Some(unit));
                    }
                    SelectedNativeDefinition::Lexical(definition) => {
                        if let Some(source_file) = definition.source_file {
                            lexical_definition_locations
                                .insert(semantic, (source_file, definition.name_range));
                        }
                        owner_units.insert(semantic, None);
                    }
                }
            }
            let connection = self.ready.inventory.connection();
            let mut lexical_location =
                connection.prepare_cached(GO_REVERSE_DEFINITION_LEXICAL_LOCATION_SQL)?;
            for &semantic in &definition_semantics {
                if owner_units.contains_key(&semantic)
                    || lexical_definition_locations.contains_key(&semantic)
                {
                    continue;
                }
                if cancellation.is_cancelled() {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
                let Some(crate::analyzer::resolution::SelectedSemanticProvenance::FragmentLocal(
                    local,
                )) = self
                    .ready
                    .lexical_source()
                    .semantic_provenance(semantic, cancellation)?
                else {
                    continue;
                };
                #[cfg(test)]
                {
                    let plan = explain_go_reverse_definition_plan(
                        connection,
                        i64::from(local.mount().ordinal().get()),
                        local.local_key().get(),
                    )?;
                    LAST_GO_REVERSE_DEFINITION_PLAN.with(|last| *last.borrow_mut() = plan);
                }
                let location = lexical_location
                    .query_row(
                        params![
                            i64::from(local.mount().ordinal().get()),
                            local.local_key().get()
                        ],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                crate::analyzer::Range {
                                    start_byte: row.get(1)?,
                                    end_byte: row.get(2)?,
                                    start_line: row.get(3)?,
                                    end_line: row.get(4)?,
                                },
                            ))
                        },
                    )
                    .optional()?;
                if let Some((relative_path, name_range)) = location {
                    lexical_definition_locations.insert(
                        semantic,
                        (
                            crate::analyzer::ProjectFile::new(
                                self.ready.project.root(),
                                relative_path,
                            ),
                            name_range,
                        ),
                    );
                }
            }
            drop(lexical_location);
            for (candidate, answer) in answers {
                let owner = answer
                    .reference_owner()
                    .flatten()
                    .and_then(|semantic| owner_units.get(&semantic).cloned().flatten());
                let binding_targets = answer
                    .binding()
                    .targets()
                    .iter()
                    .filter_map(|semantic| {
                        if let Some(Some(unit)) = owner_units.get(semantic) {
                            return Some(GoReverseBindingTarget::Unit(unit.clone()));
                        }
                        lexical_definition_locations.get(semantic).map(
                            |(source_file, name_range)| GoReverseBindingTarget::Lexical {
                                source_file: source_file.clone(),
                                name_range: *name_range,
                            },
                        )
                    })
                    .collect();
                references.push(GoReverseConfirmedReference {
                    locator: candidate.locator,
                    answer,
                    owner,
                    binding_targets,
                });
            }
        }
        self.ready.finish(
            GoReverseConfirmed {
                target: candidates.target,
                references,
                completion: completion.clone(),
                candidate_inventory_complete,
            },
            &completion,
            cancellation,
        )
    }
}

#[cfg(test)]
pub(crate) fn explain_go_reverse_candidate_plan(
    connection: &rusqlite::Connection,
    context_id: i64,
    file_version: i64,
    identity: i64,
    target_exported: bool,
) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(&format!(
        "EXPLAIN QUERY PLAN {GO_REVERSE_CANDIDATE_SITES_SQL}"
    ))?;
    statement
        .query_map(
            params![context_id, file_version, identity, target_exported],
            |row| row.get(3),
        )?
        .collect()
}

#[cfg(test)]
pub(crate) fn explain_go_reverse_definition_plan(
    connection: &rusqlite::Connection,
    mount_ordinal: i64,
    semantic_key: i64,
) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(&format!(
        "EXPLAIN QUERY PLAN {GO_REVERSE_DEFINITION_LEXICAL_LOCATION_SQL}"
    ))?;
    statement
        .query_map(params![mount_ordinal, semantic_key], |row| row.get(3))?
        .collect()
}

#[cfg(test)]
pub(crate) fn last_go_reverse_candidate_plan_for_test() -> Vec<String> {
    LAST_GO_REVERSE_CANDIDATE_PLAN.with(|last| last.borrow().clone())
}

#[cfg(test)]
pub(crate) fn last_go_reverse_candidate_paths_for_test() -> Vec<String> {
    LAST_GO_REVERSE_CANDIDATE_PATHS.with(|last| last.borrow().clone())
}

#[cfg(test)]
pub(crate) fn last_go_reverse_definition_plan_for_test() -> Vec<String> {
    LAST_GO_REVERSE_DEFINITION_PLAN.with(|last| last.borrow().clone())
}

#[cfg(test)]
pub(crate) fn mark_go_context_incomplete_for_test(
    store: &super::super::AnalyzerStore,
    context_id: i64,
) -> Result<()> {
    store.conn.execute(move |connection| {
        connection.execute(
            "UPDATE go_context_publications SET complete=0 WHERE context_id=?1",
            [context_id],
        )?;
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn seed_go_reverse_plan_decoys_for_test(
    store: &super::super::AnalyzerStore,
    context_id: i64,
    importer_path: &'static str,
    count: usize,
) -> Result<()> {
    store.conn.execute(move |connection| {
        let tx = connection.transaction()?;
        let importer_package: i64 = tx.query_row(
            "SELECT package_id FROM go_context_source_files WHERE context_id=?1 AND rel_path=?2",
            params![context_id, importer_path],
            |row| row.get(0),
        )?;
        for index in 0..count {
            let import_path = format!("example.test/reverse-decoy{index}");
            tx.execute(
                "INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps) VALUES(?1,?2,'decoy','','',zeroblob(32),1,jsonb('[]'))",
                params![context_id, import_path],
            )?;
            let decoy = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps) VALUES(?1,?2,?3,'go',?4,1,jsonb('[]'))",
                params![context_id, importer_package, format!("example.test/reverse-decoy{index}"), decoy],
            )?;
        }
        tx.commit()?;
        Ok(())
    })
}
