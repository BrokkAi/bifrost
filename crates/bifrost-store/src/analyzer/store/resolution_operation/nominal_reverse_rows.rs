//! Query-local nominal reverse candidates from the shared lookup identity index.
//! Candidate rows are provisional; each selected file-scoped forward
//! operation confirms every returned reference.

use super::nominal_reverse::*;
pub use super::nominal_reverse::{
    NominalReverseCandidateOutcome, NominalReverseCandidateSet, NominalReverseConfirmed,
    NominalReverseConfirmedReference,
};
use super::nominal_rules::nominal_language_rules;
use super::reverse::*;
use super::*;
use crate::analyzer::resolution::{ResolutionLookupSemanticRecipe, SelectedSemanticLocator};
use crate::analyzer::store::resolution_operation::native_units;
use brokk_bifrost_core::analyzer::common::language_for_target;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ALL_RESOLUTION_NAMESPACES, ResolutionNamespace, ResolutionSiteId,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use rusqlite::OptionalExtension;
use std::collections::VecDeque;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static LAST_JVM_REVERSE_CANDIDATE_PLAN: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

static JVM_REVERSE_DEFINITION_SEMANTICS_SQL: std::sync::LazyLock<String> =
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
WHERE mount.mount_ordinal=?1 AND mount.storage_language=?2
  AND units.in_declarations=1
  AND {complete}
"#,
            complete = super::super::PARSED_BLOB_COMPLETE_CONDITION,
        )
    });

pub(crate) const JVM_REVERSE_CANDIDATE_MOUNTS_SQL: &str = r#"
SELECT mount.mount_ordinal, mount.storage_language, mount.persisted_relative_path, mount.blob_id,
       meta.content_package,
       EXISTS(
         SELECT 1 FROM main.resolution_qualified_routes AS route
           INDEXED BY resolution_qualified_routes_source_lookup
         WHERE route.blob_id=mount.blob_id AND route.source_lookup=?1
       ) AS has_qualified_route,
       EXISTS(
         SELECT 1 FROM main.resolution_paths AS root
           INDEXED BY resolution_paths_root_terminal
         WHERE root.blob_id=mount.blob_id AND root.root_terminal=?1
           AND root.end_node=-1
       ) AS has_root_demand
FROM temp.selected_resolution_mounts AS mount
JOIN main.blob_meta AS meta ON meta.blob_id=mount.blob_id
WHERE mount.storage_language=?2 AND mount.semantic_language=?3
  AND (
    EXISTS(
      SELECT 1 FROM main.resolution_reference_lookup_identities AS names
        INDEXED BY resolution_reference_lookup_identities_identity
      WHERE names.blob_id=mount.blob_id AND names.identity_id=?1
    )
    OR EXISTS(
      SELECT 1 FROM main.resolution_qualified_routes AS route
        INDEXED BY resolution_qualified_routes_source_lookup
      WHERE route.blob_id=mount.blob_id AND route.source_lookup=?1
    )
    OR EXISTS(
      SELECT 1 FROM main.resolution_paths AS root
        INDEXED BY resolution_paths_root_terminal
        WHERE root.blob_id=mount.blob_id AND root.root_terminal=?1
          AND root.end_node=-1
    )
    OR EXISTS(
      SELECT 1 FROM main.resolution_paths AS reference_path
        INDEXED BY resolution_paths_end_lookup_identity
      JOIN main.resolution_sites AS site
        ON site.blob_id=reference_path.blob_id
       AND site.site=reference_path.start_node AND site.role=0
      WHERE reference_path.blob_id=mount.blob_id
        AND reference_path.end_lead_identity=?1
    )
  )
"#;

const JVM_REVERSE_REFERENCE_SEMANTIC_SQL: &str = "SELECT semantic_key FROM main.resolution_semantic_sites WHERE blob_id=?1 AND source_site=?2 AND semantic_role='reference'";

struct NominalReverseCandidateMount {
    ordinal: u32,
    candidate_language: String,
    path: String,
    blob_id: i64,
    package: Option<String>,
    has_root: bool,
    sites: Vec<(ResolutionSiteId, ReverseNominationRoute)>,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Find every selected JVM source site whose indexed lookup identity could
    /// refer to the JVM `target`, then narrow by its declaration access.
    /// Fully qualified references do not require an import, so no importer
    /// filter is applied here.
    #[doc(hidden)]
    pub fn nominal_reverse_candidate_sites(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<NominalReverseCandidateOutcome> {
        if cancellation.is_cancelled() {
            return Ok(NominalReverseCandidateOutcome::Cancelled);
        }
        let language = language_for_target(target);
        let Some(language_rules) = nominal_language_rules(language) else {
            return Ok(NominalReverseCandidateOutcome::TargetUncovered(format!(
                "non-JVM target: {target:?}"
            )));
        };
        let rules = language_rules.reverse_target_rules();
        let Some((_, target_storage_language)) = rules
            .candidate_languages()
            .iter()
            .find(|(candidate, _)| *candidate == language)
        else {
            return Ok(NominalReverseCandidateOutcome::TargetUncovered(format!(
                "non-JVM target: {target:?}"
            )));
        };
        let relative_path = crate::path_utils::rel_path_string(target.source());
        let Some(target_mount) = self
            .ready
            .inventory
            .mount_record_for_path(target_storage_language, &relative_path)?
        else {
            return Ok(NominalReverseCandidateOutcome::TargetUncovered(format!(
                "JVM target is outside the selected source mounts: {relative_path}"
            )));
        };
        let connection = self.ready.inventory.connection();
        let mut statement =
            connection.prepare_cached(JVM_REVERSE_DEFINITION_SEMANTICS_SQL.as_str())?;
        let target_semantics = statement
            .query_map(
                rusqlite::params![
                    i64::from(target_mount.ordinal().get()),
                    target_storage_language
                ],
                |row| row.get::<_, i64>(0),
            )?
            .map(|key| {
                key.map(|key| {
                    SemanticId::local(
                        target_mount.ordinal().get(),
                        u32::try_from(key).expect("JVM definition key fits u32"),
                    )
                })
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let target_definitions = match native_units::project_native_definition_units(
            &self.ready,
            &target_semantics,
            cancellation,
            &ResolutionSession::unbounded(),
        )? {
            SelectedNativeDefinitions::Ready(rows) => rows,
            SelectedNativeDefinitions::Unavailable => {
                return Ok(NominalReverseCandidateOutcome::Unavailable(format!(
                    "JVM target definitions are not projectable: {relative_path}"
                )));
            }
            SelectedNativeDefinitions::Cancelled => {
                return Ok(NominalReverseCandidateOutcome::Cancelled);
            }
        };
        let Some((target_semantic, _)) = target_definitions.iter().find(|(_, definition)| {
            matches!(definition, SelectedNativeDefinition::Unit(unit) if unit == target)
        }) else {
            return Ok(NominalReverseCandidateOutcome::TargetUncovered(format!(
                "JVM target has no selected definition identity: {target:?}"
            )));
        };

        let target_semantic = *target_semantic;
        let NominalReverseTargetAccess {
            visibility,
            owner: owner_semantic,
            boundary,
            completion,
        } = rules.target_access(self, target_semantic, target, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(NominalReverseCandidateOutcome::Cancelled);
        }
        let mut evidence = Box::new(ReverseEvidence::new(target_semantic));
        evidence.binding.record(
            ReverseSubject::Target(target_semantic),
            ReverseEvidenceOrigin::Access,
            completion,
        );
        let mut surfaces = Vec::new();
        let target_package = target.package_name();
        let descriptor = NominalReverseTarget {
            storage_language: target_storage_language,
            semantic: target_semantic,
            unit: target,
            owner: owner_semantic,
            package: target_package,
            visibility,
            boundary,
        };
        let mut families =
            rules.target_families(&descriptor, &self.ready.typed_source(), cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(NominalReverseCandidateOutcome::Cancelled);
        }
        rules.complete_target_families(
            self,
            target_semantic,
            &target_definitions,
            &mut families,
            cancellation,
        )?;
        evidence.enumeration.record(
            ReverseSubject::Target(target_semantic),
            ReverseEvidenceOrigin::Nomination,
            families.completion,
        );
        let mut spellings = vec![target.terminal_name().to_owned()];
        for route in families.nominations {
            if !spellings.contains(&route.member_name) {
                spellings.push(route.member_name);
            }
            // Owner routes nominate receiver/type sites too. Only the forward
            // binding, never an owner spelling, can admit a reference.
            for owner in route.owner_segments {
                if !spellings.contains(&owner) {
                    spellings.push(owner);
                }
            }
        }
        let peer_naming = rules.peer_naming(&descriptor);
        if let PeerNaming::OpenIncomplete(reason) = &peer_naming {
            evidence.binding.record(
                ReverseSubject::Target(target_semantic),
                ReverseEvidenceOrigin::Access,
                ResolutionCompletion::incomplete([*reason]),
            );
        }
        let hierarchy_route = rules.hierarchy_route(&descriptor);
        let peer_language_inventory_open = self.jvm_peer_language_may_name_target(
            &descriptor,
            &peer_naming,
            hierarchy_route.as_ref(),
            cancellation,
        )?;
        if cancellation.is_cancelled() {
            return Ok(NominalReverseCandidateOutcome::Cancelled);
        }
        let subclass_paths = if let Some(route) = &hierarchy_route {
            // The selected Java hierarchy is a source inventory, not a closed
            // classpath universe. Even a completed source walk cannot prove
            // that no additional subtype route exists outside that universe.
            if route.open_world {
                evidence.binding.record(
                    ReverseSubject::Target(target_semantic),
                    ReverseEvidenceOrigin::Hierarchy,
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(
                            owner_semantic.unwrap_or(target_semantic),
                        ),
                    ]),
                );
            }
            if let Some(owner_semantic) = owner_semantic {
                match native_units::project_native_definition_units(
                    &self.ready,
                    std::slice::from_ref(&owner_semantic),
                    cancellation,
                    &ResolutionSession::unbounded(),
                )? {
                    SelectedNativeDefinitions::Ready(rows) => {
                        let owner = rows
                            .into_iter()
                            .find_map(|(_, definition)| match definition {
                                SelectedNativeDefinition::Unit(unit) if unit.is_class() => {
                                    Some(unit)
                                }
                                _ => None,
                            });
                        if let Some(owner) = owner {
                            match self.jvm_reverse_subclass_source_paths(
                                owner_semantic,
                                owner,
                                cancellation,
                                &mut evidence,
                            )? {
                                Some(paths) => paths,
                                None => return Ok(NominalReverseCandidateOutcome::Cancelled),
                            }
                        } else {
                            evidence.metadata.record(
                                ReverseSubject::Target(target_semantic),
                                ReverseEvidenceOrigin::Projection,
                                ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::UnsupportedSemantic(owner_semantic),
                                ]),
                            );
                            HashSet::default()
                        }
                    }
                    SelectedNativeDefinitions::Unavailable => {
                        evidence.metadata.record(
                            ReverseSubject::Target(target_semantic),
                            ReverseEvidenceOrigin::Projection,
                            ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(owner_semantic),
                            ]),
                        );
                        HashSet::default()
                    }
                    SelectedNativeDefinitions::Cancelled => {
                        return Ok(NominalReverseCandidateOutcome::Cancelled);
                    }
                }
            } else {
                evidence.metadata.record(
                    ReverseSubject::Target(target_semantic),
                    ReverseEvidenceOrigin::Projection,
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                    ]),
                );
                HashSet::default()
            }
        } else {
            HashSet::default()
        };
        if peer_language_inventory_open {
            evidence.enumeration.record(
                ReverseSubject::Target(target_semantic),
                ReverseEvidenceOrigin::InventoryBoundary,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                ]),
            );
        }
        let mut candidates =
            HashMap::<(String, String, ResolutionSiteId), Vec<ReverseNomination>>::default();
        let mut candidate_packages = HashMap::<(String, String), Option<String>>::default();
        let lexical = self.ready.lexical_source();
        for spelling in &spellings {
            for &(semantic_language, storage_language) in rules.candidate_languages() {
                for namespace in ALL_RESOLUTION_NAMESPACES
                    .iter()
                    .filter(|namespace| **namespace != ResolutionNamespace::TypeOrValue)
                {
                    if cancellation.is_cancelled() {
                        return Ok(NominalReverseCandidateOutcome::Cancelled);
                    }
                    let lookup = ResolutionLookupSemanticRecipe::new(
                        semantic_language,
                        *namespace,
                        spelling,
                    )
                    .semantic(&self.ready.shared_names());
                    let Some(_identity) = lookup.shared_name_id() else {
                        continue;
                    };
                    let input_ordinal = surfaces.len();
                    surfaces.push(lookup);
                    #[cfg(any(test, feature = "test-support"))]
                    LAST_JVM_REVERSE_CANDIDATE_PLAN.with(|last| {
                        *last.borrow_mut() = explain_jvm_reverse_candidate_plan(
                            connection,
                            i64::from(_identity.get()),
                            storage_language,
                            semantic_language.config_label(),
                        )
                        .expect("explain populated JVM reverse candidate query");
                    });
                    let Some(mounts) = self.jvm_reverse_candidate_mounts(
                        lookup,
                        input_ordinal,
                        storage_language,
                        semantic_language.config_label(),
                        cancellation,
                    )?
                    else {
                        return Ok(NominalReverseCandidateOutcome::Cancelled);
                    };
                    for NominalReverseCandidateMount {
                        ordinal,
                        candidate_language,
                        path,
                        blob_id,
                        package,
                        has_root,
                        sites,
                    } in mounts
                    {
                        if package.is_none() {
                            evidence.binding.record(
                                ReverseSubject::Context(ReverseContextWitness::new(
                                    self, ordinal, blob_id,
                                )),
                                ReverseEvidenceOrigin::Access,
                                ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::UnsupportedSemantic(
                                        target_semantic,
                                    ),
                                ]),
                            );
                        }
                        candidate_packages
                            .insert((candidate_language.clone(), path.clone()), package.clone());

                        let context = ReverseContextWitness::new(self, ordinal, blob_id);
                        let obligation = evidence.enumeration.record(
                            ReverseSubject::Context(context.clone()),
                            ReverseEvidenceOrigin::Nomination,
                            ResolutionCompletion::Complete,
                        );
                        if has_root || rules.inspect_imports_without_root(&candidate_language) {
                            let known_sites = sites.iter().map(|(site, _)| *site).collect();
                            let Some(import_completion) = rules.import_inventory(
                                self,
                                ordinal,
                                blob_id,
                                lookup,
                                target_semantic,
                                &known_sites,
                                cancellation,
                            )?
                            else {
                                return Ok(NominalReverseCandidateOutcome::Cancelled);
                            };
                            evidence.enumeration.record(
                                ReverseSubject::Context(context.clone()),
                                ReverseEvidenceOrigin::Import,
                                import_completion.clone(),
                            );
                        }
                        for (site, route) in sites {
                            candidates
                                .entry((candidate_language.clone(), path.clone(), site))
                                .or_default()
                                .push(ReverseNomination {
                                    locator: SelectedSemanticLocator::new(
                                        candidate_language.clone(),
                                        path.clone(),
                                        site,
                                        LoweredSemanticRole::Reference,
                                    ),
                                    surface: Some(lookup),
                                    context: context.clone(),
                                    route,
                                    evidence: if route == ReverseNominationRoute::Root {
                                        ReverseNominationEvidence::ImportedRoot
                                    } else {
                                        ReverseNominationEvidence::NamedIndex
                                    },
                                    input_ordinal,
                                    binder_scope: None,
                                    obligations: vec![ReverseObligationLink {
                                        obligation: obligation.clone(),
                                    }],
                                });
                        }
                    }
                }
            }
        }

        let mut inventory_complete = true;
        let inventory_session = ResolutionSession::unbounded();
        for mount in self.ready.inventory.mounts()?.iter().filter(|mount| {
            rules
                .candidate_languages()
                .iter()
                .any(|(_, language)| *language == mount.storage_language())
        }) {
            if cancellation.is_cancelled() {
                return Ok(NominalReverseCandidateOutcome::Cancelled);
            }
            let inventory = lexical.reference_inventory_completion(
                mount.fragment_id(),
                cancellation,
                &inventory_session,
            )?;
            let Some(inventory) = lexical.close_completion(&inventory, cancellation)? else {
                return Ok(NominalReverseCandidateOutcome::Cancelled);
            };
            evidence.enumeration.record(
                ReverseSubject::Context(ReverseContextWitness::new(
                    self,
                    mount.ordinal().get(),
                    mount.blob_id(),
                )),
                ReverseEvidenceOrigin::Inventory,
                inventory.clone(),
            );
            inventory_complete &= inventory == ResolutionCompletion::Complete;
        }
        if !inventory_complete {
            let inventory_completion = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
            ]);
            evidence.enumeration.record(
                ReverseSubject::Target(target_semantic),
                ReverseEvidenceOrigin::Inventory,
                inventory_completion.clone(),
            );
        }

        let mut result = Vec::new();
        for ((storage_language, path, _site), mut nominations) in candidates {
            let package = candidate_packages
                .get(&(storage_language.clone(), path.clone()))
                .and_then(Option::as_deref);
            // Scala companion routes are nominated conservatively, including
            // private and protected declarations. Forward access remains the
            // authority; a source-mount filter cannot prove template access.
            let include = match &peer_naming {
                PeerNaming::Closed => {
                    Language::from_config_label(&storage_language)
                        .and_then(nominal_language_rules)
                        .is_some_and(|rules| rules.has_reverse_lexical_access())
                        || (storage_language == descriptor.storage_language
                            && path == relative_path)
                }
                PeerNaming::WithinPackage(region) => {
                    package.is_none_or(|package| region.contains(package))
                        || subclass_paths.contains(&(storage_language.clone(), path.clone()))
                }
                PeerNaming::Open if hierarchy_route.is_some() => {
                    Language::from_config_label(&storage_language)
                        .and_then(nominal_language_rules)
                        .is_some_and(|rules| rules.has_reverse_lexical_access())
                        || package.is_none()
                        || package == Some(target_package)
                        || subclass_paths.contains(&(storage_language.clone(), path.clone()))
                }
                PeerNaming::Open | PeerNaming::OpenIncomplete(_) => true,
            };
            if include {
                result.append(&mut nominations);
            }
        }
        result.sort_by(|left, right| left.locator.cmp(&right.locator));
        if !matches!(
            visibility,
            Some(
                DeclaredVisibility::Public
                    | DeclaredVisibility::Private
                    | DeclaredVisibility::PackagePrivate
                    | DeclaredVisibility::Protected
            )
        ) || owner_semantic.is_none()
        {
            evidence.binding.record(
                ReverseSubject::Target(target_semantic),
                ReverseEvidenceOrigin::Access,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                ]),
            );
        }
        let completion = jvm_reverse_completion(&evidence, cancellation);
        #[cfg(test)]
        if std::env::var_os("BIFROST_REVERSE_EVIDENCE").is_some() {
            let mut physical = result.iter().map(|row| &row.locator).collect::<Vec<_>>();
            physical.sort();
            physical.dedup();
            eprintln!(
                "REVERSE-CANDIDATES {physical:?} {completion:?} {peer_language_inventory_open}"
            );
        }
        Ok(NominalReverseCandidateOutcome::Ready(
            NominalReverseCandidateSet {
                equivalent_targets: families.equivalent_targets,
                target: ReverseTarget {
                    semantic: target_semantic,
                    declaration: target.clone(),
                    context: ReverseContextWitness::new(
                        self,
                        target_mount.ordinal().get(),
                        target_mount.blob_id(),
                    ),
                    surfaces,
                },
                candidates: result,
                completion,
                peer_language_inventory_open,
                evidence,
            },
        ))
    }

    fn jvm_peer_language_may_name_target(
        &self,
        target: &NominalReverseTarget<'_>,
        naming: &PeerNaming,
        hierarchy_route: Option<&HierarchyRoute>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if matches!(naming, PeerNaming::Closed) {
            return Ok(false);
        }
        let mounts = self.mount_table().mounts()?;
        let connection = self.ready.inventory.connection();
        let mut package_statement = connection.prepare_cached(
            "SELECT meta.content_package
             FROM temp.selected_resolution_mounts AS mount
             JOIN main.blob_meta AS meta ON meta.blob_id=mount.blob_id
             WHERE mount.mount_ordinal=?1 AND mount.storage_language=?2
               AND meta.is_complete=1",
        )?;
        for &(_, storage_language) in nominal_language_rules(language_for_target(target.unit))
            .expect("admitted nominal target")
            .reverse_target_rules()
            .candidate_languages()
            .iter()
            .filter(|(_, language)| *language != target.storage_language)
        {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            for mount in mounts
                .iter()
                .filter(|mount| mount.storage_language() == storage_language)
            {
                // Protected declarations can also be named through a
                // subclass outside the explicit lexical package region.
                if let PeerNaming::WithinPackage(region) = naming
                    && hierarchy_route.is_none()
                {
                    let package = package_statement
                        .query_row(
                            rusqlite::params![i64::from(mount.ordinal().get()), storage_language],
                            |row| row.get::<_, Option<String>>(0),
                        )
                        .optional()?
                        .flatten();
                    if package
                        .as_deref()
                        .is_some_and(|package| !region.contains(package))
                    {
                        continue;
                    }
                }
                // The shared scan collects peer rows, but current producer and
                // Java-consumer contracts still leave peer-language absence
                // open when a selected peer source could name this target.
                return Ok(true);
            }
        }
        Ok(false)
    }

    // Mount discovery is also an evidence inventory: keep mounts with no sites.
    // Shared reading batches their keys without changing that inventory.
    fn jvm_reverse_candidate_mounts(
        &self,
        lookup: SemanticId,
        input_ordinal: usize,
        storage_language: &str,
        semantic_language: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<NominalReverseCandidateMount>>> {
        let connection = self.ready.inventory.connection();
        let identity = lookup
            .shared_name_id()
            .expect("reverse lookup is a shared name");
        let mut statement = connection.prepare_cached(JVM_REVERSE_CANDIDATE_MOUNTS_SQL)?;
        let mounts = statement
            .query_map(
                rusqlite::params![identity.get(), storage_language, semantic_language],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, bool>(6)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let keys = mounts
            .iter()
            .map(|row| ReverseCandidateKey {
                input_ordinal,
                context: ReverseContextWitness::new(self, row.0, row.3),
                lookup,
                lexical: true,
                root: row.6,
                qualified: row.5,
            })
            .collect::<Vec<_>>();
        let Some(groups) = read_reverse_candidates(self, &keys, cancellation)? else {
            return Ok(None);
        };
        let mut result = Vec::with_capacity(mounts.len());
        for (
            (ordinal, candidate_language, path, blob_id, package, _has_qualified, has_root),
            indexed,
        ) in mounts.into_iter().zip(groups)
        {
            let sites = indexed
                .into_iter()
                .map(|candidate| {
                    debug_assert_eq!(candidate.input_ordinal, input_ordinal);
                    debug_assert_eq!(candidate.context.blob, blob_id);
                    debug_assert!(
                        candidate.persisted_lookup >= 0
                            && candidate.provenance.0 >= 0
                            && candidate.provenance.1 >= 0
                    );
                    (candidate.site, candidate.route)
                })
                .collect::<Vec<_>>();
            result.push(NominalReverseCandidateMount {
                ordinal,
                candidate_language,
                path,
                blob_id,
                package,
                has_root,
                sites,
            });
        }
        Ok(Some(result))
    }

    fn jvm_reverse_subclass_source_paths(
        &self,
        root_semantic: SemanticId,
        root: CodeUnit,
        cancellation: &CancellationToken,
        evidence: &mut ReverseEvidence,
    ) -> Result<Option<HashSet<(String, String)>>> {
        let mut descendants = HashSet::default();
        let mut visited = HashSet::default();
        let mut pending = VecDeque::from([(root_semantic, root)]);
        let mut context_metrics = SelectedResolutionContextMetrics;
        while let Some((base_semantic, base_unit)) = pending.pop_front() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if !visited.insert(base_semantic) {
                continue;
            }
            let connection = self.ready.inventory.connection();
            let mut locators = HashMap::<SemanticId, SelectedSemanticLocator>::default();
            let mut nominations =
                HashMap::<SelectedSemanticLocator, Vec<ReverseNomination>>::default();
            for (input_ordinal, (semantic_language, storage_language)) in
                nominal_language_rules(language_for_target(&base_unit))
                    .expect("admitted nominal base")
                    .reverse_target_rules()
                    .candidate_languages()
                    .iter()
                    .copied()
                    .enumerate()
            {
                let lookup = ResolutionLookupSemanticRecipe::new(
                    semantic_language,
                    ResolutionNamespace::Type,
                    base_unit.terminal_name(),
                )
                .semantic(&self.ready.shared_names());
                let Some(_identity) = lookup.shared_name_id() else {
                    continue;
                };
                let Some(mounts) = self.jvm_reverse_candidate_mounts(
                    lookup,
                    input_ordinal,
                    storage_language,
                    semantic_language.config_label(),
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                for NominalReverseCandidateMount {
                    ordinal,
                    candidate_language,
                    path,
                    blob_id,
                    package: _,
                    has_root: _,
                    sites,
                } in mounts
                {
                    let mut semantic_statement =
                        connection.prepare_cached(JVM_REVERSE_REFERENCE_SEMANTIC_SQL)?;
                    for (site, route) in sites {
                        let semantic_key = semantic_statement
                            .query_row(rusqlite::params![blob_id, i64::from(site.get())], |row| {
                                row.get::<_, i64>(0)
                            })
                            .optional()?;
                        let Some(semantic_key) = semantic_key else {
                            evidence.metadata.record(
                                ReverseSubject::Site(
                                    SelectedSemanticLocator::new(
                                        candidate_language.clone(),
                                        path.clone(),
                                        site,
                                        LoweredSemanticRole::Reference,
                                    ),
                                    ReverseContextWitness::new(self, ordinal, blob_id),
                                ),
                                ReverseEvidenceOrigin::Hierarchy,
                                ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::UnsupportedSemantic(base_semantic),
                                ]),
                            );
                            continue;
                        };
                        let semantic = SemanticId::local(
                            ordinal,
                            u32::try_from(semantic_key)
                                .expect("Java hierarchy semantic key fits u32"),
                        );
                        let locator = SelectedSemanticLocator::new(
                            candidate_language.clone(),
                            path.clone(),
                            site,
                            LoweredSemanticRole::Reference,
                        );
                        locators.entry(semantic).or_insert_with(|| locator.clone());
                        nominations
                            .entry(locator.clone())
                            .or_default()
                            .push(ReverseNomination {
                                locator,
                                surface: Some(lookup),
                                context: ReverseContextWitness::new(self, ordinal, blob_id),
                                route,
                                evidence: if route == ReverseNominationRoute::Root {
                                    ReverseNominationEvidence::ImportedRoot
                                } else {
                                    ReverseNominationEvidence::NamedIndex
                                },
                                input_ordinal,
                                binder_scope: None,
                                obligations: Vec::new(),
                            });
                    }
                }
            }
            let reference_semantics = locators.keys().copied().collect::<Vec<_>>();
            if reference_semantics.is_empty() {
                continue;
            }
            let mut hierarchy_candidates =
                HashMap::<SelectedSemanticLocator, Vec<SemanticId>>::default();
            let mut collect = |rows: &[SelectedTypedRow<
                crate::analyzer::resolution::LoweredSupertypeProperty,
            >]| {
                for row in rows {
                    if let Some(locator) = locators.get(&row.row().reference()) {
                        hierarchy_candidates
                            .entry(locator.clone())
                            .or_default()
                            .push(row.row().definition());
                    }
                }
                Ok(!cancellation.is_cancelled())
            };
            let mut visitor = FactPageVisitor::new(&mut collect);
            let outcome = self
                .ready
                .typed_source()
                .visit_supertype_pages_for_references(
                    TypedFactRequest::new(&reference_semantics),
                    cancellation,
                    &mut visitor,
                )?;
            let (terminal, coverage) = outcome.into_parts();
            evidence.enumeration.record(
                ReverseSubject::Target(base_semantic),
                ReverseEvidenceOrigin::Hierarchy,
                coverage,
            );
            if terminal == crate::analyzer::resolution::TypedFactReadTerminal::Cancelled
                || cancellation.is_cancelled()
            {
                return Ok(None);
            }
            if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted {
                evidence.enumeration.record(
                    ReverseSubject::Target(base_semantic),
                    ReverseEvidenceOrigin::Hierarchy,
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(base_semantic),
                    ]),
                );
            }
            let candidates = hierarchy_candidates
                .keys()
                .flat_map(|locator| {
                    nominations
                        .remove(locator)
                        .expect("typed hierarchy candidate was nominated")
                })
                .collect::<Vec<_>>();
            let confirmed = match self.confirm_jvm_hierarchy_references(
                candidates,
                base_semantic,
                cancellation,
                &mut context_metrics,
                evidence,
            ) {
                Ok(answer) => answer,
                Err(_) if cancellation.is_cancelled() => return Ok(None),
                Err(error) => return Err(error),
            };
            let mut child_semantics = Vec::new();
            for (locator, answer) in confirmed {
                if answer.binding().targets().contains(&base_semantic) {
                    child_semantics.extend(
                        hierarchy_candidates
                            .get(&locator)
                            .into_iter()
                            .flatten()
                            .copied(),
                    );
                }
            }
            child_semantics.sort_unstable();
            child_semantics.dedup();
            let projected = match native_units::project_native_definition_units(
                &self.ready,
                &child_semantics,
                cancellation,
                &ResolutionSession::unbounded(),
            )? {
                SelectedNativeDefinitions::Ready(rows) => rows,
                SelectedNativeDefinitions::Unavailable => {
                    evidence.metadata.record(
                        ReverseSubject::Target(base_semantic),
                        ReverseEvidenceOrigin::Projection,
                        ResolutionCompletion::incomplete(
                            child_semantics
                                .iter()
                                .copied()
                                .map(ResolutionIncompleteReason::UnsupportedSemantic),
                        ),
                    );
                    continue;
                }
                SelectedNativeDefinitions::Cancelled => {
                    return Ok(None);
                }
            };
            for (semantic, definition) in projected {
                let SelectedNativeDefinition::Unit(unit) = definition else {
                    evidence.metadata.record(
                        ReverseSubject::Target(semantic),
                        ReverseEvidenceOrigin::Projection,
                        ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(semantic),
                        ]),
                    );
                    continue;
                };
                if !unit.is_class() {
                    evidence.metadata.record(
                        ReverseSubject::Target(semantic),
                        ReverseEvidenceOrigin::Projection,
                        ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(semantic),
                        ]),
                    );
                    continue;
                }
                descendants.insert((
                    unit.source().language().config_label().to_owned(),
                    crate::path_utils::rel_path_string(unit.source()),
                ));
                if !visited.contains(&semantic) {
                    pending.push_back((semantic, unit));
                }
            }
        }
        Ok(Some(descendants))
    }

    fn confirm_jvm_hierarchy_references(
        &self,
        candidates: Vec<NominalReverseCandidate>,
        base_semantic: SemanticId,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        evidence: &mut ReverseEvidence,
    ) -> Result<Vec<(SelectedSemanticLocator, FactResolutionAnswer)>> {
        let mut reducer = JvmHierarchyReverseReducer {
            target: base_semantic,
            references: Vec::new(),
        };
        assert!(confirm_reverse_nominations(
            self,
            &candidates,
            evidence,
            &NominalReverseAdapter,
            &mut reducer,
            cancellation,
            context_metrics,
        )?);
        Ok(reducer.references)
    }

    /// Confirm grouped candidate sites with each caller's selected JVM import
    /// context and forward operation.
    #[doc(hidden)]
    pub fn confirm_nominal_reverse_candidates(
        mut self,
        candidates: NominalReverseCandidateSet,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<(
        SelectedResolutionOperationOutcome<NominalReverseConfirmed>,
        ConsumedJvmRootPresence,
    )> {
        // Preserve the JVM public predicate: candidate-stage access and
        // hierarchy gaps also make its legacy inventory projection incomplete.
        let candidate_inventory_complete = candidates.completion == ResolutionCompletion::Complete;
        debug_assert!(candidates.candidates.iter().all(|row| {
            row.surface
                .is_some_and(|surface| candidates.target.surfaces.contains(&surface))
        }));
        debug_assert_eq!(
            candidates.target.semantic.ordinal(),
            Some(candidates.target.context.mount)
        );
        candidates.target.context.assert_selected(&self);
        let target_semantic = candidates.target.semantic;
        let peer_language_inventory_open = candidates.peer_language_inventory_open;
        let mut evidence = candidates.evidence;
        let mut reducer = JvmOrdinaryReverseReducer {
            equivalent_targets: &candidates.equivalent_targets,
            target: target_semantic,
            references: Vec::new(),
        };
        if !confirm_reverse_nominations(
            &self,
            &candidates.candidates,
            &mut evidence,
            &NominalReverseAdapter,
            &mut reducer,
            cancellation,
            context_metrics,
        )? {
            return Ok((
                SelectedResolutionOperationOutcome::Cancelled(cancelled_completion()),
                self.drain_consumed_root_presence(),
            ));
        }
        let completion = jvm_reverse_completion(&evidence, cancellation);
        let references = reducer.references;
        let root_reads = self.drain_consumed_root_presence();
        let result = self.ready.finish(
            NominalReverseConfirmed {
                equivalent_targets: candidates.equivalent_targets,
                target: target_semantic,
                references,
                completion: completion.clone(),
                candidate_inventory_complete,
                peer_language_inventory_open,
                evidence,
                selected_target: candidates.target,
                nominations: candidates.candidates,
            },
            &completion,
            cancellation,
        )?;
        assert!(
            self.consumed_root_presence().is_empty(),
            "JVM reverse finish must not read root presence after export"
        );
        Ok((result, root_reads))
    }
}

#[cfg(any(test, feature = "test-support"))]
fn explain_jvm_reverse_candidate_plan(
    connection: &rusqlite::Connection,
    identity: i64,
    storage_language: &str,
    semantic_language: &str,
) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(&format!(
        "EXPLAIN QUERY PLAN {JVM_REVERSE_CANDIDATE_MOUNTS_SQL}"
    ))?;
    statement
        .query_map(
            rusqlite::params![identity, storage_language, semantic_language],
            |row| row.get(3),
        )?
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn last_jvm_reverse_candidate_plan_for_test() -> Vec<String> {
    LAST_JVM_REVERSE_CANDIDATE_PLAN.with(|last| last.borrow().clone())
}
// The public JVM result already reports peer-language absence through its
// inventory-boundary flag. Keep the obligation, but preserve that projection
// instead of adding a second resolution-incomplete diagnostic for the boundary.
fn jvm_reverse_completion(
    evidence: &ReverseEvidence,
    cancellation: &CancellationToken,
) -> ResolutionCompletion {
    let mut cancelled = || cancellation.is_cancelled();
    let Some(enumeration) = evidence.enumeration.completion_for_with_poll(
        |obligation| !matches!(obligation.origin, ReverseEvidenceOrigin::InventoryBoundary),
        &mut cancelled,
    ) else {
        return cancelled_completion();
    };
    let Some(binding) = evidence.binding.completion_with_poll(&mut cancelled) else {
        return cancelled_completion();
    };
    let Some(metadata) = evidence.metadata.completion_with_poll(&mut cancelled) else {
        return cancelled_completion();
    };
    ResolutionCompletion::combine_all_with_poll([&enumeration, &binding, &metadata], &mut cancelled)
        .unwrap_or_else(cancelled_completion)
}

fn jvm_reverse_target_relation(
    target: SemanticId,
    answer: &FactResolutionAnswer,
) -> ReverseTargetRelation {
    let binding = answer.binding();
    if binding.targets().contains(&target) {
        ReverseTargetRelation::Matches
    } else if binding.completion() == &ResolutionCompletion::Complete {
        ReverseTargetRelation::Excluded
    } else {
        ReverseTargetRelation::Undecided
    }
}

struct JvmHierarchyReverseReducer {
    target: SemanticId,
    references: Vec<(SelectedSemanticLocator, FactResolutionAnswer)>,
}

impl ReverseFileReducer for JvmHierarchyReverseReducer {
    type Answer = FactResolutionAnswer;

    fn binding_completion<'a>(&self, answer: &'a Self::Answer) -> &'a ResolutionCompletion {
        answer.binding().completion()
    }

    fn target_relation(&self, answer: &Self::Answer) -> ReverseTargetRelation {
        jvm_reverse_target_relation(self.target, answer)
    }

    fn target(&self) -> SemanticId {
        self.target
    }

    fn cancelled(&self, stage: ReverseCancellationStage) -> Result<()> {
        Err(StoreError::new(match stage {
            ReverseCancellationStage::Context => "JVM hierarchy confirmation was cancelled",
            _ => "Java hierarchy confirmation was cancelled",
        }))
    }

    fn missing_locator(&self, locator: &SelectedSemanticLocator) -> StoreError {
        StoreError::corrupt(format!(
            "Java hierarchy candidate locator is absent from selected source: {locator:?}"
        ))
    }

    fn metadata_evidence(
        &self,
        answer: &FactResolutionAnswer,
        _relation: ReverseTargetRelation,
    ) -> Option<(ReverseEvidenceOrigin, ResolutionCompletion)> {
        Some((
            ReverseEvidenceOrigin::Hierarchy,
            answer.completion().clone(),
        ))
    }

    fn file(
        &mut self,
        _operation: &SelectedResolutionOperation<'_, '_>,
        _context: &ReverseContextWitness,
        answers: Vec<ReverseConfirmedReference>,
        _evidence: &mut ReverseEvidence,
        _cancellation: &CancellationToken,
    ) -> Result<bool> {
        self.references.extend(
            answers
                .into_iter()
                .map(|reference| (reference.locator, reference.answer)),
        );
        Ok(true)
    }
}

struct JvmOrdinaryReverseReducer<'a> {
    equivalent_targets: &'a [SemanticId],
    target: SemanticId,
    references: Vec<NominalReverseConfirmedReference>,
}

impl ReverseFileReducer for JvmOrdinaryReverseReducer<'_> {
    type Answer = FactResolutionAnswer;

    fn binding_completion<'a>(&self, answer: &'a Self::Answer) -> &'a ResolutionCompletion {
        answer.binding().completion()
    }

    fn target_relation(&self, answer: &Self::Answer) -> ReverseTargetRelation {
        if answer
            .binding()
            .targets()
            .iter()
            .any(|target| self.equivalent_targets.contains(target))
        {
            ReverseTargetRelation::Matches
        } else {
            jvm_reverse_target_relation(self.target, answer)
        }
    }

    fn target(&self) -> SemanticId {
        self.target
    }

    fn missing_locator(&self, locator: &SelectedSemanticLocator) -> StoreError {
        StoreError::corrupt(format!(
            "Java reverse candidate locator is absent from selected source: {locator:?}"
        ))
    }

    fn metadata_evidence(
        &self,
        answer: &FactResolutionAnswer,
        relation: ReverseTargetRelation,
    ) -> Option<(ReverseEvidenceOrigin, ResolutionCompletion)> {
        matches!(relation, ReverseTargetRelation::Matches).then(|| {
            (
                ReverseEvidenceOrigin::Projection,
                if answer.site_metadata().is_some() {
                    ResolutionCompletion::Complete
                } else {
                    self.unavailable()
                },
            )
        })
    }

    fn file(
        &mut self,
        operation: &SelectedResolutionOperation<'_, '_>,
        context: &ReverseContextWitness,
        answers: Vec<ReverseConfirmedReference>,
        evidence: &mut ReverseEvidence,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let Some(projected) = project_reverse_owners(
            operation,
            context,
            answers,
            self.target,
            evidence,
            cancellation,
        )?
        else {
            return Ok(false);
        };
        self.references.extend(projected.references);
        Ok(true)
    }
}

struct NominalReverseAdapter;
impl ReverseFileEvaluator for NominalReverseAdapter {
    type Answer = FactResolutionAnswer;
    fn session(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        language: Language,
        storage_language: &str,
        path: &str,
        locators: &[&SelectedSemanticLocator],
        cancellation: &CancellationToken,
        metrics: &SelectedResolutionContextMetrics,
    ) -> Result<ReverseBatch<ReverseFileSession<Self::Answer>, std::convert::Infallible>> {
        nominal_language_rules(language)
            .expect("admitted nominal caller")
            .reverse_target_rules()
            .file_evaluator()
            .session(
                operation,
                language,
                storage_language,
                path,
                locators,
                cancellation,
                metrics,
            )
    }
}
