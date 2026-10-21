//! Query-local JVM reverse candidates from the shared lookup identity index.
//! Candidate rows are provisional; each selected file-scoped JVM forward
//! operation confirms every returned reference.

use super::reverse::*;
use super::*;
use crate::analyzer::resolution::{
    LoweredSemanticRole, ResolutionLookupSemanticRecipe, SelectedSemanticLocator,
};
use crate::analyzer::store::resolution_operation::native_units;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ALL_RESOLUTION_NAMESPACES, ResolutionNamespace, ResolutionSiteId,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use rusqlite::OptionalExtension;
use std::collections::VecDeque;

const JVM_STORAGE_LANGUAGES: [(Language, &str); 3] = [
    (Language::Java, "java"),
    (Language::Kotlin, "kotlin"),
    (Language::Scala, "scala"),
];

#[cfg(test)]
thread_local! {
    static LAST_JVM_REVERSE_CANDIDATE_PLAN: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

static JAVA_REVERSE_DEFINITION_SEMANTICS_SQL: std::sync::LazyLock<String> =
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
WHERE mount.mount_ordinal=?1 AND mount.storage_language='java'
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
const JVM_REVERSE_IMPORT_SOURCE_SITE_SQL: &str = "SELECT import_source_site FROM main.resolution_semantic_catalog WHERE blob_id=?1 AND local_key=?2 AND import_source_site IS NOT NULL";

struct JvmReverseCandidateMount {
    ordinal: u32,
    candidate_language: String,
    path: String,
    blob_id: i64,
    package: Option<String>,
    has_root: bool,
    sites: Vec<(ResolutionSiteId, ReverseNominationRoute)>,
}

pub(crate) type JvmReverseCandidate = ReverseNomination;

#[derive(Debug)]
pub(crate) struct JvmReverseCandidateSet {
    pub(crate) target: ReverseTarget,
    pub(crate) candidates: Vec<JvmReverseCandidate>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) peer_language_inventory_open: bool,
    pub(super) evidence: Box<ReverseEvidence>,
}

pub(crate) enum JvmReverseCandidateOutcome {
    Ready(JvmReverseCandidateSet),
    Unavailable(String),
    Cancelled,
}

pub(crate) type JvmReverseConfirmedReference = ReverseOwnedReference;

pub(crate) struct JvmReverseConfirmed {
    pub(crate) target: SemanticId,
    pub(crate) references: Vec<JvmReverseConfirmedReference>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) candidate_inventory_complete: bool,
    pub(crate) peer_language_inventory_open: bool,
    evidence: Box<ReverseEvidence>,
    selected_target: ReverseTarget,
    nominations: Vec<ReverseNomination>,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Find every selected JVM source site whose indexed lookup identity could
    /// refer to the Java `target`, then narrow by Java declaration access.
    /// Fully qualified references do not require an import, so no importer
    /// filter is applied here.
    pub(crate) fn jvm_reverse_candidate_sites(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<JvmReverseCandidateOutcome> {
        if cancellation.is_cancelled() {
            return Ok(JvmReverseCandidateOutcome::Cancelled);
        }
        let relative_path = crate::path_utils::rel_path_string(target.source());
        let Some(target_mount) = self
            .ready
            .inventory
            .mount_record_for_path("java", &relative_path)?
        else {
            return Ok(JvmReverseCandidateOutcome::Unavailable(format!(
                "Java target is outside the selected source mounts: {relative_path}"
            )));
        };
        let connection = self.ready.inventory.connection();
        let mut statement =
            connection.prepare_cached(JAVA_REVERSE_DEFINITION_SEMANTICS_SQL.as_str())?;
        let target_semantics = statement
            .query_map([i64::from(target_mount.ordinal().get())], |row| {
                row.get::<_, i64>(0)
            })?
            .map(|key| {
                key.map(|key| {
                    SemanticId::local(
                        target_mount.ordinal().get(),
                        u32::try_from(key).expect("Java definition key fits u32"),
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
                return Ok(JvmReverseCandidateOutcome::Unavailable(format!(
                    "Java target definitions are not projectable: {relative_path}"
                )));
            }
            SelectedNativeDefinitions::Cancelled => {
                return Ok(JvmReverseCandidateOutcome::Cancelled);
            }
        };
        let Some((target_semantic, _)) = target_definitions.into_iter().find(|(_, definition)| {
            matches!(definition, SelectedNativeDefinition::Unit(unit) if unit == target)
        }) else {
            return Ok(JvmReverseCandidateOutcome::Unavailable(format!(
                "Java target has no selected definition identity: {target:?}"
            )));
        };

        let (visibility, owner_semantic, completion) =
            self.java_reverse_target_access(target_semantic, target, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(JvmReverseCandidateOutcome::Cancelled);
        }
        let mut evidence = Box::new(ReverseEvidence::new(target_semantic));
        evidence.binding.record(
            ReverseSubject::Target(target_semantic),
            ReverseEvidenceOrigin::Access,
            completion,
        );
        let mut surfaces = Vec::new();
        let target_package = target.package_name();
        let peer_language_inventory_open =
            self.jvm_peer_language_may_name_target(target_package, visibility, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(JvmReverseCandidateOutcome::Cancelled);
        }
        let subclass_paths = if visibility == Some(DeclaredVisibility::Protected) {
            // The selected Java hierarchy is a source inventory, not a closed
            // classpath universe. Even a completed source walk cannot prove
            // that no additional subtype route exists outside that universe.
            evidence.binding.record(
                ReverseSubject::Target(target_semantic),
                ReverseEvidenceOrigin::Hierarchy,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(
                        owner_semantic.unwrap_or(target_semantic),
                    ),
                ]),
            );
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
                                None => return Ok(JvmReverseCandidateOutcome::Cancelled),
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
                        return Ok(JvmReverseCandidateOutcome::Cancelled);
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
        for (semantic_language, storage_language) in JVM_STORAGE_LANGUAGES {
            for namespace in ALL_RESOLUTION_NAMESPACES
                .iter()
                .filter(|namespace| **namespace != ResolutionNamespace::TypeOrValue)
            {
                if cancellation.is_cancelled() {
                    return Ok(JvmReverseCandidateOutcome::Cancelled);
                }
                let lookup = ResolutionLookupSemanticRecipe::new(
                    semantic_language,
                    *namespace,
                    target.terminal_name(),
                )
                .semantic(&self.ready.shared_names());
                let Some(_identity) = lookup.shared_name_id() else {
                    continue;
                };
                let input_ordinal = surfaces.len();
                surfaces.push(lookup);
                #[cfg(test)]
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
                    return Ok(JvmReverseCandidateOutcome::Cancelled);
                };
                for JvmReverseCandidateMount {
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
                                ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
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
                    if has_root {
                        let known_sites = sites.iter().map(|(site, _)| *site).collect();
                        let Some(import_completion) = self.jvm_reverse_import_inventory(
                            ordinal,
                            blob_id,
                            lookup,
                            target_semantic,
                            &known_sites,
                            cancellation,
                        )?
                        else {
                            return Ok(JvmReverseCandidateOutcome::Cancelled);
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

        let mut inventory_complete = true;
        let inventory_session = ResolutionSession::unbounded();
        for mount in self
            .ready
            .inventory
            .mounts()?
            .iter()
            .filter(|mount| matches!(mount.storage_language(), "java" | "kotlin" | "scala"))
        {
            if cancellation.is_cancelled() {
                return Ok(JvmReverseCandidateOutcome::Cancelled);
            }
            let inventory = lexical.reference_inventory_completion(
                mount.fragment_id(),
                cancellation,
                &inventory_session,
            )?;
            let Some(inventory) = lexical.close_completion(&inventory, cancellation)? else {
                return Ok(JvmReverseCandidateOutcome::Cancelled);
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
            let include = match visibility {
                Some(DeclaredVisibility::Public) => true,
                Some(DeclaredVisibility::Private) => {
                    storage_language == "scala"
                        || (storage_language == "java" && path == relative_path)
                }
                Some(DeclaredVisibility::PackagePrivate) => {
                    package.is_none() || package == Some(target_package)
                }
                Some(DeclaredVisibility::Protected) => {
                    storage_language == "scala"
                        || package.is_none()
                        || package == Some(target_package)
                        || subclass_paths.contains(&(storage_language.clone(), path.clone()))
                }
                Some(DeclaredVisibility::Internal | DeclaredVisibility::CrateOrModule) => true,
                Some(DeclaredVisibility::Unknown) | None => true,
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
        let completion = jvm_reverse_completion(&evidence);
        #[cfg(test)]
        if std::env::var_os("BIFROST_REVERSE_EVIDENCE").is_some() {
            let mut physical = result.iter().map(|row| &row.locator).collect::<Vec<_>>();
            physical.sort();
            physical.dedup();
            eprintln!(
                "REVERSE-CANDIDATES {physical:?} {completion:?} {peer_language_inventory_open}"
            );
        }
        Ok(JvmReverseCandidateOutcome::Ready(JvmReverseCandidateSet {
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
        }))
    }

    fn jvm_peer_language_may_name_target(
        &self,
        target_package: &str,
        visibility: Option<DeclaredVisibility>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if matches!(visibility, Some(DeclaredVisibility::Private)) {
            return Ok(false);
        }
        let package_filter = match visibility {
            Some(DeclaredVisibility::PackagePrivate) => Some(target_package),
            _ => None,
        };
        let mounts = self.mount_table().mounts()?;
        let connection = self.ready.inventory.connection();
        let mut package_statement = connection.prepare_cached(
            "SELECT meta.content_package
             FROM temp.selected_resolution_mounts AS mount
             JOIN main.blob_meta AS meta ON meta.blob_id=mount.blob_id
             WHERE mount.mount_ordinal=?1 AND mount.storage_language=?2
               AND meta.is_complete=1",
        )?;
        for storage_language in ["kotlin", "scala"] {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            for mount in mounts
                .iter()
                .filter(|mount| mount.storage_language() == storage_language)
            {
                if let Some(target_package) = package_filter {
                    let package = package_statement
                        .query_row(
                            rusqlite::params![i64::from(mount.ordinal().get()), storage_language],
                            |row| row.get::<_, Option<String>>(0),
                        )
                        .optional()?
                        .flatten();
                    if package
                        .as_deref()
                        .is_some_and(|package| package != target_package)
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
    ) -> Result<Option<Vec<JvmReverseCandidateMount>>> {
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
            result.push(JvmReverseCandidateMount {
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

    fn jvm_reverse_import_inventory(
        &self,
        mount_ordinal: u32,
        blob_id: i64,
        lookup: SemanticId,
        target_semantic: SemanticId,
        known_sites: &HashSet<ResolutionSiteId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<ResolutionCompletion>> {
        let mut completion = ResolutionCompletion::Complete;
        let ordinal = SelectedResolutionMountOrdinal::new(mount_ordinal);
        let lexical = self.ready.lexical_source();
        let identities = self.ready.context_identities.clone();
        let connection = self.ready.inventory.connection();
        let mut import_source = connection.prepare_cached(JVM_REVERSE_IMPORT_SOURCE_SITE_SQL)?;
        let outcome = visit_selected_root_import_half_pages(
            &identities,
            &lexical,
            &lexical,
            Some(std::slice::from_ref(&ordinal)),
            cancellation,
            &mut FactPageVisitor::new(&mut |page: &[SelectedRootPathHalf]| {
                for half in page {
                    let SelectedRootPathHalf::Import {
                        route,
                        demand,
                        token,
                        ..
                    } = half
                    else {
                        continue;
                    };
                    if *demand != lookup && !route.contains(&lookup) {
                        continue;
                    }
                    let Some(token_key) = token.local_key() else {
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                        ]));
                        continue;
                    };
                    let source_site = import_source
                        .query_row(rusqlite::params![blob_id, i64::from(token_key)], |row| {
                            row.get::<_, i64>(0)
                        })
                        .optional()?;
                    let Some(source_site) = source_site else {
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                        ]));
                        continue;
                    };
                    let source_site = ResolutionSiteId::new(
                        u32::try_from(source_site).expect("Java import source site fits u32"),
                    );
                    if !known_sites.contains(&source_site) {
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                        ]));
                    }
                }
                Ok(true)
            }),
        )?;
        let (terminal, _evidence) = outcome.into_parts();
        // This reader visits every root path in the source, so its aggregate
        // completion can include unrelated open roots. Java reference
        // enumeration was certified per selected mount above; here only
        // imports carrying this exact lookup identity affect the reverse
        // candidate set, and those are checked against `known_sites` below.
        if terminal == crate::analyzer::resolution::TypedFactReadTerminal::Cancelled
            || cancellation.is_cancelled()
        {
            return Ok(None);
        }
        if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
            ]));
        }
        Ok(Some(completion))
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
                JVM_STORAGE_LANGUAGES.into_iter().enumerate()
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
                for JvmReverseCandidateMount {
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
        candidates: Vec<JvmReverseCandidate>,
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
            &JvmReverseAdapter,
            &mut reducer,
            cancellation,
            context_metrics,
        )?);
        Ok(reducer.references)
    }

    fn java_reverse_target_access(
        &self,
        target: SemanticId,
        target_unit: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<(
        Option<DeclaredVisibility>,
        Option<SemanticId>,
        ResolutionCompletion,
    )> {
        let facts = self.ready.typed_source();
        let mut visibility = None;
        let mut collect_visibility = |rows: &[SelectedTypedRow<
            crate::analyzer::resolution::LoweredDeclarationVisibilityProperty,
        >]| {
            for row in rows {
                assert_eq!(row.row().definition(), target);
                assert!(visibility.replace(row.row().visibility()).is_none());
            }
            Ok(!cancellation.is_cancelled())
        };
        let mut visitor = FactPageVisitor::new(&mut collect_visibility);
        let visibility_outcome = facts.visit_declaration_visibility_pages_for_definitions(
            TypedFactRequest::new(std::slice::from_ref(&target)),
            cancellation,
            &mut visitor,
        )?;
        let (terminal, mut completion) = visibility_outcome.into_parts();
        if terminal == crate::analyzer::resolution::TypedFactReadTerminal::Cancelled
            || cancellation.is_cancelled()
        {
            return Ok((None, None, cancelled_completion()));
        }
        if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted {
            return Err(StoreError::new(
                "Java target visibility read stopped before exhausting its exact request",
            ));
        }
        if visibility.is_none() {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target),
            ]));
        }

        let mut owner = None;
        let mut collect_owner = |rows: &[SelectedTypedRow<
            crate::analyzer::resolution::LoweredMemberOwnerProperty,
        >]| {
            for row in rows {
                assert_eq!(row.row().definition(), target);
                assert!(owner.replace(row.row().owner_definition()).is_none());
            }
            Ok(!cancellation.is_cancelled())
        };
        let mut visitor = FactPageVisitor::new(&mut collect_owner);
        let owner_outcome = facts.visit_member_owner_pages_for_definitions(
            TypedFactRequest::new(std::slice::from_ref(&target)),
            cancellation,
            &mut visitor,
        )?;
        let (terminal, owner_completion) = owner_outcome.into_parts();
        if terminal == crate::analyzer::resolution::TypedFactReadTerminal::Cancelled
            || cancellation.is_cancelled()
        {
            return Ok((visibility, None, cancelled_completion()));
        }
        if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted {
            return Err(StoreError::new(
                "Java target owner read stopped before exhausting its exact request",
            ));
        }
        completion = completion.combine(&owner_completion);
        let owner = owner.or_else(|| target_unit.is_class().then_some(target));
        if owner.is_none() {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target),
            ]));
        }
        Ok((visibility, owner, completion))
    }

    /// Confirm grouped candidate sites with each caller's selected JVM import
    /// context and forward operation.
    pub(crate) fn confirm_jvm_reverse_candidates(
        mut self,
        candidates: JvmReverseCandidateSet,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<JvmReverseConfirmed>> {
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
            target: target_semantic,
            references: Vec::new(),
        };
        if !confirm_reverse_nominations(
            &self,
            &candidates.candidates,
            &mut evidence,
            &JvmReverseAdapter,
            &mut reducer,
            cancellation,
            context_metrics,
        )? {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        let completion = jvm_reverse_completion(&evidence);
        self.ready.finish(
            JvmReverseConfirmed {
                target: target_semantic,
                references: reducer.references,
                completion: completion.clone(),
                candidate_inventory_complete,
                peer_language_inventory_open,
                evidence,
                selected_target: candidates.target,
                nominations: candidates.candidates,
            },
            &completion,
            cancellation,
        )
    }
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn last_jvm_reverse_candidate_plan_for_test() -> Vec<String> {
    LAST_JVM_REVERSE_CANDIDATE_PLAN.with(|last| last.borrow().clone())
}
struct JvmReverseAdapter;

struct JvmReverseLifecycle<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    language: Language,
    storage_language: &'a str,
    path: &'a str,
    cancellation: &'a CancellationToken,
    metrics: &'a SelectedResolutionContextMetrics,
    inventory: ResolutionCompletion,
}

struct JvmReverseScoped<'a, 'store, 'input> {
    operation: &'a SelectedResolutionOperation<'store, 'input>,
    storage_language: &'a str,
    path: &'a str,
    gaps: &'a [JvmImportContextGap],
    cancellation: &'a CancellationToken,
}

impl ReverseFileEvaluator for JvmReverseAdapter {
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
        let mut lifecycle = JvmReverseLifecycle {
            operation,
            language,
            storage_language,
            path,
            cancellation,
            metrics,
            inventory: ResolutionCompletion::Complete,
        };
        let result = confirm_reverse_session(locators, &mut lifecycle)?;
        Ok(result.map(|reports| ReverseFileSession {
            reports,
            inventory: lifecycle.inventory,
        }))
    }
}

impl<'store, 'input> ReverseLifecycle for JvmReverseLifecycle<'_, 'store, 'input> {
    type Answer = FactResolutionAnswer;
    type Limit = std::convert::Infallible;
    type Prepared = ReverseFileContext<Vec<JvmImportContextGap>>;
    type Scoped<'a>
        = JvmReverseScoped<'a, 'store, 'input>
    where
        Self: 'a;
    fn prepare(
        &mut self,
        _locators: &[&SelectedSemanticLocator],
    ) -> Result<ReverseBatch<Self::Prepared, Self::Limit>> {
        Ok(
            match self.operation.jvm_reverse_import_context(
                self.language,
                self.path,
                self.cancellation,
            )? {
                JvmImportContext::Ready {
                    context,
                    scoped_gaps,
                    ..
                } => {
                    self.inventory = context.inventory_completion().clone();
                    ReverseBatch::Ready(ReverseFileContext {
                        context: *context,
                        payload: scoped_gaps,
                    })
                }
                JvmImportContext::Unavailable => ReverseBatch::UnsupportedContext,
                JvmImportContext::Cancelled => ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Context,
                    completion: cancelled_completion(),
                },
            },
        )
    }
    fn validate(
        &mut self,
        prepared: &Self::Prepared,
    ) -> Result<ReverseBatch<SelectedResolutionContextInputs, Self::Limit>> {
        Ok(
            match self.operation.prepare_context(
                prepared.context.clone(),
                self.cancellation,
                self.metrics,
            )? {
                SelectedResolutionContextValidationOutcome::Ready(context) => {
                    ReverseBatch::Ready(context)
                }
                SelectedResolutionContextValidationOutcome::Cancelled => ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Prepare,
                    completion: cancelled_completion(),
                },
            },
        )
    }
    fn with_scope<'a, T>(
        &'a mut self,
        prepared: &'a Self::Prepared,
        run: impl FnOnce(&mut Self::Scoped<'a>) -> Result<ReverseBatch<T, Self::Limit>>,
    ) -> Result<ReverseBatch<T, Self::Limit>> {
        run(&mut JvmReverseScoped {
            operation: self.operation,
            storage_language: self.storage_language,
            path: self.path,
            gaps: &prepared.payload,
            cancellation: self.cancellation,
        })
    }
    fn finish(
        &mut self,
        reports: Vec<ReverseSessionReport<Self::Answer>>,
    ) -> ReverseSessionOutcome<Self::Answer, Self::Limit> {
        Ok(ReverseBatch::Ready(reports))
    }
}

impl ReverseScopedLifecycle for JvmReverseScoped<'_, '_, '_> {
    type Answer = FactResolutionAnswer;
    type Limit = std::convert::Infallible;
    fn blueprint(
        &mut self,
        context: SelectedResolutionContextInputs,
    ) -> Result<ReverseBatch<SelectedFactOperationBlueprint, Self::Limit>> {
        Ok(
            match self
                .operation
                .ready
                .collect_blueprint(context, self.cancellation)?
            {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => {
                    ReverseBatch::Ready(blueprint)
                }
                SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    ..
                } => ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Blueprint,
                    completion: cancellation_completion,
                },
            },
        )
    }
    fn register(
        &mut self,
        blueprint: &SelectedFactOperationBlueprint,
    ) -> Result<ReverseBatch<(), Self::Limit>> {
        Ok(
            match self
                .operation
                .ready
                .register_context(blueprint, self.cancellation)?
            {
                ContextRegistrationOutcome::Cancelled => ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Register,
                    completion: cancelled_completion(),
                },
                _ => ReverseBatch::Ready(()),
            },
        )
    }
    fn locate(
        &mut self,
        locator: &SelectedSemanticLocator,
    ) -> Result<ReverseBatch<LocatedSemantics, Self::Limit>> {
        Ok(
            match self.operation.ready.lookup_locator(
                &self.operation.ready.lexical_source(),
                locator,
                self.cancellation,
            )? {
                LocatedSemantic::Found(semantic) => {
                    ReverseBatch::Ready(LocatedSemantics::Found(vec![semantic]))
                }
                LocatedSemantic::Missing => ReverseBatch::Ready(LocatedSemantics::Missing),
                LocatedSemantic::Cancelled => ReverseBatch::Cancelled {
                    stage: ReverseCancellationStage::Locator,
                    completion: cancelled_completion(),
                },
            },
        )
    }
    fn with_evaluator<T>(
        &mut self,
        blueprint: &SelectedFactOperationBlueprint,
        run: impl FnOnce(
            &mut dyn ReverseSessionEvaluator<Answer = Self::Answer, Limit = Self::Limit>,
        ) -> Result<ReverseBatch<T, Self::Limit>>,
    ) -> Result<ReverseBatch<T, Self::Limit>> {
        let lexical = self.operation.ready.lexical_source();
        let typed = self.operation.ready.typed_source();
        let lexical = SeamProfiled::observing(&lexical);
        let typed = SeamProfiled::observing(&typed);
        self.operation.with_jvm_forward_operation(
            self.storage_language,
            blueprint,
            &lexical,
            &typed,
            self.path,
            Some(self.gaps),
            self.cancellation,
            &ResolutionSession::unbounded(),
            None,
            |forward| {
                run(&mut ReverseEvaluatorFn {
                    marker: std::marker::PhantomData,
                    run: |_locator: &SelectedSemanticLocator, reference: SemanticId| {
                        if self.cancellation.is_cancelled() {
                            return Ok(ReverseBatch::Cancelled {
                                stage: ReverseCancellationStage::Projection,
                                completion: cancelled_completion(),
                            });
                        }
                        Ok(ReverseBatch::Ready(vec![
                            forward.resolve_reference_with_metrics(
                                reference,
                                &mut ResolutionBatchMetrics::default(),
                            )?,
                        ]))
                    },
                })
            },
        )
    }
}

// The public JVM result already reports peer-language absence through its
// inventory-boundary flag. Keep the obligation, but preserve that projection
// instead of adding a second resolution-incomplete diagnostic for the boundary.
fn jvm_reverse_completion(evidence: &ReverseEvidence) -> ResolutionCompletion {
    evidence
        .enumeration
        .completion_for(|obligation| {
            !matches!(obligation.origin, ReverseEvidenceOrigin::InventoryBoundary)
        })
        .combine(&evidence.binding.completion())
        .combine(&evidence.metadata.completion())
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

struct JvmOrdinaryReverseReducer {
    target: SemanticId,
    references: Vec<JvmReverseConfirmedReference>,
}

impl ReverseFileReducer for JvmOrdinaryReverseReducer {
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
