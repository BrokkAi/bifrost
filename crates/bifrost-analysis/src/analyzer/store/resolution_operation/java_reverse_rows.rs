//! Query-local Java reverse candidates from the shared lookup identity index.
//! Candidate rows are provisional; the selected file-scoped Java forward
//! operation confirms every returned reference.

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

#[cfg(test)]
thread_local! {
    static LAST_JAVA_REVERSE_CANDIDATE_PLAN: std::cell::RefCell<Vec<String>> = const {
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

pub(crate) const JAVA_REVERSE_CANDIDATE_MOUNTS_SQL: &str = r#"
SELECT mount.mount_ordinal, mount.persisted_relative_path, mount.blob_id,
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
WHERE mount.storage_language='java'
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
  )
"#;

const JAVA_REVERSE_REFERENCE_SEMANTIC_SQL: &str = "SELECT semantic_key FROM main.resolution_semantic_sites WHERE blob_id=?1 AND source_site=?2 AND semantic_role='reference'";
const JAVA_REVERSE_IMPORT_SOURCE_SITE_SQL: &str = "SELECT import_source_site FROM main.resolution_semantic_catalog WHERE blob_id=?1 AND local_key=?2 AND import_source_site IS NOT NULL";

#[derive(Clone)]
pub(crate) struct JavaReverseCandidate {
    pub(crate) locator: SelectedSemanticLocator,
}

pub(crate) struct JavaReverseCandidateSet {
    pub(crate) target: SemanticId,
    pub(crate) candidates: Vec<JavaReverseCandidate>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) peer_language_inventory_open: bool,
}

pub(crate) enum JavaReverseCandidateOutcome {
    Ready(JavaReverseCandidateSet),
    Unavailable(String),
    Cancelled,
}

pub(crate) struct JavaReverseConfirmedReference {
    pub(crate) locator: SelectedSemanticLocator,
    pub(crate) answer: FactResolutionAnswer,
    pub(crate) owner: Option<CodeUnit>,
}

pub(crate) struct JavaReverseConfirmed {
    pub(crate) target: SemanticId,
    pub(crate) references: Vec<JavaReverseConfirmedReference>,
    pub(crate) completion: ResolutionCompletion,
    pub(crate) candidate_inventory_complete: bool,
    pub(crate) peer_language_inventory_open: bool,
}

impl SelectedResolutionOperation<'_, '_> {
    /// Find every Java source site whose indexed simple-name identity could
    /// refer to `target`, then narrow by Java declaration access. Java fully
    /// qualified references do not require an import, so no importer filter is
    /// applied here.
    pub(crate) fn java_reverse_candidate_sites(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<JavaReverseCandidateOutcome> {
        if cancellation.is_cancelled() {
            return Ok(JavaReverseCandidateOutcome::Cancelled);
        }
        let relative_path = crate::path_utils::rel_path_string(target.source());
        let Some(target_mount) = self.mount_table().mount_for_path("java", &relative_path)? else {
            return Ok(JavaReverseCandidateOutcome::Unavailable(format!(
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
                return Ok(JavaReverseCandidateOutcome::Unavailable(format!(
                    "Java target definitions are not projectable: {relative_path}"
                )));
            }
            SelectedNativeDefinitions::Cancelled => {
                return Ok(JavaReverseCandidateOutcome::Cancelled);
            }
        };
        let Some((target_semantic, _)) = target_definitions.into_iter().find(|(_, definition)| {
            matches!(definition, SelectedNativeDefinition::Unit(unit) if unit == target)
        }) else {
            return Ok(JavaReverseCandidateOutcome::Unavailable(format!(
                "Java target has no selected definition identity: {target:?}"
            )));
        };

        let (visibility, owner_semantic, mut completion) =
            self.java_reverse_target_access(target_semantic, target, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(JavaReverseCandidateOutcome::Cancelled);
        }
        let target_package = target.package_name();
        let peer_language_inventory_open =
            self.java_peer_language_may_name_target(target_package, visibility, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(JavaReverseCandidateOutcome::Cancelled);
        }
        let subclass_paths = if visibility == Some(DeclaredVisibility::Protected) {
            // The selected Java hierarchy is a source inventory, not a closed
            // classpath universe. Even a completed source walk cannot prove
            // that no additional subtype route exists outside that universe.
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(
                    owner_semantic.unwrap_or(target_semantic),
                ),
            ]));
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
                            match self.java_reverse_subclass_source_paths(
                                owner_semantic,
                                owner,
                                cancellation,
                                &mut completion,
                            )? {
                                Some(paths) => paths,
                                None => return Ok(JavaReverseCandidateOutcome::Cancelled),
                            }
                        } else {
                            completion = completion.combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(owner_semantic),
                            ]));
                            HashSet::default()
                        }
                    }
                    SelectedNativeDefinitions::Unavailable => {
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(owner_semantic),
                        ]));
                        HashSet::default()
                    }
                    SelectedNativeDefinitions::Cancelled => {
                        return Ok(JavaReverseCandidateOutcome::Cancelled);
                    }
                }
            } else {
                completion = completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                ]));
                HashSet::default()
            }
        } else {
            HashSet::default()
        };
        let mut candidates = HashMap::<(String, ResolutionSiteId), ()>::default();
        let mut candidate_packages = HashMap::<String, Option<String>>::default();
        let lexical = self.ready.lexical_source();
        for namespace in ALL_RESOLUTION_NAMESPACES
            .iter()
            .filter(|namespace| **namespace != ResolutionNamespace::TypeOrValue)
        {
            if cancellation.is_cancelled() {
                return Ok(JavaReverseCandidateOutcome::Cancelled);
            }
            let lookup = ResolutionLookupSemanticRecipe::new(
                Language::Java,
                *namespace,
                target.terminal_name(),
            )
            .semantic(&self.ready.shared_names());
            let Some(identity) = lookup.shared_name_id() else {
                continue;
            };
            #[cfg(test)]
            LAST_JAVA_REVERSE_CANDIDATE_PLAN.with(|last| {
                *last.borrow_mut() =
                    explain_java_reverse_candidate_plan(connection, i64::from(identity.get()))
                        .expect("explain populated Java reverse candidate query");
            });
            let mut statement = connection.prepare_cached(JAVA_REVERSE_CANDIDATE_MOUNTS_SQL)?;
            for row in statement.query_map([i64::from(identity.get())], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })? {
                let (_ordinal, path, blob_id, package, has_qualified, has_root) = row?;
                if package.is_none() {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                    ]));
                }
                candidate_packages.insert(path.clone(), package.clone());
                let Some(sites) = self.java_reverse_lookup_sites(
                    blob_id,
                    lookup,
                    has_qualified,
                    has_root,
                    cancellation,
                )?
                else {
                    return Ok(JavaReverseCandidateOutcome::Cancelled);
                };
                if has_root {
                    let Some(import_completion) = self.java_reverse_import_inventory(
                        _ordinal,
                        blob_id,
                        lookup,
                        target_semantic,
                        &sites,
                        cancellation,
                    )?
                    else {
                        return Ok(JavaReverseCandidateOutcome::Cancelled);
                    };
                    completion = completion.combine(&import_completion);
                }
                for site in sites {
                    candidates.entry((path.clone(), site)).or_default();
                }
            }
        }

        let mut inventory_complete = true;
        let inventory_session = ResolutionSession::unbounded();
        for mount in self
            .mount_table()
            .mounts()?
            .into_iter()
            .filter(|mount| mount.storage_language() == "java")
        {
            if cancellation.is_cancelled() {
                return Ok(JavaReverseCandidateOutcome::Cancelled);
            }
            let inventory = lexical.reference_inventory_completion(
                mount.fragment(),
                cancellation,
                &inventory_session,
            )?;
            let Some(inventory) = lexical.close_completion(&inventory, cancellation)? else {
                return Ok(JavaReverseCandidateOutcome::Cancelled);
            };
            inventory_complete &= inventory == ResolutionCompletion::Complete;
            completion = completion.combine(&inventory);
        }
        if !inventory_complete {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
            ]));
        }

        let mut result = Vec::new();
        for ((path, site), ()) in candidates {
            let package = candidate_packages.get(&path).and_then(Option::as_deref);
            let include = match visibility {
                Some(DeclaredVisibility::Public) => true,
                Some(DeclaredVisibility::Private) => path == relative_path,
                Some(DeclaredVisibility::PackagePrivate) => {
                    package.is_none() || package == Some(target_package)
                }
                Some(DeclaredVisibility::Protected) => {
                    package.is_none()
                        || package == Some(target_package)
                        || subclass_paths.contains(&path)
                }
                Some(DeclaredVisibility::Internal | DeclaredVisibility::CrateOrModule) => true,
                Some(DeclaredVisibility::Unknown) | None => true,
            };
            if include {
                result.push(JavaReverseCandidate {
                    locator: SelectedSemanticLocator::new(
                        "java",
                        path,
                        site,
                        LoweredSemanticRole::Reference,
                    ),
                });
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
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
            ]));
        }
        Ok(JavaReverseCandidateOutcome::Ready(
            JavaReverseCandidateSet {
                target: target_semantic,
                candidates: result,
                completion,
                peer_language_inventory_open,
            },
        ))
    }

    fn java_peer_language_may_name_target(
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
                // Public declarations can be named through a qualified route
                // from any peer source. Package-private declarations require
                // a matching selected package row. Protected declarations may
                // be named by peer subclasses, whose hierarchy is not a closed
                // source universe, so any selected peer source keeps coverage
                // open until a peer inverse provider exists.
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn java_reverse_lookup_sites(
        &self,
        blob_id: i64,
        lookup: SemanticId,
        has_qualified: bool,
        has_root: bool,
        cancellation: &CancellationToken,
    ) -> Result<Option<HashSet<ResolutionSiteId>>> {
        let lexical = self.ready.lexical_source();
        let Some(mut sites) =
            lexical.lookup_reference_sites(blob_id, lookup, None, cancellation)?
        else {
            return Ok(None);
        };
        if has_root {
            let Some(root_sites) =
                lexical.prefixed_root_demand_reference_sites(blob_id, lookup, cancellation)?
            else {
                return Ok(None);
            };
            sites.extend(root_sites);
        }
        if has_qualified {
            let Some(qualified_sites) =
                lexical.qualified_route_reference_sites(blob_id, lookup, cancellation)?
            else {
                return Ok(None);
            };
            sites.extend(qualified_sites);
        }
        Ok(Some(sites.into_iter().collect()))
    }

    fn java_reverse_import_inventory(
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
        let mut import_source = connection.prepare_cached(JAVA_REVERSE_IMPORT_SOURCE_SITE_SQL)?;
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

    fn java_reverse_subclass_source_paths(
        &self,
        root_semantic: SemanticId,
        root: CodeUnit,
        cancellation: &CancellationToken,
        completion: &mut ResolutionCompletion,
    ) -> Result<Option<HashSet<String>>> {
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
            for namespace in [ResolutionNamespace::Type] {
                let lookup = ResolutionLookupSemanticRecipe::new(
                    Language::Java,
                    namespace,
                    base_unit.terminal_name(),
                )
                .semantic(&self.ready.shared_names());
                let Some(identity) = lookup.shared_name_id() else {
                    continue;
                };
                let mut statement = connection.prepare_cached(JAVA_REVERSE_CANDIDATE_MOUNTS_SQL)?;
                for row in statement.query_map([i64::from(identity.get())], |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, bool>(5)?,
                    ))
                })? {
                    let (ordinal, path, blob_id, _package, has_qualified, has_root) = row?;
                    let Some(sites) = self.java_reverse_lookup_sites(
                        blob_id,
                        lookup,
                        has_qualified,
                        has_root,
                        cancellation,
                    )?
                    else {
                        return Ok(None);
                    };
                    let mut semantic_statement =
                        connection.prepare_cached(JAVA_REVERSE_REFERENCE_SEMANTIC_SQL)?;
                    for site in sites {
                        let semantic_key = semantic_statement
                            .query_row(rusqlite::params![blob_id, i64::from(site.get())], |row| {
                                row.get::<_, i64>(0)
                            })
                            .optional()?;
                        let Some(semantic_key) = semantic_key else {
                            *completion = completion.combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(base_semantic),
                            ]));
                            continue;
                        };
                        let semantic = SemanticId::local(
                            ordinal,
                            u32::try_from(semantic_key)
                                .expect("Java hierarchy semantic key fits u32"),
                        );
                        locators.entry(semantic).or_insert_with(|| {
                            SelectedSemanticLocator::new(
                                "java",
                                path.clone(),
                                site,
                                LoweredSemanticRole::Reference,
                            )
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
            let (terminal, evidence) = outcome.into_parts();
            *completion = completion.combine(&evidence);
            if terminal == crate::analyzer::resolution::TypedFactReadTerminal::Cancelled
                || cancellation.is_cancelled()
            {
                return Ok(None);
            }
            if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted {
                *completion = completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(base_semantic),
                ]));
            }
            let candidates = hierarchy_candidates
                .keys()
                .cloned()
                .map(|locator| JavaReverseCandidate { locator })
                .collect::<Vec<_>>();
            let (confirmed, forward_completion) = match self.confirm_java_hierarchy_references(
                candidates,
                base_semantic,
                cancellation,
                &mut context_metrics,
            ) {
                Ok(answer) => answer,
                Err(_) if cancellation.is_cancelled() => return Ok(None),
                Err(error) => return Err(error),
            };
            *completion = completion.combine(&forward_completion);
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
                    *completion = completion.combine(&ResolutionCompletion::incomplete(
                        child_semantics
                            .iter()
                            .copied()
                            .map(ResolutionIncompleteReason::UnsupportedSemantic),
                    ));
                    continue;
                }
                SelectedNativeDefinitions::Cancelled => {
                    return Ok(None);
                }
            };
            for (semantic, definition) in projected {
                let SelectedNativeDefinition::Unit(unit) = definition else {
                    *completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(semantic),
                    ]));
                    continue;
                };
                if !unit.is_class() {
                    *completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(semantic),
                    ]));
                    continue;
                }
                descendants.insert(crate::path_utils::rel_path_string(unit.source()));
                if !visited.contains(&semantic) {
                    pending.push_back((semantic, unit));
                }
            }
        }
        Ok(Some(descendants))
    }

    fn confirm_java_hierarchy_references(
        &self,
        candidates: Vec<JavaReverseCandidate>,
        base_semantic: SemanticId,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<(
        Vec<(SelectedSemanticLocator, FactResolutionAnswer)>,
        ResolutionCompletion,
    )> {
        let mut groups = HashMap::<String, Vec<JavaReverseCandidate>>::default();
        for candidate in candidates {
            groups
                .entry(candidate.locator.relative_path().to_owned())
                .or_default()
                .push(candidate);
        }
        let mut references = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        for (path, mut candidates) in groups {
            if cancellation.is_cancelled() {
                return Err(StoreError::new("Java hierarchy confirmation was cancelled"));
            }
            candidates.sort_by(|left, right| left.locator.cmp(&right.locator));
            let context = match self.java_import_context(&path, cancellation)? {
                JavaImportContext::Ready { context, .. } => *context,
                JavaImportContext::Unavailable => {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(base_semantic),
                    ]));
                    continue;
                }
                JavaImportContext::Cancelled => {
                    return Err(StoreError::new("Java hierarchy confirmation was cancelled"));
                }
            };
            completion = completion.combine(context.inventory_completion());
            let context = match self.prepare_context(context, cancellation, context_metrics)? {
                SelectedResolutionContextValidationOutcome::Ready(context) => context,
                SelectedResolutionContextValidationOutcome::Cancelled => {
                    return Err(StoreError::new("Java hierarchy confirmation was cancelled"));
                }
            };
            let ready = &self.ready;
            let persisted_lexical = ready.lexical_source();
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint = match ready.collect_blueprint(context, cancellation)? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled { .. } => {
                    return Err(StoreError::new("Java hierarchy confirmation was cancelled"));
                }
            };
            if matches!(
                ready.register_context(&blueprint, cancellation)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Err(StoreError::new("Java hierarchy confirmation was cancelled"));
            }
            let mut located = Vec::with_capacity(candidates.len());
            for candidate in candidates {
                match ready.lookup_locator(&persisted_lexical, &candidate.locator, cancellation)? {
                    LocatedSemantic::Found(reference) => {
                        located.push((candidate.locator, reference))
                    }
                    LocatedSemantic::Missing => {
                        return Err(StoreError::corrupt(format!(
                            "Java hierarchy candidate locator is absent from selected source: {:?}",
                            candidate.locator
                        )));
                    }
                    LocatedSemantic::Cancelled => {
                        return Err(StoreError::new("Java hierarchy confirmation was cancelled"));
                    }
                }
            }
            let (answers, group_completion) = self.with_java_forward_operation(
                &blueprint,
                &observed_lexical,
                &observed_typed,
                &path,
                cancellation,
                &ResolutionSession::unbounded(),
                |operation| {
                    let mut answers = Vec::with_capacity(located.len());
                    for (locator, reference) in located {
                        if cancellation.is_cancelled() {
                            return Ok((Vec::new(), cancelled_completion()));
                        }
                        let mut metrics = ResolutionBatchMetrics::default();
                        let answer =
                            operation.resolve_reference_with_metrics(reference, &mut metrics)?;
                        answers.push((locator, answer));
                    }
                    let completion = answers
                        .iter()
                        .fold(ResolutionCompletion::Complete, |completion, (_, answer)| {
                            completion.combine(answer.completion())
                        });
                    Ok((answers, completion))
                },
            )?;
            completion = completion.combine(&group_completion);
            references.extend(answers);
        }
        Ok((references, completion))
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

    /// Confirm grouped candidate sites with each caller's selected Java import
    /// context and forward operation.
    pub(crate) fn confirm_java_reverse_candidates(
        mut self,
        candidates: JavaReverseCandidateSet,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<JavaReverseConfirmed>> {
        let candidate_inventory_complete = candidates.completion == ResolutionCompletion::Complete;
        let target_semantic = candidates.target;
        let peer_language_inventory_open = candidates.peer_language_inventory_open;
        let mut completion = candidates.completion;
        let mut groups = HashMap::<String, Vec<JavaReverseCandidate>>::default();
        for candidate in candidates.candidates {
            groups
                .entry(candidate.locator.relative_path().to_owned())
                .or_default()
                .push(candidate);
        }
        let mut references = Vec::new();
        for (path, mut candidates) in groups {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            candidates.sort_by(|left, right| left.locator.cmp(&right.locator));
            let context = match self.java_reverse_import_context(&path, cancellation)? {
                JavaImportContext::Ready { context, .. } => *context,
                JavaImportContext::Unavailable => {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                    ]));
                    continue;
                }
                JavaImportContext::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            completion = completion.combine(context.inventory_completion());
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
                SelectedFactOperationBlueprintConstruction::Cancelled { .. } => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
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
                            "Java reverse candidate locator is absent from selected source: {:?}",
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
            let (answers, forward_completion) = self.with_java_forward_operation(
                &blueprint,
                &observed_lexical,
                &observed_typed,
                &path,
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
                    completion = completion.combine(&ResolutionCompletion::incomplete(
                        definition_semantics
                            .iter()
                            .copied()
                            .map(ResolutionIncompleteReason::UnsupportedSemantic),
                    ));
                    Vec::new()
                }
                SelectedNativeDefinitions::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            let units = definitions
                .into_iter()
                .filter_map(|(semantic, definition)| match definition {
                    SelectedNativeDefinition::Unit(unit) => Some((semantic, unit)),
                    SelectedNativeDefinition::Lexical(_) => None,
                })
                .collect::<HashMap<_, _>>();
            for (candidate, answer) in answers {
                let owner = answer
                    .reference_owner()
                    .flatten()
                    .and_then(|semantic| units.get(&semantic).cloned());
                if answer
                    .reference_owner()
                    .is_some_and(|owner| owner.is_some())
                    && owner.is_none()
                {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                    ]));
                }
                references.push(JavaReverseConfirmedReference {
                    locator: candidate.locator,
                    answer,
                    owner,
                });
            }
        }
        self.ready.finish(
            JavaReverseConfirmed {
                target: target_semantic,
                references,
                completion: completion.clone(),
                candidate_inventory_complete,
                peer_language_inventory_open,
            },
            &completion,
            cancellation,
        )
    }
}

#[cfg(test)]
fn explain_java_reverse_candidate_plan(
    connection: &rusqlite::Connection,
    identity: i64,
) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare(&format!(
        "EXPLAIN QUERY PLAN {JAVA_REVERSE_CANDIDATE_MOUNTS_SQL}"
    ))?;
    statement.query_map([identity], |row| row.get(3))?.collect()
}

#[cfg(test)]
pub(crate) fn last_java_reverse_candidate_plan_for_test() -> Vec<String> {
    LAST_JAVA_REVERSE_CANDIDATE_PLAN.with(|last| last.borrow().clone())
}
