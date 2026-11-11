//! Query-local JVM reverse candidates from the shared lookup identity index.
//! Candidate rows are provisional; each selected file-scoped JVM forward
//! operation confirms every returned reference.

use super::nominal_rules::nominal_language_rules;
use super::reverse::*;
use super::*;
use crate::analyzer::resolution::{
    CompanionTypeRelation, EndpointSignature, JvmAliasProperty, LoweredMemberOwnerProperty,
    SelectedSemanticLocator, SelectedTypedFactSource, StackPattern,
};
use brokk_bifrost_core::analyzer::common::language_for_target;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
use brokk_bifrost_core::analyzer::source_facts::{DeclarationAccessBoundary, PackageAccessRegion};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use rusqlite::OptionalExtension;

use super::nominal_reverse::*;

const JVM_STORAGE_LANGUAGES: [(Language, &str); 3] = [
    (Language::Java, "java"),
    (Language::Kotlin, "kotlin"),
    (Language::Scala, "scala"),
];

pub(super) struct JavaReverseTargetRules;
pub(super) struct KotlinReverseTargetRules;
pub(super) struct ScalaReverseTargetRules;

impl NominalReverseTargetRules for JavaReverseTargetRules {
    fn complete_target_families(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        target: SemanticId,
        definitions: &[(SemanticId, SelectedNativeDefinition)],
        families: &mut TargetFamilies,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        complete_jvm_target_families(operation, target, definitions, families, cancellation)
    }

    fn target_access(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        target: SemanticId,
        unit: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<NominalReverseTargetAccess> {
        operation.jvm_reverse_target_access(target, unit, cancellation)
    }
    fn import_inventory(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        mount: u32,
        blob: i64,
        lookup: SemanticId,
        target: SemanticId,
        known_sites: &HashSet<ResolutionSiteId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<ResolutionCompletion>> {
        operation.jvm_reverse_import_inventory(
            mount,
            blob,
            lookup,
            target,
            known_sites,
            cancellation,
        )
    }
    fn file_evaluator(&self) -> &'static dyn ReverseFileEvaluator<Answer = FactResolutionAnswer> {
        &JvmReverseAdapter
    }

    fn candidate_languages(&self) -> &'static [(Language, &'static str)] {
        &JVM_STORAGE_LANGUAGES
    }
    fn inspect_imports_without_root(&self, storage_language: &str) -> bool {
        storage_language == "java"
    }
    fn hierarchy_route(&self, target: &NominalReverseTarget<'_>) -> Option<HierarchyRoute> {
        (target.visibility == Some(DeclaredVisibility::Protected))
            .then_some(HierarchyRoute { open_world: true })
    }

    fn target_families(
        &self,
        target: &NominalReverseTarget<'_>,
        _facts: &dyn SelectedTypedFactSource,
        _cancellation: &CancellationToken,
    ) -> Result<TargetFamilies> {
        let mut families = TargetFamilies::empty();
        let mut owners = target
            .unit
            .fq_segments_debug()
            .into_iter()
            .filter_map(|(kind, name)| matches!(kind, "Type" | "Nested").then_some(name))
            .collect::<Vec<_>>();
        if target.unit.is_class() {
            owners.pop();
        }
        if !owners.is_empty() && (target.unit.is_class() || owners.len() > 1) {
            families.nominations.push(NominalReverseFamilyRoute {
                member_name: target.unit.terminal_name().to_owned(),
                owner_segments: owners,
            });
            // Owner spellings nominate known lexical routes, but the selected
            // source hierarchy cannot certify every inherited nested route.
            families.completion = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target.semantic),
            ]);
        }
        Ok(families)
    }

    fn peer_naming(&self, target: &NominalReverseTarget<'_>) -> PeerNaming {
        match target.visibility {
            Some(DeclaredVisibility::Private) => PeerNaming::Closed,
            Some(DeclaredVisibility::PackagePrivate) => {
                PeerNaming::WithinPackage(PackageAccessRegion::Exact(target.package.into()))
            }
            Some(DeclaredVisibility::Public | DeclaredVisibility::Protected) => PeerNaming::Open,
            _ => PeerNaming::OpenIncomplete(ResolutionIncompleteReason::UnsupportedSemantic(
                target.semantic,
            )),
        }
    }
}

impl NominalReverseTargetRules for KotlinReverseTargetRules {
    fn complete_target_families(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        target: SemanticId,
        definitions: &[(SemanticId, SelectedNativeDefinition)],
        families: &mut TargetFamilies,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        complete_jvm_target_families(operation, target, definitions, families, cancellation)
    }

    fn target_access(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        target: SemanticId,
        unit: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<NominalReverseTargetAccess> {
        operation.jvm_reverse_target_access(target, unit, cancellation)
    }
    fn import_inventory(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        mount: u32,
        blob: i64,
        lookup: SemanticId,
        target: SemanticId,
        known_sites: &HashSet<ResolutionSiteId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<ResolutionCompletion>> {
        operation.jvm_reverse_import_inventory(
            mount,
            blob,
            lookup,
            target,
            known_sites,
            cancellation,
        )
    }
    fn file_evaluator(&self) -> &'static dyn ReverseFileEvaluator<Answer = FactResolutionAnswer> {
        &JvmReverseAdapter
    }

    fn candidate_languages(&self) -> &'static [(Language, &'static str)] {
        &JVM_STORAGE_LANGUAGES
    }
    fn inspect_imports_without_root(&self, storage_language: &str) -> bool {
        storage_language == "java"
    }
    fn hierarchy_route(&self, target: &NominalReverseTarget<'_>) -> Option<HierarchyRoute> {
        (target.visibility == Some(DeclaredVisibility::Protected))
            .then_some(HierarchyRoute { open_world: true })
    }

    fn target_families(
        &self,
        target: &NominalReverseTarget<'_>,
        facts: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
    ) -> Result<TargetFamilies> {
        jvm_reverse_alias_families(target.semantic, facts, cancellation)
    }

    fn peer_naming(&self, target: &NominalReverseTarget<'_>) -> PeerNaming {
        match target.visibility {
            Some(DeclaredVisibility::Private) => PeerNaming::Closed,
            Some(DeclaredVisibility::Public | DeclaredVisibility::Protected) => PeerNaming::Open,
            _ => PeerNaming::OpenIncomplete(ResolutionIncompleteReason::UnsupportedSemantic(
                target.semantic,
            )),
        }
    }
}

impl NominalReverseTargetRules for ScalaReverseTargetRules {
    fn complete_target_families(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        target: SemanticId,
        definitions: &[(SemanticId, SelectedNativeDefinition)],
        families: &mut TargetFamilies,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        complete_jvm_target_families(operation, target, definitions, families, cancellation)
    }

    fn target_access(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        target: SemanticId,
        unit: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<NominalReverseTargetAccess> {
        operation.jvm_reverse_target_access(target, unit, cancellation)
    }
    fn import_inventory(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        mount: u32,
        blob: i64,
        lookup: SemanticId,
        target: SemanticId,
        known_sites: &HashSet<ResolutionSiteId>,
        cancellation: &CancellationToken,
    ) -> Result<Option<ResolutionCompletion>> {
        operation.jvm_reverse_import_inventory(
            mount,
            blob,
            lookup,
            target,
            known_sites,
            cancellation,
        )
    }
    fn file_evaluator(&self) -> &'static dyn ReverseFileEvaluator<Answer = FactResolutionAnswer> {
        &JvmReverseAdapter
    }

    fn candidate_languages(&self) -> &'static [(Language, &'static str)] {
        &JVM_STORAGE_LANGUAGES
    }
    fn inspect_imports_without_root(&self, storage_language: &str) -> bool {
        storage_language == "java"
    }
    fn hierarchy_route(&self, target: &NominalReverseTarget<'_>) -> Option<HierarchyRoute> {
        (target.visibility == Some(DeclaredVisibility::Protected))
            .then_some(HierarchyRoute { open_world: true })
    }

    fn target_families(
        &self,
        target: &NominalReverseTarget<'_>,
        facts: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
    ) -> Result<TargetFamilies> {
        let mut families = jvm_reverse_alias_families(target.semantic, facts, cancellation)?;
        // An object's member already confirms to its authored identity. Its
        // singleton owner is a route, never an equivalent member definition.
        if !target.unit.is_class() || target.unit.is_synthetic() {
            return Ok(families);
        }
        jvm_reverse_companion_families(
            target.semantic,
            facts,
            cancellation,
            &mut families,
            &["apply", "unapply", "unapplySeq"],
        )?;
        Ok(families)
    }

    fn peer_naming(&self, target: &NominalReverseTarget<'_>) -> PeerNaming {
        match &target.boundary {
            Some(DeclarationAccessBoundary::Package(region)) => {
                PeerNaming::WithinPackage(PackageAccessRegion::Enclosing(region.clone()))
            }
            Some(DeclarationAccessBoundary::Template(_)) => PeerNaming::Closed,
            None => match target.visibility {
                Some(DeclaredVisibility::Private) => PeerNaming::Closed,
                Some(DeclaredVisibility::Public | DeclaredVisibility::Protected) => {
                    PeerNaming::Open
                }
                _ => PeerNaming::OpenIncomplete(ResolutionIncompleteReason::UnsupportedSemantic(
                    target.semantic,
                )),
            },
        }
    }
}

fn jvm_reverse_companion_families(
    target: SemanticId,
    facts: &dyn SelectedTypedFactSource,
    cancellation: &CancellationToken,
    families: &mut TargetFamilies,
    member_names: &[&str],
) -> Result<()> {
    let mut companions = Vec::new();
    let outcome = facts.visit_companion_relation_pages_for_enclosing_types(
        TypedFactRequest::new(&[target]),
        cancellation,
        &mut FactPageVisitor::new(&mut |page: &[SelectedTypedRow<CompanionTypeRelation>]| {
            companions.extend(page.iter().map(|row| row.row().companion_type()));
            Ok(!cancellation.is_cancelled())
        }),
    )?;
    jvm_reverse_family_read(families, outcome, target, cancellation)?;
    for chunk in companions.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
        let outcome = facts.visit_member_owner_pages_for_owners(
            TypedFactRequest::new(chunk),
            cancellation,
            &mut FactPageVisitor::new(&mut |page: &[SelectedTypedRow<
                LoweredMemberOwnerProperty,
            >]| {
                for row in page {
                    let member = row.row();
                    if member_names.contains(&member.member_name()) {
                        families.equivalent_targets.push(member.definition());
                        families.nominations.push(NominalReverseFamilyRoute {
                            member_name: member.member_name().to_owned(),
                            owner_segments: Vec::new(),
                        });
                    }
                }
                Ok(!cancellation.is_cancelled())
            }),
        )?;
        jvm_reverse_family_read(families, outcome, target, cancellation)?;
    }
    Ok(())
}

fn jvm_reverse_alias_families(
    target: SemanticId,
    facts: &dyn SelectedTypedFactSource,
    cancellation: &CancellationToken,
) -> Result<TargetFamilies> {
    let mut families = TargetFamilies::empty();
    let outcome = facts.visit_jvm_alias_pages_for_definitions(
        TypedFactRequest::new(&[target]),
        cancellation,
        &mut FactPageVisitor::new(&mut |page: &[SelectedTypedRow<JvmAliasProperty>]| {
            for row in page {
                let alias = row.row();
                assert_eq!(alias.definition, target);
                // A binary owner path is the package segments followed by
                // one binary type name; only that type is an owner spelling.
                families.nominations.push(NominalReverseFamilyRoute {
                    member_name: alias.member_name.clone(),
                    owner_segments: alias.owner_segments.last().cloned().into_iter().collect(),
                });
            }
            Ok(!cancellation.is_cancelled())
        }),
    )?;
    jvm_reverse_family_read(&mut families, outcome, target, cancellation)?;
    Ok(families)
}

fn jvm_reverse_family_read(
    families: &mut TargetFamilies,
    outcome: crate::analyzer::resolution::TypedFactReadOutcome,
    target: SemanticId,
    cancellation: &CancellationToken,
) -> Result<()> {
    let (terminal, completion) = outcome.into_parts();
    families.completion = families.completion.combine(&completion);
    if cancellation.is_cancelled()
        || terminal == crate::analyzer::resolution::TypedFactReadTerminal::Cancelled
    {
        families.completion = families.completion.combine(&cancelled_completion());
    } else if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted {
        return Err(StoreError::new(format!(
            "JVM target family read stopped before exhausting {target:?}"
        )));
    }
    Ok(())
}

impl SelectedResolutionOperation<'_, '_> {
    pub(super) fn jvm_reverse_import_inventory(
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
        let mut import_kind = connection.prepare_cached(JVM_REVERSE_IMPORT_KIND_SQL)?;
        let mut local_uses = connection.prepare_cached(JVM_REVERSE_LOCAL_USE_SQL)?;
        let mut unverified_local_use = false;
        let mut has_local_use = false;
        if let Some(identity) = lookup.shared_name_id() {
            let sites = local_uses
                .query_map(rusqlite::params![blob_id, identity.get()], |row| {
                    row.get::<_, u32>(0)
                })?;
            for site in sites {
                let site = ResolutionSiteId::new(site?);
                has_local_use = true;
                unverified_local_use |= !known_sites.contains(&site);
            }
        }
        if unverified_local_use {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
            ]));
        }
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
                    let Some(token_key) = token.local_key() else {
                        if has_local_use || *demand == lookup || route.contains(&lookup) {
                            completion = completion.combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                            ]));
                        }
                        continue;
                    };
                    let import_kind = import_kind
                        .query_row(rusqlite::params![blob_id, i64::from(token_key)], |row| {
                            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                        })
                        .optional()?;
                    if import_kind
                        .as_ref()
                        .is_some_and(|(_, kind)| kind == "static_on_demand")
                        && has_local_use
                    {
                        // The current binder does not certify which static wildcard owner
                        // exposes this local name. Keep this target open until it does.
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                        ]));
                    }
                    if *demand != lookup && !route.contains(&lookup) {
                        continue;
                    }
                    let Some((source_site, _)) = import_kind else {
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
        // completion can include unrelated open roots. Check exact lookup
        // imports against known sites, and open only targets with selected
        // local uses when an on-demand static import can expose their name.
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

    pub(super) fn jvm_reverse_target_access(
        &self,
        target: SemanticId,
        target_unit: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<NominalReverseTargetAccess> {
        let facts = self.ready.typed_source();
        let mut visibility = None;
        let mut boundary = None;
        let mut collect_visibility = |rows: &[SelectedTypedRow<
            crate::analyzer::resolution::LoweredDeclarationVisibilityProperty,
        >]| {
            for row in rows {
                assert_eq!(row.row().definition(), target);
                assert!(visibility.replace(row.row().visibility()).is_none());
                boundary = row.row().boundary().cloned();
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
            return Ok(NominalReverseTargetAccess {
                visibility: None,
                owner: None,
                boundary: None,
                completion: cancelled_completion(),
            });
        }
        if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted {
            return Err(StoreError::new(
                "JVM target visibility read stopped before exhausting its exact request",
            ));
        }
        if visibility.is_none() {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target),
            ]));
        }

        // An invalid Scala qualifier has no boundary row. Its producer keeps
        // access evidence on the exact definition's reverse frontier. Read
        // that frontier before interpreting an absent qualifier as private.
        // Java keeps its existing read shape and exact-work contract.
        if nominal_language_rules(language_for_target(target_unit))
            .is_some_and(|rules| rules.has_reverse_lexical_access())
            && boundary.is_none()
            && matches!(
                visibility,
                Some(DeclaredVisibility::Private | DeclaredVisibility::Protected)
            )
        {
            let lexical = self.ready.lexical_source();
            if let Some(node) = lexical.lookup_definition_node(target, cancellation)? {
                let request = crate::analyzer::resolution::BatchCandidateRequest::new(
                    0,
                    EndpointSignature::new(
                        node,
                        StackPattern::closed([]),
                        StackPattern::closed([]),
                    ),
                );
                let outcome = lexical.visit_reverse_candidate_match_pages(
                    &[request],
                    cancellation,
                    &mut |_| Ok(!cancellation.is_cancelled()),
                )?;
                if outcome.branch_completions() != [ResolutionCompletion::Complete] {
                    visibility = None;
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(target),
                    ]));
                }
                completion = completion.combine(outcome.unconditional_completion());
            } else {
                visibility = None;
                completion = completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(target),
                ]));
            }
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
            return Ok(NominalReverseTargetAccess {
                visibility,
                owner: None,
                boundary,
                completion: cancelled_completion(),
            });
        }
        if terminal != crate::analyzer::resolution::TypedFactReadTerminal::Exhausted {
            return Err(StoreError::new(
                "JVM target owner read stopped before exhausting its exact request",
            ));
        }
        completion = completion.combine(&owner_completion);
        let owner = owner.or_else(|| target_unit.is_class().then_some(target));
        if owner.is_none() {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(target),
            ]));
        }
        Ok(NominalReverseTargetAccess {
            visibility,
            owner,
            boundary,
            completion,
        })
    }
}
pub(super) struct JvmReverseAdapter;

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

const JVM_REVERSE_LOCAL_USE_SQL: &str = "SELECT DISTINCT reference.source_site FROM main.resolution_reference_lookup_identities AS names INDEXED BY resolution_reference_lookup_identities_identity JOIN main.resolution_semantic_sites AS reference ON reference.blob_id=names.blob_id AND reference.semantic_key=names.semantic_key AND reference.semantic_role='reference' WHERE names.blob_id=?1 AND names.identity_id=?2";

const JVM_REVERSE_IMPORT_KIND_SQL: &str = "SELECT import_source_site,import_route_kind FROM main.resolution_semantic_catalog WHERE blob_id=?1 AND local_key=?2 AND import_source_site IS NOT NULL";

fn complete_jvm_target_families(
    operation: &SelectedResolutionOperation<'_, '_>,
    target_semantic: SemanticId,
    target_definitions: &[(SemanticId, SelectedNativeDefinition)],
    families: &mut TargetFamilies,
    cancellation: &CancellationToken,
) -> Result<()> {
    // Generated Scala apply/extractor declarations project to their exact
    // synthetic constructor bridge. Written companion methods do not
    // become equivalent just because their name is apply or unapply.
    for semantic in &families.equivalent_targets {
        if !target_definitions.iter().any(|(identity, definition)| {
            identity == semantic
                && matches!(definition, SelectedNativeDefinition::Unit(unit) if unit.is_function())
        }) {
            // Unitless/local generated members need an explicit bridge
            // before they can be distinguished from written callables.
            families.completion = families
                .completion
                .combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(target_semantic),
                ]));
        }
    }
    let generated_units = target_definitions
        .iter()
        .filter_map(|(semantic, definition)| {
            if !families.equivalent_targets.contains(semantic) {
                return None;
            }
            match definition {
                SelectedNativeDefinition::Unit(unit)
                    if unit.is_synthetic() && unit.is_function() =>
                {
                    Some(unit)
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    families.equivalent_targets = target_definitions
        .iter()
        .filter_map(|(semantic, definition)| match definition {
            SelectedNativeDefinition::Unit(unit)
                if families.equivalent_targets.contains(semantic)
                    && generated_units.contains(&unit) =>
            {
                Some(*semantic)
            }
            _ => None,
        })
        .collect();
    if !families.equivalent_targets.is_empty() {
        let outcome = operation.ready.typed_source().visit_member_owner_pages_for_owners(
                TypedFactRequest::new(&[target_semantic]), cancellation,
                &mut FactPageVisitor::new(&mut |page: &[SelectedTypedRow<LoweredMemberOwnerProperty>]| {
                    for row in page {
                        let member = row.row();
                        if member.kind() == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::Constructor
                            && target_definitions.iter().any(|(semantic, definition)|
                                *semantic == member.definition() && matches!(definition,
                                    SelectedNativeDefinition::Unit(unit) if generated_units.contains(&unit)))
                        {
                            families.equivalent_targets.push(member.definition());
                        }
                    }
                    Ok(!cancellation.is_cancelled())
                }),
            )?;
        jvm_reverse_family_read(families, outcome, target_semantic, cancellation)?;
    }
    Ok(())
}
