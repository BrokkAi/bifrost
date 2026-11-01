//! Direct parent bindings owned by one selected hierarchy request.
use super::*;
use crate::analyzer::resolution::{
    FactResolutionOperation, LoweredSupertypeProperty, TypedFactPageVisitor, TypedFactRequest,
};
use brokk_bifrost_core::analyzer::capabilities::HierarchyOpenReason;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionKind, ResolutionSupertypeKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;

/// Each JVM producer publishes ImplicitSuperclass only for its language-defined
/// root. That kind certifies a closed intrinsic parent independently
/// of lexical binding or of whether the synthetic reference has provider paths.
/// Both hierarchy directions apply this rule before demanding a reference.
pub fn jvm_intrinsic_parent(
    language: brokk_bifrost_core::analyzer::model::Language,
    kind: Option<ResolutionSupertypeKind>,
) -> Option<crate::analyzer::resolution::ExternalOwnerIdentity> {
    if kind != Some(ResolutionSupertypeKind::ImplicitSuperclass) {
        return None;
    }
    brokk_bifrost_jvm::intrinsics::implicit_superclass_root(language).map(|root| {
        crate::analyzer::resolution::ExternalOwnerIdentity {
            provider_id: std::sync::Arc::from("jvm-intrinsic"),
            owner_fqn: std::sync::Arc::from(root),
        }
    })
}

/// One authored or implicit parent, with all binding alternatives preserved.
#[derive(Debug)]
pub struct JvmDirectSupertype {
    pub kind: Option<ResolutionSupertypeKind>,
    pub parent_ordinal: u32,
    pub reference: SemanticId,
    pub targets: Vec<SemanticId>,
    pub completion: ResolutionCompletion,
}

/// Request-local parent bindings. Empty or incomplete bindings remain open.
#[derive(Debug)]
pub struct JvmDirectSupertypeAnswer {
    pub parents: Vec<JvmDirectSupertype>,
    pub completion: ResolutionCompletion,
}

impl JvmDirectSupertypeAnswer {
    /// Definite parents, preserving language parent order.
    pub fn edges(&self) -> impl Iterator<Item = &JvmDirectSupertype> {
        self.parents.iter().filter(|parent| {
            parent.targets.len() == 1 && parent.completion == ResolutionCompletion::Complete
        })
    }

    /// Alternatives for one parent reference; never definite edges.
    pub fn ambiguous(&self) -> impl Iterator<Item = &JvmDirectSupertype> {
        self.parents
            .iter()
            .filter(|parent| parent.targets.len() > 1)
    }

    /// Unresolved or incomplete parents with their original binding evidence.
    /// An empty complete binding still leaves the declared parent open.
    pub fn open(&self) -> impl Iterator<Item = &JvmDirectSupertype> {
        self.parents.iter().filter(|parent| {
            parent.targets.is_empty() || parent.completion != ResolutionCompletion::Complete
        })
    }
}

/// Reverse bindings for one hydrated candidate round. All identities and
/// binding receipts are owned by the current hierarchy request.
#[derive(Debug)]
pub struct JvmDirectDescendantAnswer {
    pub edges: Vec<SemanticId>,
    pub ambiguous: Vec<SemanticId>,
    /// Candidate parent references with empty or incomplete bindings.
    pub open: Vec<SemanticId>,
    pub completion: ResolutionCompletion,
    pub open_reasons: Vec<HierarchyOpenReason>,
}

/// One reverse walk with its batched source-unit projection. This value and
/// its alias/name worklist are never retained by an analyzer.
pub struct JvmDescendantWalk {
    pub answer: JvmDirectDescendantAnswer,
    pub definitions: SelectedNativeDefinitions,
    pub rounds: usize,
}

/// The caller owns read attribution; receipts die with this hierarchy query.
pub trait JvmHierarchyReadReceipts {
    type Receipt;
    fn capture<T>(&mut self, read: impl FnOnce() -> T) -> (T, Self::Receipt);
    fn replay(&mut self, receipt: &Self::Receipt);
}

impl JvmHierarchyReadReceipts for () {
    type Receipt = ();
    fn capture<T>(&mut self, read: impl FnOnce() -> T) -> (T, ()) {
        (read(), ())
    }
    fn replay(&mut self, _receipt: &()) {}
}

#[derive(Clone)]
struct ReferenceAnswer {
    targets: Vec<SemanticId>,
    completion: ResolutionCompletion,
}

/// Borrowed inside `with_jvm_hierarchy_query`; never retained across requests.
pub struct JvmHierarchyQuery<'query, 'source, R: JvmHierarchyReadReceipts = ()> {
    forward: &'query mut FactResolutionOperation<'source>,
    typed: &'query dyn SelectedTypedFactSource,
    identities: &'query SelectedContextIdentities,
    cancellation: &'query CancellationToken,
    receipts: &'query mut R,
    references: HashMap<SemanticId, (Result<ReferenceAnswer>, R::Receipt)>,
    // Selected language/kind facts certify the intrinsic coordinate. This
    // query-scoped callback retains no answer; its reads join the receipt.
    intrinsic_parent:
        &'query dyn Fn(SemanticId, Option<ResolutionSupertypeKind>) -> Result<Option<SemanticId>>,
}

impl<R: JvmHierarchyReadReceipts> JvmHierarchyQuery<'_, '_, R> {
    /// Bypass query result reuse only to witness the shared engine's #8290 bug.
    #[cfg(any(test, feature = "test-support"))]
    pub fn resolve_reference_uncached_for_test(
        &mut self,
        reference: SemanticId,
    ) -> Result<crate::analyzer::resolution::FactResolutionAnswer> {
        self.forward
            .resolve_reference_with_metrics(reference, &mut ResolutionBatchMetrics::default())
    }

    fn resolve_reference(
        &mut self,
        reference: SemanticId,
        kind: Option<ResolutionSupertypeKind>,
        supertype_slot: Option<SemanticId>,
    ) -> Result<ReferenceAnswer> {
        // Kind and slot are selected parent metadata, not a caller mode.
        // Synthetic implicit parents have their own reference sites; alias
        // RHSs have no parent kind or supertype slot. Neither can vary for
        // one reference.
        // Resolve each reference only once under this query's authority.
        // Retain errors and incompleteness too; a later read never retries
        // or upgrades the first result. No entry survives the callback.
        if let Some((_, receipt)) = self.references.get(&reference) {
            self.receipts.replay(receipt);
        } else {
            let forward = &mut self.forward;
            let identities = self.identities;
            let intrinsic_parent = self.intrinsic_parent;
            let (answer, receipt) = self.receipts.capture(|| {
                if let Some(target) = intrinsic_parent(reference, kind)? {
                    return Ok(ReferenceAnswer {
                        targets: vec![target],
                        completion: ResolutionCompletion::Complete,
                    });
                }
                let answer = forward.resolve_reference_with_metrics(
                    reference,
                    &mut ResolutionBatchMetrics::default(),
                )?;
                let mut targets = answer.binding().targets().to_vec();
                // #8500: the compiler root's selected Type identity is a
                // second shape of this same fact until it is minted as a
                // binding target. Explicit root references still resolve to
                // their selected external owner, which stays open without the JDK.
                // Read only this supertype's type slot.
                if let Some(supertype_slot) = supertype_slot
                    && targets.is_empty()
                    && answer.binding().completion() == &ResolutionCompletion::Complete
                    && answer.projections().iter().any(|projection| {
                        projection.output_slot() == supertype_slot
                            && projection.kind() == BindingProjectionKind::TargetTypeIdentity
                    })
                {
                    let mut frontiers = answer
                        .projected_frontiers()
                        .iter()
                        .filter(|frontier| frontier.slot() == supertype_slot);
                    if let (Some(frontier), None) = (frontiers.next(), frontiers.next())
                        && frontier.completion() == &ResolutionCompletion::Complete
                        && let [ResolutionSlotValue::TypeObject(ty, _)] = frontier.possible_values()
                        && let Some(owner) = identities.external_owner_identity(ty.identity())
                        && owner.provider_id.as_ref() == "jvm-intrinsic"
                        && brokk_bifrost_jvm::intrinsics::intrinsic_root_owner(&owner.owner_fqn)
                            .is_some()
                    {
                        targets.push(ty.identity());
                    }
                }
                Ok(ReferenceAnswer {
                    targets,
                    completion: answer.binding().completion().clone(),
                })
            });
            self.references.insert(reference, (answer, receipt));
        }
        self.references[&reference].0.clone()
    }

    /// Classify every parent of every candidate blob, including references
    /// whose spelling differs because an import renamed the target. Discovery
    /// and hydration are batched by the caller; this projection does no reads
    /// to enumerate candidates or map their definitions back to source units.
    pub fn jvm_direct_descendant_answer(
        &mut self,
        target: SemanticId,
        candidates: &[LoweredSupertypeProperty],
        mut completion: ResolutionCompletion,
    ) -> Result<JvmDirectDescendantAnswer> {
        let mut edges = Vec::new();
        let mut ambiguous = Vec::new();
        let mut open = Vec::new();
        for candidate in candidates {
            if matches!(
                candidate.source_kind(),
                Some(
                    ResolutionSupertypeKind::SelfType
                        | ResolutionSupertypeKind::ImplicitInterfaceMembers
                )
            ) {
                continue;
            }
            if self.cancellation.is_cancelled() {
                completion = completion.combine(&cancelled_completion());
                break;
            }
            let binding = self.resolve_reference(
                candidate.reference(),
                candidate.source_kind(),
                Some(candidate.frontier()),
            )?;
            if binding.targets.is_empty() || binding.completion != ResolutionCompletion::Complete {
                open.push(candidate.reference());
            }
            if binding.targets.contains(&target) {
                if binding.targets.len() > 1 {
                    ambiguous.push(candidate.definition());
                } else if binding.completion == ResolutionCompletion::Complete {
                    edges.push(candidate.definition());
                }
            }
        }
        edges.sort_unstable();
        edges.dedup();
        ambiguous.sort_unstable();
        ambiguous.dedup();
        open.sort_unstable();
        open.dedup();
        Ok(JvmDirectDescendantAnswer {
            edges,
            ambiguous,
            open,
            completion,
            open_reasons: Vec::new(),
        })
    }

    /// Resolve every parent reference through the same demand-aware operation.
    pub fn jvm_direct_supertype_answer(
        &mut self,
        definition: SemanticId,
    ) -> Result<JvmDirectSupertypeAnswer> {
        let mut rows = Vec::new();
        let outcome = self.typed.visit_supertype_pages_for_definitions(
            TypedFactRequest::new(&[definition]),
            self.cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                rows.extend(page.iter().map(|selected| {
                    let row = selected.row();
                    (
                        row.source_kind(),
                        row.parent_ordinal(),
                        row.reference(),
                        row.frontier(),
                    )
                }));
                Ok(true)
            }),
        )?;
        let mut completion = outcome.evidence().clone();
        if !outcome.is_exhausted() || self.cancellation.is_cancelled() {
            completion = completion.combine(&cancelled_completion());
            return Ok(JvmDirectSupertypeAnswer {
                parents: Vec::new(),
                completion,
            });
        }
        rows.sort_by_key(|(kind, ordinal, reference, _)| {
            let tier = match kind {
                Some(
                    ResolutionSupertypeKind::Superclass
                    | ResolutionSupertypeKind::ImplicitSuperclass,
                ) => 0,
                _ => 1,
            };
            (tier, *ordinal, *reference)
        });
        let mut parents = Vec::new();
        for (kind, parent_ordinal, reference, supertype_slot) in rows {
            if matches!(
                kind,
                Some(
                    ResolutionSupertypeKind::SelfType
                        | ResolutionSupertypeKind::ImplicitInterfaceMembers
                )
            ) {
                continue;
            }
            if self.cancellation.is_cancelled() {
                completion = completion.combine(&cancelled_completion());
                break;
            }
            let binding = self.resolve_reference(reference, kind, Some(supertype_slot))?;
            parents.push(JvmDirectSupertype {
                kind,
                parent_ordinal,
                reference,
                targets: binding.targets,
                completion: binding.completion,
            });
        }
        Ok(JvmDirectSupertypeAnswer {
            parents,
            completion,
        })
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Open once around the entire hierarchy or member-family walk. Each call
    /// on the borrowed query reuses the operation and its demand provider.
    pub fn with_jvm_hierarchy_query<T>(
        &self,
        context: jvm_demand::JvmForwardOperationContext<'_>,
        run: impl FnOnce(&mut JvmHierarchyQuery<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        self.with_jvm_hierarchy_query_receipts(context, &mut (), run)
    }

    /// Retain and replay the caller's receipt with each once-per-query binding.
    pub fn with_jvm_hierarchy_query_receipts<R: JvmHierarchyReadReceipts, T>(
        &self,
        context: jvm_demand::JvmForwardOperationContext<'_>,
        receipts: &mut R,
        run: impl FnOnce(&mut JvmHierarchyQuery<'_, '_, R>) -> Result<T>,
    ) -> Result<T> {
        let lexical = self.ready.lexical_source();
        let typed = self.ready.typed_source();
        let lexical = SeamProfiled::observing(&lexical);
        let typed = SeamProfiled::observing(&typed);
        let intrinsic_parent = |reference: SemanticId, kind| -> Result<Option<SemanticId>> {
            if kind != Some(ResolutionSupertypeKind::ImplicitSuperclass) {
                return Ok(None);
            }
            let Some(provenance) = self
                .ready
                .lexical_source()
                .semantic_provenance(reference, context.cancellation)?
            else {
                return Ok(None);
            };
            let mount = match provenance {
                crate::analyzer::resolution::SelectedSemanticProvenance::FragmentLocal(local) => {
                    local.mount()
                }
                crate::analyzer::resolution::SelectedSemanticProvenance::Stage(stage) => {
                    stage.mount()
                }
                crate::analyzer::resolution::SelectedSemanticProvenance::Shared(_) => {
                    return Err(StoreError::corrupt(
                        "an implicit source parent has shared provenance",
                    ));
                }
            };
            let language = self
                .ready
                .inventory
                .mount_record_by_ordinal(mount.ordinal())?
                .semantic_language();
            Ok(jvm_intrinsic_parent(language, kind).map(|owner| {
                self.ready
                    .context_identities
                    .external_owner_semantic(&owner, &self.ready.shared_names())
            }))
        };
        self.with_jvm_forward_operation(
            context.storage_language,
            context.blueprint,
            &lexical,
            &typed,
            context.caller_path,
            Some(context.import_gaps),
            context.cancellation,
            context.session,
            None,
            |forward| {
                run(&mut JvmHierarchyQuery {
                    forward,
                    typed: &typed,
                    identities: &self.ready.context_identities,
                    cancellation: context.cancellation,
                    receipts,
                    references: HashMap::default(),
                    intrinsic_parent: &intrinsic_parent,
                })
            },
        )
    }

    /// Intrinsic roots require a whole-workspace declaration expansion rather
    /// than relation-43 names (implicit parents intentionally have no row).
    /// Refuse that expansion before hydrating candidate blobs: the candidate
    /// set is the whole workspace, so no particular subset is promised. This
    /// deterministic refusal spends no budget and must not stop the session
    /// shared with later descendant queries in the same walk.
    pub fn jvm_intrinsic_descendant_cut(&self) -> JvmDescendantWalk {
        JvmDescendantWalk {
            answer: JvmDirectDescendantAnswer {
                edges: Vec::new(),
                ambiguous: Vec::new(),
                open: Vec::new(),
                completion: ResolutionCompletion::Complete,
                open_reasons: vec![HierarchyOpenReason::MemberFamily(
                    MemberFamilyReason::HierarchyTruncated,
                )],
            },
            definitions: SelectedNativeDefinitions::Ready(Vec::new()),
            rounds: 0,
        }
    }

    /// Discover reverse candidates in language-local rounds. Aliases publish
    /// their own spelling only after their structured RHS binding includes the
    /// requested target. Every round batches membership, hydration and mapping.
    pub fn jvm_descendant_walk<R: JvmHierarchyReadReceipts>(
        &self,
        query: &mut JvmHierarchyQuery<'_, '_, R>,
        target: SemanticId,
        target_name: &str,
        language: brokk_bifrost_core::analyzer::model::Language,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<JvmDescendantWalk> {
        use crate::analyzer::resolution::ResolutionLookupSemanticRecipe;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        let typed = self.ready.typed_source();
        let mut queued = vec![target_name.to_owned()];
        let mut visited_names = std::collections::HashSet::new();
        let mut visited_aliases = std::collections::HashSet::new();
        let mut pending_aliases = HashMap::default();
        let mut all_parents = Vec::new();
        let mut visited_parents = std::collections::HashSet::new();
        let mut equivalents = HashMap::default();
        equivalents.insert(target, true);
        let mut mapped = Vec::new();
        let mut answer = JvmDirectDescendantAnswer {
            edges: Vec::new(),
            ambiguous: Vec::new(),
            open: Vec::new(),
            completion: ResolutionCompletion::Complete,
            open_reasons: Vec::new(),
        };
        // Reverse discovery selects all persisted Java/Kotlin/Scala mounts of
        // the current selected snapshots, including forward dependents. Masked
        // mounts without indexed replacements are outside that coverage.
        let expected: usize = self
            .ready
            .inventory
            .languages()?
            .iter()
            .map(|language| language.expected_unmasked_mount_count())
            .sum();
        if expected != self.ready.inventory.persisted_mount_count()
            || self.ready.inventory.expected_transient_replacement_count() != 0
        {
            answer
                .open_reasons
                .push(HierarchyOpenReason::DescendantIndexUnavailable);
        }
        let mut rounds = 0;
        while !queued.is_empty() {
            let names = std::mem::take(&mut queued)
                .into_iter()
                .filter(|name| visited_names.insert(name.clone()))
                .map(|name| {
                    ResolutionLookupSemanticRecipe::new(language, ResolutionNamespace::Type, &name)
                        .semantic(&self.ready.shared_names())
                })
                .collect::<Vec<_>>();
            if names.is_empty() {
                break;
            }
            rounds += 1;
            if !session.scope_step() {
                answer.open_reasons.push(HierarchyOpenReason::MemberFamily(
                    MemberFamilyReason::HierarchyTruncated,
                ));
                break;
            }
            let Some(mounts) =
                typed.jvm_supertype_candidate_mounts(&names, cancellation, session)?
            else {
                answer.open_reasons.push(
                    if cancellation.is_cancelled() || !session.observe_cancellation() {
                        HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyTruncated)
                    } else {
                        HierarchyOpenReason::DescendantIndexUnavailable
                    },
                );
                answer.completion = answer.completion.combine(&cancelled_completion());
                break;
            };
            let Some(mut candidates) = typed.jvm_candidate_hierarchy_rows(
                &mounts,
                language.config_label(),
                &visited_names.iter().cloned().collect::<Vec<_>>(),
                cancellation,
                session,
            )?
            else {
                answer.open_reasons.push(HierarchyOpenReason::MemberFamily(
                    MemberFamilyReason::HierarchyTruncated,
                ));
                answer.completion = answer.completion.combine(&cancelled_completion());
                break;
            };
            candidates
                .parents
                .retain(|parent| visited_parents.insert((parent.definition(), parent.reference())));
            candidates
                .aliases
                .retain(|(alias, reference)| pending_aliases.insert(*alias, *reference).is_none());
            let mut definitions = candidates
                .parents
                .iter()
                .map(|parent| parent.definition())
                .chain(candidates.aliases.iter().map(|(alias, _)| *alias))
                .collect::<Vec<_>>();
            definitions.sort_unstable();
            definitions.dedup();
            let projected = native_units::project_hydrated_source_definition_units(
                &self.ready,
                &definitions,
                cancellation,
                session,
            )?;
            let SelectedNativeDefinitions::Ready(units) = projected else {
                return Ok(JvmDescendantWalk {
                    answer,
                    definitions: projected,
                    rounds,
                });
            };
            mapped.extend(units);
            all_parents.extend(candidates.parents);
            // Several aliases can share a blob, and their publication order
            // need not follow their RHS dependencies. Close the discovered
            // alias frontier iteratively before classifying its children.
            loop {
                let mut expanded = false;
                for (&alias, &reference) in &pending_aliases {
                    if visited_aliases.contains(&alias) {
                        continue;
                    }
                    let binding = query.resolve_reference(reference, None, None)?;
                    if binding.targets.is_empty()
                        || binding.completion != ResolutionCompletion::Complete
                    {
                        answer.open.push(reference);
                    }
                    if binding
                        .targets
                        .iter()
                        .any(|target| equivalents.contains_key(target))
                    {
                        let definite = binding.targets.len() == 1
                            && binding.completion == ResolutionCompletion::Complete
                            && equivalents.get(&binding.targets[0]) == Some(&true);
                        equivalents.insert(alias, definite);
                        visited_aliases.insert(alias);
                        expanded = true;
                        if let Some((_, SelectedNativeDefinition::Unit(unit))) =
                            mapped.iter().find(|(id, _)| *id == alias)
                        {
                            queued.push(unit.identifier().to_owned());
                        } else {
                            answer.open.push(reference);
                        }
                    }
                }
                if !expanded {
                    break;
                }
            }
            for (&equivalent, &definite) in &equivalents {
                let raw = query.jvm_direct_descendant_answer(
                    equivalent,
                    &all_parents,
                    ResolutionCompletion::Complete,
                )?;
                if definite {
                    answer.edges.extend(raw.edges);
                } else {
                    answer.ambiguous.extend(raw.edges);
                }
                answer.ambiguous.extend(raw.ambiguous);
                answer.open.extend(raw.open);
                answer.completion = answer.completion.combine(&raw.completion);
            }
        }
        answer.edges.sort_unstable();
        answer.edges.dedup();
        answer.ambiguous.sort_unstable();
        answer.ambiguous.dedup();
        answer.open.sort_unstable();
        answer.open.dedup();
        mapped.sort_by_key(|(id, _)| *id);
        mapped.dedup_by_key(|(id, _)| *id);
        Ok(JvmDescendantWalk {
            answer,
            definitions: SelectedNativeDefinitions::Ready(mapped),
            rounds,
        })
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// A resolved external identity's coordinate was read by the selected
    /// resolver. Expose that coordinate without attempting source-unit mapping.
    pub fn jvm_hierarchy_external_owner(
        &self,
        definition: SemanticId,
    ) -> Option<crate::analyzer::resolution::ExternalOwnerIdentity> {
        self.ready
            .context_identities
            .external_owner_identity(definition)
    }
}
