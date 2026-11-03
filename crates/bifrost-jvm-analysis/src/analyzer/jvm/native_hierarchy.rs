//! Query-local JVM parent conversion and selected hierarchy session.
use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::resolution::{
    ResolutionCompletion, SelectedFactOperationBlueprintConstruction,
    SelectedResolutionContextValidationOutcome,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_direct_supertypes::JvmDirectSupertypeAnswer;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use brokk_bifrost_core::analyzer::capabilities::{
    HierarchyAnswer, HierarchyOpenReason, HierarchyQuery, MemberFamilyAncestors,
    UnreadMemberFamilyAncestor,
};
use brokk_bifrost_core::analyzer::model::{CodeUnit, Language};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind;
use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_jvm::intrinsics::{intrinsic_root_owner, overridable_method_inventory};
use std::collections::HashMap;

struct HierarchyReadCapture<'a, A: LanguageAdapter>(&'a TreeSitterAnalyzer<A>, &'a dyn Fn());

impl<A: LanguageAdapter>
    brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_direct_supertypes::JvmHierarchyReadReceipts
    for HierarchyReadCapture<'_, A>
{
    type Receipt = brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;

    fn capture<T>(&mut self, read: impl FnOnce() -> T) -> (T, Self::Receipt) {
        brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt::capture(self.0, || {
            let result = read();
            (self.1)();
            result
        })
    }

    fn replay(&mut self, receipt: &Self::Receipt) {
        receipt.replay(self.0);
    }
}

pub(crate) struct MappedParent {
    pub kind: Option<ResolutionSupertypeKind>,
    pub ordinal: u32,
    pub targets: Vec<CodeUnit>,
    pub unread: Vec<UnreadMemberFamilyAncestor>,
    pub intrinsic_root: Option<brokk_bifrost_analysis::analyzer::resolution::ExternalOwnerIdentity>,
    pub alternatives: usize,
    pub complete: bool,
}

pub(crate) fn stopped() -> HierarchyAnswer {
    HierarchyAnswer {
        open: vec![HierarchyOpenReason::MemberFamily(
            MemberFamilyReason::HierarchyTruncated,
        )],
        ..Default::default()
    }
}

fn unavailable() -> HierarchyAnswer {
    let mut answer = stopped();
    answer
        .open
        .push(HierarchyOpenReason::DescendantIndexUnavailable);
    answer
}

fn convert(
    operation: &SelectedResolutionOperation<'_, '_>,
    raw: JvmDirectSupertypeAnswer,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
    normalize: impl FnOnce(&mut Vec<MappedParent>),
) -> Result<HierarchyAnswer> {
    let mut answer = HierarchyAnswer::default();
    if raw.completion != ResolutionCompletion::Complete {
        answer.open.extend(stopped().open);
    }
    let mut external = HashMap::new();
    let mut source = Vec::new();
    for target in raw.parents.iter().flat_map(|parent| &parent.targets) {
        if let Some(owner) = operation.jvm_hierarchy_external_owner(*target) {
            external.insert(*target, owner);
        } else {
            source.push(*target);
        }
    }
    source.sort_unstable();
    source.dedup();
    let mut units = HashMap::new();
    if !source.is_empty() {
        match operation.selected_hierarchy_definition_units(&source, cancellation, session)? {
            SelectedNativeDefinitions::Ready(definitions) => {
                for (id, definition) in definitions {
                    match definition {
                        SelectedNativeDefinition::Unit(unit) => {
                            units.insert(id, unit);
                        }
                        SelectedNativeDefinition::Intrinsic { canonical_name, .. } => {
                            external.insert(
                                id,
                                brokk_bifrost_analysis::analyzer::resolution::ExternalOwnerIdentity {
                                    provider_id: std::sync::Arc::from("jvm-intrinsic"),
                                    owner_fqn: std::sync::Arc::from(canonical_name),
                                },
                            );
                        }
                        SelectedNativeDefinition::Lexical(_) => {
                            answer.open.extend(stopped().open);
                        }
                    }
                }
            }
            SelectedNativeDefinitions::Cancelled | SelectedNativeDefinitions::Unavailable => {
                answer.open.extend(stopped().open);
            }
        }
    }
    let mut parents = Vec::new();
    for parent in raw.parents {
        let mut mapped = MappedParent {
            kind: parent.kind,
            ordinal: parent.parent_ordinal,
            targets: Vec::new(),
            unread: Vec::new(),
            intrinsic_root: None,
            alternatives: parent.targets.len(),
            complete: parent.completion == ResolutionCompletion::Complete,
        };
        for target in parent.targets {
            if let Some(unit) = units.get(&target) {
                mapped.targets.push(unit.clone());
            } else if let Some(owner) = external.get(&target) {
                if let Some(root) = intrinsic_root_owner(&owner.owner_fqn)
                    && owner.provider_id.as_ref() == "jvm-intrinsic"
                    && mapped.alternatives == 1
                    && mapped.complete
                {
                    mapped.intrinsic_root = Some(
                        brokk_bifrost_analysis::analyzer::resolution::ExternalOwnerIdentity {
                            provider_id: std::sync::Arc::from("jvm-intrinsic"),
                            owner_fqn: std::sync::Arc::from(root),
                        },
                    );
                } else {
                    // External coordinates do not carry interface metadata.
                    // Keep the unread edge open rather than inventing a root.
                    mapped.unread.push(UnreadMemberFamilyAncestor {
                        name: owner.owner_fqn.to_string(),
                        inventory: overridable_method_inventory(&owner.owner_fqn),
                    });
                }
            } else {
                mapped.complete = false;
            }
        }
        parents.push(mapped);
    }
    normalize(&mut parents);
    parents.sort_by_key(|parent| {
        (
            match parent.kind {
                Some(
                    ResolutionSupertypeKind::Superclass
                    | ResolutionSupertypeKind::ImplicitSuperclass,
                ) => 0,
                _ => 1,
            },
            parent.ordinal,
        )
    });
    for parent in parents {
        if let Some(root) = parent.intrinsic_root {
            assert_eq!(root.provider_id.as_ref(), "jvm-intrinsic");
            assert!(parent.complete && parent.alternatives == 1);
            assert!(parent.targets.is_empty() && parent.unread.is_empty());
            continue;
        }
        if parent.alternatives > 1 {
            answer.ambiguous.push(parent.targets);
            answer.open.push(HierarchyOpenReason::MemberFamily(
                MemberFamilyReason::HierarchyAmbiguous,
            ));
        } else if parent.complete {
            answer.edges.extend(parent.targets);
        }
        if parent.alternatives == 0 || !parent.complete {
            answer.open.extend(stopped().open);
        }
        answer.open.extend(
            parent
                .unread
                .into_iter()
                .map(HierarchyOpenReason::UnreadAncestor),
        );
    }
    Ok(answer)
}

struct NativeQuery<'a> {
    ancestors: &'a mut dyn FnMut(&CodeUnit) -> HierarchyAnswer,
    descendants: &'a mut dyn FnMut(&CodeUnit, &CancellationToken) -> HierarchyAnswer,
    cancellation: &'a CancellationToken,
}
impl HierarchyQuery for NativeQuery<'_> {
    fn direct_ancestors(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        (self.ancestors)(unit)
    }
    fn direct_descendants(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        (self.descendants)(unit, self.cancellation)
    }
    fn direct_descendants_within(
        &mut self,
        unit: &CodeUnit,
        scope: &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope<'_>,
    ) -> std::result::Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled>
    {
        if scope.cancellation().is_cancelled() {
            return Err(brokk_bifrost_core::analyzer::capabilities::Cancelled);
        }
        let answer = (self.descendants)(unit, scope.cancellation());
        brokk_bifrost_analysis::analyzer::i_analyzer::scope_filter_descendant_answer(answer, scope)
    }
    fn member_family_ancestors(&mut self, unit: &CodeUnit) -> MemberFamilyAncestors {
        let answer = self.direct_ancestors(unit);
        MemberFamilyAncestors {
            resolved: answer.edges,
            ambiguous: answer.ambiguous,
            unread: answer
                .open
                .into_iter()
                .filter_map(|reason| match reason {
                    HierarchyOpenReason::UnreadAncestor(ancestor) => Some(ancestor),
                    _ => None,
                })
                .collect(),
        }
    }
}

/// One forward operation per native delegate per walk, including MultiAnalyzer walks.
pub(crate) fn with_native_query<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    root: Option<&CodeUnit>,
    normalize: &mut dyn FnMut(&CodeUnit, &mut Vec<MappedParent>),
    run: &mut dyn FnMut(&mut dyn HierarchyQuery),
) {
    let result = open_native_query(inner, root, normalize, run);
    if let Err(error) = result {
        inner.record_query_failure(error);
        run(&mut NativeQuery {
            ancestors: &mut |_| stopped(),
            descendants: &mut |_, _| unavailable(),
            cancellation: &CancellationToken::default(),
        });
    }
}

fn open_native_query<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    root: Option<&CodeUnit>,
    normalize: &mut dyn FnMut(&CodeUnit, &mut Vec<MappedParent>),
    run: &mut dyn FnMut(&mut dyn HierarchyQuery),
) -> Result<()> {
    let cancellation = inner.active_query_cancellation().unwrap_or_default();
    // Reverse queries select the current Java/Kotlin/Scala workspace
    // snapshots, including dependents. An unselected root or coverage missing
    // from those snapshots is DescendantIndexUnavailable, never a closed
    // negative answer. Unindexed overlay replacements are reported likewise.
    let recipe = super::selected_operation::SelectedJvmRecipe::new(inner)?;
    let super::selected_operation::SelectedJvmOperationOutcome::Ready(operation) =
        recipe.open(&cancellation)?
    else {
        return Err(StoreError::new(
            "JVM hierarchy selected operation unavailable",
        ));
    };
    // A positioned hierarchy request reads its selected mount directly.
    // Enumerate mounts only for a rootless caller, which has no file anchor.
    let (storage_language, caller_path, caller_language) = if let Some(root) = root {
        let language = brokk_bifrost_core::analyzer::common::language_for_file(root.source());
        (
            language.config_label().to_owned(),
            brokk_bifrost_core::path_utils::rel_path_string(root.source()),
            language,
        )
    } else {
        let Some(caller) = operation.mounts()?.first() else {
            run(&mut NativeQuery {
                ancestors: &mut |_| stopped(),
                descendants: &mut |_, _| unavailable(),
                cancellation: &CancellationToken::default(),
            });
            return Ok(());
        };
        (
            caller.storage_language().to_owned(),
            caller.persisted_relative_path().to_owned(),
            caller.semantic_language(),
        )
    };
    let jvm_context::JvmImportContext::Ready {
        context,
        scoped_gaps,
        ..
    } = operation.jvm_import_context(caller_language, &caller_path, &cancellation)?
    else {
        return Err(StoreError::new("JVM hierarchy import context unavailable"));
    };
    let SelectedResolutionContextValidationOutcome::Ready(context) =
        operation.prepare_context(*context, &cancellation, &SelectedResolutionContextMetrics)?
    else {
        return Err(StoreError::new("JVM hierarchy context cancelled"));
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) =
        operation.ready.collect_blueprint(context, &cancellation)?
    else {
        return Err(StoreError::new("JVM hierarchy blueprint cancelled"));
    };
    let lexical = operation.ready.lexical_source();
    let typed = operation.ready.typed_source();
    let session = ResolutionSession::unbounded();
    let export_root_reads = || {
        brokk_bifrost_analysis::analyzer::root_presence::record_consumed_root_presence(
            inner, &operation,
        )
    };
    operation.with_jvm_hierarchy_query_receipts(
        JvmForwardOperationContext {
            storage_language: &storage_language,
            blueprint: &blueprint,
            caller_path: &caller_path,
            import_gaps: &scoped_gaps,
            lexical: &lexical,
            typed: &typed,
            cancellation: &cancellation,
            session: &session,
        },
        &mut HierarchyReadCapture(inner, &export_root_reads),
        |query| {
            let query = std::cell::RefCell::new(query);
            let mut ancestors = |unit: &CodeUnit| {
                let mut resolve = || -> Result<HierarchyAnswer> {
                    // The caller may supply a previously hydrated owner. Name
                    // its source inside this query's read attribution frame.
                    brokk_bifrost_analysis::CodeUnitIndex::get_declarations(inner, unit.source());
                    let LocatedSemantic::Found(definition) =
                        operation.selected_hierarchy_definition(unit, &cancellation, &session)?
                    else {
                        return Err(StoreError::new(format!(
                            "selected JVM hierarchy unit has no definition identity: {unit:?}"
                        )));
                    };
                    let raw = query.borrow_mut().jvm_direct_supertype_answer(definition)?;
                    convert(&operation, raw, &cancellation, &session, |parents| {
                        normalize(unit, parents)
                    })
                };
                match resolve() {
                    Ok(answer) => answer,
                    Err(error) => {
                        inner.record_query_failure(error);
                        stopped()
                    }
                }
            };
            let descendant_session = ResolutionSession::bounded(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            );
            let mut descendants = |unit: &CodeUnit, token: &CancellationToken| {
                let resolve = || -> Result<HierarchyAnswer> {
                    // Reverse membership enumerates every selected source realm. Name
                    // those authorities in the caller's receipt, including empty
                    // membership answers and files not yet nominated as candidates.
                    for language in [Language::Java, Language::Kotlin, Language::Scala] {
                        if recipe.has_language(language.config_label()) {
                            inner.record_read(inner.workspace_scope_read_key(&[language]));
                        }
                    }
                    let mut answer = HierarchyAnswer::default();
                    if brokk_bifrost_jvm::intrinsics::intrinsic_root_owner(unit.fq_name().as_str()).is_some() {
                        answer.open.extend(operation.jvm_intrinsic_descendant_cut().answer.open_reasons);
                        return Ok(answer);
                    }
                    let LocatedSemantic::Found(target) = operation.selected_hierarchy_definition(unit, token, &descendant_session)? else {
                        answer.open.push(HierarchyOpenReason::DescendantIndexUnavailable);
                        return Ok(answer);
                    };
                    for language in [Language::Java, Language::Kotlin, Language::Scala] {
                        if !recipe.has_language(language.config_label()) { continue; }
                        let walk = operation.jvm_descendant_walk(&mut query.borrow_mut(), target,
                            unit.identifier(), language, token, &descendant_session)?;
                        let raw = walk.answer;
                        answer.open.extend(raw.open_reasons);
                        if !raw.open.is_empty() || raw.completion != ResolutionCompletion::Complete {
                            answer.open.extend(stopped().open);
                        }
                        let SelectedNativeDefinitions::Ready(definitions) = walk.definitions else {
                            answer.open.extend(stopped().open);
                            continue;
                        };
                        let units = definitions.into_iter().filter_map(|(id, definition)| match definition {
                            SelectedNativeDefinition::Unit(unit) => Some((id, unit)), _ => None,
                        }).collect::<HashMap<_, _>>();
                        for id in raw.edges {
                            if let Some(unit) = units.get(&id) { answer.edges.push(unit.clone()); }
                            else { answer.open.push(HierarchyOpenReason::DescendantIndexUnavailable); }
                        }
                        for id in raw.ambiguous {
                            if let Some(unit) = units.get(&id) { answer.ambiguous.push(vec![unit.clone()]); }
                            else { answer.open.push(HierarchyOpenReason::DescendantIndexUnavailable); }
                        }
                    }
                    if !answer.ambiguous.is_empty() {
                        answer.open.push(HierarchyOpenReason::MemberFamily(MemberFamilyReason::HierarchyAmbiguous));
                    }
                    if !descendant_session.observe_cancellation() { answer.open.extend(stopped().open); }
                    Ok(answer)
                };
                match resolve() {
                    Ok(answer) => answer,
                    Err(error) => { inner.record_query_failure(error); stopped() }
                }
            };
            run(&mut NativeQuery { ancestors: &mut ancestors, descendants: &mut descendants, cancellation: &cancellation });
            Ok(())
        },
    )
}
