//! Query-local selected JVM hierarchy session.
use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::native_hierarchy::{HierarchyConversionRules, convert};
pub(crate) use brokk_bifrost_analysis::analyzer::native_hierarchy::{MappedParent, stopped};
use brokk_bifrost_analysis::analyzer::resolution::{
    ResolutionCompletion, SelectedFactOperationBlueprintConstruction,
    SelectedResolutionContextValidationOutcome,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::*;
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use brokk_bifrost_core::analyzer::capabilities::{
    HierarchyAnswer, HierarchyOpenReason, HierarchyQuery, MemberFamilyAncestors,
};
use brokk_bifrost_core::analyzer::model::{CodeUnit, Language};
use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyReason;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_core::cancellation::CancellationToken;
use std::collections::HashMap;

use super::selected_operation::HierarchyReadCapture;

fn unavailable() -> HierarchyAnswer {
    let mut answer = stopped();
    answer
        .open
        .push(HierarchyOpenReason::DescendantIndexUnavailable);
    answer
}

struct NativeQuery<'a> {
    direct_ancestors: &'a mut dyn FnMut(&CodeUnit) -> HierarchyAnswer,
    member_family_ancestors: &'a mut dyn FnMut(&CodeUnit) -> HierarchyAnswer,
    descendants: &'a mut dyn FnMut(&CodeUnit, &CancellationToken) -> HierarchyAnswer,
    cancellation: &'a CancellationToken,
}
impl HierarchyQuery for NativeQuery<'_> {
    fn direct_ancestors(&mut self, unit: &CodeUnit) -> HierarchyAnswer {
        (self.direct_ancestors)(unit)
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
        let answer = (self.member_family_ancestors)(unit);
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
    normalize_direct: &mut dyn FnMut(&CodeUnit, &mut Vec<MappedParent>),
    normalize_member_family: &mut dyn FnMut(&CodeUnit, &mut Vec<MappedParent>),
    run: &mut dyn FnMut(&mut dyn HierarchyQuery),
) {
    let result = open_native_query(inner, root, normalize_direct, normalize_member_family, run);
    if let Err(error) = result {
        inner.record_query_failure(error);
        run(&mut NativeQuery {
            direct_ancestors: &mut |_| stopped(),
            member_family_ancestors: &mut |_| stopped(),
            descendants: &mut |_, _| unavailable(),
            cancellation: &CancellationToken::default(),
        });
    }
}

fn open_native_query<A: LanguageAdapter>(
    inner: &TreeSitterAnalyzer<A>,
    root: Option<&CodeUnit>,
    normalize_direct: &mut dyn FnMut(&CodeUnit, &mut Vec<MappedParent>),
    normalize_member_family: &mut dyn FnMut(&CodeUnit, &mut Vec<MappedParent>),
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
                direct_ancestors: &mut |_| stopped(),
                member_family_ancestors: &mut |_| stopped(),
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
            let resolve_ancestors = |
                unit: &CodeUnit,
                normalize: &mut dyn FnMut(&CodeUnit, &mut Vec<MappedParent>),
            | {
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
                    convert(&operation, raw, &cancellation, &session, &HierarchyConversionRules { intrinsic_provider: "jvm-intrinsic", intrinsic_root: brokk_bifrost_jvm::intrinsics::intrinsic_root_owner, unread_inventory: brokk_bifrost_jvm::intrinsics::overridable_method_inventory }, |parents| {
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
            let mut direct_ancestors = |unit: &CodeUnit| {
                resolve_ancestors(unit, normalize_direct)
            };
            let mut member_family_ancestors = |unit: &CodeUnit| {
                resolve_ancestors(unit, normalize_member_family)
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
                    let mut answer = HierarchyAnswer::complete(Vec::new());
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
            run(&mut NativeQuery { direct_ancestors: &mut direct_ancestors, member_family_ancestors: &mut member_family_ancestors, descendants: &mut descendants, cancellation: &cancellation });
            Ok(())
        },
    )
}
