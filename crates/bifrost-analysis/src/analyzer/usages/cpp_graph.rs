mod extractor;
mod hits;
mod inverted;
mod resolver;
mod shared;
mod syntax;

use crate::analyzer::usages::common::language_for_target;
pub(in crate::analyzer::usages) use crate::analyzer::usages::cpp_call_match::cpp_split_top_level_commas;
use crate::analyzer::usages::cpp_graph::resolver::{TargetKind, TargetSpec};
use crate::analyzer::usages::cpp_graph::shared::{CppEdgeResolver, CppQueryResolver};
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{
    UsageAnalyzer, UsageEdgeResolver, UsageQueryResolver, UsageScanScope,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;

pub(in crate::analyzer::usages) use extractor::{
    BareCallTargetResolution as CppBareCallTargetResolution,
    LexicalScopeResolution as CppLexicalScopeResolution,
    enclosing_lexical_scope_components as cpp_enclosing_lexical_scope_components,
    initialized_ordinary_type_imports as cpp_initialized_effective_using_imports,
    resolve_bare_call_target as cpp_resolve_bare_call_target,
};
pub(in crate::analyzer::usages) use resolver::{
    CallArityEvidence, DesignatedInitializerOwner as CppDesignatedInitializerOwner,
    LexicalTypeResolution as CppLexicalTypeResolution, TargetKind as CppTargetKind,
    VisibilityIndex as CppVisibilityIndex, argument_children as cpp_argument_children,
    constructor_type_node as cpp_constructor_type_node, cpp_function_return_type_text,
    cpp_name_for, cpp_reference_fqn_candidates, cpp_type_name_components,
    designated_initializer_owner as cpp_designated_initializer_owner, extract_variable_name,
    field_declared_type_binding as cpp_field_declared_type_binding,
    first_type_child as cpp_first_type_child, is_declaration_name as cpp_is_declaration_name,
    is_declarator_node as cpp_is_declarator_node, normalize_type_text as normalize_cpp_type_text,
    signature_arity as cpp_signature_arity,
};
pub(crate) use shared::CppAuthoritativeUsageBatch;

#[cfg(test)]
pub(crate) fn cpp_type_owner_for_test(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<CodeUnit> {
    resolver::type_owner_of(analyzer, unit)
}

pub(crate) fn build_cpp_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CppEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_cpp_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CppEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CppDeadCodeBulkEligibility {
    BulkSafe,
    NeedsPrecise,
}

pub(crate) fn dead_code_bulk_eligibility(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    overloaded_fqns: &HashSet<String>,
) -> CppDeadCodeBulkEligibility {
    let Some(spec) = TargetSpec::from_target(analyzer, target) else {
        return CppDeadCodeBulkEligibility::NeedsPrecise;
    };
    match spec.kind {
        TargetKind::Type => CppDeadCodeBulkEligibility::BulkSafe,
        TargetKind::FreeFunction | TargetKind::Method if cpp_effectively_free_function(&spec) => {
            if overloaded_fqns.contains(target.fq_name().as_str()) || cpp_global_main(&spec) {
                CppDeadCodeBulkEligibility::NeedsPrecise
            } else {
                CppDeadCodeBulkEligibility::BulkSafe
            }
        }
        TargetKind::Constructor
        | TargetKind::FreeFunction
        | TargetKind::Method
        | TargetKind::GlobalField
        | TargetKind::MemberField => CppDeadCodeBulkEligibility::NeedsPrecise,
    }
}

pub(crate) fn is_cpp_global_main(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> bool {
    TargetSpec::from_target(analyzer, target).is_some_and(|spec| cpp_global_main(&spec))
}

fn cpp_effectively_free_function(spec: &TargetSpec) -> bool {
    spec.target.is_function() && spec.owner.as_ref().is_none_or(|owner| owner.is_module())
}

fn cpp_global_main(spec: &TargetSpec) -> bool {
    spec.target.is_function()
        && spec.target.identifier() == "main"
        && spec.target.package_name().is_empty()
        && spec.owner.is_none()
}

#[derive(Default)]
pub struct CppUsageGraphStrategy {
    _private: (),
}

impl CppUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Cpp
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Cpp {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not C/C++"),
                "CppUsageGraphStrategy",
            );
        }

        let Some(resolver) = CppQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose CppAnalyzer",
                ),
                "CppUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

impl UsageAnalyzer for CppUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        let scan_scope = UsageScanScope::new(candidate_files, false);
        self.find_graph_usages(analyzer, overloads, &scan_scope, max_usages)
            .into_fuzzy_result()
    }
}

#[cfg(test)]
mod bare_implicit_this_inverted_edge_tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, AnalyzerQueryScope, TestProject, WorkspaceAnalyzer};
    use std::sync::Arc;

    /// #1161: a bare `m()` call resolving to a method on the enclosing class
    /// (implicit-this, no receiver token at all) must be recorded as
    /// *unproven* inbound by the whole-workspace inverted builder, never
    /// silently dropped — the second same-owner drop site, alongside the
    /// explicit `this->m()` fix at #1138.
    ///
    /// This can't be asserted at the dead-code smell verdict: a genuine C++
    /// method is unconditionally `NeedsPrecise`
    /// (`dead_code_bulk_eligibility`'s catch-all arm), so the smell path
    /// never reaches the bulk inverted graph for a method target and the
    /// verdict is inconclusive-by-skip regardless of this bug. Asserting
    /// directly on `build_cpp_usage_edges`'s `unproven_inbound` map is the
    /// level that actually discriminates: before the fix the same-owner call
    /// site vanishes entirely (`unproven_inbound` has no entry for the
    /// callee); after the fix it is counted, while `edges` (the proven-edge
    /// set) stays empty for it either way, matching the sibling
    /// `this->m()` behavior.
    #[test]
    fn bare_implicit_this_call_is_recorded_as_unproven_inbound_not_dropped() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "foo.cpp");
        file.write("class Foo {\npublic:\n  void target() {}\n  void caller() { target(); }\n};\n")
            .expect("write foo.cpp");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let _scope = AnalyzerQueryScope::new(analyzer);

        let target = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "target")
            .expect("Foo::target declaration");
        let target_fqn = target.fq_name();

        let nodes: HashSet<String> = HashSet::from_iter([target_fqn.clone()]);
        let edges = build_cpp_usage_edges(analyzer, &nodes, |_| true)
            .expect("C++ edge resolver must be available for a C++ analyzer");

        assert_eq!(
            edges.unproven_inbound.get(target_fqn.as_str()).copied(),
            Some(1),
            "bare implicit-this call to Foo::target must be recorded as \
             unproven inbound, not dropped: {:?}",
            edges.unproven_inbound
        );
        assert!(
            edges
                .edges
                .keys()
                .all(|(_caller, callee)| callee != &target_fqn),
            "a same-owner call must never become a proven inbound edge: {:?}",
            edges.edges
        );
    }
}
