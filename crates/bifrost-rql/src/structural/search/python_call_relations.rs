//! Bounded Python lifecycle and superclass-call facts over exact call shapes.

use super::super::occurrences::{OccurrenceClass, OccurrenceRole};
use super::python_rule_facts::{named_children, node_text, parse_python, python_range_for_unit};
use super::*;
use crate::analyzer::structural::occurrence_rows::OccurrenceTarget;
use crate::analyzer::usages::call_shape::{CallShapeReport, call_shape_for_call};
use crate::analyzer::usages::python_class_hierarchy::{
    PythonHierarchyOutcome, PythonHierarchyReason, PythonOverrideOutcome,
};
use crate::analyzer::{CodeUnitType, DescendantIndexScope};
use brokk_bifrost_core::analyzer::structural::callable::{ArgumentListKind, CallShapeCoverage};
use brokk_bifrost_python::diagnostics::is_python_builtin_or_constant;
use brokk_bifrost_rql::OccurrenceFilter;

const CALL_VISIT_LIMIT: usize = 4096;
const DESCENDANT_VISIT_LIMIT: usize = 4096;

#[derive(Debug)]
struct CallSite {
    shape: CallShapeReport,
    method: CodeUnit,
    conditional: bool,
}

struct LifecycleMethodCalls {
    calls: Vec<CallSite>,
    occurrences: Vec<crate::analyzer::structural::occurrence_rows::OccurrenceRow>,
    environment: std::sync::Arc<super::super::lexical_environment::EnvironmentFileResult>,
    facts: std::sync::Arc<FileFacts>,
    super_aliases: HashMap<(usize, usize), String>,
}

#[derive(Debug, Clone)]
struct ResolvedCall {
    target: CodeUnit,
    owner: CodeUnit,
    rank: usize,
}

pub(super) fn unavailable_fact(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    reason: &'static str,
) -> PipelineExpansion {
    fact_expansion(
        declaration,
        &render::canonical_member_digest(analyzer, &declaration.unit),
        "call_lifecycle",
        "incomplete",
        Some(reason),
        "open",
        None,
        Some(declaration.range),
        Some(declaration.unit.clone()),
        None,
        None,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn fact_expansion(
    root: &DeclarationValue,
    root_id: &str,
    fact_kind: &'static str,
    outcome: &'static str,
    reason: Option<&'static str>,
    coverage: &'static str,
    ordinal: Option<usize>,
    site_range: Option<Range>,
    declaration: Option<CodeUnit>,
    owner: Option<CodeUnit>,
    target: Option<CodeUnit>,
    target_owner: Option<CodeUnit>,
    member_name: Option<String>,
    mro_rank: Option<usize>,
) -> PipelineExpansion {
    pipeline_expansion(PipelineValue::PythonHierarchyFact(Box::new(
        PythonHierarchyFactValue {
            root: root.clone(),
            root_id: root_id.to_owned(),
            site_range,
            fact_kind,
            outcome,
            reason,
            coverage,
            ordinal,
            base_spelling: None,
            base_resolution: None,
            declaration,
            owner,
            target,
            target_owner,
            member_name,
            mro_rank,
            target_non_trivial: None,
            target_reads_self: None,
            base_branch_definition_count: None,
            has_strict_ordering: None,
            has_non_strict_ordering: None,
            total_ordering_decorator: None,
            inherited_ne_present: None,
            inherited_ne_delegates: None,
            override_signatures: None,
        },
    )))
}

pub(super) fn expansions_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    facts: &FileFacts,
    semantic: &mut super::semantic::SemanticQueryContext<'_>,
    occurrence_cache: &mut super::occurrences::OccurrenceTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let language = crate::analyzer::common::language_for_file(declaration.unit.source());
    if language != Language::Python {
        return vec![unavailable_fact(
            analyzer,
            declaration,
            "unsupported_call_shape",
        )];
    }

    let occurrence_filter = OccurrenceFilter {
        classes: vec![OccurrenceClass::Reference, OccurrenceClass::Binding],
        roles: vec![
            OccurrenceRole::Binder,
            OccurrenceRole::ReceiverPosition,
            OccurrenceRole::ValueReference,
            OccurrenceRole::TypeOperand,
        ],
        ..OccurrenceFilter::default()
    };
    let Some(occurrences) = occurrence_cache.rows_for_file(
        analyzer,
        declaration.unit.source(),
        &occurrence_filter,
        cancellation,
    ) else {
        return vec![unavailable_fact(
            analyzer,
            declaration,
            "unresolved_super_binding",
        )];
    };
    occurrence_cache.report_completeness(
        declaration.unit.source(),
        &occurrences,
        &occurrence_filter,
        diagnostics,
    );
    let mut occurrence_rows = occurrences.rows.clone();
    if !occurrence_cache.resolve_targets_for_rows(
        analyzer,
        declaration.unit.source(),
        &mut occurrence_rows,
        cancellation,
    ) {
        return vec![unavailable_fact(
            analyzer,
            declaration,
            "unresolved_super_binding",
        )];
    }

    let (root, class_owner) = if declaration.unit.kind() == CodeUnitType::Class {
        (declaration.clone(), Some(declaration.unit.clone()))
    } else if let Some(owner) = analyzer
        .parent_of(&declaration.unit)
        .filter(CodeUnit::is_class)
    {
        let range = analyzer
            .ranges(&owner)
            .into_iter()
            .next()
            .unwrap_or(declaration.range);
        (DeclarationValue::new(owner.clone(), range), Some(owner))
    } else {
        (declaration.clone(), None)
    };
    let root_id = render::canonical_member_digest(analyzer, &root.unit);
    let hierarchy_provider = class_owner
        .as_ref()
        .and_then(|owner| analyzer.python_class_hierarchy_provider_for(owner));
    let hierarchy = class_owner
        .as_ref()
        .zip(hierarchy_provider)
        .map(|(owner, provider)| provider.class_hierarchy(owner, cancellation));
    let hierarchy_complete = hierarchy
        .as_ref()
        .is_some_and(|answer| answer.outcome == PythonHierarchyOutcome::Complete);
    let hierarchy_units = hierarchy
        .as_ref()
        .map(|answer| answer.mro.as_slice())
        .unwrap_or_default();
    let (call_sites, call_sites_truncated) =
        call_sites_for_declaration(analyzer, declaration, facts);
    let mut output = Vec::new();
    if call_sites_truncated {
        return vec![fact_expansion(
            &root,
            &root_id,
            "call_lifecycle",
            "incomplete",
            Some("visit_limit"),
            "open",
            None,
            Some(declaration.range),
            Some(declaration.unit.clone()),
            class_owner,
            None,
            None,
            None,
            None,
        )];
    }

    if let Some(class) = &class_owner
        && declaration.unit.kind() == CodeUnitType::Class
    {
        let mut environment_cache = super::environment::EnvironmentTraversalCache::default();
        for name in ["__init__", "__del__"] {
            output.extend(lifecycle_facts_for_name(
                analyzer,
                &root,
                &root_id,
                class,
                hierarchy_units,
                hierarchy_complete,
                name,
                semantic,
                occurrence_cache,
                &mut environment_cache,
                cancellation,
                diagnostics,
            ));
        }
        if hierarchy_complete {
            output.extend(init_calls_subclass_facts(
                analyzer,
                &root,
                &root_id,
                class,
                facts,
                &call_sites,
                &occurrence_rows,
                hierarchy_units,
                semantic,
                cancellation,
            ));
        } else {
            output.push(fact_expansion(
                &root,
                &root_id,
                "call_lifecycle",
                "incomplete",
                Some("incomplete_hierarchy"),
                "open",
                None,
                Some(root.range),
                None,
                Some(class.clone()),
                None,
                None,
                Some("init_calls_subclass".to_owned()),
                None,
            ));
        }
    }

    output.extend(context_facts(
        analyzer,
        &root,
        &root_id,
        facts,
        &call_sites,
        &occurrence_rows,
        hierarchy_units,
        hierarchy_complete,
        semantic,
    ));
    if output.is_empty() {
        output.push(fact_expansion(
            &root,
            &root_id,
            "call_context",
            "no_issue",
            None,
            "complete",
            None,
            Some(declaration.range),
            Some(declaration.unit.clone()),
            class_owner,
            None,
            None,
            None,
            None,
        ));
    }
    output
}

fn set_target_non_triviality(
    fact: &mut PipelineExpansion,
    analyzer: &dyn IAnalyzer,
    semantic: &mut super::semantic::SemanticQueryContext<'_>,
    target: &CodeUnit,
    occurrence_cache: &mut super::occurrences::OccurrenceTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let PipelineValue::PythonHierarchyFact(value) = &mut fact.value else {
        unreachable!("lifecycle target facts use the Python hierarchy value")
    };
    let filter = OccurrenceFilter {
        classes: vec![OccurrenceClass::Reference, OccurrenceClass::Binding],
        roles: vec![
            OccurrenceRole::Binder,
            OccurrenceRole::ReceiverPosition,
            OccurrenceRole::ValueReference,
            OccurrenceRole::TypeOperand,
        ],
        ..OccurrenceFilter::default()
    };
    value.target_non_trivial = if target.package_name() == "builtins" {
        Some(false)
    } else {
        occurrence_cache
            .rows_for_file(analyzer, target.source(), &filter, cancellation)
            .and_then(|rows| {
                occurrence_cache.report_completeness(target.source(), &rows, &filter, diagnostics);
                let mut resolved = rows.rows.clone();
                if !occurrence_cache.resolve_targets_for_rows(
                    analyzer,
                    target.source(),
                    &mut resolved,
                    cancellation,
                ) {
                    return None;
                }
                filter
                    .roles
                    .iter()
                    .all(|role| rows.completeness.covers(*role))
                    .then(|| {
                        super::python_rule_facts::python_method_non_trivial(
                            analyzer, semantic, target, &resolved,
                        )
                    })
                    .flatten()
            })
    };
    if value.target_non_trivial.is_none() {
        value.coverage = "open";
        value.reason = Some("target_body_unavailable");
    }
}

#[derive(Default)]
struct LifecycleTargetClosure {
    targets: HashSet<CodeUnit>,
    calls_unknown_class_with_self: bool,
}

enum LifecycleCallTarget {
    Target(ResolvedCall),
    UnknownClassWithSelf,
    None,
    Unavailable,
}

// These inputs keep the query-local caches and per-class MRO explicit.
#[allow(clippy::too_many_arguments)]
fn lifecycle_facts_for_name(
    analyzer: &dyn IAnalyzer,
    root: &DeclarationValue,
    root_id: &str,
    class: &CodeUnit,
    class_mro: &[CodeUnit],
    hierarchy_complete: bool,
    name: &str,
    semantic: &mut super::semantic::SemanticQueryContext<'_>,
    occurrence_cache: &mut super::occurrences::OccurrenceTraversalCache,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if !hierarchy_complete {
        return vec![lifecycle_incomplete_fact(
            root,
            root_id,
            class,
            name,
            None,
            "incomplete_hierarchy",
            root.range,
        )];
    }
    let Some(inherited) = inherited_methods(analyzer, class_mro, name) else {
        return vec![lifecycle_incomplete_fact(
            root,
            root_id,
            class,
            name,
            None,
            "visit_limit",
            root.range,
        )];
    };
    let direct = direct_methods(analyzer, class, name);
    let Some(start_method) = direct
        .first()
        .or_else(|| inherited.first().map(|entry| &entry.0))
    else {
        return vec![fact_expansion(
            root,
            root_id,
            "call_lifecycle",
            "no_issue",
            None,
            "complete",
            None,
            Some(root.range),
            None,
            Some(class.clone()),
            None,
            None,
            Some(name.to_owned()),
            None,
        )];
    };

    let closure = match transitive_lifecycle_targets(
        analyzer,
        class,
        class_mro,
        std::slice::from_ref(start_method),
        name,
        occurrence_cache,
        environment_cache,
        cancellation,
        diagnostics,
    ) {
        Ok(closure) => closure,
        Err((reason, range)) => {
            return vec![lifecycle_incomplete_fact(
                root,
                root_id,
                class,
                name,
                Some(start_method.clone()),
                reason,
                range,
            )];
        }
    };

    let mut output = Vec::new();
    if !closure.calls_unknown_class_with_self {
        let mut missing = Vec::new();
        for (target, owner, rank) in &inherited {
            if closure.targets.contains(target) {
                continue;
            }
            let Some(non_trivial) = lifecycle_target_non_trivial(
                analyzer,
                semantic,
                target,
                occurrence_cache,
                cancellation,
                diagnostics,
            ) else {
                let range = python_range_for_unit(analyzer, target).unwrap_or(root.range);
                output.push(lifecycle_incomplete_fact(
                    root,
                    root_id,
                    class,
                    name,
                    Some(start_method.clone()),
                    "target_body_unavailable",
                    range,
                ));
                continue;
            };
            if non_trivial {
                missing.push((target.clone(), owner.clone(), *rank));
            }
        }
        let mut lowest_missing = Vec::new();
        for (target, owner, rank) in &missing {
            let mut shadowed = false;
            let mut hierarchy_unknown = false;
            for (more_derived, more_derived_owner, _) in &missing {
                if more_derived == target {
                    continue;
                }
                match class_is_strict_subclass(analyzer, more_derived_owner, owner, cancellation) {
                    Some(true) => shadowed = true,
                    Some(false) => {}
                    None => hierarchy_unknown = true,
                }
            }
            if hierarchy_unknown {
                output.push(lifecycle_incomplete_fact(
                    root,
                    root_id,
                    class,
                    name,
                    Some(start_method.clone()),
                    "incomplete_hierarchy",
                    root.range,
                ));
            } else if !shadowed {
                lowest_missing.push((target.clone(), owner.clone(), *rank));
            }
        }
        for (target, owner, rank) in lowest_missing {
            match superclass_also_misses_call(
                analyzer,
                class_mro,
                &target,
                name,
                occurrence_cache,
                environment_cache,
                cancellation,
                diagnostics,
            ) {
                Some(true) => continue,
                Some(false) => {}
                None => {
                    output.push(lifecycle_incomplete_fact(
                        root,
                        root_id,
                        class,
                        name,
                        Some(start_method.clone()),
                        "incomplete_hierarchy",
                        root.range,
                    ));
                    continue;
                }
            }
            let mut fact = fact_expansion(
                root,
                root_id,
                "call_lifecycle",
                "missing_call",
                None,
                "complete",
                Some(rank),
                Some(root.range),
                Some(start_method.clone()),
                Some(class.clone()),
                Some(target.clone()),
                Some(owner),
                Some(name.to_owned()),
                Some(rank),
            );
            set_target_non_triviality(
                &mut fact,
                analyzer,
                semantic,
                &target,
                occurrence_cache,
                cancellation,
                diagnostics,
            );
            output.push(fact);
        }
    }
    if direct.is_empty() {
        // CodeQL evaluates the first inherited implementation when the class
        // has no method of its own, but still anchors the finding on the class.
        return if output.is_empty() {
            vec![fact_expansion(
                root,
                root_id,
                "call_lifecycle",
                "no_issue",
                None,
                "complete",
                None,
                Some(root.range),
                Some(start_method.clone()),
                Some(class.clone()),
                None,
                None,
                Some(name.to_owned()),
                None,
            )]
        } else {
            output
        };
    }

    for (target, owner, rank) in &inherited {
        if closure.targets.contains(target) {
            output.push(fact_expansion(
                root,
                root_id,
                "call_lifecycle",
                "called",
                None,
                "complete",
                Some(*rank),
                Some(python_range_for_unit(analyzer, start_method).unwrap_or(root.range)),
                Some(start_method.clone()),
                Some(class.clone()),
                Some(target.clone()),
                Some(owner.clone()),
                Some(name.to_owned()),
                Some(*rank),
            ));
        }
    }

    for method in direct {
        let method_range = python_range_for_unit(analyzer, &method).unwrap_or(root.range);
        let Some(method_calls) = lifecycle_calls_for_method(
            analyzer,
            &method,
            occurrence_cache,
            environment_cache,
            cancellation,
            diagnostics,
        ) else {
            output.push(lifecycle_incomplete_fact(
                root,
                root_id,
                class,
                name,
                Some(method),
                "target_body_unavailable",
                method_range,
            ));
            continue;
        };
        let LifecycleMethodCalls {
            calls,
            occurrences,
            environment,
            facts,
            super_aliases,
        } = method_calls;
        let mut reached_by_call = Vec::new();
        let mut incomplete = None;
        for call in &calls {
            let super_alias = lifecycle_super_alias_for_call(
                &call.shape,
                &occurrences,
                &environment,
                &super_aliases,
            );
            if call.shape.outcome.callee_name.as_deref() != Some(name) && super_alias != Some(name)
            {
                continue;
            }
            let target = if super_alias == Some(name) {
                lifecycle_super_call_target(analyzer, &method, class_mro, name)
            } else {
                lifecycle_call_target(
                    analyzer,
                    &method,
                    class_mro,
                    &call.shape,
                    &occurrences,
                    &facts,
                    name,
                    cancellation,
                )
            };
            match target {
                LifecycleCallTarget::Target(target) => {
                    match transitive_lifecycle_targets(
                        analyzer,
                        class,
                        class_mro,
                        std::slice::from_ref(&target.target),
                        name,
                        occurrence_cache,
                        environment_cache,
                        cancellation,
                        diagnostics,
                    ) {
                        Ok(closure) => reached_by_call.push((
                            target,
                            closure.targets,
                            call.shape.outcome.range,
                        )),
                        Err((reason, range)) => incomplete = Some((reason, range)),
                    }
                }
                LifecycleCallTarget::Unavailable => {
                    incomplete = Some(("unsupported_call_shape", call.shape.outcome.range));
                }
                LifecycleCallTarget::UnknownClassWithSelf | LifecycleCallTarget::None => {}
            }
        }
        if let Some((reason, range)) = incomplete {
            output.push(lifecycle_incomplete_fact(
                root,
                root_id,
                class,
                name,
                Some(method.clone()),
                reason,
                range,
            ));
            continue;
        }
        let mut calls_by_target: HashMap<CodeUnit, Vec<(Range, ResolvedCall)>> = HashMap::default();
        for (direct_target, targets, call_range) in reached_by_call {
            for target in targets {
                calls_by_target.entry(target.clone()).or_default().push((
                    call_range,
                    ResolvedCall {
                        target: target.clone(),
                        owner: analyzer
                            .parent_of(&target)
                            .unwrap_or_else(|| direct_target.owner.clone()),
                        rank: class_mro
                            .iter()
                            .position(|owner| analyzer.parent_of(&target).as_ref() == Some(owner))
                            .unwrap_or(direct_target.rank),
                    },
                ));
            }
        }
        let mut all_targets = calls_by_target.keys().cloned().collect::<Vec<_>>();
        all_targets.sort_by_key(|target| target.declaration_id().to_string());
        let mut reported = false;
        for calls in calls_by_target.values_mut() {
            calls.sort_by_key(|(range, _)| (range.start_byte, range.end_byte));
            calls.dedup_by(|left, right| {
                left.0.start_byte == right.0.start_byte && left.0.end_byte == right.0.end_byte
            });
        }
        let mut common_non_trivial = Vec::new();
        for target in &all_targets {
            let calls = calls_by_target
                .get(target)
                .expect("each lifecycle target retains its call sites");
            if calls.len() < 2 {
                continue;
            }
            match lifecycle_target_non_trivial(
                analyzer,
                semantic,
                target,
                occurrence_cache,
                cancellation,
                diagnostics,
            ) {
                Some(true) => common_non_trivial.push(target.clone()),
                Some(false) => {}
                None => {
                    output.push(lifecycle_incomplete_fact(
                        root,
                        root_id,
                        class,
                        name,
                        Some(method.clone()),
                        "target_body_unavailable",
                        method_range,
                    ));
                    reported = true;
                }
            }
        }
        for target in &common_non_trivial {
            let calls = calls_by_target
                .get(target)
                .expect("each common lifecycle target retains its call sites");
            let target_owner = calls[0].1.owner.clone();
            let mut shadowed = false;
            let mut hierarchy_unknown = false;
            for other in common_non_trivial.iter().filter(|other| *other != target) {
                let other_owner = analyzer
                    .parent_of(other)
                    .unwrap_or_else(|| target_owner.clone());
                match class_is_strict_subclass(analyzer, &other_owner, &target_owner, cancellation)
                {
                    Some(true) => shadowed = true,
                    Some(false) => {}
                    None => hierarchy_unknown = true,
                }
            }
            if hierarchy_unknown {
                output.push(lifecycle_incomplete_fact(
                    root,
                    root_id,
                    class,
                    name,
                    Some(method.clone()),
                    "incomplete_hierarchy",
                    method_range,
                ));
                reported = true;
                continue;
            }
            if shadowed {
                continue;
            }
            let call = &calls[0].1;
            let mut fact = fact_expansion(
                root,
                root_id,
                "call_lifecycle",
                "multiple_calls",
                None,
                "complete",
                Some(2),
                Some(method_range),
                Some(method.clone()),
                Some(class.clone()),
                Some(target.clone()),
                Some(call.owner.clone()),
                Some(name.to_owned()),
                Some(call.rank),
            );
            set_target_non_triviality(
                &mut fact,
                analyzer,
                semantic,
                target,
                occurrence_cache,
                cancellation,
                diagnostics,
            );
            output.push(fact);
            reported = true;
        }
        if !reported {
            output.push(fact_expansion(
                root,
                root_id,
                "call_lifecycle",
                "no_issue",
                None,
                "complete",
                None,
                Some(method_range),
                Some(method),
                Some(class.clone()),
                None,
                None,
                Some(name.to_owned()),
                None,
            ));
        }
    }
    if output.is_empty() {
        output.push(fact_expansion(
            root,
            root_id,
            "call_lifecycle",
            "no_issue",
            None,
            "complete",
            None,
            Some(root.range),
            None,
            Some(class.clone()),
            None,
            None,
            Some(name.to_owned()),
            None,
        ));
    }
    output
}

fn lifecycle_incomplete_fact(
    root: &DeclarationValue,
    root_id: &str,
    class: &CodeUnit,
    name: &str,
    method: Option<CodeUnit>,
    reason: &'static str,
    range: Range,
) -> PipelineExpansion {
    fact_expansion(
        root,
        root_id,
        "call_lifecycle",
        "incomplete",
        Some(reason),
        "open",
        None,
        Some(range),
        method,
        Some(class.clone()),
        None,
        None,
        Some(name.to_owned()),
        None,
    )
}

fn lifecycle_occurrence_filter() -> OccurrenceFilter {
    OccurrenceFilter {
        classes: vec![OccurrenceClass::Reference, OccurrenceClass::Binding],
        roles: vec![
            OccurrenceRole::Binder,
            OccurrenceRole::ReceiverPosition,
            OccurrenceRole::ValueReference,
            OccurrenceRole::TypeOperand,
        ],
        ..OccurrenceFilter::default()
    }
}

fn lifecycle_calls_for_method(
    analyzer: &dyn IAnalyzer,
    method: &CodeUnit,
    occurrence_cache: &mut super::occurrences::OccurrenceTraversalCache,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<LifecycleMethodCalls> {
    let range = python_range_for_unit(analyzer, method)?;
    let facts = call_facts_for_method(analyzer, method)?;
    let declaration = DeclarationValue::new(method.clone(), range);
    let (calls, truncated) = call_sites_for_declaration(analyzer, &declaration, &facts);
    if truncated {
        return None;
    }
    let filter = lifecycle_occurrence_filter();
    let occurrences =
        occurrence_cache.rows_for_file(analyzer, method.source(), &filter, cancellation)?;
    occurrence_cache.report_completeness(method.source(), &occurrences, &filter, diagnostics);
    let mut occurrence_rows = occurrences.rows.clone();
    if !occurrence_cache.resolve_targets_for_rows(
        analyzer,
        method.source(),
        &mut occurrence_rows,
        cancellation,
    ) {
        return None;
    }
    let environment = environment_cache.environment_for(analyzer, method.source());
    filter
        .roles
        .iter()
        .all(|role| occurrences.completeness.covers(*role))
        .then(|| {
            let super_aliases = lifecycle_super_alias_bindings(analyzer, method, &occurrence_rows);
            LifecycleMethodCalls {
                calls,
                occurrences: occurrence_rows,
                environment,
                facts,
                super_aliases,
            }
        })
}

fn lifecycle_super_alias_bindings(
    analyzer: &dyn IAnalyzer,
    method: &CodeUnit,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
) -> HashMap<(usize, usize), String> {
    // CodeQL follows a local alias of `super().__init__` when computing the
    // transitive target set, so preserve its exact lexical binding position.
    let mut aliases = HashMap::default();
    let Some(range) = python_range_for_unit(analyzer, method) else {
        return aliases;
    };
    let Some(source) = analyzer.get_source(&CodeUnit::file_scope(method.source().clone()), false)
    else {
        return aliases;
    };
    let Some(tree) = parse_python(&source).filter(|tree| !tree.root_node().has_error()) else {
        return aliases;
    };
    let Some(definition) = super::python_rule_facts::python_definition_node(&tree, method, &range)
    else {
        return aliases;
    };
    let Some(body) = definition.child_by_field_name("body") else {
        return aliases;
    };
    for statement in named_children(body) {
        let statements = if statement.kind() == "expression_statement" {
            named_children(statement)
        } else {
            vec![statement]
        };
        for assignment in statements
            .into_iter()
            .filter(|node| node.kind() == "assignment")
        {
            let Some(left) = assignment.child_by_field_name("left") else {
                continue;
            };
            let Some(value) = assignment.child_by_field_name("right") else {
                continue;
            };
            if left.kind() != "identifier" || value.kind() != "attribute" {
                continue;
            }
            let Some(attribute) = value.child_by_field_name("attribute") else {
                continue;
            };
            let Some(member) = node_text(&source, attribute) else {
                continue;
            };
            let Some(receiver) = value.child_by_field_name("object") else {
                continue;
            };
            if receiver.kind() != "call" {
                continue;
            }
            let Some(super_name) = receiver.child_by_field_name("function") else {
                continue;
            };
            if super_name.kind() != "identifier" {
                continue;
            }
            let super_range = Range {
                start_byte: super_name.start_byte(),
                end_byte: super_name.end_byte(),
                start_line: super_name.start_position().row.saturating_add(1),
                end_line: super_name.end_position().row.saturating_add(1),
            };
            if builtin_super_at(occurrences, super_range) != Some(true) {
                continue;
            }
            aliases.insert((left.start_byte(), left.end_byte()), member.to_owned());
        }
    }
    aliases
}

fn lifecycle_super_alias_for_call<'a>(
    shape: &CallShapeReport,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    environment: &super::super::lexical_environment::EnvironmentFileResult,
    aliases: &'a HashMap<(usize, usize), String>,
) -> Option<&'a str> {
    let callee = occurrence_at(occurrences, shape.outcome.callee_range?)?;
    let binding = match super::super::lexical_environment::binding_of(
        environment,
        callee.effective_spelling(),
        callee.range.start_byte,
        Some(callee.namespace),
    ) {
        super::super::lexical_environment::BindingOfOutcome::Reached(index)
        | super::super::lexical_environment::BindingOfOutcome::Shadowed { winner: index, .. } => {
            &environment.bindings[index]
        }
        super::super::lexical_environment::BindingOfOutcome::NoBinding
        | super::super::lexical_environment::BindingOfOutcome::Incomplete(_) => return None,
    };
    aliases
        .get(&(binding.range.start_byte, binding.range.end_byte))
        .map(String::as_str)
}

fn call_facts_for_method(
    analyzer: &dyn IAnalyzer,
    method: &CodeUnit,
) -> Option<std::sync::Arc<FileFacts>> {
    analyzer
        .structural_fact_providers()
        .into_iter()
        .find_map(|provider| provider.structural_facts(method.source()))
}

// These inputs preserve the caller's MRO base while following transitive targets.
#[allow(clippy::too_many_arguments)]
fn transitive_lifecycle_targets(
    analyzer: &dyn IAnalyzer,
    mro_base: &CodeUnit,
    mro: &[CodeUnit],
    starts: &[CodeUnit],
    name: &str,
    occurrence_cache: &mut super::occurrences::OccurrenceTraversalCache,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Result<LifecycleTargetClosure, (&'static str, Range)> {
    let mut closure = LifecycleTargetClosure::default();
    let mut pending = starts.to_vec();
    while let Some(method) = pending.pop() {
        if !closure.targets.insert(method.clone()) {
            continue;
        }
        if closure.targets.len() > CALL_VISIT_LIMIT {
            return Err((
                "visit_limit",
                python_range_for_unit(analyzer, &method).unwrap_or_else(|| {
                    analyzer
                        .ranges(mro_base)
                        .into_iter()
                        .next()
                        .expect("class range")
                }),
            ));
        }
        if method.package_name() == "builtins" {
            continue;
        }
        let method_range = python_range_for_unit(analyzer, &method)
            .ok_or_else(|| ("target_body_unavailable", analyzer.ranges(mro_base)[0]))?;
        let Some(method_calls) = lifecycle_calls_for_method(
            analyzer,
            &method,
            occurrence_cache,
            environment_cache,
            cancellation,
            diagnostics,
        ) else {
            return Err(("target_body_unavailable", method_range));
        };
        let LifecycleMethodCalls {
            calls,
            occurrences,
            environment,
            facts,
            super_aliases,
        } = method_calls;
        for call in &calls {
            let super_alias = lifecycle_super_alias_for_call(
                &call.shape,
                &occurrences,
                &environment,
                &super_aliases,
            );
            if call.shape.outcome.callee_name.as_deref() != Some(name) && super_alias != Some(name)
            {
                continue;
            }
            let target = if super_alias == Some(name) {
                lifecycle_super_call_target(analyzer, &method, mro, name)
            } else {
                lifecycle_call_target(
                    analyzer,
                    &method,
                    mro,
                    &call.shape,
                    &occurrences,
                    &facts,
                    name,
                    cancellation,
                )
            };
            match target {
                LifecycleCallTarget::Target(target) => pending.push(target.target),
                LifecycleCallTarget::UnknownClassWithSelf => {
                    closure.calls_unknown_class_with_self = true;
                }
                LifecycleCallTarget::None => {}
                LifecycleCallTarget::Unavailable => {
                    return Err(("unsupported_call_shape", call.shape.outcome.range));
                }
            }
        }
    }
    Ok(closure)
}

// Keep call-site evidence and the owning method's MRO explicit at resolution.
#[allow(clippy::too_many_arguments)]
fn lifecycle_call_target(
    analyzer: &dyn IAnalyzer,
    method: &CodeUnit,
    mro: &[CodeUnit],
    shape: &CallShapeReport,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    facts: &FileFacts,
    name: &str,
    cancellation: Option<&CancellationToken>,
) -> LifecycleCallTarget {
    let Some(receiver) = shape.outcome.receiver_range else {
        return LifecycleCallTarget::None;
    };
    if shape.outcome.coverage != CallShapeCoverage::Exact {
        return LifecycleCallTarget::Unavailable;
    }
    if let Some(super_shape) = super_call_receiver(facts, &shape.outcome.file, receiver) {
        let Some(callee) = super_shape.outcome.callee_range else {
            return LifecycleCallTarget::Unavailable;
        };
        match builtin_super_at(occurrences, callee) {
            Some(true) => return lifecycle_super_call_target(analyzer, method, mro, name),
            Some(false) => {}
            None => return LifecycleCallTarget::Unavailable,
        }
    }
    let Some(formal) = first_parameter_name(analyzer, facts, occurrences, method) else {
        return LifecycleCallTarget::None;
    };
    let Some(group) = shape
        .groups
        .iter()
        .find(|group| group.kind == ArgumentListKind::Ordinary && group.group_index == 0)
    else {
        return LifecycleCallTarget::None;
    };
    let Some(first_argument) = shape.arguments.iter().find(|argument| {
        argument.group_id == group.id && argument.argument_index == 0 && argument.name.is_none()
    }) else {
        return LifecycleCallTarget::None;
    };
    if !occurrence_is_bound_to_formal(occurrences, first_argument.range, &formal) {
        return LifecycleCallTarget::None;
    }
    let Some(target_class) = resolved_class_at(occurrences, receiver) else {
        return LifecycleCallTarget::UnknownClassWithSelf;
    };
    let Some(provider) = analyzer.python_class_hierarchy_provider_for(&target_class) else {
        return LifecycleCallTarget::Unavailable;
    };
    let hierarchy = provider.class_hierarchy(&target_class, cancellation);
    if hierarchy.outcome != PythonHierarchyOutcome::Complete {
        return LifecycleCallTarget::Unavailable;
    }
    let target = hierarchy.mro.iter().enumerate().find_map(|(rank, owner)| {
        direct_methods(analyzer, owner, name)
            .into_iter()
            .next()
            .map(|target| ResolvedCall {
                target,
                owner: owner.clone(),
                rank: mro
                    .iter()
                    .position(|candidate| candidate == owner)
                    .unwrap_or(rank),
            })
    });
    target.map_or(LifecycleCallTarget::None, LifecycleCallTarget::Target)
}

fn lifecycle_super_call_target(
    analyzer: &dyn IAnalyzer,
    method: &CodeUnit,
    mro: &[CodeUnit],
    name: &str,
) -> LifecycleCallTarget {
    let Some(owner) = analyzer.parent_of(method) else {
        return LifecycleCallTarget::None;
    };
    let Some(owner_rank) = mro.iter().position(|candidate| candidate == &owner) else {
        return LifecycleCallTarget::None;
    };
    let target = mro
        .iter()
        .enumerate()
        .skip(owner_rank + 1)
        .find_map(|(rank, owner)| {
            direct_methods(analyzer, owner, name)
                .into_iter()
                .next()
                .map(|target| ResolvedCall {
                    target,
                    owner: owner.clone(),
                    rank,
                })
        });
    target.map_or(LifecycleCallTarget::None, LifecycleCallTarget::Target)
}

fn lifecycle_target_non_trivial(
    analyzer: &dyn IAnalyzer,
    semantic: &mut super::semantic::SemanticQueryContext<'_>,
    target: &CodeUnit,
    occurrence_cache: &mut super::occurrences::OccurrenceTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<bool> {
    if target.package_name() == "builtins" {
        return Some(false);
    }
    let filter = lifecycle_occurrence_filter();
    occurrence_cache
        .rows_for_file(analyzer, target.source(), &filter, cancellation)
        .and_then(|rows| {
            occurrence_cache.report_completeness(target.source(), &rows, &filter, diagnostics);
            let mut resolved = rows.rows.clone();
            if !occurrence_cache.resolve_targets_for_rows(
                analyzer,
                target.source(),
                &mut resolved,
                cancellation,
            ) {
                return None;
            }
            filter
                .roles
                .iter()
                .all(|role| rows.completeness.covers(*role))
                .then(|| {
                    super::python_rule_facts::python_method_non_trivial(
                        analyzer, semantic, target, &resolved,
                    )
                })
                .flatten()
        })
}

fn class_is_strict_subclass(
    analyzer: &dyn IAnalyzer,
    subclass: &CodeUnit,
    superclass: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> Option<bool> {
    if subclass == superclass {
        return Some(false);
    }
    let provider = analyzer.python_class_hierarchy_provider_for(subclass)?;
    let hierarchy = provider.class_hierarchy(subclass, cancellation);
    (hierarchy.outcome == PythonHierarchyOutcome::Complete).then(|| {
        hierarchy
            .mro
            .iter()
            .skip(1)
            .any(|class| class == superclass)
    })
}

// These query-local caches and target identity remain explicit in the MRO walk.
#[allow(clippy::too_many_arguments)]
fn superclass_also_misses_call(
    analyzer: &dyn IAnalyzer,
    class_mro: &[CodeUnit],
    target: &CodeUnit,
    name: &str,
    occurrence_cache: &mut super::occurrences::OccurrenceTraversalCache,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<bool> {
    for superclass in class_mro.iter().skip(1) {
        let provider = analyzer.python_class_hierarchy_provider_for(superclass)?;
        let hierarchy = provider.class_hierarchy(superclass, cancellation);
        if hierarchy.outcome != PythonHierarchyOutcome::Complete {
            return None;
        }
        if !hierarchy
            .mro
            .iter()
            .skip(1)
            .any(|ancestor| analyzer.parent_of(target).as_ref() == Some(ancestor))
        {
            continue;
        }
        let inherited = inherited_methods(analyzer, &hierarchy.mro, name)?;
        let start = direct_methods(analyzer, superclass, name)
            .into_iter()
            .next()
            .or_else(|| inherited.first().map(|entry| entry.0.clone()));
        let Some(start) = start else {
            continue;
        };
        let closure = match transitive_lifecycle_targets(
            analyzer,
            superclass,
            &hierarchy.mro,
            std::slice::from_ref(&start),
            name,
            occurrence_cache,
            environment_cache,
            cancellation,
            diagnostics,
        ) {
            Ok(closure) => closure,
            Err(_) => return None,
        };
        if !closure.calls_unknown_class_with_self && !closure.targets.contains(target) {
            return Some(true);
        }
    }
    Some(false)
}

fn set_target_reads_self(
    fact: &mut PipelineExpansion,
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) {
    let PipelineValue::PythonHierarchyFact(value) = &mut fact.value else {
        unreachable!("initializer dispatch facts use the Python hierarchy value")
    };
    value.target_reads_self =
        super::python_rule_facts::python_method_reads_receiver(analyzer, target);
    if value.target_reads_self.is_none() {
        value.coverage = "open";
        value.reason = Some("target_receiver_read_unavailable");
    }
}

fn direct_methods(analyzer: &dyn IAnalyzer, owner: &CodeUnit, name: &str) -> Vec<CodeUnit> {
    analyzer
        .direct_children(owner)
        .into_iter()
        .filter(|unit| unit.kind() == CodeUnitType::Function && unit.terminal_name() == name)
        .collect()
}

fn inherited_methods(
    analyzer: &dyn IAnalyzer,
    mro: &[CodeUnit],
    name: &str,
) -> Option<Vec<(CodeUnit, CodeUnit, usize)>> {
    let mut inherited = Vec::new();
    for (rank, owner) in mro.iter().enumerate().skip(1) {
        if rank > CALL_VISIT_LIMIT {
            return None;
        }
        inherited.extend(
            direct_methods(analyzer, owner, name)
                .into_iter()
                .map(|method| (method, owner.clone(), rank)),
        );
    }
    Some(inherited)
}

fn call_sites_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    facts: &FileFacts,
) -> (Vec<CallSite>, bool) {
    let methods = if declaration.unit.kind() == CodeUnitType::Class {
        analyzer
            .direct_children(&declaration.unit)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Function)
            .collect::<Vec<_>>()
    } else if declaration.unit.kind() == CodeUnitType::Function {
        vec![declaration.unit.clone()]
    } else {
        Vec::new()
    };
    let mut sites = Vec::new();
    let mut seen = HashSet::default();
    for (index, node) in facts.nodes().iter().enumerate() {
        if node.kind != NormalizedKind::Call {
            continue;
        }
        let node_id = u32::try_from(index).expect("normalized node ids fit u32");
        let Some(method) = enclosing_method(analyzer, facts, node_id, &methods) else {
            continue;
        };
        let Some(shape) = call_shape_for_call(facts, declaration.unit.source(), node_id) else {
            continue;
        };
        if !seen.insert(shape.outcome.site_ast_id.clone()) {
            continue;
        }
        sites.push(CallSite {
            method,
            conditional: call_is_conditional(facts, node_id),
            shape,
        });
        if sites.len() >= CALL_VISIT_LIMIT {
            return (sites, true);
        }
    }
    (sites, false)
}

fn enclosing_method(
    analyzer: &dyn IAnalyzer,
    facts: &FileFacts,
    call: u32,
    methods: &[CodeUnit],
) -> Option<CodeUnit> {
    let mut parent = facts.node(call).parent;
    let mut inside_body = false;
    while let Some(id) = parent {
        let node = facts.node(id);
        if node.kind == NormalizedKind::Block {
            inside_body = true;
        }
        if node.kind.satisfies(NormalizedKind::Callable) {
            if !inside_body {
                return None;
            }
            return methods.iter().find_map(|method| {
                analyzer
                    .ranges(method)
                    .iter()
                    .any(|range| {
                        range.start_byte == node.range.start_byte
                            && range.end_byte == node.range.end_byte
                    })
                    .then(|| method.clone())
            });
        }
        parent = node.parent;
    }
    None
}

fn call_is_conditional(facts: &FileFacts, call: u32) -> bool {
    let mut parent = facts.node(call).parent;
    while let Some(id) = parent {
        let node = facts.node(id);
        if matches!(
            node.kind,
            NormalizedKind::If | NormalizedKind::Loop | NormalizedKind::Catch
        ) {
            return true;
        }
        if node.kind.satisfies(NormalizedKind::Callable) {
            break;
        }
        parent = node.parent;
    }
    false
}

fn occurrence_at(
    rows: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    range: Range,
) -> Option<&crate::analyzer::structural::occurrence_rows::OccurrenceRow> {
    rows.iter().find(|row| {
        row.range.start_byte == range.start_byte && row.range.end_byte == range.end_byte
    })
}

fn first_parameter_name(
    analyzer: &dyn IAnalyzer,
    facts: &FileFacts,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    method: &CodeUnit,
) -> Option<String> {
    let ranges = analyzer.ranges(method);
    let method_node = facts.nodes().iter().enumerate().find_map(|(index, node)| {
        (node.kind.satisfies(NormalizedKind::Callable)
            && ranges.iter().any(|range| {
                range.start_byte == node.range.start_byte && range.end_byte == node.range.end_byte
            }))
        .then(|| u32::try_from(index).expect("normalized node ids fit u32"))
    })?;
    facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.kind == NormalizedKind::Parameter)
        .filter_map(|(index, node)| {
            let mut parent = node.parent;
            let mut nearest_callable = None;
            while let Some(id) = parent {
                let ancestor = facts.node(id);
                if ancestor.kind.satisfies(NormalizedKind::Callable) {
                    nearest_callable = Some(id);
                    break;
                }
                parent = ancestor.parent;
            }
            if nearest_callable != Some(method_node) {
                return None;
            }
            occurrence_at(occurrences, node.range)
                .filter(|row| row.role == OccurrenceRole::Binder)
                .map(|row| {
                    (
                        node.range.start_byte,
                        u32::try_from(index).expect("normalized node ids fit u32"),
                        row.effective_spelling().to_owned(),
                    )
                })
        })
        .min_by_key(|(start, _, _)| *start)
        .map(|(_, _, name)| name)
}

fn occurrence_is_bound_to_formal(
    rows: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    range: Range,
    formal: &str,
) -> bool {
    occurrence_at(rows, range).is_some_and(|row| {
        row.effective_spelling() == formal && matches!(&row.target, OccurrenceTarget::Lexical(_))
    })
}

fn explicit_inherited_call_target(
    analyzer: &dyn IAnalyzer,
    facts: &FileFacts,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    shape: &CallShapeReport,
    method: &CodeUnit,
    inherited: &[(CodeUnit, CodeUnit, usize)],
) -> Option<ResolvedCall> {
    let receiver = shape.outcome.receiver_range?;
    if proven_super_receiver(facts, &shape.outcome.file, occurrences, receiver) == Some(true) {
        let super_shape = super_call_receiver(facts, &shape.outcome.file, receiver)?;
        if super_shape.outcome.coverage != CallShapeCoverage::Exact {
            return None;
        }
        let super_callee = super_shape.outcome.callee_range?;
        if builtin_super_at(occurrences, super_callee) != Some(true) {
            return None;
        }
        let group = super_shape
            .groups
            .iter()
            .find(|group| group.kind == ArgumentListKind::Ordinary && group.group_index == 0)?;
        let arguments = super_shape
            .arguments
            .iter()
            .filter(|argument| argument.group_id == group.id)
            .collect::<Vec<_>>();
        if arguments.len() != 2
            || arguments.iter().any(|argument| argument.name.is_some())
            || arguments[0].argument_index != 0
            || arguments[1].argument_index != 1
        {
            return None;
        }
        let class = resolved_class_at(occurrences, arguments[0].range)?;
        if method_owner(analyzer, method).as_ref() != Some(&class) {
            return None;
        }
        let formal = first_parameter_name(analyzer, facts, occurrences, method)?;
        if !occurrence_is_bound_to_formal(occurrences, arguments[1].range, &formal) {
            return None;
        }
        let (target, owner, rank) = inherited.first()?;
        return Some(ResolvedCall {
            target: target.clone(),
            owner: owner.clone(),
            rank: *rank,
        });
    }
    let base = resolved_class_at(occurrences, receiver)?;
    let (target, owner, rank) = inherited
        .iter()
        .find(|(_, candidate_owner, _)| *candidate_owner == base)?;
    let formal = first_parameter_name(analyzer, facts, occurrences, method)?;
    let group = shape
        .groups
        .iter()
        .find(|group| group.kind == ArgumentListKind::Ordinary && group.group_index == 0)?;
    let first_argument = shape.arguments.iter().find(|argument| {
        argument.group_id == group.id && argument.argument_index == 0 && argument.name.is_none()
    })?;
    occurrence_is_bound_to_formal(occurrences, first_argument.range, &formal).then(|| {
        ResolvedCall {
            target: target.clone(),
            owner: owner.clone(),
            rank: *rank,
        }
    })
}

fn super_call_receiver(
    facts: &FileFacts,
    file: &ProjectFile,
    range: Range,
) -> Option<CallShapeReport> {
    facts.nodes().iter().enumerate().find_map(|(index, node)| {
        (node.kind == NormalizedKind::Call
            && node.range.start_byte == range.start_byte
            && node.range.end_byte == range.end_byte)
            .then(|| {
                call_shape_for_call(
                    facts,
                    file,
                    u32::try_from(index).expect("normalized node ids fit u32"),
                )
            })
            .flatten()
            .filter(|shape| shape.outcome.callee_name.as_deref() == Some("super"))
    })
}

fn proven_super_receiver(
    facts: &FileFacts,
    file: &ProjectFile,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    range: Range,
) -> Option<bool> {
    let shape = super_call_receiver(facts, file, range)?;
    let callee = shape.outcome.callee_range?;
    builtin_super_at(occurrences, callee)
}

fn implicit_super_receiver(
    facts: &FileFacts,
    file: &ProjectFile,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    range: Range,
) -> bool {
    let Some(shape) = super_call_receiver(facts, file, range) else {
        return false;
    };
    shape.outcome.coverage == CallShapeCoverage::Exact
        && shape.arguments.is_empty()
        && shape
            .outcome
            .callee_range
            .is_some_and(|callee| builtin_super_at(occurrences, callee) == Some(true))
}

fn lifecycle_receiver_is_exact(
    analyzer: &dyn IAnalyzer,
    facts: &FileFacts,
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    shape: &CallShapeReport,
    method: &CodeUnit,
    target_owner: &CodeUnit,
) -> bool {
    let Some(receiver) = shape.outcome.receiver_range else {
        return false;
    };
    match proven_super_receiver(facts, &shape.outcome.file, occurrences, receiver) {
        Some(true) => return true,
        Some(false) => {}
        None => return false,
    }
    let Some(formal) = first_parameter_name(analyzer, facts, occurrences, method) else {
        return false;
    };
    resolved_class_at(occurrences, receiver).as_ref() == Some(target_owner)
        && shape
            .arguments
            .iter()
            .find(|argument| {
                shape
                    .groups
                    .iter()
                    .find(|group| {
                        group.kind == ArgumentListKind::Ordinary && group.group_index == 0
                    })
                    .is_some_and(|group| argument.group_id == group.id)
                    && argument.argument_index == 0
            })
            .is_some_and(|argument| {
                argument.name.is_none()
                    && occurrence_is_bound_to_formal(occurrences, argument.range, &formal)
            })
}

fn resolved_class_at(
    rows: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    range: Range,
) -> Option<CodeUnit> {
    let row = occurrence_at(rows, range)?;
    match &row.target {
        OccurrenceTarget::Resolved(targets) if targets.len() == 1 => targets
            .first()
            .filter(|target| target.kind() == CodeUnitType::Class)
            .cloned(),
        _ => None,
    }
}

fn builtin_super_at(
    rows: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    range: Range,
) -> Option<bool> {
    let row = occurrence_at(rows, range)?;
    match &row.target {
        OccurrenceTarget::Resolved(targets) if targets.len() == 1 => {
            let target = targets.first()?;
            Some(
                target.kind() == CodeUnitType::Function
                    && target.package_name() == "builtins"
                    && target.terminal_name() == "super",
            )
        }
        OccurrenceTarget::Lexical(_) => Some(false),
        OccurrenceTarget::Unresolved(DefinitionLookupStatus::NoDefinition)
            if row.effective_spelling() == "super"
                && is_python_builtin_or_constant(row.effective_spelling()) =>
        {
            Some(true)
        }
        _ => None,
    }
}

fn method_owner(analyzer: &dyn IAnalyzer, method: &CodeUnit) -> Option<CodeUnit> {
    analyzer.parent_of(method).filter(CodeUnit::is_class)
}

fn is_inherited_target(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    current_owner: &CodeUnit,
    mro: &[CodeUnit],
) -> Option<usize> {
    let owner = analyzer.parent_of(target)?;
    if owner == *current_owner {
        return None;
    }
    mro.iter().position(|candidate| candidate == &owner)
}

#[allow(clippy::too_many_arguments)]
fn init_calls_subclass_facts(
    analyzer: &dyn IAnalyzer,
    root: &DeclarationValue,
    root_id: &str,
    owner: &CodeUnit,
    facts: &FileFacts,
    call_sites: &[CallSite],
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    mro: &[CodeUnit],
    semantic: &mut super::semantic::SemanticQueryContext<'_>,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    let methods = direct_methods(analyzer, owner, "__init__");
    if methods.is_empty() {
        return Vec::new();
    }
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return vec![fact_expansion(
            root,
            root_id,
            "call_lifecycle",
            "incomplete",
            Some("incomplete_hierarchy"),
            "open",
            None,
            Some(root.range),
            methods.first().cloned(),
            Some(owner.clone()),
            None,
            None,
            Some("init_calls_subclass".to_owned()),
            None,
        )];
    };
    let token = cancellation.cloned().unwrap_or_default();
    let scope = DescendantIndexScope::whole_workspace(&token);
    let Some(direct_descendants) = provider.get_direct_descendants_within(owner, &scope) else {
        return vec![fact_expansion(
            root,
            root_id,
            "call_lifecycle",
            "incomplete",
            Some("visit_limit"),
            "open",
            None,
            Some(root.range),
            methods.first().cloned(),
            Some(owner.clone()),
            None,
            None,
            Some("init_calls_subclass".to_owned()),
            None,
        )];
    };
    let mut descendants = Vec::new();
    let mut pending = direct_descendants.into_iter().collect::<Vec<_>>();
    let mut seen = HashSet::default();
    while let Some(class) = pending.pop() {
        if !seen.insert(class.clone()) {
            continue;
        }
        if seen.len() > DESCENDANT_VISIT_LIMIT {
            return vec![fact_expansion(
                root,
                root_id,
                "call_lifecycle",
                "incomplete",
                Some("visit_limit"),
                "open",
                None,
                Some(root.range),
                methods.first().cloned(),
                Some(owner.clone()),
                None,
                None,
                Some("init_calls_subclass".to_owned()),
                None,
            )];
        }
        descendants.push(class.clone());
        if let Some(next) = provider.get_direct_descendants_within(&class, &scope) {
            pending.extend(next);
        } else {
            return vec![fact_expansion(
                root,
                root_id,
                "call_lifecycle",
                "incomplete",
                Some("visit_limit"),
                "open",
                None,
                Some(root.range),
                methods.first().cloned(),
                Some(owner.clone()),
                None,
                None,
                Some("init_calls_subclass".to_owned()),
                None,
            )];
        }
    }
    let Some(python_provider) = analyzer.python_class_hierarchy_provider_for(owner) else {
        return vec![fact_expansion(
            root,
            root_id,
            "call_lifecycle",
            "incomplete",
            Some("incomplete_hierarchy"),
            "open",
            None,
            Some(root.range),
            methods.first().cloned(),
            Some(owner.clone()),
            None,
            None,
            Some("init_calls_subclass".to_owned()),
            None,
        )];
    };
    let mut output = Vec::new();
    for method in &methods {
        for call in call_sites.iter().filter(|call| {
            call.method == *method
                && call.shape.outcome.receiver_range.is_some()
                && call
                    .shape
                    .outcome
                    .callee_name
                    .as_deref()
                    .is_some_and(|name| !name.starts_with('_'))
        }) {
            if call.shape.outcome.coverage != CallShapeCoverage::Exact || call.conditional {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_lifecycle",
                    "incomplete",
                    Some(if call.conditional {
                        "conditional_call"
                    } else {
                        "unsupported_call_shape"
                    }),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(method.clone()),
                    Some(owner.clone()),
                    None,
                    None,
                    Some("init_calls_subclass".to_owned()),
                    None,
                ));
                continue;
            }
            let Some(receiver) = call.shape.outcome.receiver_range else {
                continue;
            };
            let Some(formal) = first_parameter_name(analyzer, facts, occurrences, method) else {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_lifecycle",
                    "incomplete",
                    Some("receiver_binding_unknown"),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(method.clone()),
                    Some(owner.clone()),
                    None,
                    None,
                    Some("init_calls_subclass".to_owned()),
                    None,
                ));
                continue;
            };
            if !occurrence_is_bound_to_formal(occurrences, receiver, &formal) {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_lifecycle",
                    "incomplete",
                    Some("receiver_binding_unknown"),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(method.clone()),
                    Some(owner.clone()),
                    None,
                    None,
                    Some("init_calls_subclass".to_owned()),
                    None,
                ));
                continue;
            }
            let name = call.shape.outcome.callee_name.as_deref().unwrap();
            let dispatch =
                semantic.dispatch_at_source(&call.shape.outcome.file, call.shape.outcome.range);
            let dispatch_reason = if !dispatch.coverage.is_exhaustive()
                || dispatch.arms.len() != 1
                || dispatch
                    .arms
                    .iter()
                    .any(|arm| dispatch.dispatch_label(arm) != "proven_dispatch")
            {
                Some(if dispatch.arms.len() > 1 {
                    "dynamic_dispatch"
                } else {
                    "unresolved_dispatch"
                })
            } else {
                None
            };
            let Some((called_owner, called_rank)) =
                mro.iter().enumerate().find_map(|(rank, candidate_owner)| {
                    direct_methods(analyzer, candidate_owner, name)
                        .into_iter()
                        .next()
                        .map(|_| (candidate_owner.clone(), rank))
                })
            else {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_lifecycle",
                    "incomplete",
                    Some("unresolved_dispatch"),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(method.clone()),
                    Some(owner.clone()),
                    None,
                    None,
                    Some("init_calls_subclass".to_owned()),
                    None,
                ));
                continue;
            };
            for descendant in &descendants {
                let Some(descendant_method) =
                    direct_methods(analyzer, descendant, name).first().cloned()
                else {
                    continue;
                };
                let answer = python_provider.method_override(&descendant_method, cancellation);
                if answer.outcome == PythonOverrideOutcome::Overrides
                    && answer.target_owner.as_ref() == Some(&called_owner)
                {
                    let mut fact = fact_expansion(
                        root,
                        root_id,
                        "call_lifecycle",
                        "init_calls_subclass",
                        None,
                        "complete",
                        None,
                        Some(call.shape.outcome.range),
                        Some(method.clone()),
                        Some(owner.clone()),
                        Some(descendant_method.clone()),
                        Some(descendant.clone()),
                        Some(name.to_owned()),
                        Some(called_rank),
                    );
                    set_target_reads_self(&mut fact, analyzer, &descendant_method);
                    output.push(fact);
                }
                if matches!(
                    answer.outcome,
                    PythonOverrideOutcome::Incomplete | PythonOverrideOutcome::Unsupported
                ) {
                    output.push(fact_expansion(
                        root,
                        root_id,
                        "call_lifecycle",
                        "incomplete",
                        Some(answer.reason.map(PythonHierarchyReason::label).unwrap_or(
                            if answer.outcome == PythonOverrideOutcome::Unsupported {
                                "unsupported_language"
                            } else {
                                "incomplete_hierarchy"
                            },
                        )),
                        "open",
                        None,
                        Some(call.shape.outcome.range),
                        Some(method.clone()),
                        Some(owner.clone()),
                        None,
                        None,
                        Some("init_calls_subclass".to_owned()),
                        None,
                    ));
                }
            }
            if let Some(reason) = dispatch_reason {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_lifecycle",
                    "incomplete",
                    Some(reason),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(method.clone()),
                    Some(owner.clone()),
                    None,
                    None,
                    Some("init_calls_subclass".to_owned()),
                    None,
                ));
            }
        }
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn context_facts(
    analyzer: &dyn IAnalyzer,
    root: &DeclarationValue,
    root_id: &str,
    facts: &FileFacts,
    call_sites: &[CallSite],
    occurrences: &[crate::analyzer::structural::occurrence_rows::OccurrenceRow],
    mro: &[CodeUnit],
    hierarchy_complete: bool,
    semantic: &mut super::semantic::SemanticQueryContext<'_>,
) -> Vec<PipelineExpansion> {
    let mut output = Vec::new();
    for call in call_sites {
        let subject_method = &call.method;
        let method_owner = method_owner(analyzer, subject_method);
        let name = call.shape.outcome.callee_name.as_deref();
        if name == Some("super") {
            let Some(callee_range) = call.shape.outcome.callee_range else {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_context",
                    "incomplete",
                    Some("unsupported_call_shape"),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(subject_method.clone()),
                    method_owner.clone(),
                    None,
                    None,
                    Some("super".to_owned()),
                    None,
                ));
                continue;
            };
            match builtin_super_at(occurrences, callee_range) {
                Some(false) => continue,
                None => {
                    output.push(fact_expansion(
                        root,
                        root_id,
                        "call_context",
                        "incomplete",
                        Some("unresolved_super_binding"),
                        "open",
                        None,
                        Some(call.shape.outcome.range),
                        Some(subject_method.clone()),
                        method_owner.clone(),
                        None,
                        None,
                        Some("super".to_owned()),
                        None,
                    ));
                    continue;
                }
                Some(true) => {}
            }
            let Some(owner) = method_owner.as_ref() else {
                continue;
            };
            let first_group =
                call.shape.groups.iter().find(|group| {
                    group.kind == ArgumentListKind::Ordinary && group.group_index == 0
                });
            let positional = first_group
                .map(|group| {
                    call.shape
                        .arguments
                        .iter()
                        .filter(|argument| argument.group_id == group.id && argument.name.is_none())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if positional.len() < 2 || call.shape.outcome.coverage != CallShapeCoverage::Exact {
                continue;
            }
            let Some(formal) = first_parameter_name(analyzer, facts, occurrences, subject_method)
            else {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_context",
                    "incomplete",
                    Some("receiver_binding_unknown"),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(subject_method.clone()),
                    Some(owner.clone()),
                    None,
                    None,
                    Some("super".to_owned()),
                    None,
                ));
                continue;
            };
            if !occurrence_is_bound_to_formal(occurrences, positional[1].range, &formal) {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_context",
                    "incomplete",
                    Some("receiver_binding_unknown"),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(subject_method.clone()),
                    Some(owner.clone()),
                    None,
                    None,
                    Some("super".to_owned()),
                    None,
                ));
                continue;
            }
            let Some(class_arg) = resolved_class_at(occurrences, positional[0].range) else {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_context",
                    "incomplete",
                    Some("unresolved_super_binding"),
                    "open",
                    None,
                    Some(call.shape.outcome.range),
                    Some(subject_method.clone()),
                    Some(owner.clone()),
                    None,
                    None,
                    Some("super".to_owned()),
                    None,
                ));
                continue;
            };
            if class_arg != *owner {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_context",
                    "super_mismatch",
                    None,
                    "complete",
                    None,
                    Some(call.shape.outcome.range),
                    Some(subject_method.clone()),
                    Some(owner.clone()),
                    Some(class_arg.clone()),
                    Some(class_arg),
                    Some("super".to_owned()),
                    None,
                ));
            } else {
                output.push(fact_expansion(
                    root,
                    root_id,
                    "call_context",
                    "no_issue",
                    None,
                    "complete",
                    None,
                    Some(call.shape.outcome.range),
                    Some(subject_method.clone()),
                    Some(owner.clone()),
                    Some(owner.clone()),
                    Some(owner.clone()),
                    Some("super".to_owned()),
                    None,
                ));
            }
        }
        if name != Some("__del__") || call.shape.outcome.coverage != CallShapeCoverage::Exact {
            continue;
        }
        if subject_method.terminal_name() == "__del__"
            && hierarchy_complete
            && let Some(owner) = method_owner.as_ref()
            && let Some(inherited) = inherited_methods(analyzer, mro, "__del__")
            && let Some(target) = explicit_inherited_call_target(
                analyzer,
                facts,
                occurrences,
                &call.shape,
                subject_method,
                &inherited,
            )
        {
            output.push(fact_expansion(
                root,
                root_id,
                "call_context",
                "approved_cleanup",
                None,
                "complete",
                None,
                Some(call.shape.outcome.range),
                Some(subject_method.clone()),
                Some(owner.clone()),
                Some(target.target),
                Some(target.owner),
                Some("__del__".to_owned()),
                Some(target.rank),
            ));
            continue;
        }
        if subject_method.terminal_name() == "__del__"
            && hierarchy_complete
            && let Some(owner) = method_owner.as_ref()
            && call.shape.outcome.receiver_range.is_some_and(|receiver| {
                implicit_super_receiver(facts, &call.shape.outcome.file, occurrences, receiver)
            })
            && first_parameter_name(analyzer, facts, occurrences, subject_method).is_some()
            && let Some((target, target_owner, rank)) = inherited_methods(analyzer, mro, "__del__")
                .and_then(|mut methods| (!methods.is_empty()).then(|| methods.remove(0)))
        {
            output.push(fact_expansion(
                root,
                root_id,
                "call_context",
                "approved_cleanup",
                None,
                "complete",
                None,
                Some(call.shape.outcome.range),
                Some(subject_method.clone()),
                Some(owner.clone()),
                Some(target),
                Some(target_owner),
                Some("__del__".to_owned()),
                Some(rank),
            ));
            continue;
        }
        let answer =
            semantic.dispatch_at_source(&call.shape.outcome.file, call.shape.outcome.range);
        let exact = answer.coverage.is_exhaustive()
            && !answer.arms.is_empty()
            && answer
                .arms
                .iter()
                .all(|arm| answer.dispatch_label(arm) == "proven_dispatch");
        if !exact {
            output.push(fact_expansion(
                root,
                root_id,
                "call_context",
                "incomplete",
                Some("unresolved_dispatch"),
                "open",
                None,
                Some(call.shape.outcome.range),
                Some(subject_method.clone()),
                method_owner.clone(),
                None,
                None,
                Some("__del__".to_owned()),
                None,
            ));
            continue;
        }
        let approved = if subject_method.terminal_name() == "__del__" && hierarchy_complete {
            if let Some(owner) = method_owner.as_ref() {
                answer.arms.iter().all(|arm| {
                    let Some(target) = arm.target_unit.as_ref() else {
                        return false;
                    };
                    let Some(target_owner) = analyzer.parent_of(target) else {
                        return false;
                    };
                    is_inherited_target(analyzer, target, owner, mro).is_some()
                        && lifecycle_receiver_is_exact(
                            analyzer,
                            facts,
                            occurrences,
                            &call.shape,
                            subject_method,
                            &target_owner,
                        )
                })
            } else {
                false
            }
        } else {
            false
        };
        output.push(fact_expansion(
            root,
            root_id,
            "call_context",
            if approved {
                "approved_cleanup"
            } else {
                "explicit_delete_call"
            },
            None,
            "complete",
            None,
            Some(call.shape.outcome.range),
            Some(subject_method.clone()),
            method_owner.clone(),
            answer.arms.first().and_then(|arm| arm.target_unit.clone()),
            answer
                .arms
                .first()
                .and_then(|arm| arm.target_unit.as_ref())
                .and_then(|target| analyzer.parent_of(target)),
            Some("__del__".to_owned()),
            None,
        ));
    }
    output
}
