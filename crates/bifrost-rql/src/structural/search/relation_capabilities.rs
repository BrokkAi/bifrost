//! Query-level coverage for language-owned structural relations.
//!
//! Relation expansion normally discovers unsupported coverage while it visits
//! a matching seed. That is too late for an empty relation: an adapter that
//! emits no rows can otherwise look exactly like an adapter that exhaustively
//! proved there are no rows. This module checks the authored relation contract
//! against the languages in the selected source scope before execution starts.
//! The producer modules remain the owners of the support predicates; this is a
//! shared preflight, not a second set of language implementations.

use super::*;
use crate::analyzer::semantic::{CapabilitySupport, SemanticCapability};
use crate::analyzer::{LanguageDialect, WorkspaceAnalyzer};
use crate::query::{
    AssignmentRelationKind, CodeQueryPlan, CodeQueryPlanSource, PlanPartitioning, QueryPathScope,
    QueryStep,
};
use crate::structural::execution::plan::{
    source_enumeration_constraint_with_inherited_steps, source_file_matches_constraint,
};

/// Report unsupported relation coverage once for the selected source scope.
pub(super) fn preflight(
    plan: &CodeQueryPlan,
    files: &[ProjectFile],
    workspace: Option<&WorkspaceAnalyzer>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let mut reported = BTreeSet::new();
    preflight_plan(plan, files, workspace, &[], &mut reported, diagnostics);
}

fn preflight_plan(
    plan: &CodeQueryPlan,
    files: &[ProjectFile],
    workspace: Option<&WorkspaceAnalyzer>,
    inherited_steps: &[QueryStep],
    reported: &mut BTreeSet<(LanguageDialect, String)>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    let dialects = source_dialects(plan, files, inherited_steps);
    for step in &plan.steps {
        match step {
            QueryStep::AssignmentRelations(filter) => {
                let requested = if filter.relations.is_empty() {
                    vec![AssignmentRelationKind::SelfAssignment]
                } else {
                    filter.relations.clone()
                };
                for dialect in &dialects {
                    for relation in &requested {
                        if !assignment_relations::supports_relation(*dialect, *relation) {
                            report_unsupported(
                                reported,
                                diagnostics,
                                *dialect,
                                format!("assignment relation `{}`", relation.label()),
                            );
                        }
                    }
                }
            }
            QueryStep::BranchRelations(filter) => {
                for dialect in &dialects {
                    let requested =
                        branch_relations::requested_relations(dialect.language(), filter);
                    for relation in requested {
                        if !branch_relations::supports_relation(dialect.language(), relation) {
                            report_unsupported(
                                reported,
                                diagnostics,
                                *dialect,
                                format!("branch relation `{}`", relation.label()),
                            );
                        }
                    }
                }
            }
            QueryStep::FailureHandlerState => {
                for dialect in &dialects {
                    if !failure_handler_state::supports_language(dialect.language()) {
                        report_unsupported(
                            reported,
                            diagnostics,
                            *dialect,
                            "failure-handler state relation".to_owned(),
                        );
                    }
                }
            }
            QueryStep::NilnessOperations => {
                for dialect in &dialects {
                    if !effects::nilness_supports_dialect(*dialect) {
                        report_unsupported(
                            reported,
                            diagnostics,
                            *dialect,
                            "nilness operations".to_owned(),
                        );
                    }
                }
            }
            QueryStep::SwitchCoverage => {
                for dialect in &dialects {
                    let file = files.iter().find(|file| {
                        let language = crate::analyzer::common::language_for_file(file);
                        LanguageDialect::for_path(language, file.rel_path()) == *dialect
                    });
                    let support = file
                        .and_then(|file| {
                            workspace.and_then(|workspace| {
                                workspace.program_semantics_provider_for_file(file)
                            })
                        })
                        .map(|provider| {
                            provider
                                .capabilities()
                                .support(SemanticCapability::SwitchFacts)
                        })
                        .unwrap_or(CapabilitySupport::Unsupported);
                    if !support.is_complete() {
                        report_unsupported(
                            reported,
                            diagnostics,
                            *dialect,
                            "switch coverage".to_owned(),
                        );
                    }
                }
            }
            // `loop_candidates` is a shared producer with a C++ cache rather
            // than a language omission: all analyzable languages reach the
            // same complete candidate builder today. Do not turn a genuine
            // supported-empty loop set into an incomplete result.
            QueryStep::LoopRelations => {}
            _ => {}
        }
    }

    let inherited_for_children =
        PlanPartitioning::safe_union_inherited_steps(plan, inherited_steps).unwrap_or_default();
    for child in plan.source.child_plans() {
        preflight_plan(
            child,
            files,
            workspace,
            &inherited_for_children,
            reported,
            diagnostics,
        );
    }
}

fn report_unsupported(
    reported: &mut BTreeSet<(LanguageDialect, String)>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    dialect: LanguageDialect,
    relation: String,
) {
    if !reported.insert((dialect, relation.clone())) {
        return;
    }
    let language = dialect.language();
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: language.config_label(),
        message: format!(
            "{} adapter does not produce {relation} for the selected source scope (unsupported_relation)",
            language.config_label()
        ),
        exhausted_roots: Vec::new(),
    });
}

/// The source files whose language adapters can contribute rows to a plan.
///
/// A narrowed policy unit still receives the whole workspace file list here.
/// The unit's seed file controls row enumeration, but support coverage is a
/// property of the query's selected language/path scope and must not disappear
/// merely because this one unit has no matching procedure.
fn source_dialects(
    plan: &CodeQueryPlan,
    files: &[ProjectFile],
    inherited_steps: &[QueryStep],
) -> BTreeSet<LanguageDialect> {
    match &plan.source {
        CodeQueryPlanSource::Seed(seed) => selected_dialects(
            files,
            &seed.languages,
            &seed.where_globs,
            source_enumeration_constraint_with_inherited_steps(plan, inherited_steps),
        ),
        CodeQueryPlanSource::Occurrences(seed) => {
            selected_dialects(files, &seed.languages, &seed.where_globs, None)
        }
        CodeQueryPlanSource::Scopes(seed) => {
            selected_dialects(files, &seed.languages, &seed.where_globs, None)
        }
        CodeQueryPlanSource::Bindings(seed) => {
            selected_dialects(files, &seed.languages, &seed.where_globs, None)
        }
        CodeQueryPlanSource::Paths(seed) => {
            selected_dialects(files, &seed.languages, &seed.where_globs, None)
        }
        CodeQueryPlanSource::GenerationSites(seed) => {
            selected_dialects(files, &seed.languages, &seed.where_globs, None)
        }
        CodeQueryPlanSource::Exports(seed) => {
            selected_dialects(files, &seed.languages, &seed.where_globs, None)
        }
        CodeQueryPlanSource::Set { branches, .. } => {
            let inherited_for_branches =
                PlanPartitioning::safe_union_inherited_steps(plan, inherited_steps)
                    .unwrap_or_default();
            branches
                .iter()
                .flat_map(|branch| source_dialects(branch, files, &inherited_for_branches))
                .collect()
        }
        CodeQueryPlanSource::Correlate(correlation) => {
            source_dialects(&correlation.code, files, &[])
        }
        CodeQueryPlanSource::RequireBoth(requirement) => {
            source_dialects(&requirement.code, files, &[])
        }
        CodeQueryPlanSource::DependencyEvidence(_) | CodeQueryPlanSource::ConfigurationFacts(_) => {
            BTreeSet::new()
        }
    }
}

fn selected_dialects(
    files: &[ProjectFile],
    languages: &[Language],
    where_globs: &QueryPathScope,
    source_enumeration_constraint: Option<
        crate::structural::execution::plan::SourceEnumerationConstraint,
    >,
) -> BTreeSet<LanguageDialect> {
    files
        .iter()
        .filter_map(|file| {
            let language = crate::analyzer::common::language_for_file(file);
            if !Language::ANALYZABLE.contains(&language)
                || (!languages.is_empty() && !languages.contains(&language))
                || !where_globs.matches(&rel_path_string(file))
                || !source_file_matches_constraint(file, source_enumeration_constraint)
            {
                return None;
            }
            Some(LanguageDialect::for_path(language, file.rel_path()))
        })
        .collect()
}
