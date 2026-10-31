//! Exact identity filtering for a value expression selected by a call argument,
//! a structured value match, or a resolved decorator structural match.

use super::*;
use crate::analyzer::usages::call_binding::{CallBindingCoverage, CallBindingMapping};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, ResolvedValueIdentity, ResolvedValueIdentityKind,
    resolve_value_identity_with_source_outcome as resolve_value_identity_with_source,
};
use crate::query::{CallIdentity, ResolvedCallIdentityKind, ResolvedValueFilter};
use tree_sitter::Node;

enum FilterOutcome {
    Match,
    Different,
    Incomplete(Incompleteness, String),
}

pub(super) fn call_binding_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    value: &CallBindingValue,
    filter: &ResolvedValueFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let row = value.row();
    let outcome = if row.argument_id.is_none()
        || row.terminal
        || row.mapping != CallBindingMapping::Exact
        || value.site.report.coverage != CallBindingCoverage::Exhaustive
    {
        FilterOutcome::Incomplete(
            Incompleteness::Content,
            "call actual does not have an exact, exhaustive formal binding".to_owned(),
        )
    } else {
        match analyzer.get_source(&CodeUnit::file_scope(value.file().clone()), false) {
            Some(source) => expression_filter_outcome(
                analyzer,
                environment_cache,
                value.file(),
                &source,
                row.range.start_byte,
                row.range.end_byte,
                filter,
                cancellation,
                diagnostics,
            ),
            None => FilterOutcome::Incomplete(
                Incompleteness::Operational(DerivationExecutionCause::Provider),
                "source text is unavailable".to_owned(),
            ),
        }
    };
    match outcome {
        FilterOutcome::Match => vec![pipeline_expansion(PipelineValue::CallBinding(Box::new(
            value.clone(),
        )))],
        FilterOutcome::Different => Vec::new(),
        FilterOutcome::Incomplete(incompleteness, reason) => {
            record_incomplete(diagnostics, incompleteness, value.file(), reason);
            Vec::new()
        }
    }
}

pub(super) fn structural_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &Arc<SeedMatch>,
    filter: &ResolvedValueFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let fact = seed.facts.node(seed.fact_match.node);
    if fact.kind == crate::analyzer::structural::NormalizedKind::Decorator
        && matches!(
            seed.language,
            crate::analyzer::Language::Python | crate::analyzer::Language::CSharp
        )
    {
        return decorator_expansions(
            analyzer,
            environment_cache,
            seed,
            filter,
            cancellation,
            diagnostics,
        );
    }

    let source = seed.facts.source();
    if !matches!(
        seed.language,
        crate::analyzer::Language::Python | crate::analyzer::Language::CSharp
    ) {
        record_incomplete(
            diagnostics,
            Incompleteness::Content,
            &seed.file,
            "structural match is not a supported exact-value node".to_owned(),
        );
        return Vec::new();
    }

    let outcome = expression_filter_outcome(
        analyzer,
        environment_cache,
        &seed.file,
        source,
        fact.range.start_byte,
        fact.range.end_byte,
        filter,
        cancellation,
        diagnostics,
    );
    match outcome {
        FilterOutcome::Match => vec![pipeline_expansion(PipelineValue::StructuralMatch(
            Arc::clone(seed),
        ))],
        FilterOutcome::Different => Vec::new(),
        FilterOutcome::Incomplete(incompleteness, reason) => {
            record_incomplete(diagnostics, incompleteness, &seed.file, reason);
            Vec::new()
        }
    }
}

pub(super) fn decorator_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    seed: &Arc<SeedMatch>,
    filter: &ResolvedValueFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let fact = seed.facts.node(seed.fact_match.node);
    if fact.kind != crate::analyzer::structural::NormalizedKind::Decorator {
        record_incomplete(
            diagnostics,
            Incompleteness::Content,
            &seed.file,
            "structural match is not a decorator node".to_owned(),
        );
        return Vec::new();
    }
    let source = seed.facts.source();
    let Some(tree) = parse_tree_for_language(&seed.file, seed.language, source)
        .filter(|tree| !tree.root_node().has_error())
    else {
        record_incomplete(
            diagnostics,
            Incompleteness::Operational(DerivationExecutionCause::Provider),
            &seed.file,
            "decorator syntax is unavailable".to_owned(),
        );
        return Vec::new();
    };
    let Some(decorator) = exact_node(
        tree.root_node(),
        fact.range.start_byte,
        fact.range.end_byte,
        &["attribute", "decorator"],
    ) else {
        record_incomplete(
            diagnostics,
            Incompleteness::Content,
            &seed.file,
            "decorator node range is not unique in the syntax tree".to_owned(),
        );
        return Vec::new();
    };

    // C# attributes are declaration decorators, but their name is a type
    // reference rather than a Python-style value expression. Resolve the
    // complete attribute name through the C# resolver so aliases and the
    // `Attribute` suffix all share one declaration identity.
    if seed.language == crate::analyzer::Language::CSharp {
        let Some(name) = decorator.child_by_field_name("name") else {
            record_incomplete(
                diagnostics,
                Incompleteness::Content,
                &seed.file,
                "C# attribute has no structured name node".to_owned(),
            );
            return Vec::new();
        };
        let Some(terminal_name) = csharp_attribute_terminal_name_node(name) else {
            record_incomplete(
                diagnostics,
                Incompleteness::Content,
                &seed.file,
                "C# attribute name has no terminal type node".to_owned(),
            );
            return Vec::new();
        };
        let request = DefinitionLookupRequest {
            file: seed.file.clone(),
            line: None,
            column: None,
            start_byte: Some(terminal_name.start_byte()),
            end_byte: Some(terminal_name.end_byte()),
        };
        let identity = match resolve_value_identity_with_source(
            analyzer,
            request,
            seed.file.clone(),
            Arc::<str>::from(source),
            cancellation,
        ) {
            Ok(Some(identity)) => identity,
            result => {
                let incompleteness = match result {
                    Ok(None) => Incompleteness::Content,
                    Err(cause) => Incompleteness::Operational(cause),
                    Ok(Some(_)) => unreachable!("resolved identities returned above"),
                };
                record_incomplete(
                    diagnostics,
                    incompleteness,
                    &seed.file,
                    "C# attribute resolver could not prove one exact declaration identity"
                        .to_owned(),
                );
                return Vec::new();
            }
        };
        return match filter_matches(&identity, &filter.resolves_to) {
            true => vec![pipeline_expansion(PipelineValue::StructuralMatch(
                Arc::clone(seed),
            ))],
            false => Vec::new(),
        };
    }

    if seed.language != crate::analyzer::Language::Python {
        record_incomplete(
            diagnostics,
            Incompleteness::Content,
            &seed.file,
            "resolved decorator identity is unsupported for this language".to_owned(),
        );
        return Vec::new();
    }

    let Some(expression) = decorator.named_child(0) else {
        record_incomplete(
            diagnostics,
            Incompleteness::Content,
            &seed.file,
            "decorator has no expression".to_owned(),
        );
        return Vec::new();
    };
    let outcome = expression_filter_outcome(
        analyzer,
        environment_cache,
        &seed.file,
        source,
        expression.start_byte(),
        expression.end_byte(),
        filter,
        cancellation,
        diagnostics,
    );
    match outcome {
        FilterOutcome::Match => vec![pipeline_expansion(PipelineValue::StructuralMatch(
            Arc::clone(seed),
        ))],
        FilterOutcome::Different => Vec::new(),
        FilterOutcome::Incomplete(incompleteness, reason) => {
            record_incomplete(diagnostics, incompleteness, &seed.file, reason);
            Vec::new()
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn expression_filter_outcome(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    file: &ProjectFile,
    source: &str,
    start_byte: usize,
    end_byte: usize,
    filter: &ResolvedValueFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> FilterOutcome {
    let Some(tree) = parse_tree_for_language(
        file,
        crate::analyzer::common::language_for_file(file),
        source,
    )
    .filter(|tree| !tree.root_node().has_error()) else {
        return FilterOutcome::Incomplete(
            Incompleteness::Operational(DerivationExecutionCause::Provider),
            "expression syntax is unavailable".to_owned(),
        );
    };
    let accepted_kinds = match crate::analyzer::common::language_for_file(file) {
        crate::analyzer::Language::Python => &[
            "call",
            "attribute",
            "identifier",
            "string",
            "integer",
            "float",
            "true",
            "false",
            "none",
            "list",
            "tuple",
            "dictionary",
            "set",
            "keyword_argument",
            "parenthesized_expression",
        ][..],
        crate::analyzer::Language::CSharp => &[
            "member_access_expression",
            "conditional_access_expression",
            "element_access_expression",
            "identifier",
            "string_literal",
            "character_literal",
        ][..],
        _ => &[][..],
    };
    let Some(mut expression) = exact_node(tree.root_node(), start_byte, end_byte, accepted_kinds)
    else {
        return FilterOutcome::Incomplete(
            Incompleteness::Content,
            "selected expression range has no unique structured value node".to_owned(),
        );
    };
    while matches!(
        expression.kind(),
        "keyword_argument" | "parenthesized_expression"
    ) {
        let child = if expression.kind() == "keyword_argument" {
            expression.child_by_field_name("value")
        } else {
            expression.named_child(0)
        };
        let Some(child) = child else {
            return FilterOutcome::Incomplete(
                Incompleteness::Content,
                "value wrapper has no expression child".to_owned(),
            );
        };
        expression = child;
    }
    if matches!(
        expression.kind(),
        "string"
            | "integer"
            | "float"
            | "true"
            | "false"
            | "none"
            | "list"
            | "tuple"
            | "dictionary"
            | "set"
    ) {
        return FilterOutcome::Different;
    }
    if !matches!(
        expression.kind(),
        "call"
            | "attribute"
            | "identifier"
            | "member_access_expression"
            | "conditional_access_expression"
            | "element_access_expression"
    ) {
        return FilterOutcome::Incomplete(
            Incompleteness::Content,
            format!(
                "{} expressions do not have a direct declaration identity",
                expression.kind()
            ),
        );
    }

    if crate::analyzer::common::language_for_file(file) == crate::analyzer::Language::CSharp
        && let Some(expected_member) = expected_member_name(&filter.resolves_to)
        && let Some(actual_member) = csharp_member_access_name(expression, source)
        && actual_member != expected_member
    {
        return FilterOutcome::Different;
    }

    let reference_expression = if expression.kind() == "call" {
        let Some(function) = expression.child_by_field_name("function") else {
            return FilterOutcome::Incomplete(
                Incompleteness::Content,
                "constructor call has no function expression".to_owned(),
            );
        };
        function
    } else {
        expression
    };
    if reference_expression.kind() == "identifier" {
        let identifier = reference_expression;
        match python_rule_facts::builtin_value_identity_at_range(
            analyzer,
            environment_cache,
            file,
            source,
            identifier.start_byte(),
            identifier.end_byte(),
            cancellation,
            diagnostics,
        ) {
            Ok(Some(identity)) => {
                return if filter_matches(
                    &ResolvedValueIdentity {
                        kind: ResolvedValueIdentityKind::ActiveSemanticModel,
                        identity,
                        aliases: Vec::new(),
                    },
                    &filter.resolves_to,
                ) {
                    FilterOutcome::Match
                } else {
                    FilterOutcome::Different
                };
            }
            Err(reason) => {
                return FilterOutcome::Incomplete(
                    Incompleteness::Operational(DerivationExecutionCause::Provider),
                    reason,
                );
            }
            Ok(None) => {}
        }
    }

    let (focus_start_byte, focus_end_byte) = if crate::analyzer::common::language_for_file(file)
        == crate::analyzer::Language::Python
        && reference_expression.kind() == "attribute"
    {
        // Python's external import binder resolves a module-qualified member
        // from the complete attribute path (ssl.PROTOCOL_TLSv1). Focusing
        // only its terminal identifier loses the imported module identity.
        (
            reference_expression.start_byte(),
            reference_expression.end_byte(),
        )
    } else {
        definition_focus_range(reference_expression).unwrap_or((
            reference_expression.start_byte(),
            reference_expression.end_byte(),
        ))
    };
    let request = DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(focus_start_byte),
        end_byte: Some(focus_end_byte),
    };
    let identity = match resolve_value_identity_with_source(
        analyzer,
        request,
        file.clone(),
        Arc::<str>::from(source),
        cancellation,
    ) {
        Ok(Some(identity)) => identity,
        result => {
            let incompleteness = match result {
                Ok(None) => Incompleteness::Content,
                Err(cause) => Incompleteness::Operational(cause),
                Ok(Some(_)) => unreachable!("resolved identities returned above"),
            };
            return FilterOutcome::Incomplete(
                incompleteness,
                "resolver could not prove one unshadowed exact declaration identity".to_owned(),
            );
        }
    };
    if filter_matches(&identity, &filter.resolves_to) {
        FilterOutcome::Match
    } else {
        FilterOutcome::Different
    }
}

fn filter_matches(identity: &ResolvedValueIdentity, expected: &CallIdentity) -> bool {
    match expected {
        CallIdentity::Stable(expected) => {
            identity.identity == *expected || identity.aliases.iter().any(|alias| alias == expected)
        }
        CallIdentity::Qualified {
            resolved: Some(resolved),
            ..
        } => {
            let kind = match identity.kind {
                ResolvedValueIdentityKind::WorkspaceDeclaration => {
                    ResolvedCallIdentityKind::WorkspaceDeclaration
                }
                ResolvedValueIdentityKind::ActiveSemanticModel => {
                    ResolvedCallIdentityKind::ActiveSemanticModel
                }
            };
            resolved.kind == kind && identity.identity == resolved.identity
        }
        CallIdentity::Qualified { resolved: None, .. } => false,
    }
}

fn expected_member_name(identity: &CallIdentity) -> Option<&str> {
    let CallIdentity::Qualified { value, .. } = identity else {
        return None;
    };
    value.rsplit_once('.').map(|(_, member)| member)
}

fn csharp_member_access_name<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let member = match node.kind() {
        "member_access_expression" => node.child_by_field_name("name")?,
        "conditional_access_expression" => node
            .named_children(&mut node.walk())
            .find_map(|child| child.child_by_field_name("name"))?,
        _ => return None,
    };
    member.utf8_text(source.as_bytes()).ok()
}

fn exact_node<'tree>(
    root: Node<'tree>,
    start_byte: usize,
    end_byte: usize,
    accepted_kinds: &[&str],
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    let mut selected = None;
    while let Some(node) = stack.pop() {
        if node.start_byte() == start_byte
            && node.end_byte() == end_byte
            && accepted_kinds.contains(&node.kind())
        {
            if selected.is_some() {
                return None;
            }
            selected = Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    selected
}

fn definition_focus_range(node: Node<'_>) -> Option<(usize, usize)> {
    let mut focus = match node.kind() {
        "member_access_expression" => node.child_by_field_name("name")?,
        "conditional_access_expression" => node
            .named_children(&mut node.walk())
            .find_map(|child| child.child_by_field_name("name"))?,
        "element_access_expression" => node.child_by_field_name("subscript")?,
        _ => node,
    };
    while let Some(child) = focus.named_child(0) {
        focus = child;
    }
    (focus.start_byte() < focus.end_byte()).then_some((focus.start_byte(), focus.end_byte()))
}

fn csharp_attribute_terminal_name_node(mut name: Node<'_>) -> Option<Node<'_>> {
    loop {
        let next = match name.kind() {
            "qualified_name" | "alias_qualified_name" => name
                .child_by_field_name("name")
                .or_else(|| name.named_child(name.named_child_count().saturating_sub(1))),
            "generic_name" => name
                .child_by_field_name("name")
                .or_else(|| name.named_child(0)),
            _ => return Some(name),
        }?;
        name = next;
    }
}

fn record_incomplete(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    incompleteness: Incompleteness,
    file: &ProjectFile,
    reason: String,
) {
    let language = crate::analyzer::common::language_for_file(file).config_label();
    let message = format!("resolved_value: {reason}");
    if let Some(diagnostic) = diagnostics.iter_mut().find(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && diagnostic.language == language
            && diagnostic.message == message
    }) {
        diagnostic.incompleteness = diagnostic.incompleteness.combine(incompleteness);
        return;
    }
    diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
        incompleteness,
        related: Vec::new(),
        source: None,
        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language,
        message,
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    }));
}
