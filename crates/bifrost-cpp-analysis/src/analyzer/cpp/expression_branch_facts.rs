//! Bounded C and C++ syntax qualification for expression and branch policy facts.
//!
//! This module deliberately does not parse source text. It joins the C/C++
//! lowerer's exact semantic source mappings back to the analyzer-generation
//! prepared tree, then publishes only the syntax/storage classification that
//! language-neutral flow analysis cannot recover from the IR.

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::assignment_facts::OverwrittenLocalCandidate;

use brokk_bifrost_analysis::analyzer::assignment_facts::OverwrittenLocalCandidates;

use brokk_bifrost_analysis::analyzer::assignment_facts::OverwrittenLocalSourceKind;

use brokk_bifrost_analysis::analyzer::assignment_facts::PlainAssignmentVerdict;

use brokk_bifrost_analysis::analyzer::assignment_facts::join_binding_write;

use brokk_bifrost_analysis::analyzer::common::CandidateState;

use brokk_bifrost_analysis::analyzer::common::exact_span;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;

use brokk_bifrost_analysis::analyzer::semantic::CallableTargetResolution;

use brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle;

use brokk_bifrost_analysis::analyzer::semantic::ProgramPointId;

use brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact;

use brokk_bifrost_analysis::analyzer::semantic::SemanticEffect;

use brokk_bifrost_analysis::analyzer::semantic::SemanticValueKind;

use brokk_bifrost_analysis::analyzer::semantic::SourceMappingKind;

use brokk_bifrost_analysis::analyzer::semantic::ValueId;

use brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;

use crate::analyzer::CppAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::LanguageDialect;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use brokk_bifrost_cpp::structural::declarator_name_node;
use std::collections::HashMap;
use tree_sitter::Node;

use brokk_bifrost_cpp::declarations::node_text;

use crate::analyzer::cpp::semantic::cpp_binding_declaration;

use crate::analyzer::cpp::semantic::cpp_declarator_contains_kind;

use crate::analyzer::cpp::semantic::cpp_declarator_initializer;

use crate::analyzer::cpp::semantic::cpp_local_declarators;

use crate::analyzer::cpp::semantic::cpp_type_is_fundamental;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CAssignmentSyntaxVerdict {
    Supported,
    Excluded,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CAssignmentCandidate {
    pub point: Option<ProgramPointId>,
    pub target: Option<ValueId>,
    pub rhs_value: Option<ValueId>,
    pub range: Range,
    pub rhs_range: Option<Range>,
    pub next_assignment_start: Option<usize>,
    pub verdict: CAssignmentSyntaxVerdict,
    pub storage_kind: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct CAssignmentCandidates {
    pub rows: Vec<CAssignmentCandidate>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

const DEFAULT_MAX_SOURCE_BYTES: usize = 1_048_576;

pub fn c_assignment_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> CAssignmentCandidates {
    if !matches!(
        procedure.artifact().key().language(),
        LanguageDialect::CppC | LanguageDialect::Standard(Language::Cpp)
    ) || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return build_c_assignment_candidates(workspace, procedure, cancellation);
    }
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()) else {
        return build_c_assignment_candidates(workspace, procedure, cancellation);
    };
    (*cpp.c_assignment_candidates_for(workspace, procedure, cancellation)).clone()
}

pub(crate) fn build_c_assignment_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> CAssignmentCandidates {
    if !matches!(
        procedure.artifact().key().language(),
        LanguageDialect::CppC | LanguageDialect::Standard(Language::Cpp)
    ) {
        return CAssignmentCandidates {
            rows: Vec::new(),
            complete: true,
            reason: None,
        };
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable("cancelled");
    }

    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        procedure.artifact().key().path().as_path(),
    );
    let syntax = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Cpp)
        .map(|provider| {
            provider.structural_syntax_limited(&file, DEFAULT_MAX_SOURCE_BYTES, cancellation)
        });
    let syntax = match syntax {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
        Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
            return unavailable("source_budget_exhausted");
        }
        Some(StructuralSyntaxLimitedOutcome::Cancelled) => return unavailable("cancelled"),
        Some(StructuralSyntaxLimitedOutcome::Unavailable) | None => {
            return unavailable("prepared_syntax_unavailable");
        }
    };
    let Ok(syntax) = validate_prepared_syntax_source_for_procedure(
        workspace,
        procedure,
        &file,
        syntax.into_inner(),
    ) else {
        return unavailable("source_identity_mismatch");
    };
    let semantics = procedure.semantics();
    let Some(procedure_mapping) = semantics.source_mapping(semantics.source()) else {
        return unavailable("procedure_mapping_missing");
    };
    let procedure_span = procedure_mapping.locator.anchor().span();
    let Some(procedure_node) = syntax.tree().root_node().named_descendant_for_byte_range(
        procedure_span.start_byte() as usize,
        procedure_span.end_byte() as usize,
    ) else {
        return unavailable("procedure_syntax_missing");
    };
    if procedure_node.start_byte() != procedure_span.start_byte() as usize
        || procedure_node.end_byte() != procedure_span.end_byte() as usize
        || procedure_node.has_error()
    {
        return unavailable("procedure_syntax_inexact");
    }

    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()) else {
        return unavailable("cpp_analyzer_unavailable");
    };
    let is_c_source = file
        .rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("c");
    let file_facts = cpp.file_facts_for(
        &file,
        syntax.source(),
        syntax.tree().root_node(),
        is_c_source,
    );
    let local_parameter_names = local_parameter_names(semantics, syntax.source());
    let call_sites = call_sites_by_span(semantics);
    let mut assignments = Vec::new();
    let mut calls = Vec::new();
    let mut has_preprocessing = false;
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id()
            && matches!(node.kind(), "function_definition" | "lambda_expression")
        {
            continue;
        }
        if node.kind() == "assignment_expression" {
            assignments.push(node);
        }
        if node.kind() == "call_expression"
            && call_has_local_parameter_argument(
                semantics,
                syntax.source(),
                node,
                &local_parameter_names,
                &call_sites,
            )
        {
            calls.push(node);
        }
        has_preprocessing |= node.kind().starts_with("preproc_");
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    assignments.sort_unstable_by_key(Node::start_byte);
    let call_macro_hazards = cpp.call_macro_hazards_for(
        &file,
        syntax.source(),
        syntax.tree().root_node(),
        is_c_source,
        &file_facts.function_like_macros,
        procedure.artifact(),
        cancellation,
    );
    let mut has_macro_hazard = calls_have_macro_hazard(
        &calls,
        syntax.source(),
        is_c_source,
        &file_facts.function_like_macros,
        &call_macro_hazards,
    );

    let mut rows = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        let row = classify_assignment(
            semantics,
            syntax.source(),
            syntax.tree().root_node(),
            assignment,
            &file_facts.trivial_types,
            &file_facts.object_like_macros,
        );
        has_macro_hazard |= row.reason == "object_like_macro";
        rows.push(row);
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
    }
    CAssignmentCandidates {
        rows,
        complete: !(has_preprocessing || has_macro_hazard),
        reason: if has_preprocessing {
            Some("preprocessing_present")
        } else {
            has_macro_hazard.then_some("macro_possible")
        },
    }
}

/// C and C++ local establishments for the overwritten-unread relation.
///
/// The syntax producer deliberately accepts any RHS expression: the value is
/// the relation subject, while calls and other RHS effects remain in the
/// semantic model. Compound assignments and updates are reads of their
/// target, so they are left to the flow derivation rather than proposed as a
/// new establishment here.
pub fn cpp_overwritten_local_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> OverwrittenLocalCandidates {
    if !matches!(
        procedure.artifact().key().language(),
        LanguageDialect::CppC | LanguageDialect::Standard(Language::Cpp)
    ) || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return build_cpp_overwritten_local_candidates(workspace, procedure, cancellation);
    }
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()) else {
        return build_cpp_overwritten_local_candidates(workspace, procedure, cancellation);
    };
    (*cpp.cpp_overwritten_candidates_for(workspace, procedure, cancellation)).clone()
}

pub(crate) fn build_cpp_overwritten_local_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> OverwrittenLocalCandidates {
    if !matches!(
        procedure.artifact().key().language(),
        LanguageDialect::CppC | LanguageDialect::Standard(Language::Cpp)
    ) {
        return overwritten_unavailable("unsupported_language");
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return overwritten_unavailable("cancelled");
    }

    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        procedure.artifact().key().path().as_path(),
    );
    let syntax = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Cpp)
        .map(|provider| {
            provider.structural_syntax_limited(&file, DEFAULT_MAX_SOURCE_BYTES, cancellation)
        });
    let syntax = match syntax {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
        Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
            return overwritten_unavailable("source_budget_exhausted");
        }
        Some(StructuralSyntaxLimitedOutcome::Cancelled) => {
            return overwritten_unavailable("cancelled");
        }
        Some(StructuralSyntaxLimitedOutcome::Unavailable) | None => {
            return overwritten_unavailable("prepared_syntax_unavailable");
        }
    };
    let Ok(syntax) = validate_prepared_syntax_source_for_procedure(
        workspace,
        procedure,
        &file,
        syntax.into_inner(),
    ) else {
        return overwritten_unavailable("source_identity_mismatch");
    };
    let semantics = procedure.semantics();
    let Some(procedure_mapping) = semantics.source_mapping(semantics.source()) else {
        return overwritten_unavailable("procedure_mapping_missing");
    };
    let procedure_span = procedure_mapping.locator.anchor().span();
    let Some(procedure_node) = syntax.tree().root_node().named_descendant_for_byte_range(
        procedure_span.start_byte() as usize,
        procedure_span.end_byte() as usize,
    ) else {
        return overwritten_unavailable("procedure_syntax_missing");
    };
    if procedure_node.start_byte() != procedure_span.start_byte() as usize
        || procedure_node.end_byte() != procedure_span.end_byte() as usize
        || procedure_node.has_error()
    {
        return overwritten_unavailable("procedure_syntax_inexact");
    }

    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()) else {
        return overwritten_unavailable("cpp_analyzer_unavailable");
    };
    let is_c_source = file
        .rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("c");
    let file_facts = cpp.file_facts_for(
        &file,
        syntax.source(),
        syntax.tree().root_node(),
        is_c_source,
    );
    let unstable_bindings = crate::analyzer::cpp::semantic::cpp_unstable_scalar_bindings(
        procedure,
        &syntax,
        &file_facts.scalar_types,
    );
    let local_parameter_names = local_parameter_names(semantics, syntax.source());
    let call_sites = call_sites_by_span(semantics);
    let mut writes = Vec::new();
    let mut calls = Vec::new();
    let mut has_preprocessing = false;
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return overwritten_unavailable("cancelled");
        }
        if node.id() != procedure_node.id()
            && matches!(node.kind(), "function_definition" | "lambda_expression")
        {
            continue;
        }
        if node.kind().starts_with("preproc_") {
            has_preprocessing = true;
        }
        if node.kind() == "call_expression"
            && call_has_local_parameter_argument(
                semantics,
                syntax.source(),
                node,
                &local_parameter_names,
                &call_sites,
            )
        {
            calls.push(node);
        }
        if node.kind() == "declaration" {
            for declarator in cpp_local_declarators(node) {
                if cpp_declarator_initializer(node, declarator).is_some()
                    && let Some(target) = declarator_name_node(declarator)
                {
                    writes.push(CppOverwrittenWrite::Candidate {
                        point_node: node,
                        target,
                        source_kind: OverwrittenLocalSourceKind::DeclarationInitializer,
                    });
                }
            }
        }
        if node.kind() == "assignment_expression" {
            let Some(operator) = node.child_by_field_name("operator") else {
                writes.push(CppOverwrittenWrite::Open(node, "operator_missing"));
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                stack.extend(children.into_iter().rev());
                continue;
            };
            if node_text(operator, syntax.source()) == "=" {
                let Some(left) = node.child_by_field_name("left") else {
                    writes.push(CppOverwrittenWrite::Open(node, "left_operand_missing"));
                    let mut cursor = node.walk();
                    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                    stack.extend(children.into_iter().rev());
                    continue;
                };
                if left.kind() == "identifier" {
                    writes.push(CppOverwrittenWrite::Candidate {
                        point_node: node,
                        target: left,
                        source_kind: OverwrittenLocalSourceKind::PlainAssignment,
                    });
                } else {
                    writes.push(CppOverwrittenWrite::Excluded(left, "nonlocal_target"));
                }
            }
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }

    let call_macro_hazards = cpp.call_macro_hazards_for(
        &file,
        syntax.source(),
        syntax.tree().root_node(),
        is_c_source,
        &file_facts.function_like_macros,
        procedure.artifact(),
        cancellation,
    );
    let mut has_macro_hazard = calls_have_macro_hazard(
        &calls,
        syntax.source(),
        is_c_source,
        &file_facts.function_like_macros,
        &call_macro_hazards,
    );

    writes.sort_unstable_by_key(|write| write.start_byte());
    let write_spans = writes
        .iter()
        .map(CppOverwrittenWrite::span)
        .collect::<brokk_bifrost_core::hash::HashSet<_>>();
    let mut points_by_span: HashMap<
        (usize, usize),
        Vec<&brokk_bifrost_analysis::analyzer::semantic::ProgramPoint>,
    > = HashMap::default();
    for point in semantics.points() {
        if let Some(mapping) = semantics
            .source_mapping(point.source)
            .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
        {
            let span = mapping.locator.anchor().span();
            let span = (span.start_byte() as usize, span.end_byte() as usize);
            if !write_spans.contains(&span) {
                continue;
            }
            points_by_span.entry(span).or_default().push(point);
        }
    }

    let mut rows = Vec::with_capacity(writes.len());
    for write in writes {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return overwritten_unavailable("cancelled");
        }
        let row = |node: Node<'_>, source_kind, verdict, reason| OverwrittenLocalCandidate {
            points: Vec::new(),
            target: None,
            rhs_value: None,
            range: node_range(node),
            source_kind,
            verdict,
            reason,
        };
        let (point_node, target, source_kind) = match write {
            CppOverwrittenWrite::Candidate {
                point_node,
                target,
                source_kind,
            } => (point_node, target, source_kind),
            CppOverwrittenWrite::Excluded(node, reason) => {
                rows.push(row(
                    node,
                    OverwrittenLocalSourceKind::PlainAssignment,
                    PlainAssignmentVerdict::Excluded,
                    reason,
                ));
                continue;
            }
            CppOverwrittenWrite::Open(node, reason) => {
                rows.push(row(
                    node,
                    OverwrittenLocalSourceKind::PlainAssignment,
                    PlainAssignmentVerdict::Unknown,
                    reason,
                ));
                continue;
            }
        };
        if point_node.has_error() || target.has_error() {
            rows.push(row(
                target,
                source_kind,
                PlainAssignmentVerdict::Unknown,
                "syntax_unresolved",
            ));
            continue;
        }
        let mut macro_hazard = node_contains_object_like_macro(
            syntax.source(),
            point_node,
            &file_facts.object_like_macros,
        );
        let joined = match join_binding_write(
            semantics,
            &points_by_span,
            syntax.source(),
            procedure_node,
            point_node,
            target,
        ) {
            Ok(joined) => joined,
            Err((verdict, reason)) => {
                rows.push(row(target, source_kind, verdict, reason));
                continue;
            }
        };
        let Some((declaration, declarator)) =
            cpp_binding_declaration(joined.parameter, joined.declaration)
        else {
            rows.push(row(
                target,
                source_kind,
                PlainAssignmentVerdict::Unknown,
                "declarator_identity_unproved",
            ));
            continue;
        };
        let (verdict, reason) = cpp_overwritten_storage_verdict(
            syntax.source(),
            declaration,
            declarator,
            &file_facts.trivial_types,
        );
        let (verdict, reason) = if unstable_bindings.contains(&joined.binding) {
            (
                PlainAssignmentVerdict::Unknown,
                "address_or_reference_escape",
            )
        } else {
            (verdict, reason)
        };
        macro_hazard |= node_contains_object_like_macro(
            syntax.source(),
            joined.declaration,
            &file_facts.object_like_macros,
        );
        has_macro_hazard |= macro_hazard;
        rows.push(OverwrittenLocalCandidate {
            points: vec![joined.point],
            target: Some(joined.binding),
            rhs_value: Some(joined.value),
            range: node_range(target),
            source_kind,
            verdict,
            reason,
        });
    }

    OverwrittenLocalCandidates {
        rows,
        complete: !(has_preprocessing || has_macro_hazard),
        reason: if has_preprocessing {
            Some("preprocessing_present")
        } else {
            has_macro_hazard.then_some("macro_possible")
        },
    }
}

enum CppOverwrittenWrite<'tree> {
    Candidate {
        point_node: Node<'tree>,
        target: Node<'tree>,
        source_kind: OverwrittenLocalSourceKind,
    },
    Excluded(Node<'tree>, &'static str),
    Open(Node<'tree>, &'static str),
}

impl CppOverwrittenWrite<'_> {
    fn start_byte(&self) -> usize {
        match self {
            Self::Candidate { point_node, .. } => point_node.start_byte(),
            Self::Excluded(node, _) | Self::Open(node, _) => node.start_byte(),
        }
    }

    fn span(&self) -> (usize, usize) {
        match self {
            Self::Candidate { point_node, .. } => (point_node.start_byte(), point_node.end_byte()),
            Self::Excluded(node, _) | Self::Open(node, _) => (node.start_byte(), node.end_byte()),
        }
    }
}

fn overwritten_unavailable(reason: &'static str) -> OverwrittenLocalCandidates {
    OverwrittenLocalCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    }
}

fn cpp_overwritten_storage_verdict(
    source: &str,
    declaration: Node<'_>,
    declarator: Node<'_>,
    trivial_types: &crate::analyzer::cpp::semantic::TrivialTypeIndex,
) -> (PlainAssignmentVerdict, &'static str) {
    if declaration.has_error() || declarator.has_error() {
        return (
            PlainAssignmentVerdict::Unknown,
            "declaration_syntax_unresolved",
        );
    }
    if has_object_qualifier(source, declaration, declarator, "volatile") {
        return (PlainAssignmentVerdict::Unknown, "volatile_object");
    }
    if has_atomic_qualifier(source, declaration, declarator) {
        return (PlainAssignmentVerdict::Unknown, "atomic_object");
    }
    if has_object_qualifier(source, declaration, declarator, "const") {
        return (PlainAssignmentVerdict::Unknown, "const_object");
    }
    if has_unsupported_storage_class(source, declaration) {
        return (PlainAssignmentVerdict::Unknown, "unsupported_storage_class");
    }
    if ["array_declarator", "reference_declarator"]
        .into_iter()
        .any(|kind| cpp_declarator_contains_kind(declarator, kind))
    {
        return (PlainAssignmentVerdict::Unknown, "unsupported_declarator");
    }
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return (PlainAssignmentVerdict::Unknown, "declared_type_missing");
    };
    let pointer_type = cpp_declarator_contains_kind(declarator, "pointer_declarator");
    if !pointer_type
        && !cpp_type_is_fundamental(type_node)
        && !trivial_types.named_enum_use_is_unambiguous(source, type_node)
    {
        return (PlainAssignmentVerdict::Unknown, "unsupported_declared_type");
    }
    (PlainAssignmentVerdict::Supported, "qualified")
}

fn node_contains_object_like_macro(
    source: &str,
    root: Node<'_>,
    object_like_macros: &brokk_bifrost_core::hash::HashSet<Box<str>>,
) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" && object_like_macros.contains(node_text(node, source)) {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn unavailable(reason: &'static str) -> CAssignmentCandidates {
    let CandidateState {
        rows,
        complete,
        reason,
    } = CandidateState::unavailable(reason);
    CAssignmentCandidates {
        rows,
        complete,
        reason,
    }
}

fn call_sites_by_span(
    semantics: &brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics,
) -> HashMap<(usize, usize), &brokk_bifrost_analysis::analyzer::semantic::SemanticCallSite> {
    semantics
        .call_sites()
        .iter()
        .filter_map(|site| {
            let mapping = semantics.source_mapping(site.source)?;
            (mapping.kind == SourceMappingKind::Exact).then_some((
                (
                    mapping.locator.anchor().span().start_byte() as usize,
                    mapping.locator.anchor().span().end_byte() as usize,
                ),
                site,
            ))
        })
        .collect()
}

fn call_has_local_parameter_argument(
    semantics: &brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics,
    source: &str,
    call: Node<'_>,
    local_parameter_names: &brokk_bifrost_core::hash::HashSet<Box<str>>,
    call_sites: &HashMap<
        (usize, usize),
        &brokk_bifrost_analysis::analyzer::semantic::SemanticCallSite,
    >,
) -> bool {
    if let Some(site) = call_sites.get(&(call.start_byte(), call.end_byte()))
        && site.arguments.iter().any(|argument| {
            semantics.value(argument.value).is_some_and(|value| {
                matches!(
                    &value.kind,
                    SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
                )
            })
        })
    {
        return true;
    }

    // C/C++ expression values are deliberately published as temporaries at a
    // call boundary, so the call row does not preserve whether an identifier
    // argument came from a local or parameter. Recover that fact from the
    // procedure's declaration mappings and the argument's structured AST.
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut stack = vec![arguments];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" && local_parameter_names.contains(node_text(node, source)) {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn local_parameter_names(
    semantics: &brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics,
    source: &str,
) -> brokk_bifrost_core::hash::HashSet<Box<str>> {
    semantics
        .values()
        .iter()
        .filter_map(|value| {
            if !matches!(
                value.kind,
                SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
            ) {
                return None;
            }
            let mapping = semantics.source_mapping(value.source)?;
            let span = mapping.locator.anchor().span();
            source
                .get(span.start_byte() as usize..span.end_byte() as usize)
                .filter(|name| !name.is_empty())
                .map(Box::<str>::from)
        })
        .collect()
}

pub(crate) fn build_file_call_macro_hazards(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    source: &str,
    root: Node<'_>,
    is_c_source: bool,
    function_like_macros: &brokk_bifrost_core::hash::HashSet<Box<str>>,
    artifact: &SemanticArtifact,
    cancellation: Option<&CancellationToken>,
) -> brokk_bifrost_core::hash::HashMap<(usize, usize), bool> {
    let mut hazards = brokk_bifrost_core::hash::HashMap::default();
    let unique_c_function_names = if is_c_source {
        unique_c_function_definition_names(root, source)
    } else {
        brokk_bifrost_core::hash::HashSet::default()
    };
    let ArtifactCallSpans {
        relevant: relevant_call_spans,
        known: known_call_spans,
        resolved: resolved_call_spans,
        procedure_spans,
    } = relevant_call_spans_for_artifact(
        analyzer,
        artifact,
        source,
        root,
        &unique_c_function_names,
        cancellation,
    );
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            analyzer.record_query_incomplete(
                brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::Cancelled,
            );
            return brokk_bifrost_core::hash::HashMap::default();
        }
        if node.kind() == "call_expression"
            && (relevant_call_spans.contains(&(node.start_byte(), node.end_byte()))
                || (!known_call_spans.contains(&(node.start_byte(), node.end_byte()))
                    && procedure_spans.iter().any(|(start, end)| {
                        *start <= node.start_byte() && node.end_byte() <= *end
                    })))
        {
            let Some(callee) = node.child_by_field_name("function") else {
                hazards.insert((node.start_byte(), node.end_byte()), true);
                continue;
            };
            if callee.kind() == "identifier"
                && function_like_macros.contains(node_text(callee, source))
            {
                hazards.insert((callee.start_byte(), callee.end_byte()), true);
            } else if !is_c_source && is_std_swap(callee, source) {
                hazards.insert((callee.start_byte(), callee.end_byte()), false);
            } else {
                hazards.insert(
                    (callee.start_byte(), callee.end_byte()),
                    !resolved_call_spans.contains(&(node.start_byte(), node.end_byte())),
                );
            }
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    hazards
}

/// Byte spans of an artifact's calls, grouped by what the macro-hazard scan
/// needs to know about them, and the spans of its procedures.
struct ArtifactCallSpans {
    relevant: brokk_bifrost_core::hash::HashSet<(usize, usize)>,
    known: brokk_bifrost_core::hash::HashSet<(usize, usize)>,
    resolved: brokk_bifrost_core::hash::HashSet<(usize, usize)>,
    procedure_spans: Vec<(usize, usize)>,
}

fn relevant_call_spans_for_artifact(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    artifact: &SemanticArtifact,
    source: &str,
    root: Node<'_>,
    unique_c_function_names: &brokk_bifrost_core::hash::HashSet<Box<str>>,
    cancellation: Option<&CancellationToken>,
) -> ArtifactCallSpans {
    let mut relevant = brokk_bifrost_core::hash::HashSet::default();
    let mut known = brokk_bifrost_core::hash::HashSet::default();
    let mut resolved = brokk_bifrost_core::hash::HashSet::default();
    let mut procedure_spans = Vec::new();
    for semantics in artifact.procedures() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            analyzer.record_query_incomplete(
                brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::Cancelled,
            );
            return ArtifactCallSpans {
                relevant,
                known,
                resolved,
                procedure_spans,
            };
        }
        let Some(mapping) = semantics.source_mapping(semantics.source()) else {
            continue;
        };
        if mapping.kind != SourceMappingKind::Exact {
            continue;
        }
        let span = mapping.locator.anchor().span();
        procedure_spans.push((span.start_byte() as usize, span.end_byte() as usize));
        let Some(procedure_node) = root
            .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
        else {
            continue;
        };
        if procedure_node.start_byte() != span.start_byte() as usize
            || procedure_node.end_byte() != span.end_byte() as usize
            || procedure_node.has_error()
        {
            continue;
        }
        let local_parameter_names = local_parameter_names(semantics, source);
        let call_sites = call_sites_by_span(semantics);
        for site in semantics.call_sites() {
            let Some(mapping) = semantics
                .source_mapping(site.source)
                .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
            else {
                continue;
            };
            let call_span = mapping.locator.anchor().span();
            let call_span = (
                call_span.start_byte() as usize,
                call_span.end_byte() as usize,
            );
            let Some(call_node) = root.named_descendant_for_byte_range(call_span.0, call_span.1)
            else {
                continue;
            };
            if call_node.start_byte() != call_span.0
                || call_node.end_byte() != call_span.1
                || call_node.kind() != "call_expression"
            {
                continue;
            }
            known.insert(call_span);
            let direct_c_function_definition = call_node
                .child_by_field_name("function")
                .is_some_and(|callee| {
                    callee.kind() == "identifier"
                        && unique_c_function_names.contains(node_text(callee, source))
                });
            if direct_c_function_definition
                || matches!(&site.declared_targets, CallableTargetResolution::Proven(_))
            {
                resolved.insert(call_span);
            }
            if call_has_local_parameter_argument(
                semantics,
                source,
                call_node,
                &local_parameter_names,
                &call_sites,
            ) {
                relevant.insert(call_span);
            }
        }
    }
    ArtifactCallSpans {
        relevant,
        known,
        resolved,
        procedure_spans,
    }
}

fn unique_c_function_definition_names(
    root: Node<'_>,
    source: &str,
) -> brokk_bifrost_core::hash::HashSet<Box<str>> {
    let mut counts = HashMap::<Box<str>, usize>::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition"
            && let Some(name) = node
                .child_by_field_name("declarator")
                .and_then(declarator_name_node)
                .filter(|name| name.kind() == "identifier")
        {
            *counts
                .entry(Box::<str>::from(node_text(name, source)))
                .or_default() += 1;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    counts
        .into_iter()
        .filter_map(|(name, count)| (count == 1).then_some(name))
        .collect()
}

fn calls_have_macro_hazard(
    calls: &[Node<'_>],
    source: &str,
    is_c_source: bool,
    function_like_macros: &brokk_bifrost_core::hash::HashSet<Box<str>>,
    hazards: &brokk_bifrost_core::hash::HashMap<(usize, usize), bool>,
) -> bool {
    calls.iter().any(|call| {
        let Some(callee) = call.child_by_field_name("function") else {
            return true;
        };
        if callee.kind() == "identifier" && function_like_macros.contains(node_text(callee, source))
        {
            return true;
        }
        if !is_c_source && is_std_swap(callee, source) {
            return false;
        }
        hazards
            .get(&(callee.start_byte(), callee.end_byte()))
            .copied()
            .unwrap_or(true)
    })
}

fn is_std_swap(callee: Node<'_>, source: &str) -> bool {
    callee.kind() == "qualified_identifier"
        && callee
            .child_by_field_name("scope")
            .is_some_and(|scope| node_text(scope, source) == "std")
        && callee
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source) == "swap")
}

fn classify_assignment(
    semantics: &brokk_bifrost_analysis::analyzer::semantic::ProcedureSemantics,
    source: &str,
    root: Node<'_>,
    assignment: Node<'_>,
    trivial_types: &crate::analyzer::cpp::semantic::TrivialTypeIndex,
    object_like_macros: &brokk_bifrost_core::hash::HashSet<Box<str>>,
) -> CAssignmentCandidate {
    let range = node_range(assignment);
    let next_assignment_start = next_assignment_start(assignment);
    if assignment.has_error() {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "preprocessing_or_recovery",
        );
    }
    let Some(operator) = assignment.child_by_field_name("operator") else {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "operator_missing",
        );
    };
    if node_text(operator, source) != "=" {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Excluded,
            "compound",
            "compound_assignment",
        );
    }
    let Some(left) = assignment.child_by_field_name("left") else {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "left_operand_missing",
        );
    };
    let Some(right) = assignment.child_by_field_name("right") else {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "right_operand_missing",
        );
    };
    if left.kind() != "identifier" {
        let storage = match left.kind() {
            "field_expression" => "member",
            "subscript_expression" => "element",
            "pointer_expression" => "indirect",
            _ => "indirect",
        };
        return candidate(
            range,
            Some(node_range(right)),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Excluded,
            storage,
            "nonlocal_target",
        );
    }
    let rhs_identifier = match bare_identifier_rhs(right) {
        Ok(Some(identifier)) => identifier,
        Ok(None) => {
            return candidate(
                range,
                Some(node_range(right)),
                next_assignment_start,
                CAssignmentSyntaxVerdict::Excluded,
                "ordinary_local",
                "rhs_not_bare_identifier",
            );
        }
        Err(()) => {
            return candidate(
                range,
                Some(node_range(right)),
                next_assignment_start,
                CAssignmentSyntaxVerdict::Unknown,
                "unknown",
                "rhs_syntax_unresolved",
            );
        }
    };
    if object_like_macros.contains(node_text(left, source))
        || object_like_macros.contains(node_text(rhs_identifier, source))
    {
        return candidate(
            range,
            Some(node_range(right)),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "object_like_macro",
        );
    }
    let rhs_range = node_range(right);

    let point = semantics.points().iter().find(|point| {
        semantics
            .source_mapping(point.source)
            .is_some_and(|mapping| {
                mapping.kind == SourceMappingKind::Exact
                    && exact_span(mapping.locator.anchor().span(), assignment)
            })
    });
    let Some(point) = point else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "assignment_point_unmapped",
        );
    };
    let local_assignments = point
        .events
        .iter()
        .filter_map(|event| match event.effect {
            SemanticEffect::Assignment { target, value }
                if semantics.value(target).is_some_and(|row| {
                    matches!(
                        &row.kind,
                        SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
                    )
                }) =>
            {
                Some((target, value))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(target, rhs_value)] = local_assignments.as_slice() else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "local_assignment_join_ambiguous",
        );
    };
    let Some(target_row) = semantics.value(*target) else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "target_value_missing",
        );
    };
    let Some(target_mapping) = semantics.source_mapping(target_row.source) else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "target_mapping_missing",
        );
    };
    if target_mapping.kind != SourceMappingKind::Exact {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "target_mapping_inexact",
        );
    }
    let target_span = target_mapping.locator.anchor().span();
    let Some(name) = root.named_descendant_for_byte_range(
        target_span.start_byte() as usize,
        target_span.end_byte() as usize,
    ) else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declaration_name_missing",
        );
    };
    if !exact_span(target_span, name) || name.kind() != "identifier" || name.has_error() {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declaration_name_inexact",
        );
    }
    let Some((declaration, declarator)) = containing_local_declarator(name) else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declarator_identity_unproved",
        );
    };
    if declarator_name_node(declarator).is_none_or(|actual| actual.id() != name.id()) {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declarator_identity_mismatch",
        );
    }
    if declaration.has_error() || declarator.has_error() {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declaration_syntax_unresolved",
        );
    }
    if has_object_qualifier(source, declaration, declarator, "volatile") {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "volatile",
            "volatile_object",
        );
    }
    if has_atomic_qualifier(source, declaration, declarator) {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "atomic",
            "atomic_object",
        );
    }
    if has_object_qualifier(source, declaration, declarator, "const") {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "const_object",
        );
    }
    if has_unsupported_storage_class(source, declaration) {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "unsupported_storage_class",
        );
    }
    if ["array_declarator", "reference_declarator"]
        .into_iter()
        .any(|kind| cpp_declarator_contains_kind(declarator, kind))
    {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "unsupported_declarator",
        );
    }
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declared_type_missing",
        );
    };
    let pointer_type = cpp_declarator_contains_kind(declarator, "pointer_declarator");
    if !pointer_type
        && !cpp_type_is_fundamental(type_node)
        && !trivial_types.named_enum_use_is_unambiguous(source, type_node)
    {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "unsupported_declared_type",
        );
    }
    completed_candidate(
        point.id,
        *target,
        *rhs_value,
        range,
        rhs_range,
        next_assignment_start,
        CAssignmentSyntaxVerdict::Supported,
        "ordinary_local",
        "qualified",
    )
}

fn candidate(
    range: Range,
    rhs_range: Option<Range>,
    next_assignment_start: Option<usize>,
    verdict: CAssignmentSyntaxVerdict,
    storage_kind: &'static str,
    reason: &'static str,
) -> CAssignmentCandidate {
    CAssignmentCandidate {
        point: None,
        target: None,
        rhs_value: None,
        range,
        rhs_range,
        next_assignment_start,
        verdict,
        storage_kind,
        reason,
    }
}

#[allow(clippy::too_many_arguments)]
fn completed_candidate(
    point: ProgramPointId,
    target: ValueId,
    rhs_value: ValueId,
    range: Range,
    rhs_range: Range,
    next_assignment_start: Option<usize>,
    verdict: CAssignmentSyntaxVerdict,
    storage_kind: &'static str,
    reason: &'static str,
) -> CAssignmentCandidate {
    CAssignmentCandidate {
        point: Some(point),
        target: Some(target),
        rhs_value: Some(rhs_value),
        range,
        rhs_range: Some(rhs_range),
        next_assignment_start,
        verdict,
        storage_kind,
        reason,
    }
}

fn next_assignment_start(assignment: Node<'_>) -> Option<usize> {
    let statement = assignment.parent()?;
    if statement.kind() != "expression_statement" || statement.has_error() {
        return None;
    }
    let mut cursor = statement.walk();
    let mut expressions = statement.named_children(&mut cursor);
    if expressions.next()?.id() != assignment.id() || expressions.next().is_some() {
        return None;
    }

    let block = statement.parent()?;
    if block.kind() != "compound_statement" || block.has_error() {
        return None;
    }
    let mut next = statement.next_named_sibling()?;
    while next.kind() == "comment" {
        next = next.next_named_sibling()?;
    }
    if next.kind() != "expression_statement" || next.has_error() {
        return None;
    }
    let mut cursor = next.walk();
    let mut expressions = next.named_children(&mut cursor);
    let expression = expressions.next()?;
    if expressions.next().is_some()
        || expression.kind() != "assignment_expression"
        || expression.has_error()
    {
        return None;
    }
    Some(expression.start_byte())
}

fn containing_local_declarator(name: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut current = name;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "declaration" | "parameter_declaration" | "optional_parameter_declaration"
        ) {
            let declarator = cpp_local_declarators(parent)
                .into_iter()
                .find(|candidate| {
                    candidate.start_byte() <= name.start_byte()
                        && candidate.end_byte() >= name.end_byte()
                })?;
            return Some((parent, declarator));
        }
        if matches!(
            parent.kind(),
            "function_definition" | "parameter_declaration"
        ) {
            return None;
        }
        current = parent;
    }
    None
}

fn bare_identifier_rhs(mut node: Node<'_>) -> Result<Option<Node<'_>>, ()> {
    loop {
        if node.has_error() {
            return Err(());
        }
        match node.kind() {
            "identifier" => return Ok(Some(node)),
            "parenthesized_expression" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let Some(child) = children.next() else {
                    return Err(());
                };
                if children.next().is_some() {
                    return Err(());
                }
                node = child;
            }
            _ => return Ok(None),
        }
    }
}

pub(crate) fn has_object_qualifier(
    source: &str,
    declaration: Node<'_>,
    declarator: Node<'_>,
    expected: &str,
) -> bool {
    let mut outer = declarator;
    while outer.kind() == "init_declarator" {
        let Some(inner) = outer.child_by_field_name("declarator") else {
            return false;
        };
        outer = inner;
    }
    if let Some(pointer) = cpp_outermost_pointer_declarator(outer) {
        let mut cursor = pointer.walk();
        return pointer
            .named_children(&mut cursor)
            .any(|node| node.kind() == "type_qualifier" && node_text(node, source) == expected);
    }
    if cpp_declarator_contains_kind(outer, "pointer_declarator") {
        return false;
    }
    declaration_direct_qualifier(source, declaration, expected)
}

fn cpp_outermost_pointer_declarator(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "pointer_declarator" {
            return Some(node);
        }
        if let Some(inner) = node.child_by_field_name("declarator") {
            node = inner;
        } else if node.kind() == "parenthesized_declarator" {
            node = node.named_child(0)?;
        } else {
            return None;
        }
    }
}

pub(crate) fn has_atomic_qualifier(
    source: &str,
    declaration: Node<'_>,
    declarator: Node<'_>,
) -> bool {
    declaration_direct_atomic(source, declaration)
        || declaration
            .child_by_field_name("type")
            .is_some_and(|node| subtree_has_atomic(source, node))
        || subtree_has_atomic(source, declarator)
}

fn declaration_direct_qualifier(source: &str, declaration: Node<'_>, expected: &str) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .any(|node| node.kind() == "type_qualifier" && node_text(node, source) == expected)
}

fn declaration_direct_atomic(source: &str, declaration: Node<'_>) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .any(|node| node_is_atomic(source, node))
}

fn subtree_has_atomic(source: &str, root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node_is_atomic(source, node) {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn node_is_atomic(source: &str, node: Node<'_>) -> bool {
    matches!(node.kind(), "atomic_type_specifier" | "_Atomic")
        || (node.kind() == "type_qualifier" && node_text(node, source) == "_Atomic")
}

fn has_unsupported_storage_class(source: &str, declaration: Node<'_>) -> bool {
    let mut cursor = declaration.walk();
    declaration.named_children(&mut cursor).any(|child| {
        child.kind() == "storage_class_specifier"
            && !matches!(node_text(child, source), "auto" | "register")
    })
}

#[cfg(test)]
mod tests {

    use crate::analyzer::cpp::expression_branch_facts::*;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegment;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    #[test]
    fn c_assignment_candidates_reports_source_budget_exhaustion() {
        // Keep the padding volume while bounded lines let materialization reach
        // the downstream assignment-candidate source budget.
        let padding =
            format!("{}\n", "x".repeat(1_024)).repeat(DEFAULT_MAX_SOURCE_BYTES.div_ceil(1_024));
        let source = format!(
            "void oversized(void) {{ int first = 1; int second = 2; first = second; second = first; }}\n/*{padding}*/\n"
        );
        assert!(source.len() > DEFAULT_MAX_SOURCE_BYTES);
        let fixture =
            AnalyzerFixture::new_for_language(Language::Cpp, &[("main.c", source.as_str())]);
        let file = ProjectFile::new(fixture.project_root(), "main.c");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("oversized C semantic materialization");
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = outcome
        else {
            panic!("oversized C semantic materialization must be complete: {outcome:#?}");
        };
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("oversized")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("oversized C procedure");

        let candidates = c_assignment_candidates(&fixture.analyzer, &procedure, None);

        assert!(candidates.rows.is_empty(), "{candidates:#?}");
        assert!(!candidates.complete, "{candidates:#?}");
        assert_eq!(
            candidates.reason,
            Some("source_budget_exhausted"),
            "{candidates:#?}"
        );
    }
}
