//! Structured C/C++ local-initializer access facts.
//!
//! This is a syntax-side producer only. Binding identity and value identity
//! remain the flow layer's responsibility; the RQL relation joins these rows
//! to exact establish/read events from that layer.

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::common::exact_span;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use brokk_bifrost_analysis::analyzer::semantic::{ProcedureHandle, SourceMappingKind};

use brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::LanguageDialect;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
pub use brokk_bifrost_core::analyzer::cpp_facts::{
    CppInitializerAccessKind, CppInitializerCandidate, CppInitializerCandidates,
    CppInitializerSyntaxVerdict,
};
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use brokk_bifrost_cpp::structural::declarator_name_node;
use tree_sitter::Node;

use crate::analyzer::cpp::expression_branch_facts::has_object_qualifier;

use brokk_bifrost_cpp::declarations::node_text;

use crate::analyzer::cpp::semantic::cpp_declarator_initializer;

use crate::analyzer::cpp::semantic::cpp_local_declarators;

const MAX_SOURCE_BYTES: usize = 1_048_576;

pub fn cpp_initializer_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> CppInitializerCandidates {
    if !matches!(
        procedure.artifact().key().language(),
        LanguageDialect::CppC | LanguageDialect::Standard(Language::Cpp)
    ) {
        return complete();
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
        .map(|provider| provider.structural_syntax_limited(&file, MAX_SOURCE_BYTES, cancellation));
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
    let Some(mapping) = semantics.source_mapping(semantics.source()) else {
        return unavailable("procedure_mapping_missing");
    };
    if mapping.kind != SourceMappingKind::Exact {
        return unavailable("procedure_mapping_inexact");
    }
    let span = mapping.locator.anchor().span();
    let Some(procedure_node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
    else {
        return unavailable("procedure_syntax_missing");
    };
    if !exact_span(span, procedure_node) || procedure_node.has_error() {
        return unavailable("procedure_syntax_inexact");
    }

    let Some(cpp) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        crate::analyzer::cpp::CppAnalyzer,
    >(workspace.analyzer()) else {
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

    let mut declarations = Vec::new();
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
        has_preprocessing |= node.kind().starts_with("preproc_");
        if node.kind() == "declaration" {
            for declarator in cpp_local_declarators(node) {
                let Some(initializer) = cpp_declarator_initializer(node, declarator) else {
                    continue;
                };
                let Some(name) = declarator_name_node(declarator) else {
                    continue;
                };
                let const_object = has_object_qualifier(syntax.source(), node, declarator, "const");
                declarations.push((node, initializer, name, const_object));
            }
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }

    let mut rows = Vec::new();
    let mut has_macro_hazard = false;
    for (declaration, initializer, _name, const_object) in declarations {
        let mut identifiers = Vec::new();
        let mut nodes = vec![initializer];
        while let Some(node) = nodes.pop() {
            if node.id() != initializer.id()
                && matches!(node.kind(), "function_definition" | "lambda_expression")
            {
                continue;
            }
            if node.kind() == "identifier" {
                identifiers.push(node);
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            nodes.extend(children.into_iter().rev());
        }
        for access in identifiers {
            let access_kind = classify_access(access, initializer, syntax.source());
            let macro_hazard = file_facts
                .object_like_macros
                .contains(node_text(access, syntax.source()));
            has_macro_hazard |= macro_hazard;
            let (verdict, reason) = if const_object {
                (CppInitializerSyntaxVerdict::Excluded, "const_object")
            } else if access_kind == CppInitializerAccessKind::AddressOnly {
                (CppInitializerSyntaxVerdict::Excluded, "address_only")
            } else if access_kind == CppInitializerAccessKind::Unevaluated {
                (CppInitializerSyntaxVerdict::Excluded, "unevaluated_context")
            } else if macro_hazard {
                (CppInitializerSyntaxVerdict::Unknown, "object_like_macro")
            } else if declaration.has_error() || initializer.has_error() || access.has_error() {
                (CppInitializerSyntaxVerdict::Unknown, "syntax_unresolved")
            } else {
                (CppInitializerSyntaxVerdict::Supported, "qualified")
            };
            rows.push(CppInitializerCandidate {
                declaration_range: node_range(declaration),
                initializer_range: node_range(initializer),
                access_range: node_range(access),
                access_kind,
                verdict,
                storage_kind: "ordinary_local",
                reason,
            });
        }
    }
    rows.sort_unstable_by_key(|row| {
        (
            row.declaration_range.start_byte,
            row.access_range.start_byte,
        )
    });
    CppInitializerCandidates {
        rows,
        complete: !(has_preprocessing || has_macro_hazard),
        reason: if has_preprocessing {
            Some("preprocessing_present")
        } else {
            has_macro_hazard.then_some("macro_possible")
        },
    }
}

fn classify_access(
    access: Node<'_>,
    initializer: Node<'_>,
    source: &str,
) -> CppInitializerAccessKind {
    let mut current = access;
    let mut assignment = false;
    let mut increment = false;
    let mut address_only = false;
    let mut unevaluated = false;
    while let Some(parent) = current.parent() {
        if parent.start_byte() < initializer.start_byte()
            || parent.end_byte() > initializer.end_byte()
        {
            break;
        }
        if matches!(
            parent.kind(),
            "sizeof_expression"
                | "decltype_expression"
                | "type_descriptor"
                | "noexcept_expression"
                | "requires_expression"
                | "typeid_expression"
        ) {
            unevaluated = true;
        }
        if parent.kind() == "pointer_expression"
            && parent
                .child_by_field_name("operator")
                .is_some_and(|operator| node_text(operator, source) == "&")
        {
            address_only = true;
        }
        if parent.kind() == "assignment_expression"
            && parent
                .child_by_field_name("left")
                .is_some_and(|left| contains_node(left, access))
        {
            assignment = true;
        }
        if matches!(parent.kind(), "update_expression" | "unary_expression")
            && parent
                .child_by_field_name("operator")
                .is_some_and(|operator| matches!(node_text(operator, source), "++" | "--"))
        {
            increment = true;
        }
        current = parent;
    }
    if unevaluated {
        CppInitializerAccessKind::Unevaluated
    } else if address_only {
        CppInitializerAccessKind::AddressOnly
    } else if assignment {
        CppInitializerAccessKind::Assignment
    } else if increment {
        CppInitializerAccessKind::Increment
    } else {
        CppInitializerAccessKind::Read
    }
}

fn contains_node(container: Node<'_>, wanted: Node<'_>) -> bool {
    container.start_byte() <= wanted.start_byte() && wanted.end_byte() <= container.end_byte()
}

fn complete() -> CppInitializerCandidates {
    CppInitializerCandidates {
        rows: Vec::new(),
        complete: true,
        reason: None,
    }
}

fn unavailable(reason: &'static str) -> CppInitializerCandidates {
    CppInitializerCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    }
}
