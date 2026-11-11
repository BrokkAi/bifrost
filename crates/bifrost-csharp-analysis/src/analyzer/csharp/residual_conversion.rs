//! The implicit conversion of a typed local's initializer (#8299).
//!
//! `string tool = Request.ReadInput();` converts the initializer to the
//! declared type. C# lets either type declare an `implicit operator`, which is
//! user code that may return any value, so lowering connects the initializer
//! to the local only when the file proves that no such operator runs. When the
//! initializer's type is known only to the workspace resolver -- another
//! file's declaration, or an external member a semantic model declares --
//! lowering keeps the value's identity and records a
//! `SemanticGapDischarge::ResidualConversion` gap at the declarator instead.
//!
//! At query time [`declarator_conversion_runs_no_user_code`] discharges that
//! gap when the resolver types the initializer as exactly the declared type.
//! An identity conversion is a standard conversion, so C# never considers a
//! user-defined operator for it.

use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, IAnalyzer};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_csharp::graph::resolver::{reference_type_text, resolve_type_fq_name_of_node};
use brokk_bifrost_csharp::graph_support::CSharpLookupContext;
use brokk_bifrost_csharp::syntax::variable_declarator_initializer;
use tree_sitter::Node;

use super::CSharpAnalyzer;
use super::external::CSharpExternalTypeLookup;

/// The declared type of the local whose initializer is `operand`, when the
/// declaration names a plain type (a keyword type, a simple name or a
/// qualified name) and the initializer is a call or a member access: the
/// values whose type only another file or a semantic model declares. A `var`
/// local, a generic, array, nullable or pointer type, and any other initializer
/// answer nothing, so their conversion keeps the ordinary unknown-call
/// handling. That includes a cast, whose own result is a conversion this proof
/// does not model, and a name or object creation, whose type the file usually
/// knows.
pub(crate) fn residual_declarator_type(operand: Node<'_>) -> Option<Node<'_>> {
    if !matches!(
        operand.kind(),
        "invocation_expression" | "member_access_expression"
    ) {
        return None;
    }
    let declarator = operand
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")?;
    if variable_declarator_initializer(declarator) != Some(operand) {
        return None;
    }
    declarator
        .parent()
        .filter(|declaration| declaration.kind() == "variable_declaration")?
        .child_by_field_name("type")
        .filter(|ty| {
            matches!(
                ty.kind(),
                "predefined_type" | "identifier" | "qualified_name"
            )
        })
}

/// Whether the declarator spanned by `conversion` in `exact_source` converts
/// its initializer by identity: the resolver types the initializer as exactly
/// one type, and the declared type names that same type.
pub(crate) fn declarator_conversion_runs_no_user_code(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    exact_source: &Arc<str>,
    conversion: std::ops::Range<usize>,
) -> bool {
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        return false;
    };
    let scope = AnalyzerQueryScope::new(csharp);
    let token = scope.token();
    let Some(prepared) = csharp.prepared_syntax_for_path(token, file) else {
        return false;
    };
    let source = prepared.source();
    if source != exact_source.as_ref() {
        return false;
    }
    let root = prepared.tree().root_node();
    let Some(declarator) = root
        .named_descendant_for_byte_range(conversion.start, conversion.end)
        .filter(|node| node.kind() == "variable_declarator" && node.byte_range() == conversion)
    else {
        return false;
    };
    let Some(initializer) = variable_declarator_initializer(declarator) else {
        return false;
    };
    let Some(declared_node) = residual_declarator_type(initializer) else {
        return false;
    };
    let declared =
        resolve_type_fq_name_of_node(csharp, file, source, declared_node).or_else(|| {
            let context = CSharpLookupContext::at(source, declared_node, || true)
                .expect("an unbounded lookup context completes");
            match csharp
                .external_declarations(analyzer.semantic_model_overlay())
                .resolve_type_in_file(
                    &reference_type_text(declared_node, source),
                    context.namespace(),
                    &csharp.using_namespaces_of(token, file),
                    &csharp.using_aliases_of(token, file),
                ) {
                CSharpExternalTypeLookup::Unique(candidate) => Some(candidate.fqn),
                CSharpExternalTypeLookup::Absent | CSharpExternalTypeLookup::Ambiguous => None,
            }
        });
    let Some(declared) = declared else {
        return false;
    };
    crate::analyzer::usages::get_definition::csharp::csharp_expression_value_type(
        analyzer,
        token,
        csharp,
        file,
        source,
        root,
        initializer,
    )
    .is_some_and(|value| value == declared)
}
