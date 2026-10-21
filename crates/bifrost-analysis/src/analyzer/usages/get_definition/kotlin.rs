//! Kotlin syntax and external-model projections used by native points and signature help.

use super::*;
use crate::analyzer::semantic_model::{SemanticModelSymbol, SemanticModelSymbolKind};
use brokk_bifrost_jvm::kotlin::declarations::kotlin_identifier_text;
use brokk_bifrost_jvm::kotlin::syntax::{
    kotlin_call_with_callee, kotlin_callee, kotlin_named_argument_label,
};

const KOTLIN_PACKAGE_MARKER: &str = "bifrost:kotlin-package";

/// Expand a point inside a Kotlin named-argument label to the exact parsed
/// identifier token. The generic location resolver treats the opening
/// backtick as punctuation, while the producer publishes the full AST span.
pub(crate) fn kotlin_site_for_focus(
    mut site: ResolvedReferenceSite,
    tree: &Tree,
    source: &str,
) -> ResolvedReferenceSite {
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return site;
    };
    let Some(parent) = node.parent() else {
        return site;
    };
    if node.kind() != "simple_identifier"
        || parent.kind() != "value_argument"
        || !kotlin_named_argument_label(parent, node)
    {
        return site;
    }
    let (start, end) = (node.start_byte(), node.end_byte());
    if start == site.focus_start_byte && end == site.focus_end_byte {
        return site;
    }
    let Some(_) = source.get(start..end) else {
        return site;
    };
    let line_starts = compute_line_starts(source);
    site.text = kotlin_identifier_text(node, source).to_owned();
    site.range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(&line_starts, start) + 1,
        end_line: find_line_index_for_offset(&line_starts, end.saturating_sub(1)) + 1,
    };
    site.focus_start_byte = start;
    site.focus_end_byte = end;
    site
}

fn kotlin_import_target_kind(kind: SemanticModelSymbolKind) -> bool {
    matches!(
        kind,
        SemanticModelSymbolKind::Class
            | SemanticModelSymbolKind::Annotation
            | SemanticModelSymbolKind::Interface
            | SemanticModelSymbolKind::Enum
            | SemanticModelSymbolKind::Module
            | SemanticModelSymbolKind::TypeAlias
            | SemanticModelSymbolKind::Constructor
            | SemanticModelSymbolKind::Method
            | SemanticModelSymbolKind::Function
            | SemanticModelSymbolKind::Field
            | SemanticModelSymbolKind::Property
            | SemanticModelSymbolKind::Constant
    )
}

fn kotlin_model_outcome(
    site: &ResolvedReferenceSite,
    records: Vec<&SemanticModelSymbol>,
    subject: &str,
) -> DefinitionLookupOutcome {
    if records.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("`{subject}` is not indexed as a Kotlin model definition"),
        );
    }
    if records.iter().any(|record| record.provenance.ambiguous) {
        // no candidates: the conflicting records are semantic-model symbols,
        // not indexed code units, so none can be offered as a target.
        return ambiguous_without_candidates(format!(
            "`{subject}` matches conflicting active Kotlin model declarations"
        ));
    }
    let target = if records.len() == 1 {
        records[0].id.clone()
    } else {
        records[0].qualified_name.clone()
    };
    let mut reference = site.clone();
    reference.text = target;
    DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status: DefinitionLookupStatus::Resolved,
        reference: Some(reference),
        definitions: Vec::new(),
        lexical_definition: None,
        diagnostics: Vec::new(),
    }
}

pub(crate) fn kotlin_package_reference_outcome(candidate: &str) -> DefinitionLookupOutcome {
    no_definition(
        "package_reference",
        format!("`{candidate}` names a package, which has no declaration to navigate to"),
    )
}

/// Project an exact active Kotlin model declaration selected by an import.
///
/// The native JVM point resolver owns workspace bindings. This is the external
/// model half of that same selected import lookup.
pub(crate) fn kotlin_import_model_outcome(
    analyzer: &dyn IAnalyzer,
    site: &ResolvedReferenceSite,
    candidate: &str,
) -> Option<DefinitionLookupOutcome> {
    let overlay = analyzer.semantic_model_overlay()?;
    let records = overlay.symbols_named(candidate).records;
    if records.iter().any(|symbol| {
        symbol.language == "kotlin"
            && symbol.kind == SemanticModelSymbolKind::Module
            && symbol
                .aliases
                .iter()
                .any(|alias| alias == KOTLIN_PACKAGE_MARKER)
    }) {
        return Some(kotlin_package_reference_outcome(candidate));
    }
    let modeled = records
        .into_iter()
        .filter(|symbol| {
            symbol.language == "kotlin"
                && symbol.externally_visible()
                && kotlin_import_target_kind(symbol.kind)
        })
        .collect::<Vec<_>>();
    (!modeled.is_empty()).then(|| kotlin_model_outcome(site, modeled, candidate))
}

/// Whether `node` is the callee token of a Kotlin call, which is what
/// signature help anchors a call site on.
pub(super) fn kotlin_call_reference_candidate(node: Node<'_>) -> bool {
    if let Some(parent) = node.parent()
        && parent.kind() == "navigation_suffix"
        && let Some(navigation) = parent.parent()
    {
        return navigation
            .parent()
            .filter(|call| call.kind() == "call_expression")
            .and_then(kotlin_callee)
            .is_some_and(|callee| callee.id() == navigation.id());
    }
    if kotlin_call_with_callee(node).is_some() {
        return true;
    }
    // `Base(...)` in a supertype list is spelled as a `constructor_invocation`
    // over a `user_type` rather than as a call expression.
    node.parent()
        .filter(|parent| parent.kind() == "user_type")
        .and_then(|user_type| user_type.parent())
        .is_some_and(|parent| parent.kind() == "constructor_invocation")
}

#[cfg(test)]
mod this_owner_regression_tests {
    use super::*;
    use crate::analyzer::kotlin::KotlinAnalyzer;
    use crate::inline_project::InlineTestProject;
    use std::sync::Arc;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4271: this@Inner failed when the nested Kotlin owner identifier carried its outer prefix"
    )]
    fn this_label_resolves_nested_class_member_by_simple_name() {
        let source = "package example\n\
class Outer {\n\
    val selected = 1\n\
    inner class Inner {\n\
        val selected = 2\n\
        inner class Nested {\n\
            val selected = 3\n\
            fun read(): Int = this@Inner.selected\n\
        }\n\
    }\n\
}\n";
        let fixture = InlineTestProject::with_language(Language::Kotlin)
            .file("Main.kt", source)
            .build();
        let analyzer = KotlinAnalyzer::new(fixture.project_arc());
        let file = fixture.file("Main.kt");
        let start = source.rfind("selected").expect("member reference");
        let request = DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + "selected".len()),
        };

        let outcome =
            resolve_definition_batch_with_source(&analyzer, vec![request], file, Arc::from(source))
                .pop()
                .expect("one Kotlin definition outcome");

        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:#?}"
        );
        assert!(
            outcome
                .definitions
                .iter()
                .any(|unit| unit.fq_name() == "example.Outer.Inner.selected"),
            "this@Inner must select Inner's member: {outcome:#?}"
        );
    }
}
