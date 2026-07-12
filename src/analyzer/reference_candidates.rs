use crate::analyzer::{Language, Range};
use tree_sitter::Node;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReferenceCandidateRanges {
    Complete(Vec<Range>),
    LimitExceeded { limit: usize },
}

/// Collect grammar-derived terminal nodes that may denote source references.
///
/// The traversal is iterative so deeply nested generated source cannot exhaust the
/// Rust stack. A zero limit is valid and reports overflow as soon as a candidate is
/// encountered.
pub(crate) fn reference_candidate_ranges(
    root: Node<'_>,
    language: Language,
    limit: usize,
) -> ReferenceCandidateRanges {
    collect_candidate_ranges(root, language, limit, CandidateFrontier::References)
}

/// Preserve the LSP's identifier-only token frontier. Semantic tokens resolve
/// declarations for coloring, so receiver keywords and compound callable names
/// must not become tokens merely because the differential engine scans them.
pub(crate) fn semantic_token_candidate_ranges(
    root: Node<'_>,
    language: Language,
    limit: usize,
) -> ReferenceCandidateRanges {
    collect_candidate_ranges(root, language, limit, CandidateFrontier::SemanticTokens)
}

#[derive(Clone, Copy)]
enum CandidateFrontier {
    References,
    SemanticTokens,
}

fn collect_candidate_ranges(
    root: Node<'_>,
    language: Language,
    limit: usize,
    frontier: CandidateFrontier,
) -> ReferenceCandidateRanges {
    let mut ranges = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let compound = matches!(frontier, CandidateFrontier::References)
            && is_compound_reference_candidate(language, node.kind());
        let candidate = match frontier {
            CandidateFrontier::References => is_reference_candidate_node(language, node.kind()),
            CandidateFrontier::SemanticTokens => {
                is_semantic_token_identifier_node(language, node.kind())
            }
        };
        if candidate
            && (node.named_child_count() == 0 || compound)
            && node.start_byte() < node.end_byte()
        {
            if ranges.len() == limit {
                return ReferenceCandidateRanges::LimitExceeded { limit };
            }
            ranges.push(Range {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            });
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    ReferenceCandidateRanges::Complete(ranges)
}

fn is_semantic_token_identifier_node(language: Language, kind: &str) -> bool {
    if language == Language::None {
        return false;
    }
    if kind == "identifier" || kind.ends_with("_identifier") {
        return true;
    }
    match language {
        Language::Php => kind == "name",
        Language::Ruby => matches!(
            kind,
            "constant" | "instance_variable" | "class_variable" | "global_variable"
        ),
        _ => false,
    }
}

pub(crate) fn is_reference_candidate_node(language: Language, kind: &str) -> bool {
    if is_semantic_token_identifier_node(language, kind) {
        return true;
    }
    match language {
        Language::None => false,
        Language::Java | Language::Go | Language::Python | Language::Php | Language::Scala => false,
        Language::Cpp => matches!(kind, "operator_name" | "destructor_name" | "this"),
        Language::JavaScript | Language::TypeScript => matches!(kind, "this"),
        Language::Rust => matches!(kind, "self" | "super" | "crate"),
        Language::CSharp => matches!(kind, "this" | "base"),
        Language::Ruby => kind == "self",
    }
}

fn is_compound_reference_candidate(language: Language, kind: &str) -> bool {
    language == Language::Cpp && matches!(kind, "operator_name" | "destructor_name")
}
