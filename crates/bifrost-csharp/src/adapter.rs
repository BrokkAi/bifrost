//! The C# answers behind `CSharpAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/csharp/adapter.rs`; every answer it gives comes from here, from
//! [`crate::declarations`] or from [`crate::syntax`].
//! `lookup_candidate_short_names` is the one split answer: the generic
//! suffix walk is `lookup_suffix_candidates`, an analysis helper four languages
//! share, so the shell keeps the assembly and calls
//! [`csharp_nested_owner_short_name_candidates`] for the `$`-encoded nested
//! spellings that are C#-specific.

use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;
use tree_sitter::Node;

pub const CSHARP_FILE_EXTENSION: &str = "cs";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer for C#.
pub static CSHARP_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &[
            "for_statement",
            "foreach_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["switch_section", "switch_expression_arm"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["goto_statement"],
        named_function_boundary_types: &[
            "method_declaration",
            "constructor_declaration",
            "local_function_statement",
            "accessor_declaration",
            "operator_declaration",
            "conversion_operator_declaration",
            "destructor_declaration",
        ],
        anonymous_function_types: &["lambda_expression", "anonymous_method_expression"],
        case_increment_predicate: Some(csharp_case_increment),
        jump_predicate: Some(|_| true),
        ..cognitive_complexity::Config::empty()
    });

fn csharp_case_increment(node: Node<'_>, _source: &str) -> u32 {
    if node.kind() == "switch_expression_arm" {
        let pattern = node.named_child(0);
        let mut cursor = node.walk();
        let guarded = node
            .named_children(&mut cursor)
            .any(|child| child.kind() == "when_clause");
        return u32::from(guarded || !pattern.is_some_and(csharp_is_irrefutable_pattern));
    }

    let mut count = 0u32;
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        if child.kind() != "case" {
            continue;
        }

        let mut pattern = None;
        let mut guarded = false;
        for label_index in index + 1..node.child_count() {
            let Some(label_child) = node.child(label_index) else {
                continue;
            };
            if label_child.kind() == ":" {
                break;
            }
            if label_child.kind() == "when_clause" {
                guarded = true;
            } else if label_child.is_named() && pattern.is_none() {
                pattern = Some(label_child);
            }
        }
        if guarded || !pattern.is_some_and(csharp_is_irrefutable_pattern) {
            count = count.saturating_add(1);
        }
    }
    count
}

fn csharp_is_irrefutable_pattern(mut pattern: Node<'_>) -> bool {
    while pattern.kind() == "parenthesized_pattern" {
        let Some(inner) = pattern.named_child(0) else {
            return false;
        };
        pattern = inner;
    }
    matches!(pattern.kind(), "discard" | "var_pattern")
        || (pattern.kind() == "declaration_pattern"
            && pattern
                .child_by_field_name("type")
                .is_some_and(|ty| ty.kind() == "implicit_type"))
}

pub fn csharp_extract_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    before_args
        .rsplit_once('.')
        .map(|(receiver, _)| receiver.to_string())
}

/// The `short_name` spellings a dotted C# path can have been stored under, one
/// per length of its leading type-nesting run.
///
/// A declaration's `short_name` is assembled in `declarations.rs`: a nested type
/// joins its owner with `$`, and a member joins its owning type with `.`. The
/// `$` run is therefore always a *prefix* of the separators -- `Outer$Inner`,
/// `Outer$Inner.Method` -- and a spelling that returns to `$` after a `.`, such
/// as `Outer.Inner$Method`, names nothing this analyzer can persist.
///
/// So the reachable spellings of an `n`-part path are the `n - 1` prefix runs,
/// not the `2^(n-1)` free choices of separator. The mask enumeration this
/// replaced spent the difference on store lookups that could never match: since
/// [`crate::syntax::csharp_normalize_full_name`] maps `$` back to `.`, every
/// mask normalizes to the same name, so the extra spellings were alternate
/// lookup keys for one target rather than distinct candidates. Each one still
/// cost its own SQL query, which made a single visible-type search over a file
/// with a deep namespace cost thousands of them (#1806).
///
/// Paths longer than nine parts keep the single collapsed spelling the mask
/// walk used, so this returns a subset of what it returned at every length.
pub fn csharp_nested_owner_short_name_candidates(normalized: &str) -> Vec<String> {
    let parts: Vec<_> = normalized
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() < 2 {
        return Vec::new();
    }

    let separator_count = parts.len() - 1;
    if separator_count > 8 {
        let mut encoded = parts[..separator_count].join("$");
        encoded.push('.');
        encoded.push_str(parts[separator_count]);
        return vec![encoded];
    }

    (1..=separator_count)
        .map(|nested_run| {
            let mut encoded = String::from(parts[0]);
            for (index, part) in parts.iter().enumerate().skip(1) {
                encoded.push(if index <= nested_run { '$' } else { '.' });
                encoded.push_str(part);
            }
            encoded
        })
        .collect()
}

pub fn csharp_callable_return_type_text(signature: &str) -> Option<&str> {
    let declaration_head = signature
        .split(['(', '{', ';', '='])
        .next()
        .unwrap_or(signature)
        .trim_end();
    let name = declaration_head.split_whitespace().last()?;
    let return_type = crate::syntax::csharp_signature_return_type(signature, name)?;
    signature.find(&return_type).map(|start| {
        let end = start + return_type.len();
        &signature[start..end]
    })
}

#[cfg(test)]
mod tests {
    use super::csharp_nested_owner_short_name_candidates;

    /// Every spelling is a leading `$` run followed by `.` for the rest, and
    /// there is exactly one per run length.
    ///
    /// The count is the point. Each spelling becomes its own store lookup, so a
    /// walk that returned every `.`/`$` mask cost `2^(n-1)` lookups per probe,
    /// which made one visible-type search over a six-segment namespace issue
    /// thousands of them (#1806). A short name never returns to `$` after a
    /// `.`, so the mixed spellings could match nothing and were pure cost.
    #[test]
    fn nested_owner_spellings_are_one_per_nesting_run_not_one_per_separator_mask() {
        assert_eq!(
            csharp_nested_owner_short_name_candidates("Outer.Inner.Member"),
            vec!["Outer$Inner.Member", "Outer$Inner$Member"]
        );

        for parts in 2..=9 {
            let path = (0..parts)
                .map(|part| format!("P{part}"))
                .collect::<Vec<_>>()
                .join(".");
            let candidates = csharp_nested_owner_short_name_candidates(&path);
            assert_eq!(
                candidates.len(),
                parts - 1,
                "a {parts}-part path must yield one spelling per nesting run, not 2^(n-1): {candidates:?}"
            );
            for candidate in &candidates {
                let last_dollar = candidate.rfind('$');
                let first_dot = candidate.find('.');
                assert!(
                    match (last_dollar, first_dot) {
                        (Some(dollar), Some(dot)) => dollar < dot,
                        _ => true,
                    },
                    "`{candidate}` returns to `$` after a `.`, which no C# short name does"
                );
            }
        }
    }

    /// A path too deep to enumerate keeps the single collapsed spelling, so the
    /// candidate set is a subset of the mask walk's at every length.
    #[test]
    fn a_path_deeper_than_nine_parts_keeps_one_collapsed_spelling() {
        let path = (0..12)
            .map(|part| format!("P{part}"))
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(
            csharp_nested_owner_short_name_candidates(&path),
            vec!["P0$P1$P2$P3$P4$P5$P6$P7$P8$P9$P10.P11"]
        );
    }
}
