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

use crate::syntax::csharp_is_irrefutable_pattern;
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

pub fn csharp_extract_call_receiver(reference: &str) -> Option<String> {
    brokk_bifrost_core::analyzer::common::extract_call_reference_parts(reference, &["."])
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
/// This linear list includes every legal nesting run at arbitrary depth.
pub fn csharp_nested_owner_short_name_candidates(normalized: &str) -> Vec<String> {
    let parts: Vec<_> = normalized
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() < 2 {
        return Vec::new();
    }

    let separator_count = parts.len() - 1;

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

#[cfg(test)]
mod tests {
    use super::{
        csharp_case_increment, csharp_extract_call_receiver, csharp_is_irrefutable_pattern,
        csharp_nested_owner_short_name_candidates,
    };
    use tree_sitter::{Parser, Tree};

    fn parsed(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar loads");
        parser.parse(source, None).expect("C# source parses")
    }

    fn node<'tree>(tree: &'tree Tree, kind: &str) -> tree_sitter::Node<'tree> {
        let mut pending = vec![tree.root_node()];
        while let Some(current) = pending.pop() {
            if current.kind() == kind {
                return current;
            }
            pending.extend(
                (0..current.child_count())
                    .rev()
                    .filter_map(|index| current.child(index)),
            );
        }
        panic!("expected {kind} syntax node")
    }

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

        for parts in 2..=24 {
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

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "ae2a8d00737b: quicksilver round 8 on brokk-bifrost-csharp: deep nested declarations lost their lookup spelling"
    )]
    fn nested_declaration_spellings_remain_addressable_at_every_depth() {
        use crate::declarations::parse_csharp_file;
        use brokk_bifrost_core::analyzer::ProjectFile;

        for depth in [9, 10, 11, 24] {
            let mut source = String::new();
            for part in 0..depth {
                source.push_str(&format!("class P{part} {{ "));
            }
            source.push_str("void Method() {} ");
            source.push_str(&"}".repeat(depth));
            let tree = parsed(&source);
            assert!(!tree.root_node().has_error());
            let file = ProjectFile::new(std::env::temp_dir(), "Nested.cs");
            let declarations = parse_csharp_file(&file, &source, &tree);
            assert!(
                declarations.declarations().len() >= depth,
                "nested declaration inventory must be populated"
            );
            for declaration in declarations.declarations() {
                let stored = declaration.short_name();
                if !stored.contains('$') {
                    continue;
                }
                let displayed = stored.replace('$', ".");
                let candidates = csharp_nested_owner_short_name_candidates(&displayed);
                assert!(
                    candidates.iter().any(|candidate| candidate == stored),
                    "declaration {stored} at depth {depth} is absent from {candidates:?}"
                );
            }
        }
    }

    #[test]
    fn switch_pattern_grammar_distinguishes_irrefutable_and_guarded_cases() {
        let source = r#"
class C {
    int M(object value) {
        switch (value) {
            case _: break;
            case var any: break;
            case object typed: break;
            case 1: break;
            case var guarded when true: break;
        }
        return value switch { _ => 0, var any when true => 1, 1 => 2 };
    }
}
        "#;
        let tree = parsed(source);
        let mut pending = vec![tree.root_node()];
        let mut sections = Vec::new();
        while let Some(current) = pending.pop() {
            if current.kind() == "switch_section" {
                sections.push(current);
            }
            pending.extend(
                (0..current.child_count())
                    .rev()
                    .filter_map(|index| current.child(index)),
            );
        }
        assert_eq!(sections.len(), 5, "grammar exposes all switch sections");
        let case_tokens = sections
            .iter()
            .map(|section| {
                (0..section.child_count())
                    .filter_map(|index| section.child(index))
                    .filter(|child| child.kind() == "case")
                    .count()
            })
            .sum::<usize>();
        assert_eq!(case_tokens, 5, "grammar exposes each switch case token");
        assert_eq!(
            sections
                .iter()
                .map(|section| csharp_case_increment(*section, source))
                .sum::<u32>(),
            3
        );

        let expression = node(&tree, "switch_expression_arm");
        let pattern = expression.named_child(0).expect("switch arm pattern");
        assert!(
            csharp_is_irrefutable_pattern(pattern),
            "grammar pattern kind is {}, children: {:?}",
            pattern.kind(),
            (0..pattern.child_count())
                .filter_map(|index| pattern.child(index))
                .map(|child| (child.kind(), &source[child.byte_range()]))
                .collect::<Vec<_>>()
        );
        assert_eq!(csharp_case_increment(expression, source), 0);
    }

    #[test]
    fn call_receiver_extraction_handles_member_and_bare_invocations() {
        assert_eq!(
            csharp_extract_call_receiver("value.Member()"),
            Some("value".into())
        );
        assert_eq!(csharp_extract_call_receiver("Member()"), None);
    }
}
