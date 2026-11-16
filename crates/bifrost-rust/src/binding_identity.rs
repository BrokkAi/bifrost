//! Source-byte identity of Rust pattern binders.
//!
//! The answer is syntax-only. A caller still has to prove that an identifier
//! denotes a value binding rather than a constant or constructor.

use std::collections::{BTreeMap, HashMap};

use brokk_bifrost_core::analyzer::structural::spec::{
    BindingSyntax, BindingWorkBound, BindingWorkLimit,
};
use tree_sitter::Node;

use crate::lexical_scope::{
    RustPatternName, RustStrictPatternIndex, rust_pattern_binding_identifiers,
};

type AnchorAnswer = Result<Option<RustBindingAnchor>, BindingWorkLimit>;
type PatternAnchorAnswer = Result<Option<HashMap<usize, RustBindingAnchor>>, BindingWorkLimit>;

/// One logical binder's source anchor. Multiple alternative spellings of the
/// same `or_pattern` binder have the same anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustBindingAnchor {
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BindingMode {
    Move,
    MoveMut,
    Ref,
    RefMut,
}

/// Return the logical binder anchor, or `None` when an or-pattern's
/// alternatives disagree about binder names or modes. `None` is incomplete
/// evidence; consumers must not interpret it as an absent binding.
pub fn rust_binding_anchor(name: Node<'_>, source: &str) -> Option<RustBindingAnchor> {
    rust_binding_anchor_checked(name, source).ok().flatten()
}

pub fn rust_binding_anchor_checked(name: Node<'_>, source: &str) -> AnchorAnswer {
    let Some(or_pattern) = nearest_or_pattern(name) else {
        return Ok(Some(anchor(name)));
    };
    let mut root = name;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    Ok(or_pattern_anchors(
        or_pattern,
        root,
        source,
        &mut RustStrictPatternIndex::default(),
    )?
    .and_then(|anchors| anchors.get(&name.id()).copied()))
}

/// Calculate each outer disjunction once for a file-local binding request.
/// The count is returned for the bounded-work regression, not persisted.
pub fn rust_binding_anchors(
    root: Node<'_>,
    source: &str,
    binders: &[Node<'_>],
) -> (Vec<Option<RustBindingAnchor>>, usize) {
    let (answers, walks) = rust_binding_anchors_checked(root, source, binders);
    (
        answers
            .into_iter()
            .map(|answer| answer.ok().flatten())
            .collect(),
        walks,
    )
}

pub fn rust_binding_anchors_checked(
    root: Node<'_>,
    source: &str,
    binders: &[Node<'_>],
) -> (Vec<AnchorAnswer>, usize) {
    rust_binding_anchors_with_index(
        root,
        source,
        binders,
        &mut RustStrictPatternIndex::default(),
    )
}

fn rust_binding_anchors_with_index(
    root: Node<'_>,
    source: &str,
    binders: &[Node<'_>],
    index: &mut RustStrictPatternIndex,
) -> (Vec<AnchorAnswer>, usize) {
    let mut groups: HashMap<usize, PatternAnchorAnswer> = HashMap::new();
    let mut walks = 0;
    let anchors = binders
        .iter()
        .map(|binder| {
            let Some(or_pattern) = nearest_or_pattern(*binder) else {
                return Ok(Some(anchor(*binder)));
            };
            let group = groups.entry(or_pattern.id()).or_insert_with(|| {
                walks += 1;
                or_pattern_anchors(or_pattern, root, source, index)
            });
            match group {
                Ok(anchors) => Ok(anchors
                    .as_ref()
                    .and_then(|anchors| anchors.get(&binder.id()).copied())),
                Err(limit) => Err(*limit),
            }
        })
        .collect();
    (anchors, walks)
}

fn or_pattern_anchors(
    or_pattern: Node<'_>,
    root: Node<'_>,
    source: &str,
    index: &mut RustStrictPatternIndex,
) -> PatternAnchorAnswer {
    // A generated disjunction must not make one binder query scale with an
    // unbounded number of alternatives. Above this bound, keep identity Open.
    // Syntax sizing census (2026-11-12): Nushell, 455,312 tracked Rust LOC,
    // hit this bound in 0/153 candidate-bearing outer groups; byte p99/max
    // were 829/854 (about 9.6x maximum headroom). Tantivy hit 0/12 and Tokio
    // 0/6. These samples size ordinary source, not arbitrary generated input.
    if or_pattern
        .end_byte()
        .saturating_sub(or_pattern.start_byte())
        > 8_192
    {
        return Err(BindingWorkLimit {
            bound: BindingWorkBound::OrPatternBytes,
            limit: 8_192,
            value: or_pattern
                .end_byte()
                .saturating_sub(or_pattern.start_byte()),
        });
    }
    let candidates = rust_pattern_binding_identifiers(or_pattern);
    // The same census found Nushell candidate p99/max 16/17: at least 7.5x
    // maximum headroom, with 0/153 hits across 455,312 Rust LOC. Tantivy had
    // 0/12 hits and Tokio 0/6. Count nested disjunctions in their outer group.
    if candidates.len() > 128 {
        return Err(BindingWorkLimit {
            bound: BindingWorkBound::OrPatternCandidates,
            limit: 128,
            value: candidates.len(),
        });
    }
    let mut binders = Vec::new();
    for binder in candidates {
        let Some(raw) = source.get(binder.byte_range()) else {
            return Ok(None);
        };
        let text = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(raw);
        match index.classify_identity_checked(root, source, binder)? {
            RustPatternName::Binding => {
                binders.push((
                    binder,
                    text,
                    binding_mode(binder, or_pattern),
                    anchor(binder),
                ));
            }
            RustPatternName::ValueItem => {}
            RustPatternName::Unknown => return Ok(None),
        }
    }
    // Process nested disjunctions before their enclosing alternatives. The
    // candidate's anchor is rewritten at each level, so repeated occurrences
    // from one inner disjunction count as one binder in the outer alternative.
    let mut pending = vec![(or_pattern, 0usize)];
    let mut disjunctions = Vec::new();
    while let Some((node, depth)) = pending.pop() {
        if node.kind() == "or_pattern" {
            disjunctions.push((depth, node));
        }
        let mut cursor = node.walk();
        pending.extend(
            node.named_children(&mut cursor)
                .map(|child| (child, depth + 1)),
        );
    }
    disjunctions.sort_by_key(|(depth, _)| std::cmp::Reverse(*depth));
    for (_, disjunction) in disjunctions {
        let mut cursor = disjunction.walk();
        let alternatives: Vec<_> = disjunction
            .named_children(&mut cursor)
            .filter(|child| !matches!(child.kind(), "line_comment" | "block_comment"))
            .collect();
        // A leading `|` is a valid single-alternative or-pattern.
        if alternatives.is_empty() {
            return Ok(None);
        }
        let mut expected: Option<BTreeMap<&str, BindingMode>> = None;
        let mut first_by_name: HashMap<&str, RustBindingAnchor> = HashMap::new();
        for alternative in alternatives {
            let mut names = BTreeMap::new();
            for (binder, text, mode, shared) in &binders {
                if alternative.start_byte() <= binder.start_byte()
                    && binder.end_byte() <= alternative.end_byte()
                {
                    if let Some((old_mode, old_anchor)) = names.insert(*text, (*mode, *shared))
                        && (old_mode != *mode || old_anchor != *shared)
                    {
                        return Ok(None);
                    }
                    first_by_name
                        .entry(*text)
                        .and_modify(|first| {
                            if shared.start_byte < first.start_byte {
                                *first = *shared;
                            }
                        })
                        .or_insert(*shared);
                }
            }
            let modes = names
                .into_iter()
                .map(|(name, (mode, _))| (name, mode))
                .collect();
            if expected.as_ref().is_some_and(|previous| previous != &modes) {
                return Ok(None);
            }
            expected = Some(modes);
        }
        for (binder, text, _, shared) in &mut binders {
            if disjunction.start_byte() <= binder.start_byte()
                && binder.end_byte() <= disjunction.end_byte()
                && let Some(first) = first_by_name.get(*text)
            {
                *shared = *first;
            }
        }
    }
    Ok(Some(
        binders
            .into_iter()
            .map(|(binder, _, _, shared)| (binder.id(), shared))
            .collect(),
    ))
}

/// The immediate grammar parent and CodeQL's narrow initializer shape.
pub fn rust_binding_syntax(name: Node<'_>) -> Option<BindingSyntax> {
    let parent = name.parent()?;
    let whole_let_initializer = matches!(parent.kind(), "let_declaration" | "let_condition")
        && parent
            .child_by_field_name("pattern")
            .is_some_and(|pattern| pattern.id() == name.id())
        && parent.child_by_field_name("value").is_some()
        && parent.child_by_field_name("alternative").is_none();
    Some(BindingSyntax {
        immediate_parent_kind: parent.kind().to_owned(),
        whole_let_initializer,
        whole_match_arm_identifier: parent.kind() == "match_pattern"
            && parent.parent().is_some_and(|arm| arm.kind() == "match_arm"),
    })
}

fn nearest_or_pattern(mut node: Node<'_>) -> Option<Node<'_>> {
    let mut outermost = None;
    while let Some(parent) = node.parent() {
        if parent.kind() == "or_pattern" {
            outermost = Some(parent);
        }
        if matches!(
            parent.kind(),
            "let_declaration"
                | "let_condition"
                | "match_arm"
                | "parameter"
                | "closure_parameters"
                | "for_expression"
        ) {
            break;
        }
        node = parent;
    }
    outermost
}

fn binding_mode(mut node: Node<'_>, stop: Node<'_>) -> BindingMode {
    let mut by_ref = false;
    let mut mutable = false;
    if let Some(field) = node.parent()
        && field.kind() == "field_pattern"
        && field
            .child_by_field_name("name")
            .is_some_and(|name| name.id() == node.id())
    {
        for index in 0..field.child_count() {
            if let Some(modifier) = field.child(index) {
                by_ref |= modifier.kind() == "ref";
                mutable |= matches!(modifier.kind(), "mut" | "mutable_specifier");
            }
        }
    }
    while let Some(parent) = node.parent() {
        if parent.id() == stop.id() {
            break;
        }
        by_ref |= parent.kind() == "ref_pattern";
        mutable |= parent.kind() == "mut_pattern";
        node = parent;
    }
    match (by_ref, mutable) {
        (false, false) => BindingMode::Move,
        (false, true) => BindingMode::MoveMut,
        (true, false) => BindingMode::Ref,
        (true, true) => BindingMode::RefMut,
    }
}

fn anchor(node: Node<'_>) -> RustBindingAnchor {
    RustBindingAnchor {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn anchors_named(source: &str, wanted: &str) -> Vec<Option<RustBindingAnchor>> {
        let tree = crate::lexical_scope::parse_rust_tree_uncached(source).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut found = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier"
                && source
                    .get(node.byte_range())
                    .is_some_and(|name| name == wanted || name.strip_prefix("r#") == Some(wanted))
                && nearest_or_pattern(node).is_some()
            {
                found.push((node.start_byte(), rust_binding_anchor(node, source)));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        found.sort_by_key(|(byte, _)| *byte);
        found.into_iter().map(|(_, anchor)| anchor).collect()
    }

    fn checked_pattern_answers(pattern: &str) -> (usize, usize, Vec<AnchorAnswer>) {
        let source = format!("fn f(v: i32) {{ match v {{ {pattern} => () }} }}");
        let tree = crate::lexical_scope::parse_rust_tree_uncached(&source).unwrap();
        assert!(!tree.root_node().has_error(), "{source}");
        let mut pending = vec![tree.root_node()];
        let mut outer = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "or_pattern" {
                outer = Some(node);
                break;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let outer = outer.expect("outer disjunction");
        let binders = rust_pattern_binding_identifiers(outer);
        let (answers, walks) = rust_binding_anchors_checked(tree.root_node(), &source, &binders);
        assert_eq!(walks, 1, "nested candidates share their outer group");
        (
            outer.end_byte() - outer.start_byte(),
            binders.len(),
            answers,
        )
    }

    #[test]
    fn checked_anchor_accepts_exact_byte_and_candidate_bounds() {
        let unpadded = "A(x) /**/ | B(x)";
        let exact_bytes = format!("A(x) /*{}*/ | B(x)", "a".repeat(8_192 - unpadded.len()));
        let exact_candidates = std::iter::repeat_n("A(x)", 128)
            .collect::<Vec<_>>()
            .join("|");
        for (pattern, expected_span, expected_candidates) in
            [(exact_bytes, Some(8_192), 2), (exact_candidates, None, 128)]
        {
            let (span, candidates, answers) = checked_pattern_answers(&pattern);
            if let Some(expected_span) = expected_span {
                assert_eq!(span, expected_span);
            }
            assert_eq!(candidates, expected_candidates);
            assert!(answers.iter().all(|answer| matches!(answer, Ok(Some(_)))));
            assert!(answers.windows(2).all(|pair| pair[0] == pair[1]));
        }
    }

    #[test]
    fn checked_anchor_counts_nested_disjunctions_before_the_candidate_limit() {
        let nested = std::iter::repeat_n("A(x)", 128)
            .collect::<Vec<_>>()
            .join("|");
        let (_, candidates, answers) =
            checked_pattern_answers(&format!("Outer({nested}) | Other(A(x))"));
        assert_eq!(candidates, 129);
        assert_eq!(
            answers,
            vec![
                Err(BindingWorkLimit {
                    bound: BindingWorkBound::OrPatternCandidates,
                    limit: 128,
                    value: 129,
                });
                129
            ]
        );
    }

    #[test]
    fn checked_anchor_reuses_complete_scope_summary() {
        // A wide import exceeded the old classifier's work allowance while
        // the queried or-pattern stayed below both anchor limits. Complete
        // canonical preparation now reuses decided bindings on summary hits.
        let source = format!(
            "use dep::{{{}}}; enum E {{ A(i32), B(i32) }} fn f(v: E) {{ match v {{ E::A(x) | E::B(x) => () }} }}",
            (0..100_010)
                .map(|i| format!("I{i}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let tree = crate::lexical_scope::parse_rust_tree_uncached(&source).unwrap();
        let root = tree.root_node();
        let mut pending = vec![root];
        let mut binders = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "identifier" && source.get(node.byte_range()) == Some("x") {
                binders.push(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        assert_eq!(binders.len(), 2);
        let mut index = RustStrictPatternIndex::default();
        let first = index.classify_identity_checked(root, &source, binders[0]);
        assert_eq!(
            index.source_file_scans, 1,
            "the complete source scope was memoized"
        );
        let repeated = index.classify_identity_checked(root, &source, binders[1]);
        assert_eq!(
            first, repeated,
            "a completed summary must reuse its decision"
        );
        assert_eq!(index.source_file_scans, 1);
        assert_eq!(first, Ok(RustPatternName::Binding));
        assert_eq!(
            index.classify(root, &source, binders[0]),
            RustPatternName::Binding
        );
        let (anchors, _) = rust_binding_anchors_checked(root, &source, &binders);
        assert!(anchors.iter().all(|answer| matches!(answer, Ok(Some(_)))));
    }

    #[test]
    fn or_alternatives_share_first_source_byte_anchor() {
        let source = "enum E { A(i32), B(i32) } fn f(v: E) { match v { E::A(x) | E::B(x) => {} } }";
        let tree = crate::lexical_scope::parse_rust_tree_uncached(source).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut binders = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" && source.get(node.byte_range()) == Some("x") {
                binders.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(binders.len(), 2);
        let first = source.find("(x)").unwrap() + 1;
        assert!(binders.iter().all(|node| rust_binding_anchor(*node, source)
            == Some(RustBindingAnchor {
                start_byte: first,
                end_byte: first + 1
            })));
    }

    #[test]
    fn mismatched_or_alternatives_are_open() {
        let source = "enum E { A(i32), B(i32) } fn f(v: E) { match v { E::A(x) | E::B(y) => {} } }";
        let tree = crate::lexical_scope::parse_rust_tree_uncached(source).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut result = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" && source.get(node.byte_range()) == Some("x") {
                result = Some(rust_binding_anchor(node, source));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(result, Some(None));
    }

    #[test]
    fn nested_or_alternatives_share_one_anchor() {
        let source = "enum E { A(i32), B(i32), C(i32) } fn f(v: E) { match v { E::A(x) | E::B(x) | E::C(x) => {} } }";
        let first = source.find("A(x)").unwrap() + 2;
        assert_eq!(
            anchors_named(source, "x"),
            vec![
                Some(RustBindingAnchor {
                    start_byte: first,
                    end_byte: first + 1
                });
                3
            ]
        );
    }

    #[test]
    fn leading_pipe_has_one_complete_alternative() {
        let source = "fn f(v: i32) { match v { | x => {} } }";
        let first = source.find("| x").unwrap() + 2;
        assert_eq!(
            anchors_named(source, "x"),
            vec![Some(RustBindingAnchor {
                start_byte: first,
                end_byte: first + 1,
            })]
        );
    }

    #[test]
    fn nested_disjunctions_inside_alternatives_share_one_anchor() {
        let source = "fn f(v: i32) { match v { X(A(x) | B(x)) | Y(A(x) | B(x)) => {} } }";
        let first = source.find("A(x)").unwrap() + 2;
        assert_eq!(
            anchors_named(source, "x"),
            vec![
                Some(RustBindingAnchor {
                    start_byte: first,
                    end_byte: first + 1
                });
                4
            ]
        );
    }

    #[test]
    fn comments_are_not_alternatives() {
        let source = "fn f(v: i32) { match v { A(x) | /* explanation */ B(x) => {} } }";
        let first = source.find("A(x)").unwrap() + 2;
        assert_eq!(
            anchors_named(source, "x"),
            vec![
                Some(RustBindingAnchor {
                    start_byte: first,
                    end_byte: first + 1
                });
                2
            ]
        );
    }

    #[test]
    fn long_or_chain_uses_explicit_worklist() {
        let arms = std::iter::repeat_n("A(x)", 256)
            .collect::<Vec<_>>()
            .join(" | ");
        let source = format!("fn f(v: i32) {{ match v {{ {arms} => {{}} }} }}");
        let tree = crate::lexical_scope::parse_rust_tree_uncached(&source).unwrap();
        let first = source.find("A(x)").unwrap() + 2;
        let binder = tree
            .root_node()
            .named_descendant_for_byte_range(first, first + 1)
            .unwrap();
        assert_eq!(rust_binding_anchor(binder, &source), None);
    }

    #[test]
    #[hardwon("#10389: many or-pattern groups share one indexed file scan")]
    fn many_or_groups_share_one_lexical_file_scan() {
        let source = (0..128)
            .map(|i| format!("fn f{i}(v: i32) {{ match v {{ A(x{i}) | B(x{i}) => () }} }}"))
            .collect::<Vec<_>>()
            .join("\n");
        let tree = crate::lexical_scope::parse_rust_tree_uncached(&source).unwrap();
        let root = tree.root_node();
        let mut stack = vec![root];
        let mut binders = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier"
                && source
                    .get(node.byte_range())
                    .is_some_and(|name| name.starts_with('x'))
                && nearest_or_pattern(node).is_some()
            {
                binders.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let mut index = RustStrictPatternIndex::default();
        let (anchors, walks) = rust_binding_anchors_with_index(root, &source, &binders, &mut index);
        assert_eq!(walks, 128);
        assert_eq!(anchors.len(), 256);
        assert_eq!(index.source_file_scans, 1);
    }

    #[test]
    fn batch_of_128_alternatives_walks_the_disjunction_once() {
        let arms = std::iter::repeat_n("A(x)", 128)
            .collect::<Vec<_>>()
            .join(" | ");
        let source = format!("fn f(v: i32) {{ match v {{ {arms} => {{}} }} }}");
        let tree = crate::lexical_scope::parse_rust_tree_uncached(&source).unwrap();
        let root = tree.root_node();
        let mut stack = vec![root];
        let mut binders = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" && source.get(node.byte_range()) == Some("x") {
                binders.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(binders.len(), 128);
        let (answers, walks) = rust_binding_anchors(root, &source, &binders);
        assert_eq!(walks, 1);
        assert!(answers.iter().all(|answer| *answer == answers[0]));
    }

    #[test]
    fn shorthand_field_modifiers_match_explicit_field_modifiers() {
        for modifier in ["ref", "mut"] {
            let source = format!(
                "enum E {{ A {{ x: i32 }}, B {{ x: i32 }} }} fn f(v: E) {{ match v {{ E::A {{ {modifier} x }} | E::B {{ x: {modifier} x }} => {{}} }} }}"
            );
            let tree = crate::lexical_scope::parse_rust_tree_uncached(&source).unwrap();
            let first = source.find(&format!("{modifier} x")).unwrap() + modifier.len() + 1;
            let mut stack = vec![tree.root_node()];
            let mut anchors = Vec::new();
            while let Some(node) = stack.pop() {
                if matches!(node.kind(), "identifier" | "shorthand_field_identifier")
                    && source.get(node.byte_range()) == Some("x")
                    && nearest_or_pattern(node).is_some()
                {
                    anchors.push(rust_binding_anchor(node, &source));
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            assert_eq!(
                anchors,
                vec![
                    Some(RustBindingAnchor {
                        start_byte: first,
                        end_byte: first + 1
                    });
                    2
                ],
                "{modifier}"
            );
        }
    }

    #[test]
    fn constant_alternatives_do_not_change_binder_set() {
        let source = "const C: i32 = 1; const D: i32 = 2; enum E { A((i32,i32)), B((i32,i32)) } fn f(v: E) { match v { E::A((x,C)) | E::B((x,D)) => {} } }";
        let first = source.find("(x,C)").unwrap() + 1;
        assert_eq!(
            anchors_named(source, "x"),
            vec![
                Some(RustBindingAnchor {
                    start_byte: first,
                    end_byte: first + 1
                });
                2
            ]
        );
    }

    #[test]
    fn raw_name_and_reference_destructuring_preserve_binding_mode() {
        let raw = "enum E { A(i32), B(i32) } fn f(v: E) { match v { E::A(r#x) | E::B(x) => {} } }";
        let first = raw.find("r#x").unwrap();
        assert_eq!(
            anchors_named(raw, "x"),
            vec![
                Some(RustBindingAnchor {
                    start_byte: first,
                    end_byte: first + 3
                });
                2
            ]
        );
        let by_value = "enum E { A(&'static i32), B(i32) } fn f(v: E) { match v { E::A(&x) | E::B(x) => {} } }";
        let first = by_value.find("&x").unwrap() + 1;
        assert_eq!(
            anchors_named(by_value, "x"),
            vec![
                Some(RustBindingAnchor {
                    start_byte: first,
                    end_byte: first + 1
                });
                2
            ]
        );
    }

    #[test]
    fn initializer_is_only_the_whole_identifier_let_pattern() {
        let source = "fn f(v: Option<(i32,i32)>) { let whole = 1; let (left,right) = (1,2); let Some(else_name) = v else { return }; if let if_whole = 1 {} while let while_whole = 1 { break; } }";
        let tree = crate::lexical_scope::parse_rust_tree_uncached(source).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut facts = BTreeMap::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" {
                let name = source.get(node.byte_range()).unwrap();
                if matches!(
                    name,
                    "whole" | "left" | "right" | "else_name" | "if_whole" | "while_whole"
                ) {
                    facts.insert(
                        name,
                        rust_binding_syntax(node).unwrap().whole_let_initializer,
                    );
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(facts.get("whole"), Some(&true));
        assert_eq!(facts.get("left"), Some(&false));
        assert_eq!(facts.get("right"), Some(&false));
        assert_eq!(facts.get("else_name"), Some(&false));
        assert_eq!(facts.get("if_whole"), Some(&true));
        assert_eq!(facts.get("while_whole"), Some(&true));
    }

    #[test]
    fn match_arm_parent_shape_distinguishes_whole_from_nested_identifier() {
        let source =
            "fn f(v: Option<i32>) { match v { UPPERCASE => {}, Some(NESTED) => {}, _ => {} } }";
        let tree = crate::lexical_scope::parse_rust_tree_uncached(source).unwrap();
        let mut stack = vec![tree.root_node()];
        let mut parents = BTreeMap::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" {
                let name = source.get(node.byte_range()).unwrap();
                if matches!(name, "UPPERCASE" | "NESTED") {
                    parents.insert(name, node.parent().unwrap().kind());
                    assert_eq!(
                        rust_binding_syntax(node)
                            .unwrap()
                            .whole_match_arm_identifier,
                        name == "UPPERCASE"
                    );
                    if name == "UPPERCASE" {
                        assert_eq!(node.parent().unwrap().parent().unwrap().kind(), "match_arm");
                    }
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(parents.get("UPPERCASE"), Some(&"match_pattern"));
        assert_eq!(parents.get("NESTED"), Some(&"tuple_struct_pattern"));
    }
}
