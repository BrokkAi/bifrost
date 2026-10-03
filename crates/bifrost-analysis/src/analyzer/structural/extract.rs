//! Fact extraction: parse one file and normalize it through a language spec.
//!
//! The tree is parsed from the in-memory source, walked iteratively (explicit
//! stack, per the repo's no-recursive-tree-walk rule), and dropped before
//! returning — only the flat fact arena survives, mirroring how the usage
//! inverted-edge builders treat their per-file trees.

use super::facts::FileFacts;
use super::spec::{CompiledKinds, StructuralSpec};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
use brokk_bifrost_core::analyzer::structural::collector::{
    StructuralFactCollector, StructuralFactCollectorStop,
};
use tree_sitter::{Language as TsLanguage, Node, ParseOptions, Parser};

#[derive(Debug)]
pub(crate) enum LimitedFileFacts {
    Complete(FileFacts),
    /// Complete facts plus the exact tree-sitter-node to normalized-fact
    /// mapping from the tree that was passed to the extraction pass. The
    /// index is intentionally returned only for callers that retain that
    /// exact tree, such as semantic lowering of a prepared syntax snapshot.
    CompleteWithNodeIndex {
        facts: FileFacts,
        node_ids: HashMap<usize, u32>,
    },
    Exceeded {
        minimum_fact_nodes: usize,
    },
    Cancelled,
    Unavailable,
}

/// Parse `source` with `grammar` and extract normalized facts through `spec`.
/// Returns `None` only when the parser cannot be constructed; an empty source
/// yields an empty fact set (#1459), and parse *errors* still yield facts for
/// the recoverable parts of the tree (tree-sitter trees are total).
pub fn extract_file_facts(
    spec: &dyn StructuralSpec,
    grammar: &TsLanguage,
    source: &str,
) -> Option<FileFacts> {
    match extract_file_facts_limited(spec, grammar, source, usize::MAX, None) {
        LimitedFileFacts::Complete(facts) => Some(facts),
        LimitedFileFacts::CompleteWithNodeIndex { facts, .. } => Some(facts),
        LimitedFileFacts::Exceeded { .. }
        | LimitedFileFacts::Cancelled
        | LimitedFileFacts::Unavailable => None,
    }
}

/// Extract normalized facts while refusing to materialize more than
/// `max_fact_nodes` normalized nodes plus semantic role edges. The source-byte
/// admission gate remains the bound on parser and raw-syntax work; this
/// function makes both normalized arenas cancellable and bounded before
/// allocation can run past the shared CodeQuery budget.
pub(crate) fn extract_file_facts_limited(
    spec: &dyn StructuralSpec,
    grammar: &TsLanguage,
    source: &str,
    max_fact_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> LimitedFileFacts {
    extract_file_facts_limited_with_tree(
        spec,
        grammar,
        source,
        None,
        max_fact_nodes,
        cancellation,
        false,
    )
}

/// Extract normalized facts from an already-prepared tree and retain the
/// exact mapping from tree-sitter node ids to normalized fact ids. This is the
/// same extraction pass used by [`extract_file_facts_limited`]; accepting the
/// prepared tree is what makes the returned ids directly joinable to a
/// semantic producer without ranges, names, or a second parser tree.
pub(crate) fn extract_file_facts_from_tree_limited(
    spec: &dyn StructuralSpec,
    grammar: &TsLanguage,
    tree: &tree_sitter::Tree,
    source: &str,
    max_fact_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> LimitedFileFacts {
    extract_file_facts_limited_with_tree(
        spec,
        grammar,
        source,
        Some(tree),
        max_fact_nodes,
        cancellation,
        true,
    )
}

fn extract_file_facts_limited_with_tree(
    spec: &dyn StructuralSpec,
    grammar: &TsLanguage,
    source: &str,
    prepared_tree: Option<&tree_sitter::Tree>,
    max_fact_nodes: usize,
    cancellation: Option<&CancellationToken>,
    include_node_index: bool,
) -> LimitedFileFacts {
    // An empty source is a legitimate file with zero facts (empty __init__.py
    // and placeholder .ts fixtures are real workspace members). Rejecting it
    // as Unavailable made one empty file abort the whole provider index and
    // demote its language slice to scan mode for the session (#1459); the
    // general extraction path below handles it as an empty tree.
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return LimitedFileFacts::Cancelled;
    }
    if max_fact_nodes == 0 {
        return LimitedFileFacts::Exceeded {
            minimum_fact_nodes: 1,
        };
    }
    let parsed_tree = if prepared_tree.is_none() {
        let mut parser = Parser::new();
        if parser.set_language(grammar).is_err() {
            return LimitedFileFacts::Unavailable;
        }
        // C# hides preprocessor directive lines and inactive conditional
        // branches from the parser; every other language parses the whole
        // file.
        if let Some(ranges) = spec.parser_included_ranges(source)
            && parser.set_included_ranges(&ranges).is_err()
        {
            return LimitedFileFacts::Unavailable;
        }
        let parsed = if let Some(cancellation) = cancellation {
            let mut read = |offset: usize, _| &source.as_bytes()[offset..];
            let mut progress = |_: &tree_sitter::ParseState| cancellation.is_cancelled();
            parser.parse_with_options(
                &mut read,
                None,
                Some(ParseOptions::new().progress_callback(&mut progress)),
            )
        } else {
            parser.parse(source, None)
        };
        // Go's grammar cannot represent `new(expr)`; the repaired tree is the
        // one its facts must come from.
        parsed.map(|tree| {
            spec.reparse_grammar_gap(source, &tree, cancellation)
                .unwrap_or(tree)
        })
    } else {
        None
    };
    let Some(tree) = prepared_tree.or(parsed_tree.as_ref()) else {
        return if cancellation.is_some_and(CancellationToken::is_cancelled) {
            LimitedFileFacts::Cancelled
        } else {
            LimitedFileFacts::Unavailable
        };
    };
    let compiled = CompiledKinds::compile(grammar, spec.kind_table());
    // One per-file scan, before any call site is classified: a language whose
    // call shapes depend on file-wide facts (C/C++ function-like macros) reads
    // the whole tree once here instead of once per call.
    let call_site_context = spec.call_site_context(tree.root_node(), source);
    let mut source_facts = PrimarySourceFactCollector::new(source);

    // The parser and the iterative walk remain language-owned. The collector
    // assembles rows at each event and retains exact AST node keys for role
    // targets until the walk is complete.
    let mut collector = StructuralFactCollector::new(
        spec,
        source,
        &call_site_context,
        brokk_bifrost_core::analyzer::tree_walk::ParentIndex::unindexed(),
        max_fact_nodes,
        cancellation,
    );
    let mut node_ids = include_node_index.then(HashMap::default);

    enum ExtractionFrame<'tree> {
        Enter(Node<'tree>, Option<u32>),
    }

    let mut stack = vec![ExtractionFrame::Enter(tree.root_node(), None)];
    while let Some(frame) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return LimitedFileFacts::Cancelled;
        }
        match frame {
            ExtractionFrame::Enter(node, enclosing) => {
                collector.record_children(node);
                let mut parent_for_children = enclosing;
                if node.is_named()
                    && let Some(kind) = compiled.kind_of(&node)
                    && spec.should_extract(node, kind)
                {
                    let kind = spec.refine_kind(
                        node,
                        kind,
                        enclosing.map(|id| collector.normalized_kind(id)),
                        source,
                        &call_site_context,
                    );
                    let fact_id = match collector.enter(node, kind, enclosing, &mut source_facts) {
                        Ok(fact_id) => fact_id,
                        Err(StructuralFactCollectorStop::Exceeded) => {
                            return LimitedFileFacts::Exceeded {
                                minimum_fact_nodes: max_fact_nodes.saturating_add(1),
                            };
                        }
                        Err(StructuralFactCollectorStop::Cancelled) => {
                            return LimitedFileFacts::Cancelled;
                        }
                    };
                    if let Some(node_ids) = node_ids.as_mut() {
                        assert!(node_ids.insert(node.id(), fact_id).is_none());
                    }
                    let mut sink = collector.role_sink(&mut source_facts);
                    spec.extract(node, kind, &mut sink);
                    match collector.accept_roles(fact_id, sink.into_parts()) {
                        Ok(()) => {}
                        Err(StructuralFactCollectorStop::Exceeded) => {
                            return LimitedFileFacts::Exceeded {
                                minimum_fact_nodes: max_fact_nodes.saturating_add(1),
                            };
                        }
                        Err(StructuralFactCollectorStop::Cancelled) => {
                            return LimitedFileFacts::Cancelled;
                        }
                    }
                    parent_for_children = Some(fact_id);
                }
                // Push the children through one cursor rather than indexing
                // them. `Node::named_child(i)` walks the child list from the
                // start, so visiting a node's children by index is quadratic in
                // its child count: on goqu's vendored 248k-line
                // `sqlite3-binding.c` this walk was 99.6% of process CPU and
                // timed out 100 probes. Popping still visits children in source
                // order, so the traversal is unchanged.
                brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed_as(
                    node,
                    &mut stack,
                    |child| ExtractionFrame::Enter(child, parent_for_children),
                );
            }
        }
    }

    let rows = match collector.finish() {
        Ok(rows) => rows,
        Err(StructuralFactCollectorStop::Exceeded) => {
            return LimitedFileFacts::Exceeded {
                minimum_fact_nodes: max_fact_nodes.saturating_add(1),
            };
        }
        Err(StructuralFactCollectorStop::Cancelled) => return LimitedFileFacts::Cancelled,
    };

    let facts = FileFacts::from_source_and_rows(source.to_string(), source_facts.finish(), rows);
    if let Some(node_ids) = node_ids {
        LimitedFileFacts::CompleteWithNodeIndex { facts, node_ids }
    } else {
        LimitedFileFacts::Complete(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::super::occurrences::OccurrenceRole;
    use super::*;

    /// #1459: an empty file is a legitimate workspace member with zero facts
    /// (empty `__init__.py`, placeholder `.ts` fixtures). It must extract as
    /// an empty fact set, not `Unavailable` -- the all-or-nothing index build
    /// aborts the whole provider slice on any unavailable file.
    #[test]
    fn empty_source_extracts_zero_facts() {
        let spec = &brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC;
        let grammar = tree_sitter_python::LANGUAGE.into();
        let facts = extract_file_facts(spec, &grammar, "").expect("empty source yields facts");
        assert_eq!(facts.work_item_count(), 0);
        assert_eq!(facts.source(), "");
        let rows = facts
            .persisted_rows()
            .expect("empty facts convert to relational rows");
        let decoded = FileFacts::from_persisted_rows(String::new(), rows)
            .expect("empty relational facts hydrate");
        assert_eq!(decoded.work_item_count(), 0);
    }

    #[test]
    fn role_target_to_forward_child_resolves_after_one_collection_walk() {
        use super::super::kinds::{NormalizedKind, Role};

        let spec = &brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC;
        let grammar = tree_sitter_python::LANGUAGE.into();
        let source = "def call(value):\n    return target(value)\n";
        let facts = extract_file_facts(spec, &grammar, source).expect("python fixture extracts");
        let call_id = facts
            .nodes()
            .iter()
            .position(|node| node.kind == NormalizedKind::Call)
            .expect("call fact") as u32;
        let callee = facts
            .role_targets(call_id, Role::Callee)
            .next()
            .expect("callee role");
        let target_id = callee.node.expect("callee identifier is normalized");

        assert!(target_id > call_id, "callee is a forward child fact");
        assert_eq!(facts.node(target_id).kind, NormalizedKind::Identifier);
        assert_eq!(callee.span.text(source), "target");
        assert_eq!(
            facts.node(call_id).name.map(|span| span.text(source)),
            Some("target")
        );
    }

    /// An adapter must emit only the occurrence roles its table declares: a
    /// table and an extraction pass that disagree would turn "we cannot
    /// classify this" into a clean, empty, and wrong answer (#1473).
    ///
    /// PHP is the narrowest table left in the workspace -- it declares
    /// `member_position` and nothing else -- so it is where an undeclared
    /// emission would show. This guard used to point at Scala, which declared
    /// no roles at all until #1597 graduated it.
    #[test]
    fn an_adapter_emits_only_the_occurrence_roles_it_declares() {
        let spec = &brokk_bifrost_php::structural::PHP_STRUCTURAL_SPEC;
        let support = spec.occurrence_role_support();
        assert!(support.is_supported(OccurrenceRole::MemberPosition));

        let grammar = tree_sitter_php::LANGUAGE_PHP.into();
        let source = concat!(
            "<?php\n",
            "class Widget {\n",
            "    public function render(Helper $helper): int {\n",
            "        return $helper->build();\n",
            "    }\n",
            "}\n",
        );
        let facts = extract_file_facts(spec, &grammar, source).expect("php fixture extracts facts");
        assert!(facts.nodes().len() > 1, "fixture should produce facts");
        assert!(
            facts.occurrence_role_count() > 0,
            "the fixture must exercise the classifier"
        );
        for id in 0..facts.nodes().len() as u32 {
            for role in facts.occurrence_roles(id) {
                assert!(
                    support.is_supported(*role),
                    "php emitted undeclared role {role:?}"
                );
            }
        }
    }

    /// Occurrence roles survive relational persistence with their node addressing
    /// intact, which is the property the `(content identity, fact id)` join in
    /// later milestones depends on.
    #[test]
    fn extracted_occurrence_roles_round_trip_through_the_snapshot_codec() {
        let spec = &brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC;
        let grammar = tree_sitter_python::LANGUAGE.into();
        let source = "def render(label):\n    return label\n";
        let facts = extract_file_facts(spec, &grammar, source).expect("python fixture extracts");
        assert!(facts.occurrence_role_count() > 0);

        let rows = facts
            .persisted_rows()
            .expect("facts become relational rows");
        let decoded = FileFacts::from_persisted_rows(source.to_owned(), rows)
            .expect("relational facts hydrate");
        for id in 0..facts.nodes().len() as u32 {
            assert_eq!(decoded.occurrence_roles(id), facts.occurrence_roles(id));
        }
    }

    #[test]
    fn embedded_facts_preserve_identity_containment_limits_and_snapshots() {
        let spec = &brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC;
        let grammar = tree_sitter_python::LANGUAGE.into();
        let source = concat!(
            "class Widget:\n",
            "    pass\n",
            "def render(widget: \"Widget\") -> None:\n",
            "    pass\n",
        );
        let facts = extract_file_facts(spec, &grammar, source).expect("python fixture extracts");
        let deferred_start = source.find("Widget\"").expect("deferred Widget");
        let embedded_id = facts
            .nodes()
            .iter()
            .position(|node| {
                node.kind == super::super::kinds::NormalizedKind::Identifier
                    && node.range.start_byte == deferred_start
                    && node.range.end_byte == deferred_start + "Widget".len()
            })
            .expect("embedded identifier fact") as u32;
        let parent = facts.node(embedded_id).parent.expect("embedded parent");
        assert_eq!(
            facts.node(parent).kind,
            super::super::kinds::NormalizedKind::StringLiteral
        );
        assert!(facts.is_ancestor(parent, embedded_id));
        assert_eq!(
            facts.occurrence_roles(embedded_id),
            &[OccurrenceRole::TypeOperand]
        );

        let repeated = extract_file_facts(spec, &grammar, source).expect("repeat extracts");
        assert_eq!(
            repeated.node(embedded_id).range,
            facts.node(embedded_id).range
        );
        assert_eq!(
            repeated.occurrence_roles(embedded_id),
            facts.occurrence_roles(embedded_id)
        );

        let rows = facts
            .persisted_rows()
            .expect("facts become relational rows");
        let decoded = FileFacts::from_persisted_rows(source.to_owned(), rows)
            .expect("relational facts hydrate");
        assert_eq!(
            decoded.node(embedded_id).range,
            facts.node(embedded_id).range
        );
        assert_eq!(
            decoded.occurrence_roles(embedded_id),
            facts.occurrence_roles(embedded_id)
        );

        assert!(matches!(
            extract_file_facts_limited(spec, &grammar, source, facts.nodes().len() - 1, None,),
            LimitedFileFacts::Exceeded { .. }
        ));
    }
}
