//! Source-backed shape of native failure handlers.

use crate::analyzer::Range;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerBodyState {
    Empty,
    Nonempty,
    Open(HandlerBodyGap),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerBodyGap {
    SyntaxRecovery,
    MissingBody,
    MissingTryBody,
}

impl HandlerBodyGap {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SyntaxRecovery => "syntax_recovery",
            Self::MissingBody => "missing_body",
            Self::MissingTryBody => "missing_try_body",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerBodyShape {
    pub state: HandlerBodyState,
    pub body: Option<Range>,
    pub try_body: Option<Range>,
}

/// Classify only the exact Java catch clause selected by a normalized fact.
/// A non-comment child, including a declaration or nested callable, makes the
/// immediate handler body nonempty. Comments are never approval to suppress a
/// finding; policy suppression is a separate reviewed decision.
pub fn java_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    let Some(node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(catch.start_byte, catch.end_byte)
        .filter(|node| {
            node.kind() == "catch_clause"
                && node.start_byte() == catch.start_byte
                && node.end_byte() == catch.end_byte
        })
    else {
        return HandlerBodyShape {
            state: HandlerBodyState::Open(HandlerBodyGap::SyntaxRecovery),
            body: None,
            try_body: None,
        };
    };
    let Some(body) = node.child_by_field_name("body") else {
        return HandlerBodyShape {
            state: HandlerBodyState::Open(HandlerBodyGap::MissingBody),
            body: None,
            try_body: None,
        };
    };
    let try_node = node.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "try_statement" | "try_with_resources_statement"
        )
    });
    let try_body = try_node
        .and_then(|parent| parent.child_by_field_name("body"))
        .map(brokk_bifrost_core::analyzer::tree_walk::node_range);
    let body_range = brokk_bifrost_core::analyzer::tree_walk::node_range(body);
    if try_body.is_none() {
        return HandlerBodyShape {
            state: HandlerBodyState::Open(HandlerBodyGap::MissingTryBody),
            body: Some(body_range),
            try_body: None,
        };
    }
    if node.has_error()
        || try_node.is_some_and(|parent| parent.has_error())
        || body.kind() != "block"
        || body.has_error()
    {
        return HandlerBodyShape {
            state: HandlerBodyState::Open(HandlerBodyGap::SyntaxRecovery),
            body: Some(body_range),
            try_body,
        };
    }
    let mut cursor = body.walk();
    let nonempty = body.named_children(&mut cursor).any(|child| {
        !child.is_extra() && !matches!(child.kind(), "line_comment" | "block_comment" | "comment")
    });
    HandlerBodyShape {
        state: if nonempty {
            HandlerBodyState::Nonempty
        } else {
            HandlerBodyState::Empty
        },
        body: Some(body_range),
        try_body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, LanguageDialect};
    use brokk_bifrost_core::analyzer::prepared_syntax::{
        PreparedSourceOrigin, PreparedSyntaxSource,
    };
    use brokk_bifrost_core::analyzer::tree_walk::node_range;
    use brokk_bifrost_jvm::java::declarations::parse_tree;
    use std::sync::Arc;

    fn catch_shapes(source: &str) -> Vec<HandlerBodyShape> {
        let tree = parse_tree(source).expect("Java grammar parses source");
        let catches = brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind(
            tree.root_node(),
            "catch_clause",
        )
        .into_iter()
        .map(node_range)
        .collect::<Vec<_>>();
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::from(source)),
            tree,
            vec![0],
            LanguageDialect::Standard(Language::Java),
            PreparedSourceOrigin::Disk,
            None,
        );
        catches
            .into_iter()
            .map(|catch| java_catch_body_shape(&prepared, catch))
            .collect()
    }

    #[test]
    fn java_empty_catch_shape_is_exact_and_comments_are_not_acceptance() {
        for source in [
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception ignored) {} } }",
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception ignored) { /* ignored */ } } }",
            "class A { void f() { try (Resource r = open()) {} catch (Exception e) {} } }",
            "class A { void f() { try {} catch (IOException | RuntimeException e) {} } }",
        ] {
            let shapes = catch_shapes(source);
            let [shape] = shapes.as_slice() else {
                panic!("one native catch clause: {source}");
            };
            assert_eq!(shape.state, HandlerBodyState::Empty, "{source}");
            assert!(shape.body.is_some(), "{source}");
            assert!(shape.try_body.is_some(), "{source}");
        }
    }

    #[test]
    fn java_catch_with_any_immediate_statement_is_nonempty() {
        for source in [
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception e) { throw e; } } }",
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception e) { int x = 1; } } }",
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception e) { class Inner {} } } }",
        ] {
            let shapes = catch_shapes(source);
            let [shape] = shapes.as_slice() else {
                panic!("one native catch clause: {source}");
            };
            assert_eq!(shape.state, HandlerBodyState::Nonempty, "{source}");
        }
        assert!(
            catch_shapes("class A { void f() { try {} finally {} } }").is_empty(),
            "finally is not a catch handler"
        );
    }

    #[test]
    fn recovered_java_catch_shape_stays_open() {
        let source = "class A { void f() { try {} catch (Exception e) { if ( } } }";
        let shapes = catch_shapes(source);
        let [shape] = shapes.as_slice() else {
            panic!("recovered source retains one catch clause");
        };
        assert_eq!(
            shape.state,
            HandlerBodyState::Open(HandlerBodyGap::SyntaxRecovery)
        );
    }
}
