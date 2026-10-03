//! Source-backed shape of native failure handlers.

use crate::analyzer::Range;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use tree_sitter::Node;

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

/// How a grammar attaches the handler body to the handler node.
#[derive(Clone, Copy)]
enum HandlerBody {
    /// The body is this required field.
    Field(&'static str),
    /// The body is the unique unnamed child of `body_kind` (Python's
    /// `except_clause` suite).
    OnlyChild,
    /// The body is an optional field or unique child of `body_kind` that the
    /// grammar omits when the handler has no statements (Kotlin `catch`,
    /// Ruby `rescue`). Its absence in recovery-free syntax is an empty body.
    OmittedWhenEmpty(Option<&'static str>),
}

/// Native syntax of one language's failure handler. Each language supplies
/// data rather than a mode: which node is the handler, which node owns the
/// protected body, how the handler body is found, and which immediate body
/// children perform no work.
struct HandlerSyntax {
    handler_kinds: &'static [&'static str],
    try_kinds: &'static [&'static str],
    /// The protected body's field on the try node; `None` when the grammar
    /// places protected statements directly in the try node (Ruby `begin`).
    try_body_field: Option<&'static str>,
    body_kind: &'static str,
    body: HandlerBody,
    is_no_op: fn(Node<'_>) -> bool,
}

const JAVA: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement", "try_with_resources_statement"],
    try_body_field: Some("body"),
    body_kind: "block",
    body: HandlerBody::Field("body"),
    is_no_op: |child| matches!(child.kind(), "line_comment" | "block_comment" | "comment"),
};

const JS_TS: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "statement_block",
    body: HandlerBody::Field("body"),
    // `;` is an empty statement: it evaluates nothing.
    is_no_op: |child| matches!(child.kind(), "comment" | "empty_statement"),
};

const PYTHON: HandlerSyntax = HandlerSyntax {
    // tree-sitter-python 0.25 spells `except*` as the same node kind.
    handler_kinds: &["except_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "block",
    body: HandlerBody::OnlyChild,
    // A suite cannot be syntactically empty, so `pass` and a bare `...` are
    // the language's spellings of an empty handler. Any other expression,
    // including a bare string, is treated as work.
    is_no_op: |child| match child.kind() {
        "comment" | "pass_statement" => true,
        "expression_statement" => {
            child.named_child_count() == 1
                && child
                    .named_child(0)
                    .is_some_and(|value| value.kind() == "ellipsis")
        }
        _ => false,
    },
};

const CSHARP: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "block",
    body: HandlerBody::Field("body"),
    is_no_op: |child| matches!(child.kind(), "comment" | "empty_statement"),
};

const PHP: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "compound_statement",
    body: HandlerBody::Field("body"),
    is_no_op: |child| matches!(child.kind(), "comment" | "empty_statement"),
};

const CPP: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "compound_statement",
    body: HandlerBody::Field("body"),
    // The grammar spells a lone `;` as an expression statement with no
    // expression.
    is_no_op: |child| {
        child.kind() == "comment"
            || (child.kind() == "expression_statement" && child.named_child_count() == 0)
    },
};

const KOTLIN: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_block"],
    try_kinds: &["try_expression"],
    // The protected block is an unnamed `statements` child that is also
    // omitted when empty; the catch clause's own position proves the try.
    try_body_field: None,
    body_kind: "statements",
    body: HandlerBody::OmittedWhenEmpty(None),
    is_no_op: |child| matches!(child.kind(), "line_comment" | "multiline_comment"),
};

const RUBY: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["rescue"],
    // A method, block or class body with `rescue` is an implicit `begin`.
    try_kinds: &["begin", "body_statement"],
    try_body_field: None,
    body_kind: "then",
    body: HandlerBody::OmittedWhenEmpty(Some("body")),
    is_no_op: |child| matches!(child.kind(), "comment" | "empty_statement"),
};

/// Classify only the exact Java catch clause selected by a normalized fact.
/// A non-comment child, including a declaration or nested callable, makes the
/// immediate handler body nonempty. Comments are never approval to suppress a
/// finding; policy suppression is a separate reviewed decision.
pub fn java_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &JAVA)
}

/// Classify an exact JavaScript or TypeScript `catch` clause, including an
/// optional-binding `catch {}`. Only the syntactic handler is classified; a
/// promise rejection callback is not a `catch` clause.
pub fn js_ts_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &JS_TS)
}

/// Classify an exact Python `except` or `except*` clause. A suite of only
/// `pass`, `...` and comments is empty.
pub fn python_except_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &PYTHON)
}

/// Classify an exact C# `catch` clause, including one with a `when` filter:
/// a filter selects the exception but does not handle it.
pub fn csharp_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &CSHARP)
}

/// Classify an exact PHP `catch` clause.
pub fn php_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &PHP)
}

/// Classify an exact C++ `catch` clause, including `catch (...)`.
pub fn cpp_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &CPP)
}

/// Classify an exact Kotlin `catch` block. An expression-position `try`
/// whose catch block is empty evaluates to `Unit` there; the handler is
/// still empty.
pub fn kotlin_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &KOTLIN)
}

/// Classify an exact Ruby `rescue` clause of a `begin` or implicit-begin
/// body. The `rescue` modifier (`value rescue nil`) is a different node.
pub fn ruby_rescue_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &RUBY)
}

fn handler_body_shape(
    syntax: &PreparedSyntaxTree,
    catch: Range,
    grammar: &HandlerSyntax,
) -> HandlerBodyShape {
    let open = |gap, body, try_body| HandlerBodyShape {
        state: HandlerBodyState::Open(gap),
        body,
        try_body,
    };
    let Some(node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(catch.start_byte, catch.end_byte)
        .filter(|node| {
            grammar.handler_kinds.contains(&node.kind())
                && node.start_byte() == catch.start_byte
                && node.end_byte() == catch.end_byte
        })
    else {
        return open(HandlerBodyGap::SyntaxRecovery, None, None);
    };
    // A second body child is recovery, not a choice between bodies.
    fn unique_child<'tree>(node: Node<'tree>, kind: &str) -> Result<Option<Node<'tree>>, ()> {
        let mut cursor = node.walk();
        let mut children = node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == kind);
        let first = children.next();
        if children.next().is_some() {
            Err(())
        } else {
            Ok(first)
        }
    }
    let body = match grammar.body {
        HandlerBody::Field(field) => {
            let Some(body) = node.child_by_field_name(field) else {
                return open(HandlerBodyGap::MissingBody, None, None);
            };
            Some(body)
        }
        HandlerBody::OnlyChild => match unique_child(node, grammar.body_kind) {
            Ok(Some(body)) => Some(body),
            Ok(None) => return open(HandlerBodyGap::MissingBody, None, None),
            Err(()) => return open(HandlerBodyGap::SyntaxRecovery, None, None),
        },
        HandlerBody::OmittedWhenEmpty(Some(field)) => node.child_by_field_name(field),
        HandlerBody::OmittedWhenEmpty(None) => match unique_child(node, grammar.body_kind) {
            Ok(body) => body,
            Err(()) => return open(HandlerBodyGap::SyntaxRecovery, None, None),
        },
    };
    let try_node = node
        .parent()
        .filter(|parent| grammar.try_kinds.contains(&parent.kind()));
    let try_body = match grammar.try_body_field {
        Some(field) => try_node
            .and_then(|parent| parent.child_by_field_name(field))
            .map(brokk_bifrost_core::analyzer::tree_walk::node_range),
        None => try_node.map(brokk_bifrost_core::analyzer::tree_walk::node_range),
    };
    let body_range = body.map(brokk_bifrost_core::analyzer::tree_walk::node_range);
    if try_body.is_none() {
        return open(HandlerBodyGap::MissingTryBody, body_range, None);
    }
    // Recovery can leave a clean-looking handler inside an ERROR node, for
    // example when tree-sitter-ruby reads `rescue E => end` as a variable
    // named `end`. Any ERROR ancestor makes the handler's shape unreliable.
    let mut ancestor = node.parent();
    let mut under_error = false;
    while let Some(parent) = ancestor {
        if parent.is_error() {
            under_error = true;
            break;
        }
        ancestor = parent.parent();
    }
    if under_error
        || node.has_error()
        || try_node.is_some_and(|parent| parent.has_error())
        || body.is_some_and(|body| body.kind() != grammar.body_kind || body.has_error())
    {
        return open(HandlerBodyGap::SyntaxRecovery, body_range, try_body);
    }
    let Some(body) = body else {
        return HandlerBodyShape {
            state: HandlerBodyState::Empty,
            body: None,
            try_body,
        };
    };
    let mut cursor = body.walk();
    let nonempty = body
        .named_children(&mut cursor)
        .any(|child| !child.is_extra() && !(grammar.is_no_op)(child));
    HandlerBodyShape {
        state: if nonempty {
            HandlerBodyState::Nonempty
        } else {
            HandlerBodyState::Empty
        },
        body: body_range,
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

    fn shapes_with(
        source: &str,
        language: tree_sitter::Language,
        dialect: Language,
        handler_kind: &str,
        classify: fn(&PreparedSyntaxTree, Range) -> HandlerBodyShape,
    ) -> Vec<HandlerBodyShape> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("grammar loads");
        let tree = parser.parse(source, None).expect("source parses");
        let handlers = brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind(
            tree.root_node(),
            handler_kind,
        )
        .into_iter()
        .map(node_range)
        .collect::<Vec<_>>();
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::from(source)),
            tree,
            vec![0],
            LanguageDialect::Standard(dialect),
            PreparedSourceOrigin::Disk,
            None,
        );
        handlers
            .into_iter()
            .map(|handler| classify(&prepared, handler))
            .collect()
    }

    fn js_states(source: &str) -> Vec<HandlerBodyState> {
        shapes_with(
            source,
            tree_sitter_javascript::LANGUAGE.into(),
            Language::JavaScript,
            "catch_clause",
            js_ts_catch_body_shape,
        )
        .into_iter()
        .map(|shape| shape.state)
        .collect()
    }

    fn python_states(source: &str) -> Vec<HandlerBodyState> {
        shapes_with(
            source,
            tree_sitter_python::LANGUAGE.into(),
            Language::Python,
            "except_clause",
            python_except_body_shape,
        )
        .into_iter()
        .map(|shape| shape.state)
        .collect()
    }

    #[test]
    fn js_ts_catch_shapes_distinguish_no_op_from_work() {
        use HandlerBodyState::{Empty, Nonempty};
        for (source, expected) in [
            ("try { f(); } catch (e) {}", Empty),
            ("try { f(); } catch {}", Empty),
            ("try { f(); } catch (e) { /* ignored */ ; }", Empty),
            ("try { f(); } catch ({ message }) {}", Empty),
            ("try { f(); } catch (e) { log(e); }", Nonempty),
            ("try { f(); } catch (e) { function later() {} }", Nonempty),
        ] {
            assert_eq!(js_states(source), vec![expected], "{source}");
        }
        let typed = shapes_with(
            "try { f(); } catch (e: unknown) {}",
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::TypeScript,
            "catch_clause",
            js_ts_catch_body_shape,
        );
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].state, Empty);
        assert!(js_states("try { f(); } finally {}").is_empty());
    }

    #[test]
    fn python_except_shapes_treat_pass_and_ellipsis_as_empty() {
        use HandlerBodyState::{Empty, Nonempty};
        for (source, expected) in [
            ("try:\n    f()\nexcept ValueError:\n    pass\n", Empty),
            ("try:\n    f()\nexcept:\n    ...\n", Empty),
            (
                "try:\n    f()\nexcept* OSError:\n    pass  # ignored\n",
                Empty,
            ),
            (
                "try:\n    f()\nexcept (A, B) as e:\n    pass\n    pass\n",
                Empty,
            ),
            ("try:\n    f()\nexcept ValueError:\n    log()\n", Nonempty),
            (
                "try:\n    f()\nexcept ValueError:\n    \"explained\"\n",
                Nonempty,
            ),
            ("try:\n    f()\nexcept ValueError:\n    raise\n", Nonempty),
            (
                "for x in y:\n    try:\n        f()\n    except ValueError:\n        continue\n",
                Nonempty,
            ),
        ] {
            assert_eq!(python_states(source), vec![expected], "{source}");
        }
        assert!(python_states("try:\n    f()\nfinally:\n    pass\n").is_empty());
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
