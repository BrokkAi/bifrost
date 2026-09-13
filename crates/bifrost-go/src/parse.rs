//! Go parsing: the grammar plus the recovery Go's own rules require.
//!
//! Go has no `new` keyword. `new` is a predeclared identifier and `new(x)` is
//! an ordinary call expression; Go 1.26 makes that visible by allowing any
//! expression as the argument rather than only a type. tree-sitter-go 0.25
//! approximates the builtin as the older language used it: `new` and `make`
//! are keyword tokens whose call takes a `special_argument_list` that must
//! open with a `_type`. `new(PackageURL(p))` and
//! `new(max(oldCommitIndex, consistentIndex))` do not satisfy that rule, so
//! the parse fails there and error recovery swallows the conversion's type
//! name -- and, in the assignment form, the whole statement that follows
//! (issue #3325).
//!
//! The repair applies Go's own rule exactly where the grammar's approximation
//! broke: the `new` token is demoted to the ordinary identifier it always was.
//! A second parse hides one interior byte of that token through tree-sitter
//! included ranges. The lexer reads the included ranges as a single stream, so
//! the surviving `n` and `w` lex as one identifier token instead of the `new`
//! keyword, and the call takes the grammar's ordinary
//! `function`/`argument_list` branch. Included ranges select bytes of the
//! original source and never move them, so the demoted token still spans
//! `new`'s exact byte range -- it reads back as `new` from the file, and every
//! other node keeps its raw-file offsets.
//!
//! Only `new` is demoted. Go 1.26 did not extend `make`, so a `make` call the
//! special form cannot parse is genuinely malformed and keeps its ERROR node,
//! as does a truncated `new(` that no reading can complete.
//!
//! Every Go parse in Bifrost goes through [`parse_go`], [`go_parse_spec`], or
//! [`go_reparse_grammar_gap`]. A declaration walk and a usage scan that parsed
//! the same file differently would disagree about node ranges, which is why
//! the repair travels with the grammar rather than with one caller.

use brokk_bifrost_core::analyzer::common::{
    node_source_text, parse_source_ranges_with_cancellation,
};
use brokk_bifrost_core::analyzer::usages::parsed_tree::ParseSpec;
use brokk_bifrost_core::cancellation::CancellationToken;
use tree_sitter::{Node, Tree};

/// The predeclared identifier tree-sitter-go lexes as a keyword.
const GO_NEW: &str = "new";

/// How many demotion rounds one file gets.
///
/// A round hides every `new` token the current tree shows as an identifier the
/// special form did not consume -- all of them at once, not one per round. A
/// further round is needed only when hiding those reveals a `new` the previous
/// parse had buried in a type position, which is what `new(new(f(x)))` nesting
/// does: the grammar puts alternate levels in the type slot, so each round
/// exposes the next layer. That converges in two rounds at every nesting depth
/// measured (2, 16, 32, 64 and 128), so this cap is headroom rather than a
/// depth limit.
///
/// It is still a cap, not a proof. A file that would need more rounds keeps
/// whatever ERROR nodes it still has; the repair never erases an error it
/// could not account for, and never claims support for arbitrary depth.
const MAX_DEMOTION_ROUNDS: usize = 4;

/// Parse Go source with the Go 1.26 `new(expr)` repair applied.
pub fn parse_go(source: &str) -> Option<Tree> {
    parse_go_with_cancellation(source, None)
}

/// Cancellation-aware form of [`parse_go`].
pub fn parse_go_with_cancellation(
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<Tree> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return None;
    }
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    let tree = if let Some(cancellation) = cancellation {
        let mut read = |offset: usize, _| &source.as_bytes()[offset..];
        let mut progress = |_: &tree_sitter::ParseState| cancellation.is_cancelled();
        parser.parse_with_options(
            &mut read,
            None,
            Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
        )
    } else {
        parser.parse(source, None)
    }?;
    Some(go_reparse_grammar_gap(source, &tree, cancellation).unwrap_or(tree))
}

/// The Go parse spec: the grammar plus the `new(expr)` repair.
///
/// This is the form the language-blind parse helpers take, so a scan that owns
/// its own tree cannot forget the repair and produce node ranges the
/// declaration walk disagrees with.
pub fn go_parse_spec(language: &tree_sitter::Language) -> ParseSpec<'_> {
    ParseSpec::recovering(language, go_reparse_grammar_gap)
}

/// Re-parse `source` with every `new` token the special form could not consume
/// demoted to an ordinary identifier, or `None` when `tree` needs no repair.
///
/// This is the post-parse form, for callers that already hold a tree: the
/// first parse is the evidence that decides whether a second one is needed at
/// all, so an intact file never pays for one.
pub fn go_reparse_grammar_gap(
    source: &str,
    tree: &Tree,
    cancellation: Option<&CancellationToken>,
) -> Option<Tree> {
    if !tree.root_node().has_error() {
        return None;
    }
    let mut demoted: Vec<usize> = Vec::new();
    let mut repaired: Option<Tree> = None;
    for _ in 0..MAX_DEMOTION_ROUNDS {
        let subject = repaired.as_ref().unwrap_or(tree);
        if !subject.root_node().has_error() {
            break;
        }
        let round = demotable_new_tokens(subject, source, &demoted);
        if round.is_empty() {
            break;
        }
        demoted.extend(round);
        demoted.sort_unstable();
        // A round that cannot parse -- cancellation is the way that happens --
        // leaves the previous round's tree standing rather than throwing away a
        // repair that already succeeded.
        let Some(next) = parse_source_ranges_with_cancellation(
            &tree_sitter_go::LANGUAGE.into(),
            source,
            &demotion_spans(source, &demoted),
            cancellation,
        ) else {
            break;
        };
        repaired = Some(next);
    }
    repaired
}

/// The start offsets of `new` tokens in `tree` that the grammar's special form
/// did not consume, excluding the already-demoted `demoted` offsets.
///
/// Sorted, because [`demotion_spans`] needs increasing spans and because the
/// caller keeps `demoted` sorted for its membership test.
fn demotable_new_tokens(tree: &Tree, source: &str, demoted: &[usize]) -> Vec<usize> {
    let mut found = Vec::new();
    let mut stack = vec![tree.root_node()];
    let mut cursor = tree.walk();
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier"
            && node_source_text(node, source) == GO_NEW
            && !parses_as_builtin_new(node)
            && demoted.binary_search(&node.start_byte()).is_err()
        {
            found.push(node.start_byte());
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    found.sort_unstable();
    found
}

/// Whether the grammar's `new` special form consumed `node` cleanly.
///
/// The aliased keyword is the `function` field of its `call_expression`, and
/// the `special_argument_list` aliased into `arguments` parses without an
/// ERROR or a missing token. Anything else -- a `new` the recovery left
/// outside a call, or one whose argument list the type rule could not read --
/// is a token Go itself would have lexed as a plain identifier.
fn parses_as_builtin_new(node: Node<'_>) -> bool {
    let Some(call) = node.parent() else {
        return false;
    };
    call.kind() == "call_expression"
        && call
            .child_by_field_name("function")
            .is_some_and(|function| function.id() == node.id())
        && call
            .child_by_field_name("arguments")
            .is_some_and(|arguments| !arguments.has_error())
}

/// The byte spans of `source` a demoting parse may read: everything except one
/// interior byte of each token in `demoted`.
///
/// Hiding the middle byte rather than the whole token is what keeps the
/// identity: the lexer joins the two surviving bytes into one identifier token
/// whose range is still the token's own, so the call keeps a `function` node
/// that reads `new` from the file at the offsets it always had.
fn demotion_spans(source: &str, demoted: &[usize]) -> Vec<(usize, usize)> {
    let mut spans = Vec::with_capacity(demoted.len() + 1);
    let mut start = 0usize;
    for &token in demoted {
        debug_assert_eq!(
            source.get(token..token + GO_NEW.len()),
            Some(GO_NEW),
            "a demoted token must be the `new` identifier: {token} in {source:?}"
        );
        spans.push((start, token + 1));
        start = token + 2;
    }
    spans.push((start, source.len()));
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The named node that starts exactly at `offset`, innermost first.
    fn node_at<'tree>(tree: &'tree Tree, offset: usize) -> Node<'tree> {
        tree.root_node()
            .descendant_for_byte_range(offset, offset + 1)
            .expect("a node covers the offset")
    }

    fn kinds_from(node: Node<'_>) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        let mut cursor = Some(node);
        while let Some(current) = cursor {
            kinds.push(current.kind());
            cursor = current.parent();
        }
        kinds
    }

    /// trivy `pkg/purl/purl.go` at `aff90786`: the Go 1.26 conversion argument
    /// the special form rejects. Before the repair `PackageURL` was an
    /// `identifier` directly under an ERROR and `(p)` was a `parenthesized_type`.
    #[test]
    fn go_1_26_conversion_argument_parses_as_a_call() {
        const SOURCE: &str = concat!(
            "package purl\n",
            "\n",
            "type PackageURL struct {\n",
            "\tName string\n",
            "}\n",
            "\n",
            "func FromString(p PackageURL) (*PackageURL, error) {\n",
            "\treturn new(PackageURL(p)), nil\n",
            "}\n",
        );
        let tree = parse_go(SOURCE).expect("parse");
        assert!(
            !tree.root_node().has_error(),
            "the Go 1.26 form must parse: {}",
            tree.root_node().to_sexp()
        );

        let builtin = SOURCE.find("new(PackageURL(p))").expect("the builtin call");
        let conversion = builtin + "new(".len();
        let argument = SOURCE.find("(p)), nil").expect("the conversion argument") + "(".len();

        let function = node_at(&tree, builtin);
        assert_eq!(function.kind(), "identifier");
        assert_eq!(function.byte_range(), builtin..builtin + GO_NEW.len());
        assert_eq!(
            node_source_text(function, SOURCE),
            GO_NEW,
            "the demoted token still reads as `new` at its own offsets"
        );
        let call = function.parent().expect("the builtin call node");
        assert_eq!(call.kind(), "call_expression");
        assert_eq!(
            call.child_by_field_name("arguments")
                .map(|arguments| arguments.kind()),
            Some("argument_list")
        );

        let name = node_at(&tree, conversion);
        assert_eq!(name.kind(), "identifier");
        assert_eq!(
            name.byte_range(),
            conversion..conversion + "PackageURL".len()
        );
        assert_eq!(
            kinds_from(name),
            vec![
                "identifier",
                "call_expression",
                "argument_list",
                "call_expression",
                "expression_list",
                "return_statement",
                "statement_list",
                "block",
                "function_declaration",
                "source_file",
            ],
            "the conversion is an ordinary call in an ordinary argument list"
        );
        assert_eq!(node_at(&tree, argument).kind(), "identifier");
    }

    /// etcd `server/etcdserver/bootstrap.go` at `9fe8452c`: the assignment form,
    /// whose recovery used to swallow the following statement and re-read its
    /// field write as the name of a `qualified_type`.
    #[test]
    fn go_1_26_assignment_keeps_the_following_statement() {
        const SOURCE: &str = concat!(
            "package etcdserver\n",
            "\n",
            "type state struct{ Commit uint64 }\n",
            "\n",
            "type wal struct {\n",
            "\tst   state\n",
            "\tents []uint64\n",
            "}\n",
            "\n",
            "func (w *wal) CommitedEntries() []uint64 { return w.ents }\n",
            "\n",
            "func bootstrap(bwal *wal, oldCommitIndex uint64, consistentIndex uint64) {\n",
            "\tbwal.st.Commit = new(max(oldCommitIndex, consistentIndex))\n",
            "\tbwal.ents = bwal.CommitedEntries()\n",
            "}\n",
        );
        let tree = parse_go(SOURCE).expect("parse");
        assert!(
            !tree.root_node().has_error(),
            "the Go 1.26 form must parse: {}",
            tree.root_node().to_sexp()
        );

        let builtin = SOURCE.find("new(max(").expect("the builtin call");
        let field = SOURCE
            .find("bwal.ents = bwal.")
            .expect("the following write")
            + "bwal.".len();

        let demoted = node_at(&tree, builtin);
        assert_eq!(node_source_text(demoted, SOURCE), GO_NEW);
        let max_call = node_at(&tree, builtin + "new(".len());
        assert_eq!(max_call.kind(), "identifier");
        assert_eq!(
            max_call.parent().map(|parent| parent.kind()),
            Some("call_expression"),
            "`max(...)` is the builtin's argument, not its type"
        );

        let written = node_at(&tree, field);
        assert_eq!(written.kind(), "field_identifier");
        assert_eq!(written.byte_range(), field..field + "ents".len());
        assert_eq!(
            kinds_from(written),
            vec![
                "field_identifier",
                "selector_expression",
                "expression_list",
                "assignment_statement",
                "statement_list",
                "block",
                "function_declaration",
                "source_file",
            ],
            "the statement after the builtin is an ordinary assignment again"
        );
    }

    /// The special form still owns every shape it could always parse, and a
    /// file that needs no repair never pays for a second parse.
    #[test]
    fn ordinary_new_and_make_keep_the_special_argument_list() {
        const SOURCE: &str = concat!(
            "package p\n",
            "\n",
            "type Row struct{ limit int }\n",
            "type List[T any] struct{ items []T }\n",
            "\n",
            "func f() {\n",
            "\ta := new(int)\n",
            "\tb := new(Row)\n",
            "\tc := new([]string)\n",
            "\td := new(List[int])\n",
            "\te := make(map[string]int)\n",
            "\tg := make(chan int, 4)\n",
            "\t_, _, _, _, _, _ = a, b, c, d, e, g\n",
            "}\n",
        );
        let tree = parse_go(SOURCE).expect("parse");
        assert!(!tree.root_node().has_error());
        assert!(
            go_reparse_grammar_gap(SOURCE, &tree, None).is_none(),
            "an intact file must not be re-parsed"
        );

        for (call, argument_kind) in [
            ("new(int)", "type_identifier"),
            ("new(Row)", "type_identifier"),
            ("new([]string)", "slice_type"),
            ("new(List[int])", "generic_type"),
            ("make(map[string]int)", "map_type"),
            ("make(chan int, 4)", "channel_type"),
        ] {
            let offset = SOURCE.find(call).unwrap_or_else(|| panic!("{call}"));
            let function = node_at(&tree, offset);
            let arguments = function
                .parent()
                .and_then(|parent| parent.child_by_field_name("arguments"))
                .unwrap_or_else(|| panic!("{call} arguments"));
            assert_eq!(
                arguments.named_child(0).map(|first| first.kind()),
                Some(argument_kind),
                "{call} keeps its type argument"
            );
        }
    }

    /// Near misses the repair must leave alone. Go 1.26 did not extend `make`,
    /// and no reading completes a truncated call, so both keep the ERROR that
    /// says so.
    #[test]
    fn malformed_builtin_calls_stay_explicit_errors() {
        for source in [
            concat!(
                "package p\n",
                "\n",
                "func f(n int) []int { return make(sliceOf(n)) }\n",
            ),
            concat!(
                "package p\n",
                "\n",
                "func f() {\n",
                "\ta := new(Foo(\n",
                "}\n"
            ),
        ] {
            let tree = parse_go(source).expect("parse");
            assert!(
                tree.root_node().has_error(),
                "malformed source keeps its error: {source:?} -> {}",
                tree.root_node().to_sexp()
            );
        }
    }

    /// An unrelated syntax error puts the whole file past the repair's gate, so
    /// this is where a `new(Type)` call that parsed perfectly well could be
    /// demoted by mistake. It must not be: the demotion is decided per token
    /// from that token's own call, not from the file's error state.
    #[test]
    fn an_unrelated_error_does_not_demote_a_working_new_call() {
        const SOURCE: &str = concat!(
            "package p\n",
            "\n",
            "type Row struct{ limit int }\n",
            "\n",
            "func broken() { if { } }\n",
            "\n",
            "func fine() *Row { return new(Row) }\n",
        );
        let tree = parse_go(SOURCE).expect("parse");
        assert!(
            tree.root_node().has_error(),
            "the unrelated error must survive"
        );

        let offset = SOURCE.find("new(Row)").expect("the builtin call");
        let arguments = node_at(&tree, offset)
            .parent()
            .and_then(|call| call.child_by_field_name("arguments"))
            .expect("arguments");
        assert_eq!(
            arguments.named_child(0).map(|first| first.kind()),
            Some("type_identifier"),
            "a working `new(Type)` keeps its special argument list"
        );
    }

    /// A user function that shadows the predeclared `new` and is called with
    /// two arguments. Go allows this, and the call must survive as an ordinary
    /// call with the statement after it intact. The identifier form parses
    /// under the grammar's own special rule -- `x` satisfies its `_type` slot
    /// and `, y` its expression tail -- while the numeric form does not and
    /// reaches the repair; both must land in the same shape.
    #[test]
    fn a_shadowed_new_function_call_keeps_the_following_statement() {
        for (source, call) in [
            (
                concat!(
                    "package p\n",
                    "func F() { new := func(a,b int) int { return a+b }; x,y := 1,2; _ = new(x,y); after() }\n",
                ),
                "new(x,y)",
            ),
            (
                concat!(
                    "package p\n",
                    "func F() { new := func(a,b int) int { return a+b }; _ = new(1,2); after() }\n",
                ),
                "new(1,2)",
            ),
        ] {
            let tree = parse_go(source).expect("parse");
            assert!(
                !tree.root_node().has_error(),
                "a shadowed `new` call must parse: {call} -> {}",
                tree.root_node().to_sexp()
            );

            let called = node_at(&tree, source.find(call).expect("the shadowed call"));
            assert_eq!(node_source_text(called, source), GO_NEW);
            assert_eq!(
                called.parent().map(|parent| parent.kind()),
                Some("call_expression"),
                "{call} stays a call"
            );

            let after = node_at(&tree, source.find("after()").expect("the next statement"));
            assert_eq!(
                after
                    .parent()
                    .and_then(|call| call.parent())
                    .map(|statement| statement.kind()),
                Some("expression_statement"),
                "{call} must not swallow the statement after it"
            );
        }
    }

    /// Included ranges select bytes of the original source, so hiding one byte
    /// of a `new` token moves nothing else. A multi-byte character and a
    /// comment before and after the repaired call keep their exact offsets.
    #[test]
    fn the_repair_moves_no_other_offset() {
        const SOURCE: &str = concat!(
            "package p\n",
            "\n",
            "// \u{4e2d}\u{6587} lead comment\n",
            "func F(s string) *string {\n",
            "\t// \u{2713} inner comment\n",
            "\treturn new(join(s, \"\u{1f600}\"))\n",
            "\t// \u{2713} trailing comment\n",
            "}\n",
        );
        let mut plain = tree_sitter::Parser::new();
        plain
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("go grammar");
        let before = plain.parse(SOURCE, None).expect("parse");
        assert!(
            before.root_node().has_error(),
            "the fixture must exercise the repair"
        );

        let tree = parse_go(SOURCE).expect("parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );

        for needle in [
            "// \u{4e2d}\u{6587} lead comment",
            "// \u{2713} inner comment",
            "// \u{2713} trailing comment",
        ] {
            let offset = SOURCE.find(needle).expect("comment");
            let comment = node_at(&tree, offset);
            assert_eq!(comment.kind(), "comment");
            assert_eq!(
                comment.byte_range(),
                offset..offset + needle.len(),
                "{needle} keeps its exact range"
            );
        }

        let emoji = SOURCE.find('\u{1f600}').expect("emoji");
        let literal = node_at(&tree, emoji);
        assert!(
            literal.start_byte() <= emoji && literal.end_byte() >= emoji + '\u{1f600}'.len_utf8(),
            "the multi-byte literal still covers its own bytes"
        );
    }

    /// A `new` the repair demotes reveals the next one: nesting is what makes a
    /// second demotion round necessary.
    #[test]
    fn nested_go_1_26_builtins_all_parse() {
        const SOURCE: &str = concat!(
            "package p\n",
            "\n",
            "func g(x int) int { return x }\n",
            "\n",
            "func f(x int) **int { return new(new(g(x))) }\n",
        );
        let tree = parse_go(SOURCE).expect("parse");
        assert!(
            !tree.root_node().has_error(),
            "both builtins must parse: {}",
            tree.root_node().to_sexp()
        );
        let inner = SOURCE.find("new(g(x))").expect("inner builtin");
        assert_eq!(node_source_text(node_at(&tree, inner), SOURCE), GO_NEW);
    }
}
