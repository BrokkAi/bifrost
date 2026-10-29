//! Grammar selection for a JS/TS source file, and the one dialect no grammar
//! here serves.
//!
//! Both languages choose their grammar by file path -- `.tsx` and `.jsx` need
//! `LANGUAGE_TSX`, `.ts` needs `LANGUAGE_TYPESCRIPT`, and the rest of
//! JavaScript needs `tree_sitter_javascript` -- and the decision itself is core
//! ([`LanguageDialect::for_path`]). `.jsx` joined the TSX side in #3322 because
//! upstream tree-sitter-javascript could not parse a reserved word as a JSX
//! attribute name, and one `<div class="x">` cost the whole rest of the file.
//! #3342 repairs the `.js` side with Brokk's JavaScript grammar instead of
//! switching it to TSX, which misreads ordinary JavaScript such as `await
//! using` declarations. Before the extraction this was
//! `js_ts_tree_sitter_language_for_file` in
//! `analyzer/usages/parsed_tree.rs`, a JS/TS-named free function in a framework
//! file that routed the same question through the analysis-side grammar
//! registry; all eight of its call sites moved here, so it is answered directly
//! from the two grammar crates instead.
//!
//! Flow is the gap. A Flow-annotated `.js` file is routed to
//! `tree_sitter_javascript`, which cannot parse `?T`, a return-type annotation
//! or an object type, and tree-sitter's error recovery does not fail locally:
//! one `r: ?P` collapses the whole enclosing `class_declaration` into a
//! `labeled_statement` and expression soup. Everything downstream then reads
//! that soup as if it were the program -- `const c: {bailout: boolean} = ...`
//! mints a field named `boolean`, declaration names are graded as references,
//! and real call sites are lost inside `ERROR` nodes. [`flow_dialect_blocks_extraction`]
//! is the one place that decides such a file contributes nothing, so
//! declaration extraction, the usage graph and semantic diagnostics cannot
//! disagree about it (#1786).

use crate::syntax::slice;
use brokk_bifrost_core::analyzer::model::LanguageDialect;
use brokk_bifrost_core::analyzer::{Language, ProjectFile};
use tree_sitter::{Language as TreeSitterLanguage, Node};

/// The typed detail every JS/TS surface reports for a Flow source the
/// JavaScript grammar could not parse.
pub const FLOW_UNSUPPORTED_DETAIL: &str =
    "Flow dialect source has parse errors; Flow is not supported";

/// The Flow pragma, which Flow itself honours only in a file's first docblock.
const FLOW_PRAGMA: &str = "@flow";

/// The tree-sitter grammar for a specific JS/TS source file, or `None` when
/// `language` is neither dialect.
pub fn js_ts_tree_sitter_language_for_file(
    file: &ProjectFile,
    language: Language,
) -> Option<TreeSitterLanguage> {
    match LanguageDialect::for_path(language, file.rel_path()) {
        LanguageDialect::TypeScriptTsx | LanguageDialect::JavaScriptJsx => {
            Some(tree_sitter_typescript::LANGUAGE_TSX.into())
        }
        LanguageDialect::Standard(language) => tree_sitter_language_for(language),
        LanguageDialect::CppC => None,
    }
}

/// Whether `file` declares itself Flow source.
///
/// Two signals, both Flow's own: the `.flow.js` filename, and the `@flow`
/// pragma in the file's leading docblock. The pragma is read out of the
/// leading `comment` nodes of the parse tree -- a shebang may precede them --
/// so `@flow` written anywhere later in the file is prose, not a declaration.
/// A comment's interior has no structure of its own, so matching the pragma
/// inside one is a text question; finding *which* text is a comment is not.
///
/// No `.flowconfig` ancestor walk: a diagnostic or extraction request reads the
/// file it was handed, and inferring the dialect from a directory the request
/// did not open is a wider question than this decision needs.
fn is_flow_annotated_source(file: &ProjectFile, root: Node<'_>, source: &str) -> bool {
    if file
        .rel_path()
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".flow.js"))
    {
        return true;
    }
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            break;
        };
        match child.kind() {
            "hash_bang_line" => continue,
            "comment" => {
                if comment_declares_flow(slice(child, source)) {
                    return true;
                }
            }
            // The first thing that is not part of the leading docblock ends it.
            _ => break,
        }
    }
    false
}

/// Whether every JS/TS surface must stop reading `file`.
///
/// Flow source the JavaScript grammar parsed cleanly is ordinary JavaScript --
/// the pragma alone changes nothing. Only the combination is fatal: the tree is
/// error-contaminated *and* the file says the errors are Flow syntax the
/// grammar was never going to accept, so what recovery produced describes no
/// program anyone wrote.
pub fn flow_dialect_blocks_extraction(file: &ProjectFile, root: Node<'_>, source: &str) -> bool {
    root.has_error() && is_flow_annotated_source(file, root, source)
}

/// Whether a comment's text spells the `@flow` pragma rather than a longer word
/// that starts with it. `@noflow` does not contain `@flow` at all.
fn comment_declares_flow(text: &str) -> bool {
    let mut rest = text;
    while let Some(offset) = rest.find(FLOW_PRAGMA) {
        rest = &rest[offset + FLOW_PRAGMA.len()..];
        if !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            return true;
        }
    }
    false
}

/// The default grammar for a JS/TS language, ignoring any per-path dialect.
///
/// Used where the scan has a `Language` but no particular file yet.
pub fn tree_sitter_language_for(language: Language) -> Option<TreeSitterLanguage> {
    match language {
        Language::JavaScript => Some(tree_sitter_javascript::LANGUAGE.into()),
        Language::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        _ => None,
    }
}

pub(crate) fn parse_with_language(
    source: &str,
    language: &TreeSitterLanguage,
) -> Result<Option<tree_sitter::Tree>, tree_sitter::LanguageError> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(language)?;
    Ok(parser.parse(source, None))
}

/// Node kinds whose bytes are payload in the JavaScript, TypeScript and TSX
/// grammars: string and template text, comments and JSX text. The Brokk
/// TypeScript grammar (TS, TSX and `.jsx`) parses a raw NUL in these and keeps
/// one in an identifier, operator or template substitution a parse error,
/// which is what lets source admission prove a NUL-bearing file is text. The
/// JavaScript grammar for plain `.js` still errors on every raw NUL, so such
/// a file finds no payload node and stays refused until that grammar accepts
/// one.
pub const JS_TS_NUL_PAYLOAD_KINDS: &[&str] =
    &["string_fragment", "comment", "html_comment", "jsx_text"];

/// String literals, including JSX attribute strings, and template literals
/// without substitutions are data that may occupy a long physical line, such
/// as an inlined SVG path. A substitution remains executable structure.
pub fn is_string_line_data(
    node: Node<'_>,
    should_stop: &mut dyn FnMut() -> bool,
) -> std::ops::ControlFlow<(), bool> {
    brokk_bifrost_core::analyzer::tree_walk::is_uninterpolated_literal(
        node,
        &["string", "template_string"],
        &["template_substitution"],
        should_stop,
    )
}

#[cfg(test)]
mod grammar_upgrade_tests {
    use super::*;

    #[test]
    fn jsx_ampersands_preserve_entities_and_declarations_in_every_dialect() {
        let source = r#"export const view = <p href="/x?a=1&b=2" tail="&" single='&'>Roles & Groups &amp;</p>;
export function after() { return view; }"#;
        for (path, language) in [
            ("view.tsx", Language::TypeScript),
            ("view.jsx", Language::JavaScript),
            // Plain `.js` uses the JavaScript grammar, repaired in 0.25.3 (#4409).
            ("view.js", Language::JavaScript),
        ] {
            let file = ProjectFile::new(std::env::current_dir().unwrap(), path);
            let grammar = js_ts_tree_sitter_language_for_file(&file, language).unwrap();
            let tree = parse_with_language(source, &grammar).unwrap().unwrap();
            assert!(
                !tree.root_node().has_error(),
                "{path}: {}",
                tree.root_node().to_sexp()
            );
            let mut nodes = vec![tree.root_node()];
            let mut entities = Vec::new();
            while let Some(node) = nodes.pop() {
                if node.kind() == "html_character_reference" {
                    entities.push(node.utf8_text(source.as_bytes()).unwrap());
                }
                let mut cursor = node.walk();
                nodes.extend(node.named_children(&mut cursor));
            }
            assert_eq!(entities, vec!["&amp;"], "{path}");
            let parsed = if language == Language::TypeScript {
                crate::typescript::parse_typescript_file(&file, source, &tree)
            } else {
                crate::javascript::parse_javascript_file(&file, source, &tree)
            };
            for expected in ["view", "after"] {
                assert!(
                    parsed
                        .declarations()
                        .iter()
                        .any(|unit| unit.identifier() == expected),
                    "{path}: missing {expected}"
                );
            }
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#4479: the released TS/TSX grammar rejected raw NUL in string/comment payloads"
    )]
    #[test]
    fn ts_tsx_raw_nul_payload_preserves_opaque_nodes_and_later_declarations() {
        for (path, language) in [
            ("view.ts", Language::TypeScript),
            ("view.tsx", Language::TypeScript),
            ("view.jsx", Language::JavaScript),
        ] {
            // `.jsx` intentionally uses the TSX grammar, while ordinary `.js`
            // continues to use its separate JavaScript grammar.
            let jsx = if path == "view.ts" {
                ""
            } else {
                "export const view = <div>{quoted}</div>;\n"
            };
            let source = format!(
                "const quoted = 'a\0b';\n/* c\0d */\nconst templated = `e\0f`;\n{jsx}export function after() {{ return quoted + templated; }}\n"
            );
            assert_eq!(
                source.as_bytes().iter().filter(|&&byte| byte == 0).count(),
                3,
                "{path}: test source must contain actual NUL bytes"
            );

            let file = ProjectFile::new(std::env::current_dir().unwrap(), path);
            let grammar = js_ts_tree_sitter_language_for_file(&file, language).unwrap();
            let tree = parse_with_language(&source, &grammar).unwrap().unwrap();
            let root = tree.root_node();
            assert!(!root.has_error(), "{path}: {}", root.to_sexp());
            assert_eq!(root.end_byte(), source.len(), "{path}: parser input tail");

            let (mut found_string, mut found_comment, mut found_template) = (false, false, false);
            let mut nodes = vec![root];
            while let Some(node) = nodes.pop() {
                let text = node.utf8_text(source.as_bytes()).unwrap();
                match node.kind() {
                    "string" if text == "'a\0b'" => found_string = true,
                    "comment" if text == "/* c\0d */" => found_comment = true,
                    "template_string" if text == "`e\0f`" => found_template = true,
                    _ => {}
                }
                let mut cursor = node.walk();
                nodes.extend(node.named_children(&mut cursor));
            }
            assert!(found_string, "{path}: raw string payload was not preserved");
            assert!(
                found_comment,
                "{path}: raw comment payload was not preserved"
            );
            assert!(
                found_template,
                "{path}: raw template payload was not preserved"
            );

            let parsed = if language == Language::TypeScript {
                crate::typescript::parse_typescript_file(&file, &source, &tree)
            } else {
                crate::javascript::parse_javascript_file(&file, &source, &tree)
            };
            assert!(
                parsed
                    .declarations()
                    .iter()
                    .any(|unit| unit.identifier() == "after"),
                "{path}: declaration after opaque NUL payload was lost"
            );
            if path != "view.ts" {
                assert!(
                    parsed
                        .declarations()
                        .iter()
                        .any(|unit| unit.identifier() == "view"),
                    "{path}: JSX declaration after opaque NUL payload was lost"
                );
            }
        }
    }

    #[test]
    fn raw_nul_in_executable_ts_tsx_contexts_remains_a_parse_error() {
        let invalid_sources = [
            "export const broken\0Name = 1;",
            "const value = `before ${broken\0Name} after`;",
        ];
        for (path, language) in [
            ("near-miss.ts", Language::TypeScript),
            ("near-miss.tsx", Language::TypeScript),
            ("near-miss.jsx", Language::JavaScript),
        ] {
            let file = ProjectFile::new(std::env::current_dir().unwrap(), path);
            let grammar = js_ts_tree_sitter_language_for_file(&file, language).unwrap();
            for source in invalid_sources {
                assert!(source.as_bytes().contains(&0));
                let tree = parse_with_language(source, &grammar).unwrap().unwrap();
                assert!(
                    tree.root_node().has_error(),
                    "{path}: executable NUL unexpectedly parsed cleanly: {}",
                    tree.root_node().to_sexp()
                );
            }
        }
    }
}
