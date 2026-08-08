//! Grammar selection for a JS/TS source file, and the one dialect no grammar
//! here serves.
//!
//! TypeScript is the only language whose grammar depends on the file path --
//! `.tsx` needs `LANGUAGE_TSX`, everything else `LANGUAGE_TYPESCRIPT` -- and the
//! decision itself is core ([`LanguageDialect::for_path`]). Before the
//! extraction this was `js_ts_tree_sitter_language_for_file` in
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
        LanguageDialect::TypeScriptTsx => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        LanguageDialect::Standard(Language::TypeScript) => {
            Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        }
        LanguageDialect::Standard(Language::JavaScript) => {
            Some(tree_sitter_javascript::LANGUAGE.into())
        }
        LanguageDialect::Standard(_) => None,
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
