//! Token and AST-label normalization for JS/TS structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer, so `analyzer/js_ts/clones.rs`
//! keeps the shared entry point; everything that knows the two grammars is
//! here.

use brokk_bifrost_core::clones::{
    CloneNormalizationRules, clone_ast_signature, normalized_clone_tokens,
};
use tree_sitter::{Language as TsLanguage, Tree};

const JS_TS_IDENTIFIER_TYPES: &[&str] = &["identifier", "property_identifier"];
const JS_TS_STRING_TYPES: &[&str] = &["string", "template_string"];
const JS_TS_NUMBER_TYPES: &[&str] = &["number"];
const JS_TS_CLONE_AST_IGNORED_TYPES: &[&str] =
    &["accessibility_modifier", "modifiers", "type_parameters"];
const JS_TS_CLONE_NORMALIZATION_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: JS_TS_IDENTIFIER_TYPES,
    string_kinds: JS_TS_STRING_TYPES,
    number_kinds: JS_TS_NUMBER_TYPES,
    boolean_kinds: &[],
    boolean_values: &["true", "false"],
    null_kinds: &[],
    null_values: &[],
    comment_kinds: &["comment"],
    ignored_ast_kinds: JS_TS_CLONE_AST_IGNORED_TYPES,
};

pub fn normalized_clone_tokens_js_ts(source: &str, parser_language: TsLanguage) -> Vec<String> {
    normalized_clone_tokens(
        parse_js_ts_tree(source, parser_language),
        source,
        JS_TS_CLONE_NORMALIZATION_RULES,
    )
}

pub fn build_js_ts_clone_ast_signature(source: &str, parser_language: TsLanguage) -> String {
    clone_ast_signature(
        parse_js_ts_tree(source, parser_language),
        source,
        JS_TS_CLONE_NORMALIZATION_RULES,
    )
}

fn parse_js_ts_tree(source: &str, parser_language: TsLanguage) -> Option<Tree> {
    crate::parse::parse_with_language(source, &parser_language)
        .expect("failed to set js/ts parser language")
}
