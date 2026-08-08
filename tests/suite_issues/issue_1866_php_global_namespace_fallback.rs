//! Issue #1866: an unqualified PHP function or constant name resolved only in
//! the caller's namespace and never fell back to the global namespace.
//!
//! PHP resolves an unqualified single-segment function or constant name in the
//! current namespace FIRST and then in the global namespace. `resolve_php_function`
//! and `resolve_php_constant` (and their structured twins) stopped after the
//! namespace join, so `tenancy()`, `config()`, `model()` and `app()` -- Laravel,
//! CodeIgniter and tenancy helper calls made from inside a namespaced class --
//! answered `no_definition` against a global helper the workspace had indexed.
//!
//! The controls hold the two halves of PHP's rule that the fallback must not
//! break: a definition in the caller's own namespace SHADOWS the global one, and
//! `\name` plus `use function` name exactly one target with no fallback at all.
//!
//! The inverse side moves with the forward answer: the per-target usage scan and
//! the whole-workspace inverted edge pass must attribute the same call sites the
//! forward resolver now answers, so a fixed forward direction does not become a
//! forward/inverse asymmetry.

use crate::common::usage_graph::{has_edge, usage_graph_at};
use crate::common::{BuiltInlineTestProject, InlineTestProject, call_tool};
use brokk_bifrost::Language;
use serde_json::{Value, json};

/// A global-namespace file declaring a plain helper, a `function_exists`-guarded
/// helper (the Laravel/CodeIgniter idiom) and a name the caller's namespace also
/// declares.
const HELPERS: &str = r#"<?php

function plain_helper(string $name): string
{
    return $name;
}

if (! function_exists('guarded_helper')) {
    function guarded_helper(string $name): string
    {
        return $name;
    }
}

function shadowed_helper(string $name): string
{
    return $name;
}

const DEMO_LIMIT = 10;
"#;

/// The caller's own namespace declares `same_namespace_helper` and a
/// `shadowed_helper` that must win over the global one.
const NAMESPACED_HELPERS: &str = r#"<?php

namespace Demo\App;

function same_namespace_helper(string $name): string
{
    return $name;
}

function shadowed_helper(string $name): string
{
    return $name;
}
"#;

const CALLER: &str = r#"<?php

namespace Demo\App;

use function guarded_helper as aliased_helper;

class Caller
{
    public function bareGlobalPlain(): string
    {
        return plain_helper('a');
    }

    public function bareGlobalGuarded(): string
    {
        return guarded_helper('a');
    }

    public function escapedGlobalPlain(): string
    {
        return \plain_helper('a');
    }

    public function viaUseFunction(): string
    {
        return aliased_helper('a');
    }

    public function sameNamespace(): string
    {
        return same_namespace_helper('a');
    }

    public function shadowed(): string
    {
        return shadowed_helper('a');
    }

    public function bareGlobalConstant(): int
    {
        return DEMO_LIMIT;
    }
}
"#;

fn php_project() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Php)
        .file("helpers.php", HELPERS)
        .file("namespaced_helpers.php", NAMESPACED_HELPERS)
        .file("Caller.php", CALLER)
        .build()
}

/// The `get_definitions_by_location` result for the occurrence of `needle` in
/// `source` that follows `after`.
fn definition_after(
    project: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    after: &str,
    needle: &str,
) -> Value {
    let anchor = source
        .find(after)
        .unwrap_or_else(|| panic!("`{after}` is not present in {path}"));
    let start = anchor
        + source[anchor..]
            .find(needle)
            .unwrap_or_else(|| panic!("`{needle}` is not present in {path} after `{after}`"));
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let args = json!({"references": [{"path": path, "line": line, "column": column}]}).to_string();
    call_tool(project, "get_definitions_by_location", &args)["results"][0].clone()
}

fn definition_fq_names(result: &Value) -> Vec<String> {
    result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| definition["fqn"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The census/product witness: a bare call from a namespaced class to a helper
/// declared in the global namespace. This is `tenancy()` in archtechx/tenancy,
/// `config()`/`model()` in CodeIgniter4 and `app()` in laravel/framework.
#[test]
fn php_bare_call_reaches_a_global_function() {
    let project = php_project();

    let plain = definition_after(
        &project,
        "Caller.php",
        CALLER,
        "bareGlobalPlain",
        "plain_helper",
    );
    assert_eq!(
        definition_fq_names(&plain),
        vec!["plain_helper".to_string()],
        "an unqualified call must fall back to the global function: {plain:#?}"
    );

    let guarded = definition_after(
        &project,
        "Caller.php",
        CALLER,
        "bareGlobalGuarded",
        "guarded_helper",
    );
    assert_eq!(
        definition_fq_names(&guarded),
        vec!["guarded_helper".to_string()],
        "a `function_exists`-guarded global helper is an ordinary global function: {guarded:#?}"
    );
}

/// The same omission applied to constants; `\DEMO_LIMIT` already worked.
#[test]
fn php_bare_constant_reaches_a_global_constant() {
    let project = php_project();

    let result = definition_after(
        &project,
        "Caller.php",
        CALLER,
        "bareGlobalConstant",
        "DEMO_LIMIT",
    );
    assert_eq!(
        definition_fq_names(&result),
        vec!["_module_.DEMO_LIMIT".to_string()],
        "an unqualified constant must fall back to the global namespace: {result:#?}"
    );
}

/// PHP's rule is current-namespace THEN global, so a definition in the caller's
/// own namespace shadows the global one of the same name. The fallback must be a
/// second candidate, never a replacement.
#[test]
fn php_same_namespace_function_shadows_the_global_one() {
    let project = php_project();

    let shadowed = definition_after(
        &project,
        "Caller.php",
        CALLER,
        "shadowed()",
        "shadowed_helper",
    );
    assert_eq!(
        definition_fq_names(&shadowed),
        vec!["Demo.App.shadowed_helper".to_string()],
        "the caller's own namespace must win over the global function: {shadowed:#?}"
    );

    let same_namespace = definition_after(
        &project,
        "Caller.php",
        CALLER,
        "sameNamespace",
        "same_namespace_helper",
    );
    assert_eq!(
        definition_fq_names(&same_namespace),
        vec!["Demo.App.same_namespace_helper".to_string()],
        "a same-namespace helper keeps resolving in its namespace: {same_namespace:#?}"
    );
}

/// `\name` and a `use function` alias each name exactly one target. Neither form
/// is unqualified, so neither gains a fallback candidate.
#[test]
fn php_escaped_and_aliased_forms_stay_exact() {
    let project = php_project();

    let escaped = definition_after(
        &project,
        "Caller.php",
        CALLER,
        "escapedGlobalPlain",
        "plain_helper",
    );
    assert_eq!(
        definition_fq_names(&escaped),
        vec!["plain_helper".to_string()],
        "`\\plain_helper` names the global function exactly: {escaped:#?}"
    );

    let aliased = definition_after(
        &project,
        "Caller.php",
        CALLER,
        "viaUseFunction",
        "aliased_helper",
    );
    assert_eq!(
        definition_fq_names(&aliased),
        vec!["guarded_helper".to_string()],
        "`use function` names the imported function exactly: {aliased:#?}"
    );
}

/// The inverted whole-workspace edge pass must record the same target the
/// forward resolver answers, or the fix trades a census gap for a
/// forward/inverse asymmetry.
#[test]
fn php_inverted_edges_attribute_the_global_function() {
    let project = php_project();
    let graph = usage_graph_at(project.root(), "{}");

    assert!(
        has_edge(&graph, "Demo.App.Caller.bareGlobalPlain", "plain_helper"),
        "the bare call must edge to the global function: {}",
        graph["edges"]
    );
    assert!(
        has_edge(
            &graph,
            "Demo.App.Caller.bareGlobalGuarded",
            "guarded_helper"
        ),
        "the guarded global helper must be edged too: {}",
        graph["edges"]
    );
    // Shadowing is symmetric: the namespaced definition takes the site, so the
    // global one must not also claim it.
    assert!(
        has_edge(
            &graph,
            "Demo.App.Caller.shadowed",
            "Demo.App.shadowed_helper"
        ),
        "the same-namespace definition owns the shadowed site: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "Demo.App.Caller.shadowed", "shadowed_helper"),
        "a shadowed global function must not claim the site: {}",
        graph["edges"]
    );
}

/// The per-target usage scan (`scan_usages_by_reference` -> the PHP extractor)
/// is the other inverse direction and must agree with the forward answer.
///
/// The assertion is per LINE, not per file: `Caller.php` already reported a
/// usage before the fix because the same file also spells `\plain_helper(...)`,
/// so a file-level assertion would pass on the escaped call alone.
fn scan_usage_lines(project: &BuiltInlineTestProject, symbol: &str, path: &str) -> Vec<u64> {
    let args = json!({"symbols": [symbol], "include_tests": true}).to_string();
    let result = call_tool(project, "scan_usages_by_reference", &args);
    let mut lines: Vec<u64> = result["results"][0]["files"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|file| file["path"].as_str() == Some(path))
        .flat_map(|file| {
            file["hits"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .filter_map(|hit| hit["line"].as_u64())
        })
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

#[test]
fn php_scan_usages_finds_the_bare_call_of_a_global_function() {
    let project = php_project();

    let bare_call_line = line_of(CALLER, "bareGlobalPlain", "plain_helper");
    let escaped_call_line = line_of(CALLER, "escapedGlobalPlain", "plain_helper");
    let lines = scan_usage_lines(&project, "plain_helper", "Caller.php");
    assert!(
        lines.contains(&bare_call_line),
        "the bare call at line {bare_call_line} is a usage of the global function: {lines:?}"
    );
    assert!(
        lines.contains(&escaped_call_line),
        "the escaped call at line {escaped_call_line} must keep its usage: {lines:?}"
    );

    // The shadowed name is the negative control: the global declaration must not
    // claim a site the caller's own namespace owns.
    assert!(
        scan_usage_lines(&project, "shadowed_helper", "Caller.php").is_empty(),
        "a shadowed global function has no usage in the namespaced caller"
    );
}

/// The 1-based line of the occurrence of `needle` that follows `after`.
fn line_of(source: &str, after: &str, needle: &str) -> u64 {
    let anchor = source
        .find(after)
        .unwrap_or_else(|| panic!("`{after}` is not present in the source"));
    let start = anchor
        + source[anchor..]
            .find(needle)
            .unwrap_or_else(|| panic!("`{needle}` is not present after `{after}`"));
    source[..start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u64
        + 1
}
