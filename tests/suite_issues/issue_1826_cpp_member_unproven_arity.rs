//! Issue #1826: a bare C++ *member* call whose argument count cannot be proven
//! answered `ambiguous` even when member lookup found exactly one logical
//! declaration.
//!
//! The bare member-call branch of `resolve_cpp_call` returned
//! `ambiguous_candidates_outcome` for any non-empty candidate set once
//! `call_arity` was `None` - no candidate-count test and no dedupe. Its three
//! sibling branches all tolerate unproven arity: the free-function branch
//! dedupes by logical entity and answers a lone candidate (#1811), the
//! qualified branch treats `None` arity as applicable, and the receiver branch
//! skips arity filtering entirely.
//!
//! Unproven arity must only *preserve* an existing overload ambiguity, never
//! create one. A declaration and its out-of-line body are one entity, not an
//! overload set. Genuine overload sets - including sets separated only by a
//! trailing `const` or a ref-qualifier - must stay ambiguous.
//!
//! These fixtures probe the same seam the reference-differential census does:
//! `resolve_definition_batch_with_source` over an exact token byte range. The
//! `get_definitions_by_location` tool reaches this call through a different
//! route that already answered it, which is why the census saw 196 sites the
//! editor path did not.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::usages::get_definition::{
    DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus,
    resolve_definition_batch_with_source,
};
use brokk_bifrost::{AnalyzerConfig, Language, ProjectFile, WorkspaceAnalyzer};
use std::sync::Arc;

/// An unresolvable quoted include poisons the macro environment, which is what
/// makes a bare-identifier argument's contribution to the argument count
/// unprovable. Every fixture here opens with it.
fn header(body: &str) -> String {
    format!("#pragma once\n#include \"missing_header_xyz.h\"\n{body}")
}

/// The definition outcome for the `occurrence`-th appearance of `needle` in
/// `source`, resolved over the token's exact byte range.
fn definition_at_occurrence(
    files: &[(&str, &str)],
    path: &str,
    needle: &str,
    occurrence: usize,
) -> DefinitionLookupOutcome {
    let mut builder = InlineTestProject::with_language(Language::Cpp);
    for (name, contents) in files {
        builder = builder.file(*name, *contents);
    }
    let project = builder.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let file: ProjectFile = project.file(path);
    let source = files
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, contents)| *contents)
        .unwrap_or_else(|| panic!("{path} is not one of the fixture files"));
    let start = source
        .match_indices(needle)
        .map(|(index, _)| index)
        .nth(occurrence)
        .unwrap_or_else(|| panic!("`{needle}` does not occur {occurrence} times in {path}"));
    let request = DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(start),
        end_byte: Some(start + needle.len()),
    };
    let mut outcomes = resolve_definition_batch_with_source(
        workspace.analyzer(),
        vec![request],
        file,
        Arc::from(source),
    );
    assert_eq!(outcomes.len(), 1, "one request, one outcome");
    outcomes.remove(0)
}

fn definition_signatures(outcome: &DefinitionLookupOutcome) -> Vec<String> {
    outcome
        .definitions
        .iter()
        .map(|unit| unit.signature().unwrap_or_default().to_string())
        .collect()
}

/// Fixture p3: a single inline member, no declaration/definition pair at all.
/// There is nothing to be ambiguous between, yet the answer was `ambiguous`.
#[test]
fn lone_inline_member_resolves_under_unproven_arity() {
    let source = header(
        r#"class Widget {
public:
    bool prepare(int settings, int supprs) { return settings + supprs > 0; }
};
"#,
    );
    let body = r#"#include "widget.h"
void Widget::run() {
    int checkSettings = 1;
    int supprs = 2;
    if (!prepare(checkSettings, supprs))
        return;
}
"#;
    let outcome = definition_at_occurrence(
        &[("widget.h", &source), ("widget.cpp", body)],
        "widget.cpp",
        "prepare",
        0,
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "a lone member declaration cannot be ambiguous under unproven arity: {outcome:#?}"
    );
}

/// Fixture p1: the header declaration plus its out-of-line body. They are one
/// logical entity - same kind, same fq name, same signature - so the candidate
/// set is one member, not an overload set.
#[test]
fn declaration_and_out_of_line_body_are_one_entity() {
    let source = header(
        r#"class Widget {
public:
    void run();
    bool prepare(int settings, int supprs);
};
"#,
    );
    let body = r#"#include "widget.h"
void Widget::run() {
    int checkSettings = 1;
    int supprs = 2;
    if (!prepare(checkSettings, supprs))
        return;
}
bool Widget::prepare(int settings, int supprs) { return settings + supprs > 0; }
"#;
    let outcome = definition_at_occurrence(
        &[("widget.h", &source), ("widget.cpp", body)],
        "widget.cpp",
        "prepare",
        0,
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "a declaration and its own body are one entity, not an overload set: {outcome:#?}"
    );
}

/// Fixture p14, the inconsistency that proves this is a defect rather than a
/// deliberate C++ overloading policy: the same call written through `this->`
/// resolves. Both spellings name the same member, so both must agree.
#[test]
fn bare_and_this_receiver_spellings_agree() {
    let source = header(
        r#"class Widget {
public:
    void run();
    void runThroughThis();
    bool prepare(int settings, int supprs);
};
"#,
    );
    let body = r#"#include "widget.h"
void Widget::run() {
    int checkSettings = 1;
    int supprs = 2;
    if (!prepare(checkSettings, supprs))
        return;
}
void Widget::runThroughThis() {
    int checkSettings = 1;
    int supprs = 2;
    if (!this->prepare(checkSettings, supprs))
        return;
}
bool Widget::prepare(int settings, int supprs) { return settings + supprs > 0; }
"#;
    let files = [("widget.h", source.as_str()), ("widget.cpp", body)];
    let bare = definition_at_occurrence(&files, "widget.cpp", "prepare", 0);
    let receiver = definition_at_occurrence(&files, "widget.cpp", "prepare", 1);
    assert_eq!(
        receiver.status,
        DefinitionLookupStatus::Resolved,
        "the `this->` control regressed: {receiver:#?}"
    );
    assert_eq!(
        bare.status, receiver.status,
        "`prepare(..)` and `this->prepare(..)` must agree; bare {bare:#?} vs receiver {receiver:#?}"
    );
}

/// Fixture p6, the primary negative control: two genuine member overloads stay
/// ambiguous, and the answer must carry both so a caller can choose.
#[test]
fn genuine_member_overloads_stay_ambiguous() {
    let source = header(
        r#"class Widget {
public:
    void run();
    bool prepare(int settings);
    bool prepare(int settings, int supprs);
};
"#,
    );
    let body = r#"#include "widget.h"
void Widget::run() {
    int checkSettings = 1;
    int supprs = 2;
    if (!prepare(checkSettings, supprs))
        return;
}
bool Widget::prepare(int settings) { return settings > 0; }
bool Widget::prepare(int settings, int supprs) { return settings + supprs > 0; }
"#;
    let outcome = definition_at_occurrence(
        &[("widget.h", &source), ("widget.cpp", body)],
        "widget.cpp",
        "prepare",
        0,
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "two real member overloads must stay ambiguous under unproven arity: {outcome:#?}"
    );
    let signatures = definition_signatures(&outcome);
    assert!(
        signatures
            .iter()
            .any(|signature| signature.contains("(int)"))
            && signatures
                .iter()
                .any(|signature| signature.contains("(int, int)")),
        "an ambiguous member answer must carry its competing overloads, got {signatures:?}"
    );
}

/// The `absl` `btree.h` `slot(size_type)` / `slot(size_type) const` shape: the
/// candidates differ only by a trailing cv-qualifier and are genuine overloads.
#[test]
fn const_qualified_member_overloads_stay_ambiguous() {
    let source = header(
        r#"class Node {
public:
    int probe(int index);
    int slot(int index);
    int slot(int index) const;
};
"#,
    );
    let body = r#"#include "btree.h"
int Node::probe(int index) {
    int position = index;
    return slot(position);
}
int Node::slot(int index) { return index; }
int Node::slot(int index) const { return index; }
"#;
    let outcome = definition_at_occurrence(
        &[("btree.h", &source), ("btree.cpp", body)],
        "btree.cpp",
        "slot",
        0,
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "a const/non-const member overload pair must stay ambiguous: {outcome:#?}"
    );
}

/// The `absl` `status_builder.h` `Log(severity) &` / `Log(severity) &&` shape:
/// the ref-qualifier is the only difference and it is a real overload split.
#[test]
fn ref_qualified_member_overloads_stay_ambiguous() {
    let source = header(
        r#"class Builder {
public:
    void emit(int severity);
    Builder& Log(int severity) & { return *this; }
    Builder Log(int severity) && { return *this; }
};
"#,
    );
    let body = r#"#include "status_builder.h"
void Builder::emit(int severity) {
    int level = severity;
    Log(level);
}
"#;
    let outcome = definition_at_occurrence(
        &[("status_builder.h", &source), ("status_builder.cpp", body)],
        "status_builder.cpp",
        "Log",
        0,
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "a `&`/`&&` ref-qualified member overload pair must stay ambiguous: {outcome:#?}"
    );
}
