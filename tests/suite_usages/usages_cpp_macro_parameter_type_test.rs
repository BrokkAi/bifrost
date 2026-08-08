//! Issue #1830: `f(MACRO T* p)` lost the reference to `T`.
//!
//! tree-sitter-cpp recovers a macro-decorated parameter by inserting a
//! zero-width `::`, so the real type `T` lands in the *scope* of a
//! `qualified_identifier` whose `name` is the declarator. The recovery hook
//! that already understands that shape for declarations and function
//! definitions (`recovered_declarator_container`) declined inside
//! `parameter_declaration`, so no candidate was ever emitted - the xxhash
//! `XXH_NOESCAPE` shape from c-blosc2.
//!
//! The plain parameter on the adjacent line is the single-token control.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

const XXH_H: &str = r#"#ifndef X_H
#define X_H

#define XXH_PUBLIC_API
#define XXH_NOESCAPE

typedef int XXH_errorcode;

struct XXH3_state_s { int x; };
typedef struct XXH3_state_s XXH3_state_t;

XXH_PUBLIC_API XXH_errorcode XXH3_freeState(XXH3_state_t* plainPtr);
XXH_PUBLIC_API XXH_errorcode XXH3_64bits_reset(XXH_NOESCAPE XXH3_state_t* macroPtr);

#endif
"#;

const PLAIN_LINE: &str = "XXH_PUBLIC_API XXH_errorcode XXH3_freeState(XXH3_state_t* plainPtr);";
const MACRO_LINE: &str =
    "XXH_PUBLIC_API XXH_errorcode XXH3_64bits_reset(XXH_NOESCAPE XXH3_state_t* macroPtr);";

type SourceRange = (usize, usize);

fn all_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    caller: &ProjectFile,
) -> BTreeSet<SourceRange> {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(caller.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_by_overload,
        ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    hits_by_overload
        .values()
        .chain(unproven_by_overload.values())
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

fn line_span(source: &str, line: &str) -> SourceRange {
    let start = source.find(line).expect("fixture line");
    (start, start + line.len())
}

fn token_range(source: &str, line: &str, token: &str) -> SourceRange {
    let line_start = source.find(line).expect("fixture line");
    let token_start = line.find(token).expect("fixture token");
    let start = line_start + token_start;
    (start, start + token.len())
}

fn declaration_target(analyzer: &CppAnalyzer, identifier: &str) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.identifier() == identifier
                && unit.kind() == CodeUnitType::Class
                && !unit.is_synthetic()
        })
        .unwrap_or_else(|| panic!("expected an indexed {identifier}"))
}

#[test]
fn macro_decorated_parameter_records_its_type_reference() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("x.h", XXH_H)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("x.h");
    let source = caller.read_to_string().expect("fixture source");
    let target = declaration_target(&analyzer, "XXH3_state_t");

    let ranges = all_ranges(&analyzer, &target, &caller);
    let plain = token_range(&source, PLAIN_LINE, "XXH3_state_t");
    let macro_decorated = token_range(&source, MACRO_LINE, "XXH3_state_t");
    assert!(
        ranges.contains(&plain),
        "the plain-parameter control regressed: {ranges:?} (expected {plain:?})"
    );
    assert!(
        ranges.contains(&macro_decorated),
        "a macro-decorated parameter must still reference its type: {ranges:?} \
         (expected {macro_decorated:?})"
    );
}

/// Negative control: when both parameter tokens name a real type, the recovery
/// must not cross-attribute them. Each type may be claimed only at its own
/// token - the recovered scope is admission evidence, never a licence to move a
/// reference onto the neighbouring token.
#[test]
fn two_type_parameter_never_cross_attributes_its_tokens() {
    let source = r#"#ifndef Y_H
#define Y_H
struct Foo { int a; };
struct Bar { int b; };
void takesBoth(Foo Bar* p);
#endif
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("y.h", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("y.h");
    let text = caller.read_to_string().expect("fixture source");
    let parameters = "void takesBoth(Foo Bar* p);";
    let (line_start, line_end) = line_span(&text, parameters);

    for identifier in ["Foo", "Bar"] {
        let target = declaration_target(&analyzer, identifier);
        let own_token = token_range(&text, parameters, identifier);
        let claimed: BTreeSet<SourceRange> = all_ranges(&analyzer, &target, &caller)
            .into_iter()
            .filter(|(start, end)| *start >= line_start && *end <= line_end)
            .collect();
        assert!(
            claimed.iter().all(|range| *range == own_token),
            "{identifier} may be claimed only at its own token {own_token:?}: {claimed:?}"
        );
    }
}
