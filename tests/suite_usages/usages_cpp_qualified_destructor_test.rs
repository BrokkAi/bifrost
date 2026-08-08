//! Issue #1831: `ns::Class::~Class()` never recorded the destructor's own type
//! reference.
//!
//! `out_of_line_destructor_type_reference` read the `name` child of the outer
//! `qualified_identifier` and required it to be a `destructor_name`. With a
//! namespace qualifier that child is another `qualified_identifier`, so the
//! terminal `~Class` occurrence - a second reference to the owner type - was
//! dropped. libzmq writes every out-of-line member at file scope with a `zmq::`
//! qualifier, which is where the census found it.
//!
//! The two-component form inside a `namespace` block is the control.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

const Z_HPP: &str = r#"#ifndef Z_HPP
#define Z_HPP
namespace zmq
{
class pair_t
{
  public:
    pair_t (int i);
    ~pair_t ();
    void doWork ();
};
class solo_t
{
  public:
    ~solo_t ();
};
}
#endif
"#;

type SourceRange = (usize, usize);

fn proven_ranges(
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
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    hits_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

fn token_range(source: &str, line: &str, token: &str) -> SourceRange {
    let line_start = source.find(line).expect("fixture line");
    let token_start = line.find(token).expect("fixture token");
    let start = line_start + token_start;
    (start, start + token.len())
}

fn class_target(analyzer: &CppAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == fq_name && !unit.is_synthetic()
        })
        .unwrap_or_else(|| panic!("expected an indexed {fq_name}"))
}

#[test]
fn namespace_qualified_out_of_line_destructor_records_its_owner_reference() {
    let definition = r#"#include "z.hpp"

zmq::pair_t::pair_t (int i)
{
    (void) i;
}

zmq::pair_t::~pair_t ()
{
    doWork ();
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("z.hpp", Z_HPP)
        .file("z_qualified.cpp", definition)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("z_qualified.cpp");
    let source = caller.read_to_string().expect("fixture source");
    let target = class_target(&analyzer, "zmq.pair_t");

    let ranges = proven_ranges(&analyzer, &target, &caller);
    let qualifier = token_range(&source, "zmq::pair_t::~pair_t ()", "pair_t");
    let terminal = {
        let line_start = source
            .find("zmq::pair_t::~pair_t ()")
            .expect("fixture line");
        let offset = "zmq::pair_t::~".len();
        (line_start + offset, line_start + offset + "pair_t".len())
    };
    assert!(
        ranges.contains(&qualifier),
        "the qualifier occurrence regressed: {ranges:?} (expected {qualifier:?})"
    );
    assert!(
        ranges.contains(&terminal),
        "the destructor name is a second reference to its owner: {ranges:?} \
         (expected {terminal:?})"
    );
}

/// Control: the two-component form inside a `namespace` block already recorded
/// both occurrences and must keep doing so.
#[test]
fn namespace_block_out_of_line_destructor_control_still_records_both() {
    let definition = r#"#include "z.hpp"
namespace zmq
{
solo_t::~solo_t ()
{
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("z.hpp", Z_HPP)
        .file("z_inblock.cpp", definition)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("z_inblock.cpp");
    let source = caller.read_to_string().expect("fixture source");
    let target = class_target(&analyzer, "zmq.solo_t");

    let ranges = proven_ranges(&analyzer, &target, &caller);
    let qualifier = token_range(&source, "solo_t::~solo_t ()", "solo_t");
    let terminal = {
        let line_start = source.find("solo_t::~solo_t ()").expect("fixture line");
        let offset = "solo_t::~".len();
        (line_start + offset, line_start + offset + "solo_t".len())
    };
    assert!(
        ranges.contains(&qualifier),
        "the two-component qualifier regressed: {ranges:?}"
    );
    assert!(
        ranges.contains(&terminal),
        "the two-component destructor name regressed: {ranges:?}"
    );
}
