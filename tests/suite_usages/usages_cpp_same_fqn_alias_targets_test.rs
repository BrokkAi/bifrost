//! Issue #1845: the C++ inverse failed closed when one type name has several
//! same-FQN declarations whose alias *targets* differ. log4cxx declares
//! `logchar` three times in `logstring.h`, once per `#if` configuration branch
//! (`char` in the UTF-8 branch, `UniChar` in the unichar branch). Every
//! candidate is canonicalized independently by
//! `type_candidate_preserving_target`, the branches disagree, and
//! `unique_type_candidate_preserving_target` returned `None` - so
//! `scan_usages` answered `verified_absent` for a typedef with hundreds of real
//! references.
//!
//! Same-FQN declarations that differ only in their alias target are alternate
//! configuration spellings of one logical name. Selection must degrade to the
//! union, never to "no usages exist".
//!
//! The regression triple is the diagnosis's G ladder: G4 (two same-FQN aliases,
//! different targets) must attribute the reference, G6 (same target) must stay
//! attributed, and G9 (two different names) must be unaffected.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::{FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CppAnalyzer, Language};
use std::collections::BTreeSet;

const CONSUMER_CPP: &str = r#"#include <log4cxx/logstring.h>

using namespace LOG4CXX_NS;

void consume()
{
	logchar c = 0;
	(void) c;
}
"#;

/// Every file carrying a proven or reviewable hit for `target`.
fn hit_files(analyzer: &CppAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    let query = UsageFinder::new().with_authoritative_scope(true).query(
        analyzer,
        std::slice::from_ref(target),
        100,
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
        .map(|hit| hit.file.to_string().replace('\\', "/"))
        .collect()
}

fn project_with_header(header: &str) -> BTreeSet<String> {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("src/main/include/log4cxx/logstring.h", header)
        .file("src/main/cpp/consumer.cpp", CONSUMER_CPP)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.fq_name().ends_with(".logchar") && !unit.is_synthetic())
        .collect::<Vec<_>>();
    assert!(
        !targets.is_empty(),
        "expected at least one indexed `logchar` declaration"
    );
    targets
        .iter()
        .flat_map(|target| hit_files(&analyzer, target))
        .collect()
}

/// G4: two `logchar` typedefs in disjoint `#if` branches whose alias targets
/// differ. Every declaration of the family must attribute the reference.
#[test]
fn same_fqn_aliases_with_differing_targets_still_attribute_the_reference() {
    let files = project_with_header(
        r#"#ifndef LOGSTRING_H
#define LOGSTRING_H

namespace LOG4CXX_NS
{

#if LOG4CXX_LOGCHAR_IS_UNICHAR || LOG4CXX_UNICHAR_API
	typedef unsigned short UniChar;
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
	typedef char logchar;
#endif

#if LOG4CXX_LOGCHAR_IS_UNICHAR
	typedef UniChar logchar;
#endif

}

#endif
"#,
    );
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("src/main/cpp/consumer.cpp")),
        "same-FQN aliases with differing targets are alternate configuration \
         spellings of one name; the reference must still be attributed: {files:?}"
    );
}

/// G6 control: the same two declarations aliasing the *same* target already
/// worked and must keep working.
#[test]
fn same_fqn_aliases_with_the_same_target_stay_attributed() {
    let files = project_with_header(
        r#"#ifndef LOGSTRING_H
#define LOGSTRING_H

namespace LOG4CXX_NS
{
	typedef unsigned short UniChar;

#if A
	typedef UniChar logchar;
#endif

#if B
	typedef UniChar logchar;
#endif
}

#endif
"#,
    );
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("src/main/cpp/consumer.cpp")),
        "the same-target control regressed: {files:?}"
    );
}

/// G9 control: two typedefs with different *names* are unrelated declarations,
/// and the one the reference names must still be attributed.
#[test]
fn distinct_alias_names_are_unaffected() {
    let files = project_with_header(
        r#"#ifndef LOGSTRING_H
#define LOGSTRING_H

namespace LOG4CXX_NS
{
	typedef unsigned short UniChar;

#if A
	typedef char otherchar;
#endif

#if B
	typedef UniChar logchar;
#endif
}

#endif
"#,
    );
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("src/main/cpp/consumer.cpp")),
        "the distinct-name control regressed: {files:?}"
    );
}

const QUALIFIED_CONSUMER_CPP: &str = r#"#include <log4cxx/logstring.h>

void consumeQualified()
{
	LOG4CXX_NS::logchar c = 0;
	(void) c;
}
"#;

const TWO_BRANCH_HEADER: &str = r#"#ifndef LOGSTRING_H
#define LOGSTRING_H

namespace LOG4CXX_NS
{

#if LOG4CXX_LOGCHAR_IS_UNICHAR || LOG4CXX_UNICHAR_API
	typedef unsigned short UniChar;
#endif

#if LOG4CXX_LOGCHAR_IS_UTF8
	typedef char logchar;
#endif

#if LOG4CXX_LOGCHAR_IS_UNICHAR
	typedef UniChar logchar;
#endif

}

#endif
"#;

fn qualified_project_hit_files(fq_name: &str) -> BTreeSet<String> {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("src/main/include/log4cxx/logstring.h", TWO_BRANCH_HEADER)
        .file("src/main/cpp/consumer.cpp", QUALIFIED_CONSUMER_CPP)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.fq_name() == fq_name && !unit.is_synthetic())
        .collect::<Vec<_>>();
    assert!(!targets.is_empty(), "expected an indexed {fq_name}");
    targets
        .iter()
        .flat_map(|target| hit_files(&analyzer, target))
        .collect()
}

/// The same family reached through a *qualified* reference, which resolves
/// through the ordinary candidate tiers instead of the using-directive import.
#[test]
fn qualified_reference_reaches_the_alias_family() {
    let files = qualified_project_hit_files("LOG4CXX_NS.logchar");
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("src/main/cpp/consumer.cpp")),
        "a qualified reference to a guarded alias family must be attributed: {files:?}"
    );
}

/// The branch that aliases `UniChar` makes the reference name `UniChar` under
/// that configuration, so the inverse on the alias *target* must cover the site
/// too - otherwise a forward answer of `UniChar` has no inverse.
#[test]
fn qualified_reference_reaches_the_branch_alias_target() {
    let files = qualified_project_hit_files("LOG4CXX_NS.UniChar");
    assert!(
        files
            .iter()
            .any(|file| file.ends_with("src/main/cpp/consumer.cpp")),
        "the configuration branch that aliases UniChar must attribute the \
         reference to UniChar: {files:?}"
    );
}

/// Negative control: two same-FQN declarations in *different* files are not one
/// guarded family, and a reference that cannot see either must not be proven.
#[test]
fn unreachable_same_fqn_alias_does_not_prove_a_reference() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/main/include/log4cxx/logstring.h",
            r#"#ifndef LOGSTRING_H
#define LOGSTRING_H
namespace LOG4CXX_NS
{
	typedef unsigned short UniChar;
	typedef UniChar logchar;
}
#endif
"#,
        )
        .file(
            "src/main/cpp/orphan.cpp",
            r#"namespace other {
	typedef int logchar;
	void useOrphan() { logchar c = 0; (void) c; }
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.fq_name() == "LOG4CXX_NS.logchar" && !unit.is_synthetic())
        .expect("expected an indexed LOG4CXX_NS.logchar");
    let files = hit_files(&analyzer, &target);
    assert!(
        !files.iter().any(|file| file.ends_with("orphan.cpp")),
        "a `logchar` in another namespace and another file is a different \
         symbol: {files:?}"
    );
}
