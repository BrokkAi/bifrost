//! #1854: the Scala inverse scan must record a bare call whose name equals the
//! name of the enclosing `def`.
//!
//! `walk_enter` enters the `function_definition` scope and only then lets
//! `seed_declaration` run. Declaring the method's own name as a shadow there
//! made the name opaque *inside its own body*, so the bare-call arm of
//! `record_reference` returned before any owner, import, or overload lookup.
//! The single factor was the enclosing name: `def tick(x, y) = tick(x) + y`
//! was dropped while the identical call inside `def tock` was recorded.
//!
//! The negative controls keep the real Scala shadows: a `def` declared in a
//! nested scope still shadows the surrounding binding, and a parameter still
//! shadows the enclosing method's own name.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::{
    FuzzyResult, ScalaUsageGraphStrategy, UsageAnalyzer, UsageHit, UsageHitSurface,
};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, Language, ScalaAnalyzer};

const SOURCE: &str = r#"package app

trait P { def tick(x: Int): Int = x }

class S extends P {
  def tick(x: Int, y: Int): Int = tick(x) + y // sibling-overload-bare-call
}

class T extends P {
  def tock(x: Int, y: Int): Int = tick(x) + y // control-different-enclosing-name
}

class R {
  def loop(n: Int): Int = if (n <= 0) 0 else loop(n - 1) // pure-recursion
}

object Free { def compute(x: Int): Int = x }

class NestedShadow {
  import app.Free.compute
  def run(x: Int): Int = {
    def compute(y: Int): Int = y * 2
    compute(x) // negative-nested-local-def
  }
}

class ParamShadow extends P {
  def tick(tick: Int => Int, x: Int): Int = tick(x) // negative-parameter-shadow
}
"#;

fn analyzer_for(source: &str) -> (crate::common::BuiltInlineTestProject, ScalaAnalyzer) {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/P.scala", source)
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definitions(analyzer: &ScalaAnalyzer, fq_name: &str) -> Vec<CodeUnit> {
    let units = analyzer.get_definitions(fq_name);
    assert!(!units.is_empty(), "missing definition for {fq_name}");
    units
}

fn find_usages(analyzer: &ScalaAnalyzer, targets: &[CodeUnit]) -> FuzzyResult {
    let candidate_files = analyzer.get_analyzed_files().into_iter().collect();
    ScalaUsageGraphStrategy::new().find_usages(analyzer, targets, &candidate_files, 1000)
}

/// The editor find-references surface, which includes the `SelfReceiver` hits
/// that the external usage surface excludes (#1638).
fn reference_hits(analyzer: &ScalaAnalyzer, targets: &[CodeUnit]) -> Vec<UsageHit> {
    find_usages(analyzer, targets)
        .all_hits_for_surface(UsageHitSurface::LspReferences)
        .into_iter()
        .collect()
}

fn external_hits(analyzer: &ScalaAnalyzer, targets: &[CodeUnit]) -> Vec<UsageHit> {
    find_usages(analyzer, targets)
        .into_either()
        .expect("expected usage graph success")
        .into_iter()
        .collect()
}

fn assert_hit_contains(hits: &[UsageHit], needle: &str) {
    assert!(
        hits.iter().any(|hit| hit.snippet.contains(needle)),
        "expected hit containing {needle:?}, got {hits:#?}"
    );
}

fn assert_no_hit_contains(hits: &[UsageHit], needle: &str) {
    assert!(
        hits.iter().all(|hit| !hit.snippet.contains(needle)),
        "expected no hit containing {needle:?}, got {hits:#?}"
    );
}

/// The headline: an overload sibling reached by a bare call from inside a `def`
/// of the same name. The control on the next class proves the enclosing name is
/// the only factor.
#[test]
fn scala_bare_call_from_a_same_named_def_records_the_inherited_overload() {
    let (_project, analyzer) = analyzer_for(SOURCE);
    let targets = definitions(&analyzer, "app.P.tick");
    let hits = reference_hits(&analyzer, &targets);
    assert_hit_contains(&hits, "control-different-enclosing-name");
    assert_hit_contains(&hits, "sibling-overload-bare-call");
}

/// Pure recursion follows the established #1638 classification: the site is
/// recorded, listed on the editor surface as a `SelfReceiver` hit, and omitted
/// from the external usage surface.
#[test]
fn scala_bare_recursive_call_is_editor_visible_and_external_excluded() {
    let (_project, analyzer) = analyzer_for(SOURCE);
    let targets = definitions(&analyzer, "app.R.loop");
    assert_hit_contains(&reference_hits(&analyzer, &targets), "pure-recursion");
    assert_no_hit_contains(&external_hits(&analyzer, &targets), "pure-recursion");
}

/// A `def` declared inside a block is a real Scala shadow: the bare call binds
/// to the local definition, not to the imported free function of the same name.
#[test]
fn scala_nested_local_def_still_shadows_an_imported_name() {
    let (_project, analyzer) = analyzer_for(SOURCE);
    let targets = definitions(&analyzer, "app.Free$.compute");
    assert_no_hit_contains(
        &reference_hits(&analyzer, &targets),
        "negative-nested-local-def",
    );
}

/// A parameter of the method still shadows the method's own name.
#[test]
fn scala_parameter_still_shadows_the_enclosing_method_name() {
    let (_project, analyzer) = analyzer_for(SOURCE);
    let targets = definitions(&analyzer, "app.P.tick");
    assert_no_hit_contains(
        &reference_hits(&analyzer, &targets),
        "negative-parameter-shadow",
    );
}
