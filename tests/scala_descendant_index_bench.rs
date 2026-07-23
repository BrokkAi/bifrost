// Measurement harness for issue #908: eager whole-workspace descendant-index build
// on the Scala inverse-member query path. Not a correctness gate; run with --ignored.
//
//   BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python \
//     --test scala_descendant_index_bench -- --ignored --nocapture --test-threads=1

mod common;

use brokk_bifrost::{CodeUnit, IAnalyzer, Language, ScalaAnalyzer, TypeHierarchyProvider};
use common::InlineTestProject;
use std::sync::Arc;
use std::time::Instant;

/// Generate a synthetic Scala workspace with `files` files, `per_file` classes each.
/// Every class extends a shared `Marker` trait plus one of: `SmallTarget` (only the
/// first 5 classes) for a realistic small-fan-in target; `Base{n}` (every 4th class)
/// for one of `bases` cross-file base traits; or `Target` (the rest) as a mega-root
/// with workspace-wide fan-in. All supertypes are cross-file, wildcard-imported.
/// Returns (path, contents) pairs.
fn synthetic_workspace(files: usize, per_file: usize, bases: usize) -> Vec<(String, String)> {
    let mut out = Vec::new();

    let mut base_src = String::from("package base\ntrait Marker\n");
    for b in 0..bases {
        base_src.push_str(&format!("trait Base{b}\n"));
    }
    base_src.push_str("class Target extends Marker {\n  def scanned(): Int = 0\n}\n");
    base_src.push_str("class SmallTarget extends Marker {\n  def probed(): Int = 0\n}\n");
    out.push(("base/Base.scala".to_string(), base_src));

    let mut idx = 0usize;
    for f in 0..files {
        let mut src = String::from("package gen\nimport base._\n");
        for _ in 0..per_file {
            let base = idx % bases;
            if idx < 5 {
                src.push_str(&format!(
                    "class C{idx} extends SmallTarget with Marker {{\n  override def probed(): Int = {idx}\n}}\n"
                ));
            } else if idx.is_multiple_of(4) {
                src.push_str(&format!(
                    "class C{idx} extends Base{base} with Marker {{\n  def scanned(): Int = {idx}\n}}\n"
                ));
            } else {
                src.push_str(&format!(
                    "class C{idx} extends Target with Marker {{\n  override def scanned(): Int = {idx}\n}}\n"
                ));
            }
            idx += 1;
        }
        out.push((format!("gen/Gen{f}.scala"), src));
    }
    out
}

fn build_analyzer(files: &[(String, String)]) -> (common::BuiltInlineTestProject, ScalaAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Scala);
    for (path, contents) in files {
        builder = builder.file(path.clone(), contents.clone());
    }
    let project = builder.build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn target(analyzer: &ScalaAnalyzer, fq: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq}"))
}

fn measure_scale(files: usize, per_file: usize, bases: usize) {
    let classes = files * per_file;
    let fixture = synthetic_workspace(files, per_file, bases);
    let (_project, analyzer) = build_analyzer(&fixture);

    let small = target(&analyzer, "base.SmallTarget");
    let base0 = target(&analyzer, "base.Base0");
    let mega = target(&analyzer, "base.Target");

    // COLD #1 — the #908 scenario: the first-ever inverse-member query on a
    // small-fan-in target. This triggers the one-time cheap stage-1 build
    // (bulk states + project-types + raw simple-name index) and then resolves
    // only SmallTarget's handful of candidates.
    let t = Instant::now();
    let small_desc = analyzer.get_descendants(&small);
    let small_ms = t.elapsed().as_secs_f64() * 1000.0;

    // COLD #2 — a moderate target (~classes/bases descendants); stage-1 already
    // built, so this is pure candidate-scoped resolution of Base0's subtree.
    let t = Instant::now();
    let base0_desc = analyzer.get_descendants(&base0);
    let base0_ms = t.elapsed().as_secs_f64() * 1000.0;

    // COLD #3 — worst case: the mega-root's whole subtree (touch-bounded: it
    // must genuinely resolve every class that extends it).
    let t = Instant::now();
    let mega_desc = analyzer.get_descendants(&mega);
    let mega_ms = t.elapsed().as_secs_f64() * 1000.0;

    // WARM floor — ancestors now cached; pure re-scan.
    let t = Instant::now();
    let warm = analyzer.get_descendants(&small);
    let warm_ms = t.elapsed().as_secs_f64() * 1000.0;

    println!(
        "[bench] classes={classes} files={files} | \
         COLD small-target(n={})={small_ms:.1}ms | \
         moderate Base0(n={})={base0_ms:.1}ms | \
         mega-root(n={})={mega_ms:.1}ms | \
         WARM small(n={})={warm_ms:.2}ms",
        small_desc.len(),
        base0_desc.len(),
        mega_desc.len(),
        warm.len(),
    );
}

#[test]
#[ignore]
fn bench_descendant_index_scaling() {
    println!("\n=== #908 post-fix: candidate-scoped descendant lookup scaling ===");
    measure_scale(400, 5, 10); // 2,000 classes
    measure_scale(800, 5, 10); // 4,000 classes
    measure_scale(1600, 5, 10); // 8,000 classes
}

#[test]
#[ignore]
fn bench_descendant_index_concurrent() {
    println!("\n=== #908 two concurrent cold inverse queries (different targets) ===");
    let fixture = synthetic_workspace(400, 5, 10); // 2,000 classes
    let (_project, analyzer) = build_analyzer(&fixture);
    let analyzer = Arc::new(analyzer);

    let a0 = target(&analyzer, "base.SmallTarget");
    let a1 = target(&analyzer, "base.Base1");

    let t = Instant::now();
    let h0 = {
        let analyzer = Arc::clone(&analyzer);
        std::thread::spawn(move || analyzer.get_descendants(&a0).len())
    };
    let h1 = {
        let analyzer = Arc::clone(&analyzer);
        std::thread::spawn(move || analyzer.get_descendants(&a1).len())
    };
    let n0 = h0.join().unwrap();
    let n1 = h1.join().unwrap();
    let both_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!(
        "[bench] 2 concurrent cold queries total wall={both_ms:.1}ms (SmallTarget n={n0}, Base1 n={n1})"
    );
}
