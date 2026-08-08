//! #1748 / #1774: the shared candidate-discovery engine used to charge one
//! `definition_candidates` store read per `use` statement in the workspace.
//!
//! `find_direct_importers_with_cancellation` visits every workspace file and
//! asks the language's import provider "could this file import the target".
//! Rust answered by resolving each `use` path to an fq name and asking the
//! store which files define it, so the cost was
//! O(workspace files x imports per file) point lookups inside one
//! `scan_usages` query -- 397k to 662k of them on the rustc tree.
//!
//! The fixture's shape is load-bearing in two ways. Half its files never
//! import the target at all, because that is the majority case on a real
//! workspace and it is the only case that pays for every one of its imports:
//! `could_import_file` is an `any(..)`, so a file that imports the target
//! stops at the first `use` that matches. The files that DO import the target
//! spell that import last, for the same reason. A fixture whose files all
//! import the target first charges nine lookups where this one charges
//! sixty-odd, and would have pinned nothing.
//!
//! The module graph is deliberately acyclic (everything imports one shared
//! `support` module, nothing imports a sibling). Cyclic module imports make
//! the Rust usage walks blow up superlinearly -- about 1 s at eight modules
//! with two neighbours each, over 600 s at twenty-four with four -- which is a
//! separate cost recorded in the v2 plan's Surprises, and would swamp what
//! these counters measure.

use crate::common::InlineTestProject;
use brokk_bifrost::usages::{UsageFinder, UsageHitKind};
use brokk_bifrost::{IAnalyzer, Language, ProjectFile, RustAnalyzer};

const CALLER_COUNT: usize = 8;
const BYSTANDER_COUNT: usize = 8;
const IMPORTS_PER_FILE: usize = 4;

fn import_heavy_project() -> (crate::common::BuiltInlineTestProject, RustAnalyzer) {
    let mut lib = String::from("pub mod target;\npub mod support;\n");
    for index in 0..CALLER_COUNT {
        lib.push_str(&format!("pub mod caller_{index};\n"));
    }
    for index in 0..BYSTANDER_COUNT {
        lib.push_str(&format!("pub mod bystander_{index};\n"));
    }

    let mut support = String::new();
    for index in 0..IMPORTS_PER_FILE {
        support.push_str(&format!("pub struct Helper{index};\n"));
    }

    let mut builder = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"importheavy\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .file("src/lib.rs", lib)
        .file("src/support.rs", support)
        .file("src/target.rs", "pub fn collect_it() -> i32 {\n    1\n}\n");

    for index in 0..CALLER_COUNT {
        let mut caller = String::new();
        for helper in 0..(IMPORTS_PER_FILE - 1) {
            caller.push_str(&format!("use crate::support::Helper{helper};\n"));
        }
        // Last, so the `any(..)` short circuit cannot hide the other imports.
        caller.push_str("use crate::target::collect_it;\n");
        for helper in 0..(IMPORTS_PER_FILE - 1) {
            caller.push_str(&format!(
                "pub fn hold_{index}_{helper}() -> Helper{helper} {{ Helper{helper} }}\n"
            ));
        }
        caller.push_str(&format!(
            "pub fn call_{index}() -> i32 {{\n    collect_it()\n}}\n"
        ));
        builder = builder.file(format!("src/caller_{index}.rs"), caller);
    }

    for index in 0..BYSTANDER_COUNT {
        let mut bystander = String::new();
        for helper in 0..IMPORTS_PER_FILE {
            bystander.push_str(&format!("use crate::support::Helper{helper};\n"));
        }
        for helper in 0..IMPORTS_PER_FILE {
            bystander.push_str(&format!(
                "pub fn keep_{index}_{helper}() -> Helper{helper} {{ Helper{helper} }}\n"
            ));
        }
        builder = builder.file(format!("src/bystander_{index}.rs"), bystander);
    }

    let project = builder.build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn collect_it_target(analyzer: &RustAnalyzer, root: &std::path::Path) -> brokk_bifrost::CodeUnit {
    let target_file = ProjectFile::new(root.to_path_buf(), "src/target.rs");
    analyzer
        .declarations(&target_file)
        .into_iter()
        .find(|unit| unit.identifier() == "collect_it")
        .expect("fixture declares collect_it")
}

#[test]
fn issue_1748_a_usage_query_resolves_import_targets_in_one_batched_read() {
    let (project, analyzer) = import_heavy_project();
    let target = collect_it_target(&analyzer, project.root());

    // Warm: the first query fills the cross-request caches this pin is not
    // about, so the second query measures steady-state candidate discovery.
    let _ = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);

    analyzer.reset_definition_candidates_query_count_for_test();
    analyzer.reset_definition_prefetch_batch_count_for_test();
    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);
    let batches = analyzer.definition_prefetch_batch_count_for_test();
    let point_lookups = analyzer.definition_candidates_query_count_for_test();

    let hits = query.result.all_hits_including_imports();
    assert!(
        hits.iter()
            .any(|hit| hit.kind == UsageHitKind::Reference || hit.kind == UsageHitKind::Import),
        "the fixture must still resolve its usages: {hits:#?}"
    );

    assert_eq!(
        1, batches,
        "candidate discovery must resolve every import target in one batched read"
    );

    // Before the batch this query charged one point lookup per `use` statement
    // it inspected, which is the same shape that charged 397k-662k on the
    // rustc tree. The bound is a fraction of the import-statement count rather
    // than an exact figure because the graph phase after discovery
    // legitimately resolves a few names of its own.
    let import_statements = CALLER_COUNT * IMPORTS_PER_FILE + BYSTANDER_COUNT * IMPORTS_PER_FILE;
    assert!(
        point_lookups * 4 < import_statements,
        "a query must not charge a point lookup per import statement: \
         {point_lookups} lookups for {import_statements} imports"
    );
}

/// The batched answer must be the same set of usages the point lookups
/// produced: every caller found, and no bystander admitted.
#[test]
fn issue_1748_batched_discovery_finds_the_same_usages() {
    let (project, analyzer) = import_heavy_project();
    let target = collect_it_target(&analyzer, project.root());

    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);
    let hit_files: std::collections::BTreeSet<String> = query
        .result
        .all_hits_including_imports()
        .iter()
        .map(|hit| hit.enclosing.source().to_string())
        .collect();

    for index in 0..CALLER_COUNT {
        let expected = format!("src/caller_{index}.rs");
        assert!(
            hit_files.iter().any(|file| file.ends_with(&expected)),
            "every caller must still be found: missing {expected} in {hit_files:?}"
        );
    }
    for index in 0..BYSTANDER_COUNT {
        let unexpected = format!("src/bystander_{index}.rs");
        assert!(
            !hit_files.iter().any(|file| file.ends_with(&unexpected)),
            "a file that never names the target must not become a hit: \
             {unexpected} in {hit_files:?}"
        );
    }
}
