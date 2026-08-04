//! A scoped Rust question must not be answered by a workspace sweep — issue #1230.
//!
//! Post-#1219 gdb sampling of the repo-scale `scan_usages_by_location` scan
//! decomposed the remaining ~3,000 CPU-s into six #1194-shaped wastes. Two of
//! them (import-origin route scans, whole-tree visible-import collection) landed
//! in #1314. The four pinned here are the rest:
//!
//! * item 3 — `resolve_module_files` materialized a fresh listing of every
//!   analyzed file and recomputed each file's allocating `rust_package_name`,
//!   *per call*, to answer "which files spell module `m`?".
//! * item 4 — `insert_namespace_export_bindings` / `collect_glob_reference_bindings`
//!   recomputed that same invariant `resolve_module_files(file, specifier)` once
//!   per export name of the module they were expanding.
//! * item 5 — `export_index_of` deep-cloned the whole cached `ExportIndex` on
//!   every cache *hit*, and callers ask per export name per pending file.
//! * item 6 — `parent_of` issues a store `definition_candidates` query per call,
//!   and `export_index_of_declarations` asks it once per declaration: every
//!   top-level item of a module asks for the *same* owner name (all 8/60 samples
//!   of `parent_of` sat under `export_index_of_declarations`).
//!
//! Every fix is an index/hoist/share/memo with identical results, so these are
//! complexity pins in the shape of `issue_1194_csharp_scan_complexity.rs`,
//! `issue_1325_csharp_census_complexity.rs`, and `issue_1334_resolver_walk_memo.rs`:
//! they assert a deterministic *count* of work — and that the count does not grow
//! with the workspace or with the number of names asked about — rather than wall
//! time. Every counter used is per-analyzer-instance (the #1099/#1325 lesson), so
//! other suites running in parallel cannot bleed in.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::AnalyzerQueryScope;
use brokk_bifrost::{IAnalyzer, Language, ProjectFile, RustAnalyzer};

/// A small Cargo-less Rust workspace: one module exporting `exports` names, a
/// second one glob-imported by a consumer, and `bystanders` unrelated modules.
///
/// The bystanders are load-bearing: they cost nothing to resolve, but each one is
/// a file a whole-workspace relisting has to visit and rename.
///
/// Each exported name comes in both shapes: a `pub const EXPORT{i}` and a
/// `pub fn export_fn{i}`. Originally only the `const`s were here, to sidestep
/// the `is_module_export_candidate` gap that #1341 has since fixed: its last
/// line, `!code_unit.is_function() || self.parent_of(code_unit).is_none()`,
/// rejected *any* function whose fq-parent resolved (i.e. any function declared
/// inside a named submodule reached via `pub mod x;`), so `export_index_of`
/// never listed such functions while non-callable items were unaffected. The
/// `const`s stay -- they are the only shape that exercised these six items
/// before -- and the functions now join them so the complexity claims (memoize /
/// hoist / share / index) are pinned over both kinds of declaration.
fn rust_module_project(exports: usize, bystanders: usize) -> crate::common::BuiltInlineTestProject {
    let mut lib = String::from("pub mod consumer;\npub mod svc;\npub mod util;\n");
    for index in 0..bystanders {
        lib.push_str(&format!("pub mod noise{index};\n"));
    }

    let mut svc = String::new();
    let mut util = String::new();
    for index in 0..exports {
        svc.push_str(&format!("pub const EXPORT{index}: usize = {index};\n"));
        svc.push_str(&format!(
            "pub fn export_fn{index}() -> usize {{ {index} }}\n"
        ));
        util.push_str(&format!("pub const HELPER{index}: usize = {index};\n"));
        util.push_str(&format!(
            "pub fn helper_fn{index}() -> usize {{ {index} }}\n"
        ));
    }

    let mut builder = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", lib)
        .file("src/svc.rs", svc)
        .file("src/util.rs", util)
        .file(
            "src/consumer.rs",
            "use crate::svc;\nuse crate::util::*;\n\n\
             pub fn consume() -> usize {\n    svc::EXPORT0 + HELPER0\n}\n",
        );
    for index in 0..bystanders {
        builder = builder.file(
            format!("src/noise{index}.rs"),
            format!("pub fn noise{index}() -> usize {{ {index} }}\n"),
        );
    }
    builder.build()
}

fn analyzer_for(project: &crate::common::BuiltInlineTestProject) -> RustAnalyzer {
    RustAnalyzer::from_project(project.project().clone())
}

fn rel_paths(files: &[ProjectFile]) -> Vec<String> {
    files
        .iter()
        .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
        .collect()
}

/// The specifiers a consumer file actually routes, plus a miss, so the pins
/// cover the rooted, bare, and unresolvable branches of `resolve_module_files`.
const SPECIFIERS: [&str; 5] = [
    "crate::svc",
    "crate::util",
    "svc",
    "self::svc",
    "crate::gone",
];

/// Item 3: repeated module resolution must not relist the workspace.
///
/// Before the fix each call materialized `get_analyzed_files()` and recomputed
/// `rust_package_name` for every analyzed file, so the listing count grew one
/// per call — the whole-workspace sweep that answered a single-module question.
#[test]
fn module_resolution_does_not_relist_the_workspace() {
    let project = rust_module_project(4, 12);
    let analyzer = analyzer_for(&project);
    let consumer = project.file("src/consumer.rs");

    // Analyzer setup legitimately enumerates the workspace once; the pin is
    // about what repeated *resolution* costs, so warm first and baseline here.
    //
    // This used to also include `src/lib.rs`, the file declaring `pub mod svc;`,
    // because the `definitions(resolved_module)` extend step matched the
    // external module's own declaration site as if it were a second file
    // backing the module's content. #1342 restricted that step to units that
    // are the module's definition, so only the content file remains.
    let warm = analyzer.resolve_module_files(&consumer, "crate::svc");
    assert_eq!(
        rel_paths(&warm),
        vec!["src/svc.rs".to_string()],
        "`crate::svc` must resolve to the module's content file"
    );

    // Warm every branch the measured loop takes, not just the rooted one.
    // `cargo_routes()` is a once-per-analyzer lazy index that itself lists the
    // workspace; the bare specifiers reach it through `resolve_crate_root_file`.
    // Warming only `crate::svc` used to reach it by accident, via the
    // `rooted && files.len() > 1` branch that the wrongly included declaring
    // file kept non-trivial -- once #1342 dropped that file the resolution
    // became single-file and the one-time build fell inside the measured
    // window. The pin is about per-call cost, so warm it deliberately instead.
    for specifier in SPECIFIERS {
        analyzer.resolve_module_files(&consumer, specifier);
    }

    analyzer.reset_analyzed_file_listing_count_for_test();
    for _ in 0..5 {
        for specifier in SPECIFIERS {
            analyzer.resolve_module_files(&consumer, specifier);
        }
    }
    let listings = analyzer.analyzed_file_listing_count_for_test();
    assert_eq!(
        listings, 0,
        "25 module resolutions must not relist the analyzed workspace at all \
         once the package index is built, relisted {listings} times"
    );
}

/// The same bound stated over workspace size: a fixed set of resolutions costs
/// the same number of listings however many unrelated modules exist.
#[test]
fn module_resolution_listings_do_not_grow_with_the_workspace() {
    let mut listings = Vec::new();
    for bystanders in [2_usize, 24] {
        let project = rust_module_project(3, bystanders);
        let analyzer = analyzer_for(&project);
        let consumer = project.file("src/consumer.rs");
        analyzer.resolve_module_files(&consumer, "crate::svc");
        analyzer.reset_analyzed_file_listing_count_for_test();
        for specifier in SPECIFIERS {
            analyzer.resolve_module_files(&consumer, specifier);
        }
        listings.push(analyzer.analyzed_file_listing_count_for_test());
    }
    assert_eq!(
        listings[0], listings[1],
        "module-resolution listings must not grow with workspace size: {listings:?}"
    );
}

/// Indexing the listing must not change which files a specifier resolves to —
/// including the bare-module, `self::`-rooted, and unresolvable branches.
#[test]
fn module_resolution_answers_are_unchanged() {
    let project = rust_module_project(3, 4);
    let analyzer = analyzer_for(&project);
    let consumer = project.file("src/consumer.rs");
    let lib = project.file("src/lib.rs");

    // Since #1342 `crate::svc` and `crate::util` carry only their content file;
    // `crate` itself still resolves to the crate root, which is a defining file
    // and not a `mod` forwarder.
    let expected: Vec<(&str, Vec<&str>)> = vec![
        ("crate::svc", vec!["src/svc.rs"]),
        ("crate::util", vec!["src/util.rs"]),
        ("crate::gone", vec![]),
        ("crate", vec!["src/lib.rs"]),
    ];
    for (specifier, files) in expected {
        assert_eq!(
            rel_paths(&analyzer.resolve_module_files(&consumer, specifier)),
            files,
            "`{specifier}` resolved from src/consumer.rs"
        );
    }

    // A repeated call against the shared index answers exactly what the first
    // one did, and resolution from a different importing file is unaffected.
    for specifier in SPECIFIERS {
        assert_eq!(
            rel_paths(&analyzer.resolve_module_files(&consumer, specifier)),
            rel_paths(&analyzer.resolve_module_files(&consumer, specifier)),
            "repeated resolution of `{specifier}` must be stable"
        );
    }
    assert_eq!(
        rel_paths(&analyzer.resolve_module_files(&lib, "svc")),
        vec!["src/svc.rs".to_string()],
        "a bare child module must still resolve from the crate root, and the \
         declaring file must not list itself (#1342)"
    );
}

/// Item 4: expanding a namespace or glob import must resolve its module files
/// once, not once per export name it then canonicalizes.
///
/// Before the hoist, `insert_namespace_export_bindings` and
/// `collect_glob_reference_bindings` recomputed the identical
/// `resolve_module_files(file, specifier)` inside their per-name loops, so the
/// count grew with the number of names the imported module exports.
#[test]
fn import_expansion_resolves_module_files_once_per_specifier() {
    let mut counts = Vec::new();
    let mut resolutions = Vec::new();
    for exports in [3_usize, 12] {
        let project = rust_module_project(exports, 4);
        let analyzer = analyzer_for(&project);
        let consumer = project.file("src/consumer.rs");
        // Warm the shared indices so the count is the reference context's own.
        analyzer.resolve_module_files(&consumer, "crate::svc");
        analyzer.reset_module_file_resolution_count_for_test();

        let context = analyzer.reference_context_of(&consumer);
        counts.push(analyzer.module_file_resolution_count_for_test());
        resolutions.push((
            context.resolve_scoped("svc", "EXPORT0"),
            context.resolve_bare("HELPER0").map(str::to_string),
        ));
    }

    assert_eq!(
        counts[0], counts[1],
        "a reference context's module-file resolutions must not grow with the \
         number of names the imported module exports (3 exports: {}, 12 exports: {})",
        counts[0], counts[1]
    );
    assert_eq!(
        resolutions[0], resolutions[1],
        "hoisting the invariant resolution must not change what the context resolves"
    );
    assert_eq!(
        resolutions[0].0.as_deref(),
        Some("svc.EXPORT0"),
        "the namespace import must still canonicalize `svc::EXPORT0`"
    );
    // A package-level `const` sits under the synthetic `_module_` scope segment
    // (declarations.rs `RUST_MODULE_SCOPE_SEGMENT`, mirroring Go's `_module_`
    // convention), unlike the raw-namespace `svc.EXPORT0` join above: this path
    // resolves through the actual canonical declaration fqn, not a bare
    // package-name join.
    assert_eq!(
        resolutions[0].1.as_deref(),
        Some("util._module_.HELPER0"),
        "the glob import must still canonicalize `HELPER0`"
    );
}

/// Item 5: the cached export index is handed out by handle, not deep-copied.
///
/// `export_index_of` is asked once per export name per pending file while
/// expanding re-export chains; cloning the whole map on every cache hit was
/// pure copying. Sharing is observable as handle identity, and the shared
/// handle must carry exactly the same index.
#[test]
fn export_index_is_shared_by_handle() {
    let project = rust_module_project(6, 3);
    let analyzer = analyzer_for(&project);
    let svc = project.file("src/svc.rs");

    let first = analyzer.export_index_of(&svc);
    let second = analyzer.export_index_of(&svc);
    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "a cache hit must return the cached handle, not a copy"
    );
    let mut names: Vec<_> = first.exports_by_name.keys().cloned().collect();
    names.sort();
    // Both shapes are listed since #1341; `EXPORT*` sorts ahead of `export_fn*`
    // because ASCII uppercase precedes lowercase.
    assert_eq!(
        names,
        (0..6)
            .map(|index| format!("EXPORT{index}"))
            .chain((0..6).map(|index| format!("export_fn{index}")))
            .collect::<Vec<_>>(),
        "the shared index must still list every export: {names:?}"
    );

    // A different file gets its own index, so sharing is per file and not a
    // single global handle.
    let util = analyzer.export_index_of(&project.file("src/util.rs"));
    assert!(
        !std::sync::Arc::ptr_eq(&first, &util),
        "distinct files must not share one export index"
    );
    assert!(
        util.exports_by_name.contains_key("HELPER0"),
        "the second file's index must be its own exports: {:?}",
        util.exports_by_name.keys().collect::<Vec<_>>()
    );
}

/// Item 6: building a file's export index must ask the store for each distinct
/// owner name once, not once per declaration that shares that owner.
///
/// `is_module_export_candidate` walks each declaration's owner chain through
/// `parent_of`, which is a `definition_candidates` store query. Every top-level
/// item in a module file names the *same* owner, so an N-item file paid N
/// identical queries; the request-scoped owner memo collapses them to one.
#[test]
fn export_index_construction_shares_owner_lookups() {
    let mut counts = Vec::new();
    let mut names = Vec::new();
    for exports in [4_usize, 16] {
        let project = rust_module_project(exports, 3);
        let analyzer = analyzer_for(&project);
        let svc = project.file("src/svc.rs");
        // The memo lives for the request scope, exactly as in #1194/#1334.
        let _scope = AnalyzerQueryScope::new(&analyzer);
        analyzer
            .test_hooks()
            .reset_definition_candidates_query_count_for_test();
        let index = analyzer.export_index_of(&svc);
        counts.push(
            analyzer
                .test_hooks()
                .definition_candidates_query_count_for_test(),
        );
        let mut exported: Vec<_> = index.exports_by_name.keys().cloned().collect();
        exported.sort();
        names.push(exported);
    }

    assert_eq!(
        counts[0], counts[1],
        "export-index construction must not issue more owner queries for more \
         same-owner declarations (4 exports: {}, 16 exports: {})",
        counts[0], counts[1]
    );
    // 16 consts plus 16 functions since #1341 lists both shapes.
    assert_eq!(
        names[1].len(),
        32,
        "every export must still be indexed: {:?}",
        names[1]
    );
    assert_eq!(
        names[0],
        (0..4)
            .map(|index| format!("EXPORT{index}"))
            .chain((0..4).map(|index| format!("export_fn{index}")))
            .collect::<Vec<_>>(),
        "memoizing owner lookups must not change the index contents"
    );
}

/// The memo is request-scoped, so it must not change the answer when no scope is
/// open: an export index built outside a query scope is the one built inside it.
#[test]
fn owner_memo_does_not_change_results_without_a_scope() {
    let project = rust_module_project(5, 3);
    let svc_path = "src/svc.rs";

    let scoped = {
        let analyzer = analyzer_for(&project);
        let _scope = AnalyzerQueryScope::new(&analyzer);
        let index = analyzer.export_index_of(&project.file(svc_path));
        let mut names: Vec<_> = index.exports_by_name.keys().cloned().collect();
        names.sort();
        names
    };
    let unscoped = {
        let analyzer = analyzer_for(&project);
        let index = analyzer.export_index_of(&project.file(svc_path));
        let mut names: Vec<_> = index.exports_by_name.keys().cloned().collect();
        names.sort();
        names
    };
    assert_eq!(
        scoped, unscoped,
        "the request-scoped owner memo must not change what an export index contains"
    );
}
