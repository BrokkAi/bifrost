//! The Rust walk caches and the route request memo record the reads their
//! fills recorded when they hit (#7262). The engine and the criterion are in
//! `brokk_bifrost_analysis::test_support::hit_parity`.
//!
//! | row | class | fixture | hit counter |
//! | --- | --- | --- | --- |
//! | `RustWalkCaches`: module_files, module_probes, owner_roots, module_domains, alias_routes, forward_import_edges, binding_edges, module_bindings, origin_routes, macro_scope_edges, macro_visible_ranges | R | hub/cyc glob cycle, alias routes, a macro | `RustWalkCaches::hit_counts` |
//! | route and package-file request memo | R | one Cargo crate | `RustWalkCaches::route_memo_hits` |
//! | `RustCrateNamingCaches` (nearest_crate, crate_paths) | C | one Cargo crate | `RustCrateNamingCaches::hit_counts` |
//! | `RustAnalyzer.declaration_source_properties`, `.rust_hierarchy_source_facts` | C | `u_a.rs` | `Arc::ptr_eq` of the kept entry (vacuous: the fills record no key) |
//!
//! Not rows:
//! - `RustAnalyzer.declaration_facts` and `.imported_code_units`: their hits
//!   record none of the fill's keys by design. Every route to
//!   `declaration_facts` records an answer digest (Usages, Callers, Callees,
//!   Importers, Dispatch) that read verification recomputes, and
//!   `imported_code_units` has no policy, flow or RQL consumer
//!   (`workspace_authority_imported_units_have_no_policy_consumers`). The
//!   authority gate's classification table records both boundaries.
//! - `RustWalkCaches.module_declarations`: only `files_in_module_package`
//!   fills reach it, so its hits happen nested inside a `module_files` fill and
//!   the outer receipt hides them; no top-level call hits it.
//! - `RustWalkCaches.include_routes`: filled only inside
//!   `RustIncludeRoutes::include_routes_for`, which needs an `include!` host.

use crate::analyzer::rust::RustAnalyzer;
use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
use brokk_bifrost_analysis::test_support::hit_parity::{Class, Evidence, Head, Rows};
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_rust::graph_support::{RustFactSource, RustSource};
use brokk_bifrost_rust::usage_walks::RustUsageWalks;
use brokk_bifrost_test_macros::hardwon;

use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

fn fixture() -> BuiltInlineTestProject {
    let file = |path: &str, source: &str| (path.to_owned(), source.to_owned());
    let mut project = InlineTestProject::with_language(Language::Rust);
    for (path, source) in [
        file(
            "Cargo.toml",
            "[package]\nname = \"prop\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        file(
            "src/lib.rs",
            "pub mod cyc;\npub mod hub;\npub mod util;\npub mod u_a;\n#[macro_use]\nmod macros;\n",
        ),
        // `hub` and `cyc` glob-re-export each other, and `carried` and `again`
        // are alias routes to `relay`.
        file(
            "src/hub.rs",
            "pub use crate::cyc::*;\npub use crate::util::*;\npub use crate::util::relay as carried;\n",
        ),
        file(
            "src/cyc.rs",
            "pub use crate::hub::*;\npub use crate::util::relay as again;\n",
        ),
        file(
            "src/util.rs",
            "pub struct Holder { pub value: String }\n\nimpl Holder {\n    pub fn get(&self) -> String { self.value.clone() }\n}\n\npub fn relay(value: String) -> String { value }\n",
        ),
        file(
            "src/macros.rs",
            "macro_rules! shout { ($e:expr) => { $e } }\n",
        ),
        file(
            "src/u_a.rs",
            "use crate::hub::{carried, relay};\npub fn u_a() { let r = carried(relay(String::new())); shout!(r); }\n",
        ),
    ] {
        project = project.file(path, source);
    }
    project.build()
}

#[test]
#[hardwon("#7262: a Rust walk-cache hit dropped the reads its fill recorded")]
fn rust_walk_caches_and_route_memo_record_the_reads_their_fills_recorded() {
    let project = fixture();
    let (base, analyzer) = super::test_support::certified_analyzer(project.root());
    let head = Head::of(project.project_dyn(), &base);
    let mut rows = Rows::new(&analyzer, &head);
    let files: Vec<_> = ["src/hub.rs", "src/cyc.rs", "src/util.rs", "src/u_a.rs"]
        .into_iter()
        .map(|path| project.file(path))
        .collect();

    {
        let scope = AnalyzerQueryScope::new(&analyzer);
        let route_hits = || analyzer.walk_caches().route_memo_hits();
        rows.row(
            "route and package-file request memo",
            Class::Replay,
            Evidence::Hits(&route_hits),
            || {
                drop(RustUsageWalks::new(&analyzer, scope.token()).expect("walks"));
                analyzer.file_routes(&files[0], None).expect("file routes");
            },
        );
        assert!(
            route_hits() > 0,
            "the file-route request memo was exercised"
        );
    }
    let scope = AnalyzerQueryScope::new(&analyzer);
    // The identities and macro declarations the walks start from come from
    // `declaration_facts`, a cache whose hits record nothing of their own (a
    // row below); asking for them first keeps that out of the walk row.
    let (identities, macros) = {
        let walks = RustUsageWalks::new(&analyzer, scope.token()).expect("walks");
        let identities: Vec<_> = files
            .iter()
            .flat_map(|file| {
                ["relay", "Holder"].into_iter().flat_map(|name| {
                    walks
                        .queries()
                        .identities_in_file_named(file, name)
                        .expect("identities")
                })
            })
            .map(|(identity, _)| identity)
            .collect();
        (
            identities,
            walks.macro_declarations_named("shout").expect("macros"),
        )
    };
    let walk_hits = |name: &'static str| {
        let analyzer = &analyzer;
        move || {
            analyzer
                .walk_caches()
                .hit_counts()
                .into_iter()
                .find(|(cache, _)| *cache == name)
                .map(|(_, hits)| hits)
                .expect("a named walk cache")
        }
    };
    let names = [
        "rust.walk.module_files",
        "rust.walk.module_probes",
        "rust.walk.owner_roots",
        "rust.walk.module_domains",
        "rust.walk.alias_routes",
        "rust.walk.forward_import_edges",
        "rust.walk.binding_edges",
        "rust.walk.module_bindings",
        "rust.walk.origin_routes",
        "rust.walk.macro_scope_edges",
        "rust.walk.macro_visible_ranges",
    ];
    let counters: Vec<_> = names.iter().map(|name| walk_hits(name)).collect();
    let evidence: Vec<(&str, &dyn Fn() -> u64)> = names
        .iter()
        .zip(&counters)
        .map(|(name, counter)| (*name, counter as &dyn Fn() -> u64))
        .collect();
    rows.row(
        "Rust walk caches",
        Class::Replay,
        Evidence::EachHits(&evidence),
        || {
            let walks = RustUsageWalks::new(&analyzer, scope.token()).expect("walks");
            for file in &files {
                walks.probed_module_files_from_segments(file, &["util".to_owned()]);
                walks.owner_roots_of(file).expect("owner roots");
                walks.macro_scope_edges_of(file).expect("macro scope edges");
                walks.forward_import_edges_of(file).expect("forward edges");
                walks.origin_routes_of(file).expect("origin routes");
                for module in walks.binding_modules_of(file).expect("binding modules") {
                    walks.bindings_at(file, &module).expect("bindings");
                    walks
                        .effective_module_domains_of(&module)
                        .expect("module domains");
                    walks.alias_routes_at(&module).expect("alias routes");
                    walks.files_for_module(&module);
                }
            }
            for identity in &identities {
                walks
                    .edges_binding_identity(identity)
                    .expect("binding edges");
            }
            for declaration in &macros {
                walks
                    .macro_visible_ranges_of(declaration)
                    .expect("macro visible ranges");
            }
        },
    );
    rows.finish();
}

#[test]
#[hardwon("#9737: a walker-local route answer let a second walk fill skip its route reads")]
fn a_walk_fill_after_its_walker_asked_the_routes_records_the_route_reads() {
    use brokk_bifrost_analysis::analyzer::{ReadKey, ReadLedger, capture_query_reads};
    use brokk_bifrost_semantic::analyzer::semantic::read_ledger::LookupKind;
    let project = fixture();
    let file = project.file("src/u_a.rs");
    let derivation_lookups = |ledger: &ReadLedger| {
        ledger
            .keys()
            .into_iter()
            .filter(|key| {
                matches!(
                    key,
                    ReadKey::Lookup {
                        kind: LookupKind::Derivation(_),
                        ..
                    }
                )
            })
            .map(|key| format!("{key:?}"))
            .collect::<std::collections::BTreeSet<_>>()
    };
    let forward_edges = |analyzer: &RustAnalyzer, scope: &AnalyzerQueryScope<'_>| {
        let walks = RustUsageWalks::new(analyzer, scope.token()).expect("walks");
        walks.forward_import_edges_of(&file).expect("forward edges");
    };
    // The route reads of the edges fill when nothing asked the routes before.
    let expected = {
        let (_base, analyzer) = super::test_support::certified_analyzer(project.root());
        let scope = AnalyzerQueryScope::new(&analyzer);
        let (_, ledger) = capture_query_reads(&analyzer, || forward_edges(&analyzer, &scope));
        derivation_lookups(&ledger)
    };
    assert!(!expected.is_empty(), "the edges fill asks route questions");

    let (_base, analyzer) = super::test_support::certified_analyzer(project.root());
    {
        // The walker asks the file's routes, and then the edges fill asks them
        // again: the fill's receipt must still hold the route reads.
        let scope = AnalyzerQueryScope::new(&analyzer);
        let walks = RustUsageWalks::new(&analyzer, scope.token()).expect("walks");
        walks.file_routes(&file);
        walks.forward_import_edges_of(&file).expect("forward edges");
    }
    let edge_hits = || {
        analyzer
            .walk_caches()
            .hit_counts()
            .into_iter()
            .find(|(cache, _)| *cache == "rust.walk.forward_import_edges")
            .map(|(_, hits)| hits)
            .expect("the forward-edge walk cache")
    };
    let before = edge_hits();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let (_, ledger) = capture_query_reads(&analyzer, || forward_edges(&analyzer, &scope));
    assert!(edge_hits() > before, "a later request hits the kept edges");
    let replayed = derivation_lookups(&ledger);
    let missing: Vec<_> = expected.difference(&replayed).collect();
    assert!(
        missing.is_empty(),
        "the kept edges replay the route reads their fill depended on: {missing:?}"
    );
}

#[test]
#[hardwon("#7262: a cache hit recorded fewer reads than the fill that built its entry")]
fn rust_crate_naming_caches_record_the_reads_their_fills_recorded() {
    let project = fixture();
    let base = WorkspaceAnalyzer::build_ephemeral_footgun(
        project.project_dyn(),
        AnalyzerConfig::default(),
    )
    .expect("the base workspace builds");
    let analyzer = RustAnalyzer::new(project.project_dyn());
    let head = Head::of(project.project_dyn(), &base);
    let mut rows = Rows::new(&analyzer, &head);
    let files: Vec<_> = ["src/hub.rs", "src/util.rs", "src/u_a.rs"]
        .into_iter()
        .map(|path| project.file(path))
        .collect();
    let hits = || {
        analyzer
            .crate_naming_caches()
            .hit_counts()
            .iter()
            .map(|(_, hits)| hits)
            .sum::<u64>()
    };
    rows.row(
        "RustCrateNamingCaches",
        Class::ConsumerKeys,
        Evidence::Hits(&hits),
        || {
            for file in &files {
                brokk_bifrost_rust::declarations::rust_package_name_with(
                    analyzer.crate_naming_caches(),
                    file,
                );
            }
        },
    );
    rows.finish();
}

/// A row whose evidence is that the cache hands back the entry it kept.
fn kept_arc<T>(
    counter: &std::cell::Cell<u64>,
    previous: &std::cell::RefCell<Option<std::sync::Arc<T>>>,
    now: std::sync::Arc<T>,
) {
    if previous
        .borrow()
        .as_ref()
        .is_some_and(|earlier| std::sync::Arc::ptr_eq(earlier, &now))
    {
        counter.set(counter.get() + 1);
    }
    *previous.borrow_mut() = Some(now);
}

#[test]
#[hardwon("#7262: a cache hit recorded fewer reads than the fill that built its entry")]
fn rust_analyzer_source_fact_caches_record_the_reads_their_fills_recorded() {
    let project = fixture();
    let base = WorkspaceAnalyzer::build_ephemeral_footgun(
        project.project_dyn(),
        AnalyzerConfig::default(),
    )
    .expect("the base workspace builds");
    let analyzer = RustAnalyzer::new(project.project_dyn());
    let head = Head::of(project.project_dyn(), &base);
    let mut rows = Rows::new(&analyzer, &head);
    let file = project.file("src/u_a.rs");
    let _scope = AnalyzerQueryScope::new(&analyzer);
    let kept = std::cell::Cell::new(0_u64);
    let previous = std::cell::RefCell::new(None);
    rows.row(
        "RustAnalyzer.declaration_source_properties",
        Class::ConsumerKeys,
        Evidence::Hits(&|| kept.get()),
        || {
            kept_arc(
                &kept,
                &previous,
                analyzer
                    .declaration_source_properties(&file, &|| true)
                    .expect("properties"),
            )
        },
    );
    let kept = std::cell::Cell::new(0_u64);
    let previous = std::cell::RefCell::new(None);
    rows.row(
        "RustAnalyzer.rust_hierarchy_source_facts",
        Class::ConsumerKeys,
        Evidence::Hits(&|| kept.get()),
        || {
            kept_arc(
                &kept,
                &previous,
                analyzer
                    .canonical_rust_hierarchy_source_facts(&file, &|| true)
                    .expect("hierarchy facts"),
            )
        },
    );
    rows.finish();
}
