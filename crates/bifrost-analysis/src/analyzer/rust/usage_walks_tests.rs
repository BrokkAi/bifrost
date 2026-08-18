//! The Rust usage-walk tests that need a live analyzer.
//!
//! `RustUsageWalks` lives in [`brokk_bifrost_rust::usage_walks`]; the walks are
//! written against a trait, but every claim below is about what they answer
//! over a real workspace whose fact rows analysis wrote, so the fixtures need
//! an analyzer and the tests live here.

#[cfg(test)]
mod tests {
    use crate::analyzer::rust::RustAnalyzer;
    use crate::analyzer::{AnalyzerTestHooks, CodeUnitIndex};
    use crate::analyzer::{IAnalyzer, Language, ProjectFile, TestProject};
    use brokk_bifrost_rust::graph_support::{
        rust_module_files_at, rust_module_files_from_path, rust_relative_module_segments,
    };
    use brokk_bifrost_rust::usage::{Domain, RustSymbolIdentity, RustSymbolNamespace};
    use brokk_bifrost_rust::usage::{usage_binding_seeds, usage_importers};
    use brokk_bifrost_rust::usage_walks::RustUsageWalks;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    fn project(files: &[(&str, &str)]) -> (tempfile::TempDir, RustAnalyzer) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        for (rel, body) in files {
            ProjectFile::new(root.clone(), rel)
                .write(body)
                .expect("write fixture file");
        }
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        // Force the analysis pass that persists the per-file fact rows.
        let _ = analyzer.get_analyzed_files();
        (temp, analyzer)
    }

    /// `modules` modules in one crate, each re-exporting a name from
    /// `neighbours` of its successors modulo the count. The import graph is
    /// therefore one strongly connected component of that size, which is the
    /// shape issue #1809 measured.
    fn cyclic_project(modules: usize, neighbours: usize) -> (tempfile::TempDir, RustAnalyzer) {
        let mut lib = String::new();
        for index in 0..modules {
            lib.push_str(&format!("pub mod m{index};\n"));
        }
        let mut files: Vec<(String, String)> = vec![("src/lib.rs".to_string(), lib)];
        for index in 0..modules {
            let mut body = String::new();
            for step in 1..=neighbours {
                let neighbour = (index + step) % modules;
                body.push_str(&format!("pub use crate::m{neighbour}::Item{neighbour};\n"));
            }
            body.push_str(&format!("pub struct Item{index};\n"));
            files.push((format!("src/m{index}.rs"), body));
        }
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(rel, body)| (rel.as_str(), body.as_str()))
            .collect();
        project(&borrowed)
    }

    fn file(analyzer: &RustAnalyzer, suffix: &str) -> ProjectFile {
        analyzer
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().ends_with(suffix))
            .unwrap_or_else(|| panic!("{suffix} is analyzed"))
    }

    fn identity_named(
        walks: &RustUsageWalks<'_>,
        file: &ProjectFile,
        name: &str,
    ) -> RustSymbolIdentity {
        walks
            .queries()
            .identities_in_file_named(file, name)
            .into_iter()
            .map(|(identity, _)| identity)
            .find(|identity| identity.namespace == RustSymbolNamespace::Type)
            .unwrap_or_else(|| panic!("{name} is declared in {file:?}"))
    }

    /// An inverted hit is a candidate, never an answer, and for an import edge
    /// the thing that decides is module resolution: two files import a `Widget`
    /// and a third only mentions the name, but exactly one of those imports
    /// resolves to the module that declares the target.
    ///
    /// Returning the candidate set unverified passes the first assertion and
    /// fails the second, which is what makes this a regression guard rather
    /// than a restatement of the implementation.
    #[test]
    fn a_candidate_importer_whose_import_resolves_elsewhere_is_rejected() {
        let (_temp, analyzer) = project(&[
            (
                "src/lib.rs",
                "pub mod service;\npub mod decoy;\npub mod consumer;\npub mod bystander;\npub mod impostor;\n",
            ),
            ("src/service.rs", "pub struct Widget;\n"),
            ("src/decoy.rs", "pub struct Widget;\n"),
            (
                "src/consumer.rs",
                "use crate::service::Widget;\npub fn take(_: Widget) {}\n",
            ),
            (
                "src/impostor.rs",
                "use crate::decoy::Widget;\npub fn take(_: Widget) {}\n",
            ),
            (
                "src/bystander.rs",
                "pub fn describe() -> &'static str { \"Widget\" }\npub struct Widget;\n",
            ),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let service = file(&analyzer, "service.rs");
        let consumer = file(&analyzer, "consumer.rs");
        let target = identity_named(&walks, &service, "Widget");

        let candidates = walks.importer_candidates_for(&target);
        assert!(
            candidates.contains(&file(&analyzer, "impostor.rs"))
                && candidates.contains(&file(&analyzer, "bystander.rs")),
            "the offered candidates must include the files this test rejects: {candidates:?}"
        );

        let importers: BTreeSet<ProjectFile> = walks
            .edges_binding_identity(&target)
            .into_iter()
            .map(|edge| edge.importer)
            .collect();
        assert_eq!(
            importers,
            BTreeSet::from([consumer]),
            "only the import that resolves to the declaring module binds the target"
        );
    }

    /// A walk result is memoized for the analyzer that produced it and for no
    /// longer. The analyzer instance is the generation: `update_all` builds a
    /// fresh one with fresh caches, which is the invalidation these
    /// analyzer-derived values actually have.
    #[test]
    fn walk_results_are_memoized_per_generation_and_retire_with_the_analyzer() {
        let (_temp, analyzer) = project(&[
            ("src/lib.rs", "pub mod service;\n"),
            ("src/service.rs", "pub struct Widget;\n"),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let first = walks.files_in_module_package("service");
        let second = RustUsageWalks::new(&analyzer).files_in_module_package("service");
        assert!(
            Arc::ptr_eq(&first, &second),
            "a second walker in the same generation must hit the cache"
        );
        // Both the file whose package IS the module and the file that
        // declares `mod service;` back it, which is what `RustModuleFiles`
        // held in its two maps.
        assert_eq!(
            *first,
            vec![file(&analyzer, "lib.rs"), file(&analyzer, "service.rs")],
            "files were {first:?}"
        );

        let updated = analyzer.update_all();
        let after = RustUsageWalks::new(&updated).files_in_module_package("service");
        assert!(
            !Arc::ptr_eq(&first, &after),
            "a generation bump must not serve the previous generation's entry"
        );
        assert_eq!(*after, *first, "the answer itself is unchanged");
    }

    /// The four-candidate filesystem probe is memoized per module path.
    ///
    /// Uncached it is four `ProjectFile` constructions and four `exists()`
    /// calls, asked once per import specifier per file. `module_probe_
    /// computations` counts the executions, so the pin is a count and not a
    /// timing: reverting `probe_module_files` to compute unconditionally makes
    /// the repeat loop bump the counter once per ask.
    #[test]
    fn the_module_probe_runs_once_per_module_path_per_generation() {
        let (_temp, analyzer) = project(&[
            ("src/lib.rs", "pub mod service;\n"),
            ("src/service.rs", "pub struct Widget;\n"),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let importer = file(&analyzer, "lib.rs");

        let before = walks.caches.module_probe_computations();
        let first = walks.probed_module_files_from_path(&importer, "crate::service");
        assert_eq!(
            walks.caches.module_probe_computations(),
            before + 1,
            "the first ask must run the probe"
        );
        assert_eq!(
            *first,
            rust_module_files_from_path(&importer, "crate::service"),
            "the memo must answer what the unmemoized probe answers"
        );

        for _ in 0..8 {
            let again = walks.probed_module_files_from_path(&importer, "crate::service");
            assert!(
                Arc::ptr_eq(&first, &again),
                "a repeat ask must hit the memo"
            );
        }
        // A second walker in the same generation shares the analyzer's caches.
        let sibling = RustUsageWalks::new(&analyzer)
            .probed_module_files_from_path(&importer, "crate::service");
        assert!(Arc::ptr_eq(&first, &sibling));
        assert_eq!(
            walks.caches.module_probe_computations(),
            before + 1,
            "no ask after the first may run the probe again"
        );

        // A miss is memoized too: most probes find nothing, and that is the
        // case the caches exist for.
        let missing = walks.probed_module_files_from_path(&importer, "crate::absent");
        assert!(missing.is_empty());
        let after_miss = walks.caches.module_probe_computations();
        let missing_again = walks.probed_module_files_from_path(&importer, "crate::absent");
        assert!(Arc::ptr_eq(&missing, &missing_again));
        assert_eq!(walks.caches.module_probe_computations(), after_miss);

        // The generation is the invalidation, exactly as for every other walk
        // cache: a fresh analyzer probes the filesystem again.
        let updated = analyzer.update_all();
        let next = RustUsageWalks::new(&updated);
        let importer = file(&updated, "lib.rs");
        let fresh = next.probed_module_files_from_path(&importer, "crate::service");
        assert_eq!(next.caches.module_probe_computations(), 1);
        assert_eq!(*fresh, *first, "the answer itself is unchanged");
    }

    /// The segment form resolves to the same candidate path as the specifier
    /// form, so the two share one memo entry.
    #[test]
    fn the_segment_and_specifier_probes_share_one_memo_entry() {
        let (_temp, analyzer) = project(&[
            ("src/lib.rs", "pub mod service;\n"),
            ("src/service.rs", "pub struct Widget;\n"),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let importer = file(&analyzer, "lib.rs");
        let segments = vec!["crate".to_string(), "service".to_string()];

        let by_segments = walks.probed_module_files_from_segments(&importer, &segments);
        let unmemoized = rust_relative_module_segments(&importer, &segments)
            .map(|relative| rust_module_files_at(&importer, &relative))
            .unwrap_or_default();
        assert_eq!(*by_segments, unmemoized);

        let count = walks.caches.module_probe_computations();
        let by_specifier = walks.probed_module_files_from_path(&importer, "crate::service");
        assert!(Arc::ptr_eq(&by_segments, &by_specifier));
        assert_eq!(walks.caches.module_probe_computations(), count);
    }

    /// The export-chain walk replaced a global worklist with recursion, so it
    /// owns the termination the worklist's `visited` set used to provide. Two
    /// modules that publish each other's name are a cycle; the walk must still
    /// return the declaration each name really reaches.
    #[test]
    fn an_export_chain_cycle_terminates_and_keeps_the_declared_origin() {
        let (_temp, analyzer) = project(&[
            ("src/lib.rs", "pub mod alpha;\npub mod beta;\n"),
            (
                "src/alpha.rs",
                "pub struct Value;\npub use crate::beta::Echo;\n",
            ),
            (
                "src/beta.rs",
                "pub struct Echo;\npub use crate::alpha::Value;\n",
            ),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let alpha = file(&analyzer, "alpha.rs");
        let beta = file(&analyzer, "beta.rs");
        let alpha_module = walks.physical_root_of(&alpha).expect("alpha is analyzed");

        let bindings = walks.bindings_at(&alpha, &alpha_module);
        let echo = bindings
            .iter()
            .find(|binding| {
                binding.name == "Echo" && binding.namespace == RustSymbolNamespace::Type
            })
            .expect("alpha republishes Echo");
        assert_eq!(
            echo.origin.file, beta,
            "the re-exported name keeps beta's declaration as its origin: {bindings:?}"
        );
    }

    /// A module that republishes a name declared beside it -- `pub(crate) use`
    /// next to the `macro_rules!` it renames -- reaches itself through its own
    /// import edge, which is a cycle of length one. The visibility upgrade the
    /// republication exists to give must survive that.
    ///
    /// This pins the answer, not the mechanism: the guard that fails when the
    /// cycle handling is removed is
    /// `usages_rust_graph_test::rust_graph_tracks_bare_macro_invocations_through_structured_visibility`,
    /// demonstrated failing before the fixed-point iteration landed.
    #[test]
    fn a_module_republishing_a_name_declared_beside_it_keeps_the_import_domain() {
        let (_temp, analyzer) = project(&[
            ("src/lib.rs", "#[macro_use]\npub mod defs;\npub mod user;\n"),
            (
                "src/defs.rs",
                "macro_rules! target { () => {}; }\npub(crate) use target;\n",
            ),
            ("src/user.rs", "use crate::defs::target;\n"),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let defs = file(&analyzer, "defs.rs");
        let defs_module = walks.physical_root_of(&defs).expect("defs is analyzed");

        let bindings = walks.bindings_at(&defs, &defs_module);
        let republished: Vec<_> = bindings
            .iter()
            .filter(|binding| {
                binding.name == "target" && binding.namespace == RustSymbolNamespace::Macro
            })
            .collect();
        assert!(
            republished
                .iter()
                .any(|binding| matches!(binding.domain, Domain::Crate(_))),
            "`pub(crate) use` must widen the macro past its own module: {bindings:?}"
        );
    }

    /// #1809: a cyclic module import graph must not cost exponential time.
    ///
    /// Twenty-four modules, each re-exporting a name from four of its
    /// successors modulo the count, so the import graph is one strongly
    /// connected component. The first cycle handling answered a re-entry from
    /// the value so far and then iterated THAT frame to a local fixed point,
    /// keeping the result out of the analyzer cache because it came out of a
    /// partial. In a cycle every member does both, so every member re-runs
    /// every other member's whole subtree and nothing is ever memoized: the
    /// recursion body ran 25,214 times at eight modules with three neighbours,
    /// growing about fourfold per added module. Measured on this exact fixture
    /// against the previous implementation: 0.19 s at six modules, 3.05 s at
    /// eight, 69.4 s at ten, and no result in 420 s at twelve. At the
    /// twenty-four used here it does not finish at all, which is this test's
    /// fail-before evidence and is what issue #1809 recorded as ">600 s at
    /// twenty-four modules". The previous implementation answered with the
    /// same names and origins this asserts, so the fix is a cost change only.
    ///
    /// The bound is on the recursion count rather than on the wall clock
    /// because the count is what changed: it is now 6 per module, and a
    /// timing assertion at that ratio would only be a slower way of saying so.
    #[test]
    fn a_cyclic_module_graph_costs_a_bounded_number_of_recursions() {
        const MODULES: usize = 24;
        const NEIGHBOURS: usize = 4;
        let (_temp, analyzer) = cyclic_project(MODULES, NEIGHBOURS);
        let walks = RustUsageWalks::new(&analyzer);
        let head = file(&analyzer, "m0.rs");
        let head_module = walks.physical_root_of(&head).expect("m0 is analyzed");

        let bindings = walks.bindings_at(&head, &head_module);

        // The cycle must still answer, and answer with the real declarations:
        // `m0` publishes its own `Item0` and the four names it re-exports,
        // each keeping the module that declares it as its origin.
        let published: BTreeSet<(String, String)> = bindings
            .iter()
            .map(|binding| {
                (
                    binding.name.clone(),
                    binding
                        .origin
                        .file
                        .rel_path()
                        .to_string_lossy()
                        .replace('\\', "/"),
                )
            })
            .collect();
        assert_eq!(
            published,
            (0..=NEIGHBOURS)
                .map(|index| (format!("Item{index}"), format!("src/m{index}.rs")))
                .collect::<BTreeSet<_>>(),
            "the cycle must resolve every re-exported name to its declaration"
        );
        assert!(
            walks.recursion_computations() <= 16 * MODULES,
            "a cyclic module graph must cost a bounded number of recursions, \
             not one per path through the cycle: {} for {MODULES} modules",
            walks.recursion_computations()
        );
    }

    /// A walk whose budget expired must stop doing work, and must publish
    /// nothing. Bifrost treats an expired scan that keeps working as a defect
    /// in its own right: the Milestone 4 rerun killed a v2 scan at 1800 s
    /// under a 120 s budget with the walk layer still running.
    ///
    /// Both halves fail before the fix, demonstrated by removing them:
    /// without the polls, the walk keeps recursing (10 computations rather
    /// than the 1 it is allowed); without the cache gates, the truncated
    /// answer is memoized for the generation and the second, uncancelled
    /// walker reads it back as the complete one.
    #[test]
    fn a_cancelled_walk_stops_promptly_and_memoizes_nothing() {
        let (_temp, analyzer) = cyclic_project(8, 3);
        let head = file(&analyzer, "m0.rs");

        let complete = {
            let walks = RustUsageWalks::new(&analyzer);
            let module = walks.physical_root_of(&head).expect("m0 is analyzed");
            walks.bindings_at(&head, &module).as_ref().clone()
        };
        assert!(
            complete.iter().any(|binding| binding.name == "Item1"),
            "the uncancelled answer carries the re-exported names: {complete:?}"
        );

        let updated = analyzer.update_all();
        // Warm the Cargo routes on the new generation: the constructor's own
        // cancellation point is not what this test is about, and a cold build
        // there would stop the walker before it ever walked.
        let module = RustUsageWalks::new(&updated)
            .physical_root_of(&head)
            .expect("m0 is analyzed");
        let keep_going = || false;
        let walks =
            RustUsageWalks::new_while(&updated, &keep_going).expect("routes build before the poll");
        let truncated = walks.bindings_at(&head, &module);
        assert_eq!(
            walks.recursion_computations(),
            1,
            "a cancelled walk must stop after the frame it was already inside"
        );
        assert!(
            !truncated.iter().any(|binding| binding.name == "Item1"),
            "the cancelled walk did not get far enough to see the re-exports, \
             which is what makes the next assertion meaningful: {truncated:?}"
        );

        let after = RustUsageWalks::new(&updated);
        assert_eq!(
            *after.bindings_at(&head, &module),
            complete,
            "a cancelled walk must not memoize its truncated answer"
        );
    }

    /// A deep re-export chain must not exhaust the stack. The walk recurses
    /// once per link, so this pins the depth the implementation is known to
    /// survive rather than asserting an unbounded guarantee.
    #[test]
    fn an_export_chain_survives_a_deep_re_export_ladder() {
        const LINKS: usize = 250;
        let mut files: Vec<(String, String)> = Vec::new();
        let mut lib = String::new();
        for index in 0..LINKS {
            lib.push_str(&format!("pub mod link{index};\n"));
        }
        files.push(("src/lib.rs".to_string(), lib));
        for index in 0..LINKS {
            let body = if index + 1 == LINKS {
                "pub struct Value;\n".to_string()
            } else {
                format!("pub use crate::link{}::Value;\n", index + 1)
            };
            files.push((format!("src/link{index}.rs"), body));
        }
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(rel, body)| (rel.as_str(), body.as_str()))
            .collect();
        let (_temp, analyzer) = project(&borrowed);
        let walks = RustUsageWalks::new(&analyzer);
        let head = file(&analyzer, "link0.rs");
        let tail = file(&analyzer, &format!("link{}.rs", LINKS - 1));
        let head_module = walks.physical_root_of(&head).expect("link0 is analyzed");

        let bindings = walks.bindings_at(&head, &head_module);
        let value = bindings
            .iter()
            .find(|binding| binding.name == "Value")
            .expect("the head of the ladder publishes Value");
        assert_eq!(
            value.origin.file, tail,
            "the whole ladder resolves to the one real declaration"
        );
    }

    /// The alias search stops at the longest prefix that has any route and does
    /// not fall back to a shorter alias, matching what the v1 fixed point did.
    /// Choosing the prefix before filtering by domain is what keeps a private
    /// alias from shadowing the public one the source means.
    #[test]
    fn the_longest_alias_prefix_wins_and_the_search_stops_there() {
        let (_temp, analyzer) = project(&[
            (
                "src/lib.rs",
                "pub mod outer;\npub mod real;\npub mod other;\n",
            ),
            ("src/real.rs", "pub mod inner;\n"),
            ("src/real/inner.rs", "pub struct Deep;\n"),
            ("src/other.rs", "pub struct Shallow;\n"),
            (
                "src/outer.rs",
                "pub use crate::real as routed;\npub use crate::real::inner as routed_inner;\n",
            ),
        ]);
        let walks = RustUsageWalks::new(&analyzer);
        let outer = file(&analyzer, "outer.rs");
        let outer_module = walks.physical_root_of(&outer).expect("outer is analyzed");

        let one = walks.alias_routes_at(&outer_module.with_suffix(&["routed".to_string()]));
        let two = walks.alias_routes_at(&outer_module.with_suffix(&["routed_inner".to_string()]));
        assert!(!one.is_empty() && !two.is_empty(), "{one:?} {two:?}");

        // `routed_inner` is a one-component alias, so the longest prefix of
        // `routed_inner` is itself and the route lands on `real::inner`, never
        // on the shorter `routed` alias.
        let resolved = walks.resolve_segments(
            &outer,
            &outer_module.package(),
            &["routed_inner".to_string()],
        );
        assert_eq!(
            resolved
                .iter()
                .map(|route| route.target_file.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([file(&analyzer, "real.rs"), file(&analyzer, "real/inner.rs"),]),
            "the alias routes to `real::inner`, backed by the file whose \
             package it is and by the file that declares it: {resolved:?}"
        );
        assert!(
            !resolved
                .iter()
                .any(|route| route.target_module.components == ["real"]),
            "the shorter `routed` alias must not answer: {resolved:?}"
        );
    }

    /// A file edit applied through the real update path must change the next
    /// usage answer. Every walk here is memoized, so this is the guard that the
    /// memo retires with the analyzer: the first query is deliberately made
    /// before the edit so every cache the second query reads is already
    /// populated with the pre-edit answer.
    ///
    /// The edit also must not cost whole-workspace work, which is the other
    /// half of Milestone 3 and the `2ba5dda4` counter idiom.
    #[test]
    fn a_single_file_edit_is_reflected_by_the_next_usage_query() {
        let (temp, analyzer) = project(&[
            (
                "src/lib.rs",
                "pub mod service;\npub mod decoy;\npub mod consumer;\n",
            ),
            ("src/service.rs", "pub struct Widget;\n"),
            ("src/decoy.rs", "pub struct Widget;\n"),
            (
                "src/consumer.rs",
                "use crate::decoy::Widget;\npub fn take(_: Widget) {}\n",
            ),
        ]);
        let service = file(&analyzer, "service.rs");
        let consumer = file(&analyzer, "consumer.rs");
        let widget_of = |analyzer: &RustAnalyzer| {
            analyzer
                .declarations(&service)
                .into_iter()
                .find(|declaration| declaration.identifier() == "Widget")
                .expect("Widget declaration")
        };

        let before = usage_importers(
            &analyzer,
            &usage_binding_seeds(&analyzer, &BTreeSet::from([widget_of(&analyzer)])),
        );
        assert!(
            !before.contains(&consumer),
            "before the edit the consumer imports the decoy: {before:?}"
        );

        consumer
            .write("use crate::service::Widget;\npub fn take(_: Widget) {}\n")
            .expect("rewrite the consumer");
        let updated = analyzer.update(&BTreeSet::from([consumer.clone()]));
        updated.reset_full_declaration_scan_count_for_test();

        let after = usage_importers(
            &updated,
            &usage_binding_seeds(&updated, &BTreeSet::from([widget_of(&updated)])),
        );
        assert!(
            after.contains(&consumer),
            "the edited import must bind the target: {after:?}"
        );
        assert_eq!(
            updated.full_declaration_scan_count_for_test(),
            0,
            "answering after a single-file edit must not scan every declaration"
        );
        assert!(
            updated.rust_usage_facts_ready(),
            "a single-file edit must never surface a readiness state"
        );
        drop(temp);
    }

    /// The point of the redesign: a usage question is indexed lookups plus
    /// bounded walks, never a pass over every declaration in the workspace.
    /// The counter is the `2ba5dda4` structural-pin idiom.
    #[test]
    fn a_usage_query_performs_no_whole_workspace_declaration_scan() {
        let (_temp, analyzer) = project(&[
            (
                "src/lib.rs",
                "pub mod service;\npub mod consumer;\npub mod unrelated;\n",
            ),
            ("src/service.rs", "pub struct Widget;\n"),
            (
                "src/consumer.rs",
                "use crate::service::Widget;\npub fn take(_: Widget) {}\n",
            ),
            ("src/unrelated.rs", "pub struct Gadget;\n"),
        ]);
        let service = file(&analyzer, "service.rs");
        let target = analyzer
            .declarations(&service)
            .into_iter()
            .find(|declaration| declaration.identifier() == "Widget")
            .expect("Widget declaration");
        let roots = BTreeSet::from([target]);
        analyzer.reset_full_declaration_scan_count_for_test();

        let seeds = usage_binding_seeds(&analyzer, &roots);
        let importers = usage_importers(&analyzer, &seeds);

        assert!(
            importers.contains(&file(&analyzer, "consumer.rs")),
            "the query still answers: {importers:?}"
        );
        assert_eq!(
            analyzer.full_declaration_scan_count_for_test(),
            0,
            "a usage query must not scan every declaration in the workspace"
        );
    }

    #[test]
    fn raw_identifier_glob_reexports_reach_the_consumer() {
        let (_temp, analyzer) = project(&[
            (
                "Cargo.toml",
                "[package]\nname = \"raw_reexport\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            ("src/lib.rs", "mod consumer;\nmod types;\n"),
            (
                "src/types.rs",
                "mod declaration;\npub use declaration::*;\n",
            ),
            (
                "src/types/declaration.rs",
                "mod r#struct;\npub use r#struct::*;\n",
            ),
            ("src/types/declaration/struct.rs", "pub struct Thing;\n"),
            (
                "src/consumer.rs",
                "use crate::types::Thing;\npub fn take(_: Thing) {}\n",
            ),
        ]);
        let target_file = file(&analyzer, "types/declaration/struct.rs");
        let consumer = file(&analyzer, "consumer.rs");
        let target = analyzer
            .declarations(&target_file)
            .into_iter()
            .find(|declaration| declaration.identifier() == "Thing")
            .expect("Thing declaration");
        let walks = RustUsageWalks::new(&analyzer);
        let identity = identity_named(&walks, &target_file, "Thing");
        let direct_edges = walks.edges_binding_identity(&identity);
        assert!(
            direct_edges
                .iter()
                .any(|edge| edge.importer.rel_path().ends_with("types/declaration.rs")),
            "raw-module glob edge: identity={identity:#?} edges={direct_edges:#?}"
        );
        let seeds = usage_binding_seeds(&analyzer, &BTreeSet::from([target]));
        let importers = usage_importers(&analyzer, &seeds);
        assert!(
            importers.contains(&consumer),
            "raw-module glob importers: {importers:#?}"
        );
    }
}
