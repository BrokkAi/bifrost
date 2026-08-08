mod extractor;
mod hits;
mod inverted;
mod resolver;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::{FuzzyResult, ReferenceGraphResult, UsageHitSurface};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::rust_graph::extractor::{
    effective_scan_files, scan_files_for_member_target, scan_files_for_target,
};
use crate::analyzer::usages::rust_graph::resolver::{
    RustGraphSeedKind, canonical_usage_target, infer_graph_seeds, infer_graph_seeds_while,
    is_graph_visible_member_target, is_member_target, local_impl_target_importer_files,
    trait_member_for_impl_member, unresolved_external_frontier_specifiers,
};
use crate::analyzer::usages::traits::{
    UsageAnalyzer, UsageEdgeResolver, UsageQueryResolver, UsageScanScope,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, RustAnalyzer, resolve_analyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(crate) use resolver::{
    RustBareTokenTreeRole, RustDefinitionProvider, RustTokenPathRole, lexical_explicit_import_fqn,
    resolve_rust_path_fqn, resolve_rust_token_tree_paths, resolve_scoped_associated_item,
    resolve_scoped_associated_item_matching, resolve_trait_associated_item,
    resolve_trait_associated_item_matching, rust_bare_token_tree_non_reference_role,
    rust_bare_token_tree_role, rust_smallest_named_node_covering,
};

/// Build the whole Rust `caller -> callee` edge set in a single inverted pass
/// over the workspace (see [`inverted`]). Returns `None` when there are no Rust
/// files. `nodes`/`keep_file` mirror the Go builder.
///
/// Both usage paths resolve references through analyzer state: per-reference name
/// resolution via the cached [`crate::analyzer::RustReferenceContext`], and the
/// forward path's re-export seeds + importer narrowing via the analyzer's
/// `usage_*` index (`RustAnalyzer::usage_seeds` / `usage_importers` /
/// `usage_binding_names`).
pub(crate) fn build_rust_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = RustEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_rust_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = RustEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

pub(in crate::analyzer::usages) fn rust_usage_candidate_files(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> HashSet<ProjectFile> {
    let _scope = crate::profiling::scope("RustQueryResolver::candidate_files");
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return HashSet::default();
    };
    let roots = {
        let _scope = crate::profiling::scope("RustQueryResolver::candidate_seeds");
        let Some(seeds) = infer_graph_seeds_while(rust, target, &|| !cancellation.is_cancelled())
        else {
            return HashSet::default();
        };
        seeds.roots
    };
    let _scope = crate::profiling::scope("RustQueryResolver::usage_candidates");
    rust.usage_candidate_files_while(&roots, &|| !cancellation.is_cancelled())
        .unwrap_or_default()
}

pub(crate) struct RustQueryResolver<'a> {
    rust: &'a RustAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for RustQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            rust: resolve_analyzer::<RustAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let rust = self.rust;
        let canonical_target = canonical_usage_target(rust, target);
        let target = &canonical_target;

        let (hits, unproven_hits) = if is_member_target(rust, target) {
            let seed_result = infer_graph_seeds(rust, target);
            if seed_result.roots.is_empty() {
                return GraphUsageOutcome::fallback_safe(
                    target.fq_name(),
                    GraphFailureReason::NoGraphSeed("no graph seed resolved"),
                    "RustExportUsageGraphStrategy",
                );
            }
            let seeds = rust.usage_binding_seeds(&seed_result.roots);
            let graph_visible = is_graph_visible_member_target(rust, target);
            let private_authoritative_scope = scan_scope.is_authoritative();
            if seed_result.kind == RustGraphSeedKind::Export
                && !graph_visible
                && !private_authoritative_scope
            {
                return GraphUsageOutcome::Resolved(FuzzyResult::success(
                    target.clone(),
                    BTreeSet::new(),
                ));
            }
            let mut scan_files = effective_scan_files(rust, scan_scope, target, &seeds);
            if seed_result.kind == RustGraphSeedKind::LocalDeclaration {
                scan_files.extend(local_impl_target_importer_files(rust, target));
            }
            let scan_target = trait_member_for_impl_member(rust, target);
            let scan_target = scan_target.as_ref().unwrap_or(target);
            let result = scan_files_for_member_target(
                analyzer,
                rust,
                scan_files,
                scan_target,
                target,
                scan_scope.cancellation(),
            );
            (result.hits, result.unproven_hits)
        } else {
            let seed_result = infer_graph_seeds(rust, target);
            if seed_result.roots.is_empty() {
                return GraphUsageOutcome::fallback_safe(
                    target.fq_name(),
                    GraphFailureReason::NoGraphSeed("no graph seed resolved"),
                    "RustExportUsageGraphStrategy",
                );
            }
            let seeds = rust.usage_binding_seeds(&seed_result.roots);
            let mut scan_files = effective_scan_files(rust, scan_scope, target, &seeds);
            if seed_result.kind == RustGraphSeedKind::LocalDeclaration {
                scan_files.extend(local_impl_target_importer_files(rust, target));
            }
            (
                scan_files_for_target(
                    analyzer,
                    rust,
                    scan_files,
                    target,
                    Some(&seeds),
                    scan_scope.cancellation(),
                ),
                BTreeSet::new(),
            )
        };

        let hits: BTreeSet<_> = hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect();
        let unproven_hits: BTreeSet<_> = unproven_hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect();

        let external_hit_count = hits
            .iter()
            .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
            .count();
        if external_hit_count > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_hit_count,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            target.clone(),
            hits,
            unproven_hits,
        ))
    }
}

pub(crate) struct RustEdgeResolver<'a> {
    rust: &'a RustAnalyzer,
}

impl<'a> UsageEdgeResolver<'a> for RustEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            rust: resolve_analyzer::<RustAnalyzer>(analyzer)?,
        })
    }

    fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_rust_edges(analyzer, self.rust, nodes, keep_file)
    }

    fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_rust_edges(analyzer, self.rust, nodes, keep_file)
    }
}

#[derive(Default)]
pub struct RustExportUsageGraphStrategy;

impl RustExportUsageGraphStrategy {
    pub fn new() -> Self {
        Self
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Rust
    }

    pub fn find_export_usages(
        analyzer: &RustAnalyzer,
        defining_file: &ProjectFile,
        export_name: &str,
        query_target: Option<&CodeUnit>,
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> ReferenceGraphResult {
        let external_frontier_specifiers =
            unresolved_external_frontier_specifiers(analyzer, defining_file, export_name);
        let hits = query_target
            .map(|target| {
                Self::new()
                    .find_usages(
                        analyzer,
                        std::slice::from_ref(target),
                        candidate_files,
                        max_usages,
                    )
                    .all_hits()
            })
            .unwrap_or_default();

        ReferenceGraphResult {
            hits,
            external_frontier_specifiers,
        }
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Rust {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Rust"),
                "RustExportUsageGraphStrategy",
            );
        }

        let Some(resolver) = RustQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose RustAnalyzer",
                ),
                "RustExportUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

impl UsageAnalyzer for RustExportUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        let scan_scope = UsageScanScope::new(candidate_files, false);
        self.find_graph_usages(analyzer, overloads, &scan_scope, max_usages)
            .into_fuzzy_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, TestProject};
    use crate::test_support::AnalyzerFixture;

    /// One crate whose `wide` module exports a broad surface, consumed through
    /// a single namespace import. The eager reference context canonicalized
    /// every one of those export names before scanning the consumer; the
    /// per-site design canonicalizes only the name a site actually wrote.
    const WIDE_EXPORT_SURFACE: usize = 20;

    fn wide_export_surface_fixture() -> Vec<(String, String)> {
        let mut wide = String::from("pub fn target() {}\n");
        for index in 0..WIDE_EXPORT_SURFACE {
            wide.push_str(&format!("pub struct Filler{index};\n"));
        }
        vec![
            (
                "Cargo.toml".to_string(),
                "[package]\nname = \"wide\"\nversion = \"0.1.0\"\nedition = \"2021\"\n".to_string(),
            ),
            (
                "src/lib.rs".to_string(),
                "pub mod wide;\npub mod consumer;\n".to_string(),
            ),
            ("src/wide.rs".to_string(), wide),
            (
                "src/consumer.rs".to_string(),
                "use crate::wide;\npub fn call() { wide::target(); }\n".to_string(),
            ),
        ]
    }

    fn fixture_for(files: &[(String, String)]) -> AnalyzerFixture {
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, body)| (path.as_str(), body.as_str()))
            .collect();
        AnalyzerFixture::new_for_language(Language::Rust, &borrowed)
    }

    fn declaration_named(analyzer: &RustAnalyzer, file: &ProjectFile, name: &str) -> CodeUnit {
        analyzer
            .declarations(file)
            .into_iter()
            .find(|unit| unit.identifier() == name)
            .unwrap_or_else(|| panic!("no declaration named {name}"))
    }

    /// D1's central claim, as a number: a scan resolves the names its sites
    /// wrote, not the export surface its candidates could reach.
    ///
    /// The consumer namespace-imports a module exporting `WIDE_EXPORT_SURFACE`
    /// + 1 names and writes exactly one of them. Before the per-site rewrite
    /// the scan built a reference context per candidate file, and building one
    /// ran `canonical_export_fqn_from_files` once per export name of every
    /// namespace-imported module -- so the count scaled with the surface, not
    /// with the sites.
    #[test]
    fn usage_scan_does_not_canonicalize_the_whole_namespace_export_surface() {
        let files = wide_export_surface_fixture();
        let fixture = fixture_for(&files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();
        let wide_file = ProjectFile::new(root.clone(), "src/wide.rs");
        let consumer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let target = declaration_named(&analyzer, &wide_file, "target");
        let candidates: HashSet<ProjectFile> = [consumer].into_iter().collect();

        analyzer.reset_export_name_canonicalization_count_for_test();
        let scope = UsageScanScope::new(&candidates, false);
        let outcome = RustExportUsageGraphStrategy::new()
            .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scope, 1000)
            .into_fuzzy_result();
        assert!(
            !outcome.all_hits().is_empty(),
            "the scan must still prove the one written site"
        );

        let canonicalizations = analyzer.export_name_canonicalization_count_for_test();
        assert!(
            canonicalizations <= 4,
            "a scan of one site behind one namespace import canonicalized \
             {canonicalizations} export names; the module exports \
             {} and only one is written",
            WIDE_EXPORT_SURFACE + 1
        );
    }

    /// D3: the scan's cancellation token must reach reference resolution.
    ///
    /// The token trips on its fourth check. The scan checks it three times
    /// before it would formerly build the candidate's reference context and
    /// once immediately after, so the eager build ran to completion inside an
    /// already-doomed scan -- the investigation's "a single build is
    /// uninterruptible end to end". With resolution moved per site, no
    /// export-name walk happens before the scan observes the cancellation.
    ///
    /// One candidate file keeps this deterministic: there is exactly one rayon
    /// task, so the checks are consumed in source order. A budget of four is
    /// the exact boundary -- at three the scan bails before the candidate's
    /// context would be built, and at four it does not. The analyzer must be
    /// cold, because a warmed context cache answers without walking anything
    /// and would make the pin vacuous.
    #[test]
    fn cancelled_usage_scan_stops_before_walking_an_export_surface() {
        let files = wide_export_surface_fixture();
        let fixture = fixture_for(&files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();
        let wide_file = ProjectFile::new(root.clone(), "src/wide.rs");
        let consumer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let target = declaration_named(&analyzer, &wide_file, "target");
        let candidates: HashSet<ProjectFile> = [consumer].into_iter().collect();

        analyzer.reset_export_name_canonicalization_count_for_test();
        let cancellation = CancellationToken::cancel_after_checks_for_test(4);
        let scope = UsageScanScope::with_cancellation(&candidates, false, &cancellation);
        let _ = RustExportUsageGraphStrategy::new().find_graph_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &scope,
            1000,
        );

        assert!(cancellation.is_cancelled());
        let canonicalizations = analyzer.export_name_canonicalization_count_for_test();
        assert!(
            canonicalizations <= 4,
            "a cancelled scan canonicalized {canonicalizations} export names"
        );
    }

    /// D2: the callsite cap is a stop condition, not a post-filter.
    ///
    /// Every caller file holds a hit, and the cap is one. Once the cap plus the
    /// one hit that proves it is exceeded is reached, no further candidate is
    /// opened -- so the scanned-file count stays well below the candidate
    /// count.
    ///
    /// The scan is a rayon fan-out, so tasks already in flight when the stop
    /// flag is set still finish. Running it in a two-thread pool bounds that
    /// overshoot to one extra file and makes the assertion deterministic
    /// regardless of how many cores the host has.
    #[test]
    #[ignore = "lands with the streaming cap (D2)"]
    fn usage_scan_stops_opening_candidates_once_the_callsite_cap_is_proven() {
        const CALLERS: usize = 24;
        let mut files = vec![
            (
                "Cargo.toml".to_string(),
                "[package]\nname = \"capped\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    .to_string(),
            ),
            (
                "src/wide.rs".to_string(),
                "pub fn target() {}\n".to_string(),
            ),
        ];
        let mut lib = String::from("pub mod wide;\n");
        for index in 0..CALLERS {
            lib.push_str(&format!("pub mod caller{index};\n"));
            files.push((
                format!("src/caller{index}.rs"),
                format!(
                    "use crate::wide::target;\npub fn call{index}() {{ target(); target(); }}\n"
                ),
            ));
        }
        files.push(("src/lib.rs".to_string(), lib));

        let fixture = fixture_for(&files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();
        let wide_file = ProjectFile::new(root.clone(), "src/wide.rs");
        let target = declaration_named(&analyzer, &wide_file, "target");
        let candidates: HashSet<ProjectFile> = (0..CALLERS)
            .map(|index| ProjectFile::new(root.clone(), format!("src/caller{index}.rs")))
            .collect();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("two-thread pool");
        // Warm the analyzer state the scan shares across candidates in the same
        // pool, so the counted run measures dispatch and nothing else.
        pool.install(|| {
            let warm_scope = UsageScanScope::new(&candidates, false);
            let _ = RustExportUsageGraphStrategy::new().find_graph_usages(
                &analyzer,
                std::slice::from_ref(&target),
                &warm_scope,
                1000,
            );
        });

        analyzer.reset_scanned_candidate_file_count_for_test();
        let outcome = pool.install(|| {
            let scope = UsageScanScope::new(&candidates, false);
            RustExportUsageGraphStrategy::new()
                .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scope, 1)
                .into_fuzzy_result()
        });
        assert!(
            matches!(outcome, FuzzyResult::TooManyCallsites { .. }),
            "the cap must still be reported: {outcome:?}"
        );

        let scanned = analyzer.scanned_candidate_file_count_for_test();
        assert!(
            scanned < CALLERS,
            "the scan opened {scanned} of {CALLERS} candidates after the cap was proven"
        );
    }

    #[test]
    fn cancelled_cold_candidate_discovery_does_not_publish_partial_index() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "Cargo.toml")
            .write("[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
            .expect("write Cargo.toml");
        let source = ProjectFile::new(root.clone(), "src/lib.rs");
        source
            .write("pub mod worker;\npub fn root() {}\n")
            .expect("write lib.rs");
        ProjectFile::new(root.clone(), "src/worker.rs")
            .write("use crate::root;\npub fn run() { root(); }\n")
            .expect("write worker.rs");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let target = analyzer
            .declarations(&source)
            .into_iter()
            .find(|unit| unit.identifier() == "root")
            .expect("root declaration");

        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        assert!(
            rust_usage_candidate_files(&analyzer, &target, &cancellation).is_empty(),
            "cancelled cold discovery must not return partial candidates"
        );
        assert!(cancellation.is_cancelled());
        // Cargo routes are the whole-workspace structure a cold discovery has
        // to build, and the only one it can publish half-finished. The usage
        // index used to be the other one; since ExecPlan Milestone 2c the
        // candidate walk never touches it, so its readiness says nothing about
        // this path (`.agents/plans/rust-usage-index-v2.md`).
        assert!(!analyzer.cargo_routes_ready_for_test());

        let candidates = rust_usage_candidate_files(&analyzer, &target, &CancellationToken::new());
        assert!(candidates.contains(&source));
        assert!(analyzer.cargo_routes_ready_for_test());
    }
}
