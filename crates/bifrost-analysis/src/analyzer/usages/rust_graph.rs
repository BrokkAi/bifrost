use crate::analyzer::rust::{
    RustBindingSeeds, usage_binding_seeds_while, usage_candidate_files_from_binding_seeds_while,
};
mod extractor;
mod hits;
mod inverted;
mod resolver;
use crate::analyzer::usages::traits::{GraphUsageAnalyzer, PreparedUsageQuery};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::{FuzzyResult, ReferenceGraphResult};
use crate::analyzer::usages::outcome::{
    CandidateUsageHits, GraphFailureReason, GraphUsageOutcome, union_candidate_usages,
};
use crate::analyzer::usages::rust_graph::extractor::{
    effective_scan_files, effective_scan_files_from_prepared_candidates,
    scan_files_for_member_target, scan_files_for_target,
};
use crate::analyzer::usages::rust_graph::resolver::infer_graph_seeds_while;
use crate::analyzer::usages::rust_graph::resolver::{
    RustGraphSeedKind, canonical_usage_target, is_graph_visible_member_target, is_member_target,
    local_impl_target_importer_files_while, trait_member_for_impl_member,
    unresolved_external_frontier_specifiers,
};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
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
/// Both usage paths resolve references through analyzer state: lazy,
/// query-scoped per-reference name resolution, and the
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

/// The strategy name every Rust usage diagnostic reports.
const RUST_STRATEGY: &str = "RustExportUsageGraphStrategy";

struct PreparedRustTargetReady {
    member: bool,
    graph_visible: bool,
    kind: RustGraphSeedKind,
    seeds: RustBindingSeeds,
    protected_files: HashSet<ProjectFile>,
    planned_files: HashSet<ProjectFile>,
}

struct PreparedRustTarget {
    target: CodeUnit,
    ready: Option<PreparedRustTargetReady>,
}

/// Request-local Rust resolver state built before generic candidate admission.
///
/// `candidate_files` is the complete pre-budget universe for the finder path.
/// `targets` retains the binding seeds that semantic execution would otherwise
/// reconstruct after admission.
pub(crate) struct PreparedRustUsageQuery {
    candidate_files: HashSet<ProjectFile>,
    targets: Vec<PreparedRustTarget>,
    enforce_admitted_scope: bool,
}

impl PreparedRustUsageQuery {
    pub(crate) fn candidate_files(&self) -> &HashSet<ProjectFile> {
        &self.candidate_files
    }

    fn prepare(
        rust: &RustAnalyzer,
        overloads: &[CodeUnit],
        supplied_candidates: &HashSet<ProjectFile>,
        authoritative: bool,
        include_finder_augmentation: bool,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        // The planning phase's request boundary; nested inside any
        // caller-owned scope (issue #2414 step 3).
        let scope = AnalyzerQueryScope::new(rust);
        let token = scope.token();
        let keep_going = || !cancellation.is_cancelled();
        let mut canonical_targets = Vec::with_capacity(overloads.len());
        for overload in overloads {
            let canonical = canonical_usage_target(rust, token, overload);
            if !canonical_targets.contains(&canonical) {
                canonical_targets.push(canonical);
            }
        }

        let mut candidate_files = supplied_candidates.clone();
        let mut targets = Vec::with_capacity(canonical_targets.len());
        for target in canonical_targets {
            let member = is_member_target(rust, &target);
            let seed_result = {
                let _scope = crate::profiling::scope("rust_graph::seed_inference");
                infer_graph_seeds_while(rust, token, &target, &keep_going)?
            };
            if seed_result.roots.is_empty() {
                targets.push(PreparedRustTarget {
                    target,
                    ready: None,
                });
                continue;
            }
            let seeds = {
                let _scope = crate::profiling::scope("rust_graph::binding_seed_discovery");
                rust.note_usage_binding_seed_preparation();
                usage_binding_seeds_while(rust, token, &seed_result.roots, &keep_going)?
            };
            crate::profiling::note_with(|| {
                format!(
                    "rust_graph seed roots={} candidate_names={}",
                    seed_result.roots.len(),
                    seeds.candidate_names().count()
                )
            });
            let graph_visible = !member || is_graph_visible_member_target(rust, &target);
            let protected_files = if include_finder_augmentation {
                let _scope = crate::profiling::scope("RustQueryResolver::usage_candidates");
                usage_candidate_files_from_binding_seeds_while(rust, token, &seeds, &keep_going)?
            } else {
                HashSet::default()
            };
            candidate_files.extend(protected_files.iter().cloned());
            targets.push(PreparedRustTarget {
                target,
                ready: Some(PreparedRustTargetReady {
                    member,
                    graph_visible,
                    kind: seed_result.kind,
                    seeds,
                    protected_files,
                    planned_files: HashSet::default(),
                }),
            });
        }

        // The outer finder admits the union, but each overload keeps its own
        // protected closure. Letting one overload inherit another's importers
        // makes every semantic scan wider without improving soundness.
        let mut graph_candidates = HashSet::default();
        for prepared in &mut targets {
            let Some(PreparedRustTargetReady {
                member,
                graph_visible,
                kind,
                seeds,
                protected_files,
                planned_files,
            }) = &mut prepared.ready
            else {
                continue;
            };
            if *member && *kind == RustGraphSeedKind::Export && !*graph_visible && !authoritative {
                continue;
            }
            let mut planning_candidates = supplied_candidates.clone();
            planning_candidates.extend(std::mem::take(protected_files));
            let planning_scope = UsageScanScope::with_cancellation(
                &planning_candidates,
                authoritative,
                cancellation,
            );
            let mut target_files = if include_finder_augmentation {
                effective_scan_files_from_prepared_candidates(
                    rust,
                    token,
                    &planning_scope,
                    &prepared.target,
                    seeds,
                )
            } else {
                effective_scan_files(rust, token, &planning_scope, &prepared.target, seeds)
            };
            if *kind == RustGraphSeedKind::LocalDeclaration {
                target_files.extend(local_impl_target_importer_files_while(
                    rust,
                    token,
                    &prepared.target,
                    &keep_going,
                )?);
            }
            keep_going().then_some(())?;
            graph_candidates.extend(target_files.iter().cloned());
            *planned_files = target_files;
        }
        candidate_files.extend(graph_candidates);

        Some(Self {
            candidate_files,
            targets,
            enforce_admitted_scope: include_finder_augmentation,
        })
    }
}

impl PreparedUsageQuery for PreparedRustUsageQuery {
    fn candidate_files(&self) -> &HashSet<ProjectFile> {
        &self.candidate_files
    }

    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        assert_eq!(language_for_target(target), Language::Rust);
        let resolver = RustQueryResolver::try_new(analyzer)
            .expect("prepared Rust usage query requires a Rust analyzer");
        resolver.find_prepared_usages(analyzer, self, scan_scope, max_usages)
    }
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
        let fallback_cancellation = CancellationToken::default();
        let cancellation = scan_scope.cancellation().unwrap_or(&fallback_cancellation);
        let Some(prepared) = PreparedRustUsageQuery::prepare(
            self.rust,
            overloads,
            scan_scope.candidate_files(),
            scan_scope.is_authoritative(),
            false,
            cancellation,
        ) else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        if let Some(cancellation) = scan_scope.cancellation() {
            let expanded_scope = UsageScanScope::with_cancellation(
                prepared.candidate_files(),
                scan_scope.is_authoritative(),
                cancellation,
            );
            self.find_prepared_usages(analyzer, &prepared, &expanded_scope, max_usages)
        } else {
            let expanded_scope =
                UsageScanScope::new(prepared.candidate_files(), scan_scope.is_authoritative());
            self.find_prepared_usages(analyzer, &prepared, &expanded_scope, max_usages)
        }
    }
}

impl RustQueryResolver<'_> {
    fn find_prepared_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        prepared: &PreparedRustUsageQuery,
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        // The scan's request boundary; nested inside any caller-owned scope
        // (issue #2414 step 3).
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let rust = self.rust;
        let candidates: Vec<_> = prepared
            .targets
            .iter()
            .map(|prepared| prepared.target.clone())
            .collect();
        union_candidate_usages(&candidates, max_usages, |target| {
            let prepared_target = prepared
                .targets
                .iter()
                .find(|prepared| &prepared.target == target)
                .expect("prepared Rust target must have retained state");
            let Some(PreparedRustTargetReady {
                member,
                graph_visible,
                kind,
                seeds,
                protected_files: _,
                planned_files,
            }) = &prepared_target.ready
            else {
                return Err(GraphFailureReason::NoGraphSeed("no graph seed resolved")
                    .diagnostic(target.fq_name(), RUST_STRATEGY));
            };
            let scan_files = if prepared.enforce_admitted_scope {
                planned_files
                    .intersection(scan_scope.candidate_files())
                    .cloned()
                    .collect()
            } else {
                planned_files.clone()
            };

            let (hits, unproven_hits) = if *member {
                let private_authoritative_scope = scan_scope.is_authoritative();
                if *kind == RustGraphSeedKind::Export
                    && !*graph_visible
                    && !private_authoritative_scope
                {
                    return Ok(CandidateUsageHits::default());
                }
                let scan_target = trait_member_for_impl_member(rust, token, target);
                let scan_target = scan_target.as_ref().unwrap_or(target);
                let result = scan_files_for_member_target(
                    analyzer,
                    token,
                    rust,
                    scan_files,
                    scan_target,
                    target,
                    scan_scope.cancellation(),
                    max_usages,
                );
                (result.hits, result.unproven_hits)
            } else {
                (
                    scan_files_for_target(
                        analyzer,
                        token,
                        rust,
                        scan_files,
                        target,
                        Some(seeds),
                        scan_scope.cancellation(),
                        max_usages,
                    ),
                    BTreeSet::new(),
                )
            };

            // A proven hit inside the target itself is a recursive call (#1638):
            // kept, classified `SelfReceiver`. The unproven channel still drops
            // them -- an unproven recursive call is not evidence of anything.
            Ok(CandidateUsageHits {
                hits,
                unproven_hits: unproven_hits
                    .into_iter()
                    .filter(|hit| &hit.enclosing != target)
                    .collect(),
            })
        })
    }
}

pub(crate) struct RustEdgeResolver<'a> {
    rust: &'a RustAnalyzer,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> RustEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            rust: resolve_analyzer::<RustAnalyzer>(analyzer)?,
        })
    }

    pub(crate) fn build_edges<F>(
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

    pub(crate) fn build_edge_weights<F>(
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
    pub const fn new() -> Self {
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
        // The export query's request boundary (issue #2414 step 3).
        let scope = AnalyzerQueryScope::new(analyzer);
        let external_frontier_specifiers = unresolved_external_frontier_specifiers(
            analyzer,
            scope.token(),
            defining_file,
            export_name,
        );
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
}

impl GraphUsageAnalyzer for RustExportUsageGraphStrategy {
    fn prepare_usage_query(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        authoritative: bool,
        cancellation: &CancellationToken,
    ) -> Option<Box<dyn PreparedUsageQuery>> {
        let target = overloads.first()?;
        if language_for_target(target) != Language::Rust {
            return None;
        }
        let resolver = RustQueryResolver::try_new(analyzer)?;
        PreparedRustUsageQuery::prepare(
            resolver.rust,
            overloads,
            candidate_files,
            authoritative,
            true,
            cancellation,
        )
        .map(|prepared| Box::new(prepared) as Box<dyn PreparedUsageQuery>)
    }

    fn find_graph_usages(
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
                RUST_STRATEGY,
            );
        }

        let Some(resolver) = RustQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose RustAnalyzer",
                ),
                RUST_STRATEGY,
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
    use crate::analyzer::{
        AnalyzerDelegate, CodeUnitIndex, FileSetProject, JavaAnalyzer, Language, MultiAnalyzer,
        TestProject,
    };
    use crate::test_support::AnalyzerFixture;
    use std::collections::BTreeMap;

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
        let borrowed: Vec<_> = files
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

    #[test]
    fn usage_scan_does_not_canonicalize_the_whole_namespace_export_surface() {
        let files = wide_export_surface_fixture();
        let fixture = fixture_for(&files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();
        let wide_file = ProjectFile::new(root.clone(), "src/wide.rs");
        let consumer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let target = declaration_named(&analyzer, &wide_file, "target");
        let candidates: HashSet<_> = [consumer].into_iter().collect();

        analyzer.reset_export_name_canonicalization_count_for_test();
        let scope = UsageScanScope::new(&candidates, false);
        let outcome = RustExportUsageGraphStrategy::new()
            .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scope, 1000)
            .into_fuzzy_result();
        assert!(!outcome.all_hits().is_empty());
        let canonicalizations = analyzer.export_name_canonicalization_count_for_test();
        assert!(
            canonicalizations <= 4,
            "one written site canonicalized {canonicalizations} names from a {}-name surface",
            WIDE_EXPORT_SURFACE + 1
        );
    }

    #[test]
    fn rust_usage_scan_uses_indexed_definition_queries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "Cargo.toml")
            .write("[package]\nname = \"shard_scope\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .expect("write Cargo.toml");
        let target_file = ProjectFile::new(root.clone(), "src/lib.rs");
        target_file
            .write("pub fn target() {}\npub fn caller() { target(); }\n")
            .expect("write Rust source");
        ProjectFile::new(root.clone(), "src/App.java")
            .write("package app; public class App {}\n")
            .expect("write Java source");
        let project = FileSetProject::new(
            root,
            [
                std::path::PathBuf::from("Cargo.toml"),
                std::path::PathBuf::from("src/lib.rs"),
                std::path::PathBuf::from("src/App.java"),
            ],
        );
        let rust = RustAnalyzer::from_project(project.clone());
        let target = declaration_named(&rust, &target_file, "target");
        let analyzer = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
            ),
            (Language::Rust, AnalyzerDelegate::Rust(rust)),
        ]));
        analyzer
            .test_hooks()
            .reset_global_usage_definition_index_build_count_for_test();
        analyzer
            .test_hooks()
            .reset_definition_candidates_query_count_for_test();
        let candidates: HashSet<_> = [target_file].into_iter().collect();
        let scope = UsageScanScope::new(&candidates, true);

        let outcome = RustExportUsageGraphStrategy::new()
            .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scope, 1000)
            .into_fuzzy_result();

        assert_eq!(outcome.all_hits_including_imports().len(), 1);
        for (language, delegate) in analyzer.delegates() {
            let builds = delegate
                .analyzer()
                .test_hooks()
                .global_usage_definition_index_build_count_for_test();
            assert_eq!(
                builds, 0,
                "Rust usage scan built the {language:?} definition shard"
            );
        }
        assert!(
            analyzer
                .test_hooks()
                .definition_candidates_query_count_for_test()
                > 0,
            "the regression must exercise persisted definition queries"
        );
    }

    #[test]
    fn cancelled_usage_scan_stops_before_walking_an_export_surface() {
        let files = wide_export_surface_fixture();
        let fixture = fixture_for(&files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();
        let wide_file = ProjectFile::new(root.clone(), "src/wide.rs");
        let consumer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let target = declaration_named(&analyzer, &wide_file, "target");
        let candidates: HashSet<_> = [consumer].into_iter().collect();

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
            "cancelled scan canonicalized {canonicalizations} export names"
        );
    }

    #[test]
    fn usage_scan_stops_opening_candidates_once_the_callsite_cap_is_proven() {
        const CALLERS: usize = 24;
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "Cargo.toml")
            .write("[package]\nname = \"capped\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .expect("write Cargo.toml");
        let target_file = ProjectFile::new(root.clone(), "src/wide.rs");
        target_file
            .write("pub fn target() {}\n")
            .expect("write target");
        let mut lib = String::from("pub mod wide;\n");
        let mut candidates = HashSet::default();
        for index in 0..CALLERS {
            lib.push_str(&format!("pub mod caller{index};\n"));
            let file = ProjectFile::new(root.clone(), format!("src/caller{index}.rs"));
            file.write(format!(
                "use crate::wide::target;\npub fn call{index}() {{ target(); target(); }}\n"
            ))
            .expect("write caller");
            candidates.insert(file);
        }
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write(&lib)
            .expect("write lib.rs");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let target = analyzer
            .declarations(&target_file)
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("target declaration");
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("two-thread pool");

        analyzer.reset_scanned_candidate_file_count_for_test();
        let outcome = pool.install(|| {
            let scope = UsageScanScope::new(&candidates, false);
            RustExportUsageGraphStrategy::new().find_graph_usages(
                &analyzer,
                std::slice::from_ref(&target),
                &scope,
                1,
            )
        });

        assert!(matches!(
            outcome,
            GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites { .. })
        ));
        let opened = analyzer.scanned_candidate_file_count_for_test();
        assert!(opened < CALLERS, "opened all {opened} candidate files");
    }

    #[test]
    fn recursive_reference_is_classified_before_the_external_cap() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "src/lib.rs");
        file.write("pub fn target(n: usize) { if n > 0 { target(n - 1); } }\n")
            .expect("write lib.rs");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let target = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "target")
            .expect("target declaration");
        let candidates: HashSet<_> = [file].into_iter().collect();
        let scope = UsageScanScope::new(&candidates, true);
        let outcome = RustExportUsageGraphStrategy::new()
            .find_graph_usages(&analyzer, std::slice::from_ref(&target), &scope, 0)
            .into_fuzzy_result();

        assert!(
            !matches!(outcome, FuzzyResult::TooManyCallsites { .. }),
            "recursive reference must not trip the external cap: {outcome:?}"
        );
        assert!(outcome.all_hits().is_empty());
        let editor_hits = outcome.all_hits_including_imports();
        assert_eq!(editor_hits.len(), 1, "recursive hit: {editor_hits:#?}");
        assert_eq!(
            editor_hits.iter().next().expect("recursive hit").kind,
            crate::analyzer::usages::model::UsageHitKind::SelfReceiver
        );
    }

    #[test]
    fn prepared_overloads_keep_target_local_scan_plans() {
        let files = vec![
            (
                "Cargo.toml".to_string(),
                "[workspace]\nmembers = [\"alpha\", \"beta\"]\nresolver = \"2\"\n".to_string(),
            ),
            (
                "alpha/Cargo.toml".to_string(),
                "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    .to_string(),
            ),
            (
                "alpha/src/lib.rs".to_string(),
                "pub mod caller;\npub fn target_alpha() {}\n".to_string(),
            ),
            (
                "alpha/src/caller.rs".to_string(),
                "use crate::target_alpha;\npub fn call() { target_alpha(); }\n".to_string(),
            ),
            (
                "beta/Cargo.toml".to_string(),
                "[package]\nname = \"beta\"\nversion = \"0.1.0\"\nedition = \"2021\"\n".to_string(),
            ),
            (
                "beta/src/lib.rs".to_string(),
                "pub mod caller;\npub fn target_beta() {}\n".to_string(),
            ),
            (
                "beta/src/caller.rs".to_string(),
                "use crate::target_beta;\npub fn call() { target_beta(); }\n".to_string(),
            ),
        ];
        let fixture = fixture_for(&files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();
        let alpha_file = ProjectFile::new(root.clone(), "alpha/src/lib.rs");
        let alpha_caller = ProjectFile::new(root.clone(), "alpha/src/caller.rs");
        let beta_file = ProjectFile::new(root.clone(), "beta/src/lib.rs");
        let beta_caller = ProjectFile::new(root, "beta/src/caller.rs");
        let alpha = declaration_named(&analyzer, &alpha_file, "target_alpha");
        let beta = declaration_named(&analyzer, &beta_file, "target_beta");

        let prepared = PreparedRustUsageQuery::prepare(
            &analyzer,
            &[alpha.clone(), beta.clone()],
            &HashSet::default(),
            false,
            true,
            &CancellationToken::new(),
        )
        .expect("prepared overload query");
        let alpha_plan = prepared
            .targets
            .iter()
            .find(|target| target.target == alpha)
            .and_then(|target| target.ready.as_ref())
            .expect("alpha plan");
        let beta_plan = prepared
            .targets
            .iter()
            .find(|target| target.target == beta)
            .and_then(|target| target.ready.as_ref())
            .expect("beta plan");

        assert!(alpha_plan.planned_files.contains(&alpha_caller));
        assert!(!alpha_plan.planned_files.contains(&beta_caller));
        assert!(beta_plan.planned_files.contains(&beta_caller));
        assert!(!beta_plan.planned_files.contains(&alpha_caller));
        assert!(prepared.candidate_files().contains(&alpha_caller));
        assert!(prepared.candidate_files().contains(&beta_caller));
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
            PreparedRustUsageQuery::prepare(
                &analyzer,
                std::slice::from_ref(&target),
                &HashSet::default(),
                false,
                true,
                &cancellation,
            )
            .is_none(),
            "cancelled cold preparation must not return a partial plan"
        );
        assert!(cancellation.is_cancelled());
        // Cargo routes are the whole-workspace structure a cold discovery has
        // to build, and the only one it can publish half-finished. The usage
        // index used to be the other one; under usage v2 the candidate walk
        // composes from rows and there is no index whose readiness could say
        // anything about this path.
        assert!(!analyzer.cargo_routes_ready_for_test());

        let prepared = PreparedRustUsageQuery::prepare(
            &analyzer,
            std::slice::from_ref(&target),
            &HashSet::default(),
            false,
            true,
            &CancellationToken::new(),
        )
        .expect("uncancelled preparation");
        assert!(prepared.candidate_files().contains(&source));
        assert!(analyzer.cargo_routes_ready_for_test());
    }
}
