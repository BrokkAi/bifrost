use crate::analyzer::CodeUnitIndex;
use crate::analyzer::QueryToken;
use crate::analyzer::rust::canonical_rust_hierarchy_type;
use crate::analyzer::rust::{RustBindingSeeds, RustReferenceNamespace};
use crate::analyzer::rust::{
    has_rust_value_constructor, is_rust_const_or_static_declaration, is_rust_enum_declaration,
    is_rust_trait_declaration, is_rust_trait_impl_member_declaration,
    resolve_imported_export_from_binder_forward, trait_implementer_names,
    usage_binding_local_names, usage_binding_names, usage_binding_seeds,
    usage_declaration_visible_at, usage_exact_root_for_resolution,
    usage_exact_root_for_resolution_with_walks, usage_has_exact_scoped_binding,
    usage_identity_visible_at, usage_import_path_matches_seed, usage_importers,
    usage_local_module_prefix_visible_at, usage_reference_at, usage_reference_at_with_walks,
    usage_root_declaration_matches_at,
};
use crate::analyzer::tree_walk::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::ImportKind;
use crate::analyzer::usages::common::{
    classify_recursive_hits, reclassify_import_hit_at, same_node,
};
// Relocated to `brokk_bifrost_rust::graph::ast` with the inverted pass (W7): the
// five helpers it needed from this file and `hits.rs` are pure AST readers, and
// this file is parked on the definition route's `RustTypeLookupCache`.
use crate::analyzer::usages::get_definition::{
    AnalyzerRustDefinitionProvider, RustMacroMatcherCandidateGate, RustTypeLookupCache,
    ingest_file_macro_matcher_roles, rust_associated_call_applicable_candidates,
    rust_expression_type_definition_candidates_cached, rust_expression_type_definition_fqn_cached,
    rust_field_definition_type_candidates_cached, rust_is_type_definition,
    rust_resolve_type_node_fqn,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{UsageHit, UsageHitSurface};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use crate::analyzer::usages::rust_graph::hits::{
    member_hit_enclosing, push_member_hit, push_self_receiver_member_hit, push_unproven_member_hit,
    record_hit, record_import_hit, record_module_qualified_hits, rust_path_segments,
};
use crate::analyzer::usages::rust_graph::resolver::{
    RustBareTokenTreeRole, RustDefinitionProvider, RustTokenPathRole, RustTokenTreeRoleCache,
    canonical_imported_impl_target, is_graph_visible_member_target, is_trait_owner,
    resolve_exact_owner_associated_item_matching, resolve_rust_path_fqn,
    resolve_rust_token_tree_paths, rust_token_path_segment_is_qualified,
    rust_unique_nominal_reference_namespace, token_tree_ancestor, trait_member_for_impl_member,
};
use crate::analyzer::usages::traits::UsageScanScope;
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile, RustAnalyzer, RustReferenceContext,
    TypeHierarchyProvider,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::rust_facts::{RUST_OCCURRENCE_CODE, RustIncludeBindingKind};
use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
use brokk_bifrost_rust::field_roles::rust_struct_field_references;
use brokk_bifrost_rust::graph::ast::is_rust_type_node;
pub(super) use brokk_bifrost_rust::graph::ast::{
    first_generic_type_argument, rust_reference_namespace, type_node_last_segment,
};
use brokk_bifrost_rust::graph_support::{
    RustSource, is_rust_enum_variant_declaration, is_rust_macro_export_declaration,
    resolve_module_package,
};
use brokk_bifrost_rust::imports::rust_crate_root_package;
use brokk_bifrost_rust::lexical_scope::{self, RustLexicalScopeIndex};
use brokk_bifrost_rust::usage::RustReferenceResolution;
use brokk_bifrost_rust::usage_includes::RustIncludeRoutes;
use brokk_bifrost_rust::usage_queries::RustUsageQueries;
use brokk_bifrost_rust::usage_walks::RustUsageWalks;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tree_sitter::{Node, Parser, Tree};

pub(super) fn effective_scan_files(
    analyzer: &RustAnalyzer,
    token: QueryToken<'_>,
    scan_scope: &UsageScanScope<'_>,
    target: &CodeUnit,
    seeds: &RustBindingSeeds,
) -> HashSet<ProjectFile> {
    effective_scan_files_with_additional_importers(
        analyzer,
        token,
        scan_scope,
        target,
        seeds,
        || {
            if target.is_module() {
                usage_importers(analyzer, token, seeds)
            } else {
                seeds.verified_importer_files().cloned().collect()
            }
        },
    )
}

/// Complete the effective scan set after the finder has already admitted the
/// protected Rust importer closure.
///
/// The generic finder must know that closure before it applies file and byte
/// budgets. Repeating `usage_importers` here cannot add a file, because every
/// importer it returns is already in `scan_scope`; it only repeats the walk.
pub(super) fn effective_scan_files_from_prepared_candidates(
    analyzer: &RustAnalyzer,
    token: QueryToken<'_>,
    scan_scope: &UsageScanScope<'_>,
    target: &CodeUnit,
    seeds: &RustBindingSeeds,
) -> HashSet<ProjectFile> {
    effective_scan_files_with_additional_importers(
        analyzer,
        token,
        scan_scope,
        target,
        seeds,
        HashSet::default,
    )
}

fn effective_scan_files_with_additional_importers(
    analyzer: &RustAnalyzer,
    token: QueryToken<'_>,
    scan_scope: &UsageScanScope<'_>,
    target: &CodeUnit,
    seeds: &RustBindingSeeds,
    additional_importers: impl FnOnce() -> HashSet<ProjectFile>,
) -> HashSet<ProjectFile> {
    let _scope = crate::profiling::scope("rust_graph::effective_scan_files");
    let candidate_files = scan_scope.candidate_files();
    let analyzed = analyzer.get_analyzed_files();
    let seed_names: HashSet<&str> = seeds.candidate_names().collect();
    let mentioned_files = if target.is_module() {
        HashSet::default()
    } else {
        let queries = RustUsageQueries::new(analyzer);
        std::iter::once(target.identifier())
            .chain(seed_names.iter().copied())
            .flat_map(|name| queries.files_mentioning(name, RUST_OCCURRENCE_CODE))
            .collect()
    };
    let filtered_candidates: HashSet<_> = candidate_files
        .iter()
        .filter(|file| analyzed.contains(*file))
        // The binding graph supplies a conservative file universe. For a
        // non-module target, every reportable site must still spell either the
        // declaration name or one of the structurally verified aliases carried
        // by the seed closure. This is admission only; the AST resolver remains
        // the proof for every retained site.
        .filter(|file| target.is_module() || mentioned_files.contains(*file))
        .cloned()
        .collect();
    let include_files: HashSet<_> = if scan_scope.is_authoritative() {
        HashSet::default()
    } else {
        let _scope = crate::profiling::scope("rust_graph::include_candidate_discovery");
        RustIncludeRoutes::new(analyzer, token)
            .all_included_files()
            .iter()
            .filter(|file| analyzed.contains(*file))
            .filter(|file| target.is_module() || mentioned_files.contains(*file))
            .cloned()
            .collect()
    };

    crate::profiling::note_with(|| {
        format!(
            "rust_graph candidates supplied={} analyzed={} filtered={} includes={} authoritative={}",
            candidate_files.len(),
            analyzed.len(),
            filtered_candidates.len(),
            include_files.len(),
            scan_scope.is_authoritative()
        )
    });

    if scan_scope.is_authoritative() {
        return filtered_candidates;
    }

    if !candidate_files.is_empty() && filtered_candidates.is_empty() {
        return std::iter::once(target.source().clone())
            .chain(include_files)
            .collect();
    }

    let referencing_files = if target.is_module() {
        let _scope = crate::profiling::scope("rust_graph::reference_candidate_discovery");
        analyzer.referencing_files_of(target.source())
    } else {
        HashSet::default()
    };
    if !filtered_candidates.is_empty() {
        let importers = additional_importers();
        crate::profiling::note_with(|| {
            format!(
                "rust_graph augmented supplied candidates with importers={} referencing={}",
                importers.len(),
                referencing_files.len()
            )
        });
        return filtered_candidates
            .into_iter()
            .chain(importers)
            .chain(referencing_files)
            .chain(include_files)
            .chain(std::iter::once(target.source().clone()))
            .collect();
    }

    let importers = {
        let _scope = crate::profiling::scope("rust_graph::importer_candidate_discovery");
        usage_importers(analyzer, token, seeds)
    };

    let textual_candidates: HashSet<_> = {
        let _scope = crate::profiling::scope("rust_graph::textual_candidate_fallback");
        analyzed
            .into_iter()
            .filter(|file| {
                if scan_scope.is_cancelled() {
                    return false;
                }
                file.read_to_string().ok().is_some_and(|source| {
                    if scan_scope.is_cancelled() {
                        return false;
                    }
                    source.contains(target.identifier())
                        || seed_names
                            .iter()
                            .any(|seed_name| source.contains(seed_name))
                })
            })
            .collect()
    };
    crate::profiling::note_with(|| {
        format!(
            "rust_graph inferred importers={} referencing={} textual={}",
            importers.len(),
            referencing_files.len(),
            textual_candidates.len()
        )
    });

    importers
        .into_iter()
        .chain(referencing_files)
        .chain(include_files)
        .chain(textual_candidates)
        .chain(std::iter::once(target.source().clone()))
        .collect()
}

struct UsageCapStop {
    proven_external_hits: AtomicUsize,
    max_usages: usize,
}

#[derive(Default)]
struct RustScanPhaseTimings {
    prepared_syntax_ns: AtomicU64,
    reference_context_ns: AtomicU64,
    lexical_scope_ns: AtomicU64,
    ast_scan_ns: AtomicU64,
}

impl RustScanPhaseTimings {
    fn start() -> Option<Instant> {
        crate::profiling::enabled().then(Instant::now)
    }

    fn record(counter: &AtomicU64, started: Option<Instant>) {
        let Some(started) = started else {
            return;
        };
        let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        counter.fetch_add(nanos, Ordering::Relaxed);
    }

    fn report(&self, candidate_count: usize) {
        crate::profiling::note_with(|| {
            format!(
                "rust_graph scan candidates={} prepared_syntax_ms={:.1} reference_context_ms={:.1} lexical_scope_ms={:.1} ast_scan_ms={:.1}",
                candidate_count,
                self.prepared_syntax_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                self.reference_context_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                self.lexical_scope_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                self.ast_scan_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            )
        });
    }
}

impl UsageCapStop {
    fn new(max_usages: usize) -> Self {
        Self {
            proven_external_hits: AtomicUsize::new(0),
            max_usages,
        }
    }

    fn reached(&self) -> bool {
        self.proven_external_hits.load(Ordering::Relaxed) > self.max_usages
    }

    fn record(&self, hits: &BTreeSet<UsageHit>) {
        let external = hits
            .iter()
            .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
            .count();
        if external != 0 {
            self.proven_external_hits
                .fetch_add(external, Ordering::Relaxed);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_files_for_target(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    files: HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: Option<&RustBindingSeeds>,
    cancellation: Option<&CancellationToken>,
    max_usages: usize,
) -> BTreeSet<UsageHit> {
    let hits = Mutex::new(BTreeSet::new());
    let cap = UsageCapStop::new(max_usages);
    let files_vec: Vec<_> = files.into_iter().collect();
    let timings = RustScanPhaseTimings::default();
    // Shared across every file: the alias closure reachable from the target
    // roots. `effective_scan_files` already treats these names as the textual
    // universe a hit can be written under.
    let seed_names: HashSet<&str> = match seeds {
        Some(seeds) => seeds.candidate_names().collect(),
        None => HashSet::default(),
    };
    let keep_going = || !cancellation.is_some_and(CancellationToken::is_cancelled);

    // Parsing each file inside the scan, rather than prefetching every candidate
    // up front, keeps hits accumulating from the first file onward: a scan that
    // runs out of budget still reports the sites it proved.
    files_vec.par_iter().for_each_init(
        || AnalyzerRustDefinitionProvider::new(rust, true),
        |support, file| {
            if cap.reached() || cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            rust.note_scanned_candidate_file();
            let started = RustScanPhaseTimings::start();
            let Some(prepared) = rust.prepared_syntax(token, file) else {
                RustScanPhaseTimings::record(&timings.prepared_syntax_ns, started);
                return;
            };
            RustScanPhaseTimings::record(&timings.prepared_syntax_ns, started);
            let source = prepared.source();
            let tree = prepared.tree();
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }

            let line_starts = prepared.line_starts();
            // Per file, not once for the scan: the include-route walker carries the
            // cycle bookkeeping its recursion needs, which is `RefCell` state and
            // therefore not `Sync`. Constructing it is a handful of memo probes,
            // and every route it composes is memoized on the analyzer, so the
            // repeated construction costs no repeated work.
            let include_routes = RustIncludeRoutes::new(rust, token);
            let started = RustScanPhaseTimings::start();
            let lexical_scope = RustLexicalScopeIndex::new(tree.root_node(), source);
            RustScanPhaseTimings::record(&timings.lexical_scope_ns, started);
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            let started = RustScanPhaseTimings::start();
            let refs = rust.reference_context_of(token, file);
            RustScanPhaseTimings::record(&timings.reference_context_ns, started);
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            let (mut direct_names, _) = match seeds {
                Some(seeds) => usage_binding_names(rust, token, file, seeds),
                None => (HashSet::default(), HashSet::default()),
            };
            // Prepared seeds already carry every verified direct alias. Glob
            // edges are normalized to named edges and namespace edges to
            // qualified paths while the seed closure is built, so scanning
            // every binder/export name and resolving it back to the target is
            // redundant here. Treat identities rooted in this file as direct
            // names as well, including a re-export beside its declaration.
            if let Some(seeds) = seeds {
                for identity in seeds.identities_in_file(file) {
                    direct_names.insert(identity.name().to_string());
                }
            }
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            let use_binding_names = rust_local_use_alias_names(tree.root_node(), source, &|name| {
                name == target.identifier()
                    || seed_names.contains(name)
                    || direct_names.contains(name)
            });
            let mut macro_candidate_names = HashSet::default();
            if !target.is_module() {
                macro_candidate_names
                    .insert(strip_raw_identifier_prefix(target.identifier()).to_string());
                macro_candidate_names.extend(
                    seed_names
                        .iter()
                        .map(|name| strip_raw_identifier_prefix(name).to_string()),
                );
                macro_candidate_names.extend(
                    direct_names
                        .iter()
                        .map(|name| strip_raw_identifier_prefix(name).to_string()),
                );
                macro_candidate_names.extend(
                    use_binding_names
                        .iter()
                        .map(|name| strip_raw_identifier_prefix(name).to_string()),
                );
            }
            let macro_candidate_gate = if target.is_module() {
                RustMacroMatcherCandidateGate::All
            } else {
                RustMacroMatcherCandidateGate::Names(&macro_candidate_names)
            };
            let mut token_tree_roles = RustTokenTreeRoleCache::default();
            ingest_file_macro_matcher_roles(
                &mut token_tree_roles,
                token,
                analyzer,
                support,
                file,
                source,
                tree,
                macro_candidate_gate,
                cancellation,
            );
            let usage_walks = if seeds.is_some() {
                RustUsageWalks::new_while(rust, token, &keep_going)
            } else {
                None
            };
            if seeds.is_some() && usage_walks.is_none() {
                return;
            }
            let mut local_hits = BTreeSet::new();
            let mut ctx = ScanCtx {
                file,
                source,
                line_starts,
                analyzer,
                rust,
                refs: &refs,
                support,
                seeds,
                target,
                target_is_path_qualifier: target.is_class() || rust.is_type_alias(target),
                target_is_module: target.is_module(),
                target_is_macro: target.is_macro(),
                target_is_pattern_value: is_rust_const_or_static_declaration(rust, target),
                name_gate: ScanNameGate {
                    target_identifier: target.identifier(),
                    seed_names: &seed_names,
                    direct_names: &direct_names,
                    use_binding_names: &use_binding_names,
                },
                direct_names: &direct_names,
                lexical_scope: &lexical_scope,
                include_routes: &include_routes,
                usage_walks,
                token_tree_roles,
                cancellation,
                cancellation_checks_remaining: 0,
                hits: &mut local_hits,
            };
            let started = RustScanPhaseTimings::start();
            scan_node(tree.root_node(), token, &mut ctx);
            let primary_scan_ms = started.map(|started| started.elapsed().as_secs_f64() * 1_000.0);
            let qualified_started = RustScanPhaseTimings::start();
            if !cancellation.is_some_and(CancellationToken::is_cancelled) {
                record_module_qualified_hits(tree.root_node(), &mut ctx);
            }
            let qualified_scan_ms = qualified_started
                .map(|started| started.elapsed().as_secs_f64() * 1_000.0)
                .unwrap_or_default();
            if let Some(started) = started
                && started.elapsed().as_millis() >= 100
            {
                crate::profiling::note_with(|| {
                    format!(
                        "rust_graph slow AST scan file={file:?} bytes={} primary_ms={:.1} qualified_ms={qualified_scan_ms:.1} elapsed_ms={:.1}",
                        source.len(),
                        primary_scan_ms.unwrap_or_default(),
                        started.elapsed().as_secs_f64() * 1_000.0,
                    )
                });
            }
            RustScanPhaseTimings::record(&timings.ast_scan_ns, started);

            // A cancellation checkpoint can stop the iterative AST walk after
            // it has already proved direct hits in this file. Commit those
            // hits before returning so a narrowed, single-file candidate scope
            // retains the same partial-result contract as a multi-file scan.
            let local_hits = classify_recursive_hits(analyzer, local_hits, target);
            if !local_hits.is_empty() {
                cap.record(&local_hits);
                let mut sink = hits.lock().expect("poisoned Rust graph collector");
                sink.extend(local_hits);
            }
        },
    );

    timings.report(files_vec.len());

    hits.into_inner().expect("poisoned Rust graph collector")
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) rust: &'a RustAnalyzer,
    pub(super) refs: &'a RustReferenceContext<'a>,
    pub(super) support: &'a dyn RustDefinitionProvider,
    seeds: Option<&'a RustBindingSeeds>,
    target: &'a CodeUnit,
    pub(super) target_is_path_qualifier: bool,
    pub(super) target_is_module: bool,
    target_is_macro: bool,
    target_is_pattern_value: bool,
    name_gate: ScanNameGate<'a>,
    direct_names: &'a HashSet<String>,
    lexical_scope: &'a RustLexicalScopeIndex,
    include_routes: &'a RustIncludeRoutes<'a>,
    usage_walks: Option<RustUsageWalks<'a>>,
    token_tree_roles: RustTokenTreeRoleCache,
    pub(super) cancellation: Option<&'a CancellationToken>,
    cancellation_checks_remaining: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
}

fn included_import_resolves_to_target(
    file: &ProjectFile,
    source: &str,
    byte: usize,
    local_name: &str,
    target: &CodeUnit,
    include_routes: &RustIncludeRoutes<'_>,
) -> bool {
    let routes = include_routes.include_routes_for(file);
    if routes.is_empty() {
        return false;
    }
    let binders = lexical_scope::visible_import_binders_with_scopes_at(source, byte);
    for (scope_start, binder) in binders {
        if let Some(binding) = binder.bindings.get(local_name) {
            let candidates = routes
                .iter()
                .flat_map(|route| {
                    include_routes.include_import_target_identities(
                        route,
                        source,
                        scope_start,
                        binding,
                        target.identifier(),
                    )
                })
                .collect::<HashSet<_>>();
            return candidates.len() == 1
                && candidates.iter().any(|identity| {
                    identity.file == *target.source() && identity.name == target.identifier()
                });
        }
        let glob_targets = binder
            .bindings
            .values()
            .filter(|binding| binding.kind == ImportKind::Glob)
            .flat_map(|binding| {
                routes.iter().filter_map(|route| {
                    let candidates = include_routes.include_import_target_identities(
                        route,
                        source,
                        scope_start,
                        binding,
                        target.identifier(),
                    );
                    (candidates.len() == 1)
                        .then(|| candidates.into_iter().next().expect("one candidate"))
                })
            })
            .collect::<HashSet<_>>();
        if !glob_targets.is_empty() {
            return glob_targets.len() == 1
                && glob_targets.iter().any(|identity| {
                    identity.file == *target.source() && identity.name == target.identifier()
                });
        }
    }
    let host_targets = routes
        .iter()
        .flat_map(|route| {
            let has_named_binding = route.host_bindings.iter().any(|binding| {
                binding.kind != RustIncludeBindingKind::Glob && binding.local_name == local_name
            });
            route
                .host_bindings
                .iter()
                .filter(move |binding| {
                    (binding.kind != RustIncludeBindingKind::Glob
                        && binding.local_name == local_name)
                        || (!has_named_binding
                            && binding.kind == RustIncludeBindingKind::Glob
                            && binding.local_name == "*")
                })
                .flat_map(|binding| {
                    let suffix = if binding.kind == RustIncludeBindingKind::Glob {
                        vec![target.identifier()]
                    } else {
                        Vec::new()
                    };
                    include_routes.include_path_target_identities(route, binding, &suffix)
                })
        })
        .collect::<HashSet<_>>();
    if !host_targets.is_empty() {
        return host_targets.len() == 1
            && host_targets.iter().any(|identity| {
                identity.file == *target.source() && identity.name == target.identifier()
            });
    }
    false
}

/// Resolve the path written by an import declaration in an included file.
///
/// The normal Rust reference graph sees the physical file as a separate module,
/// while Rust evaluates the import at the `include!` host.  Calls to the
/// imported name already use [`included_import_resolves_to_target`], but the
/// path terminal in `use crate::...::name;` needs the same host route.  Match
/// the complete import path before using the route so an unrelated path with
/// the same terminal name cannot become a false positive.
fn included_import_path_resolves_to_target(
    file: &ProjectFile,
    source: &str,
    byte: usize,
    segments: &[&str],
    target: &CodeUnit,
    include_routes: &RustIncludeRoutes<'_>,
) -> bool {
    if segments.is_empty() {
        return false;
    }
    let path = segments
        .iter()
        .map(|segment| {
            if *segment == "$crate" {
                "crate"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("::");
    let routes = include_routes.include_routes_for(file);
    if routes.is_empty() {
        return false;
    }
    for (scope_start, binder) in lexical_scope::visible_import_binders_with_scopes_at(source, byte)
    {
        let Some(binding) = binder.bindings.values().find(|binding| {
            let imported_path = match binding.kind {
                ImportKind::Named => binding
                    .imported_name
                    .as_deref()
                    .map(|name| format!("{}::{name}", binding.module_specifier)),
                ImportKind::Namespace => Some(binding.module_specifier.clone()),
                _ => None,
            };
            imported_path.as_deref() == Some(path.as_str())
        }) else {
            continue;
        };
        let candidates = routes
            .iter()
            .flat_map(|route| {
                include_routes.include_import_target_identities(
                    route,
                    source,
                    scope_start,
                    binding,
                    target.identifier(),
                )
            })
            .collect::<HashSet<_>>();
        return candidates.len() == 1
            && candidates.iter().any(|identity| {
                identity.file == *target.source() && identity.name == target.identifier()
            });
    }
    false
}

fn included_host_path_resolves_to_target(
    file: &ProjectFile,
    source: &str,
    byte: usize,
    segments: &[&str],
    target: &CodeUnit,
    include_routes: &RustIncludeRoutes<'_>,
) -> bool {
    let Some(local_name) = segments.first() else {
        return false;
    };
    if lexical_scope::visible_import_binders_with_scopes_at(source, byte)
        .iter()
        .any(|(_, binder)| binder.bindings.contains_key(*local_name))
    {
        return false;
    }
    let routes = include_routes.include_routes_for(file);
    let suffix = &segments[1..];
    let candidates = routes
        .iter()
        .flat_map(|route| {
            route
                .host_bindings
                .iter()
                .filter(|binding| binding.local_name == *local_name)
                .flat_map(|binding| {
                    include_routes.include_path_target_identities(route, binding, suffix)
                })
        })
        .collect::<HashSet<_>>();
    candidates.len() == 1
        && candidates.iter().any(|identity| {
            identity.file == *target.source() && identity.name == target.identifier()
        })
}

/// The names a source token must carry before resolution can possibly prove it
/// references the target.
///
/// `usage_reference_at` only answers `Exact` for an identity in
/// `seeds.root_origins`, so every hit terminates at a declaration whose own name
/// is `target_identifier`. The written spelling can differ from that name only
/// by travelling an import edge, and an origin route's path is one of
/// `[local_name]`, `[local_name, target_name]` or `[target_name]` - so the
/// spelling is always either a propagated alias (`seed_names`) or a local
/// binding name in this file (`direct_names`).
struct ScanNameGate<'a> {
    target_identifier: &'a str,
    seed_names: &'a HashSet<&'a str>,
    direct_names: &'a HashSet<String>,
    use_binding_names: &'a HashSet<&'a str>,
}

impl ScanNameGate<'_> {
    fn admits(&self, name: &str) -> bool {
        name == self.target_identifier
            || self.seed_names.contains(name)
            || self.direct_names.contains(name)
            || self.use_binding_names.contains(name)
    }
}

/// Local names introduced by `use ... as name;` in this file that rename a name
/// the gate already admits.
///
/// The seed alias closure only propagates module-extent aliases, and the
/// reverse-import index only carries edges it could route, so a function-local
/// or otherwise unrouted `use ... as name;` can bind the target under a name in
/// neither. `usage_has_exact_scoped_binding` reads those from the file's own
/// import syntax, so the gate learns them from the same place.
///
/// Only renames of an already-admitted name are collected: an import binds the
/// target only when its path resolves to the target, and by the same
/// origin-route argument the path's final segment carries the target's own name
/// or a propagated alias. A plain `use` binds that final segment unchanged, so
/// it needs no entry here.
fn rust_local_use_alias_names<'a>(
    root: Node<'_>,
    source: &'a str,
    base_admits: &dyn Fn(&str) -> bool,
) -> HashSet<&'a str> {
    let node_text = |node: Node<'_>| {
        source
            .get(node.start_byte()..node.end_byte())
            .map(str::trim)
    };
    let mut names = HashSet::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "use_as_clause"
            && let Some(path) = node.child_by_field_name("path")
            && let Some(alias) = node.child_by_field_name("alias")
        {
            let imported = if matches!(path.kind(), "scoped_identifier" | "scoped_type_identifier")
            {
                path.child_by_field_name("name").unwrap_or(path)
            } else {
                path
            };
            if node_text(imported).is_some_and(base_admits)
                && let Some(alias_text) = node_text(alias)
            {
                names.insert(alias_text);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor).collect::<Vec<_>>());
    }
    names
}

impl ScanCtx<'_> {
    /// Cheap necessary condition for a written path to reference the target.
    ///
    /// `usage_reference_at` only answers `Exact` for an identity in
    /// `seeds.root_origins`. Its origin-route branch compares the whole written
    /// path against a route whose last segment is the propagated origin name,
    /// and its declaration branches filter on `identity.name == terminal`, so a
    /// value or type target must be spelled in the path. Its module-alias branch
    /// resolves segments structurally and yields Module identities only, so a
    /// module target can be reached by a path that never spells it (`super::*`,
    /// an aliased module prefix) and cannot be gated on names at all.
    pub(super) fn path_could_name_target(&self, segments: &[&str]) -> bool {
        if self.target_is_module {
            return true;
        }
        let Some(terminal) = segments.last() else {
            return false;
        };
        self.name_gate.admits(terminal)
            || (self.target_is_path_qualifier
                && segments
                    .iter()
                    .any(|segment| self.name_gate.admits(segment)))
    }

    /// The single-segment counterpart of [`Self::path_could_name_target`].
    fn identifier_could_name_target(&self, text: &str) -> bool {
        self.target_is_module || self.name_gate.admits(text)
    }

    /// Whether a token-tree path segment is worth resolving. A target reachable
    /// as a path prefix is named by an interior segment, so those admit every
    /// position rather than only the one that terminates the written path.
    pub(super) fn token_path_name_admits(&self, name: &str) -> bool {
        self.target_is_path_qualifier || self.identifier_could_name_target(name)
    }

    pub(super) fn node_could_name_target(&self, node: Node<'_>) -> bool {
        if self.target_is_module {
            return true;
        }
        let mut stack = vec![node];
        while let Some(candidate) = stack.pop() {
            if matches!(
                candidate.kind(),
                "identifier" | "type_identifier" | "self" | "crate" | "super"
            ) {
                let Some(text) = simple_node_text(candidate, self.source) else {
                    continue;
                };
                if self.name_gate.admits(strip_raw_identifier_prefix(&text)) {
                    return true;
                }
            }
            let mut cursor = candidate.walk();
            stack.extend(candidate.children(&mut cursor));
        }
        false
    }

    pub(super) fn cancellation_requested(&mut self) -> bool {
        periodic_cancellation_requested(self.cancellation, &mut self.cancellation_checks_remaining)
    }

    pub(super) fn target_identifier(&self) -> &str {
        self.target.identifier()
    }

    fn target_reference_namespace(&self) -> RustReferenceNamespace {
        if self.target.is_module() {
            RustReferenceNamespace::PathPrefix
        } else if self.target.is_macro() {
            RustReferenceNamespace::Macro
        } else if self.target.is_class() || self.rust.is_type_alias(self.target) {
            RustReferenceNamespace::Type
        } else {
            RustReferenceNamespace::Value
        }
    }

    fn target_has_type_value_namespace_collision(&self) -> bool {
        let candidates = self.support.fqn(&self.target.fq_name());
        let has_type = candidates
            .iter()
            .any(|candidate| candidate.is_class() || self.rust.is_type_alias(candidate));
        let has_value = candidates
            .iter()
            .any(|candidate| candidate.is_function() || candidate.is_field());
        has_type && has_value
    }

    pub(super) fn matches_unique_resolved_fqn(&self, fqn: &str) -> bool {
        if self.target.fq_name() != fqn {
            return false;
        }
        let mut declarations = self.support.fqn(fqn);
        declarations.sort();
        declarations.dedup();
        declarations.len() == 1 && declarations.first() == Some(self.target)
    }

    pub(super) fn matches_unique_resolved_fqn_in_namespace(
        &self,
        fqn: &str,
        namespace: RustReferenceNamespace,
    ) -> bool {
        if self.target.fq_name() != fqn {
            return false;
        }
        let mut declarations = self
            .support
            .fqn(fqn)
            .into_iter()
            .filter(|candidate| match namespace {
                RustReferenceNamespace::Type => {
                    candidate.is_class() || self.rust.is_type_alias(candidate)
                }
                RustReferenceNamespace::Value => {
                    candidate.is_function()
                        || candidate.is_field()
                        || has_rust_value_constructor(self.rust, candidate)
                }
                RustReferenceNamespace::Macro => candidate.is_macro(),
                RustReferenceNamespace::PathPrefix => {
                    candidate.is_module()
                        || candidate.is_class()
                        || self.rust.is_type_alias(candidate)
                }
                RustReferenceNamespace::Any => true,
            })
            .collect::<Vec<_>>();
        declarations.sort();
        declarations.dedup();
        declarations.len() == 1 && declarations.first() == Some(self.target)
    }

    pub(super) fn matches_unique_visible_candidate_in_namespace(
        &self,
        candidates: impl IntoIterator<Item = CodeUnit>,
        byte: usize,
        namespace: RustReferenceNamespace,
    ) -> bool {
        let mut declarations = candidates
            .into_iter()
            .filter(|candidate| match namespace {
                RustReferenceNamespace::Type => {
                    candidate.is_class() || self.rust.is_type_alias(candidate)
                }
                RustReferenceNamespace::Value => {
                    candidate.is_function()
                        || candidate.is_field()
                        || has_rust_value_constructor(self.rust, candidate)
                }
                RustReferenceNamespace::Macro => candidate.is_macro(),
                RustReferenceNamespace::PathPrefix => {
                    candidate.is_module()
                        || candidate.is_class()
                        || self.rust.is_type_alias(candidate)
                }
                RustReferenceNamespace::Any => true,
            })
            .filter(|candidate| {
                usage_declaration_visible_at(
                    self.rust,
                    self.refs.token(),
                    candidate,
                    self.file,
                    byte,
                )
            })
            .collect::<Vec<_>>();
        declarations.sort();
        declarations.dedup();
        declarations.len() == 1 && declarations.first() == Some(self.target)
    }

    pub(super) fn matches_identifier(
        &self,
        text: &str,
        byte: usize,
        namespace: RustReferenceNamespace,
    ) -> bool {
        if !self.identifier_could_name_target(text) {
            debug_assert!(
                !self.matches_resolved_identifier(text, byte, namespace),
                "scan name gate skipped an identifier that resolves to the target: \
                 file={:?} text={:?} byte={byte} target={:?} direct_names={:?} \
                 seed_names={:?}",
                self.file,
                text,
                self.target,
                self.name_gate.direct_names,
                self.name_gate.seed_names,
            );
            return false;
        }
        self.matches_resolved_identifier(text, byte, namespace)
    }

    fn matches_resolved_identifier(
        &self,
        text: &str,
        byte: usize,
        namespace: RustReferenceNamespace,
    ) -> bool {
        let shadowed = namespace != RustReferenceNamespace::Macro
            && (self.lexical_scope.name_bound_at(text, byte)
                || self.item_shadows_target(text, byte));
        if !shadowed
            && namespace == RustReferenceNamespace::Value
            && included_import_resolves_to_target(
                self.file,
                self.source,
                byte,
                text,
                self.target,
                self.include_routes,
            )
        {
            return true;
        }
        if !self.direct_names.contains(text)
            && !self.seeds.is_some_and(|seeds| {
                usage_has_exact_scoped_binding(
                    self.rust,
                    self.refs.token(),
                    self.file,
                    seeds,
                    text,
                    byte,
                    namespace,
                )
            })
        {
            return false;
        }
        if self.seeds.is_none_or(|seeds| {
            let resolution = self.resolve_reference_at(
                self.file,
                seeds,
                &[text],
                byte,
                namespace,
                shadowed,
                false,
            );
            resolution.is_exact()
        }) {
            return true;
        }
        !shadowed
            && self.refs.resolve_bare(text).is_some_and(|fqn| {
                self.matches_unique_visible_resolved_fqn_in_namespace(&fqn, byte, namespace)
                    && self.authorize_exact_target_segments(&[text], byte, namespace, false)
            })
    }

    pub(super) fn matches_path(
        &self,
        segments: &[&str],
        byte: usize,
        namespace: RustReferenceNamespace,
        root_shadowed: bool,
        leading_absolute: bool,
    ) -> bool {
        if !self.path_could_name_target(segments) {
            debug_assert!(
                !self.matches_resolved_path(
                    segments,
                    byte,
                    namespace,
                    root_shadowed,
                    leading_absolute
                ),
                "scan name gate skipped a path that resolves to the target: \
                 file={:?} segments={:?} byte={byte} target={:?}",
                self.file,
                segments,
                self.target,
            );
            return false;
        }
        self.matches_resolved_path(segments, byte, namespace, root_shadowed, leading_absolute)
    }

    fn matches_resolved_path(
        &self,
        segments: &[&str],
        byte: usize,
        namespace: RustReferenceNamespace,
        root_shadowed: bool,
        leading_absolute: bool,
    ) -> bool {
        if namespace == RustReferenceNamespace::Value
            && !root_shadowed
            && included_import_path_resolves_to_target(
                self.file,
                self.source,
                byte,
                segments,
                self.target,
                self.include_routes,
            )
        {
            return true;
        }
        if namespace == RustReferenceNamespace::Value
            && !root_shadowed
            && included_host_path_resolves_to_target(
                self.file,
                self.source,
                byte,
                segments,
                self.target,
                self.include_routes,
            )
        {
            return true;
        }
        if self.seeds.is_some_and(|seeds| {
            let resolution = self.resolve_reference_at(
                self.file,
                seeds,
                segments,
                byte,
                namespace,
                root_shadowed,
                leading_absolute,
            );
            resolution.is_exact()
        }) {
            return true;
        }
        if root_shadowed && !leading_absolute {
            return false;
        }
        self.reference_context_path_matches_target(segments, byte, namespace, leading_absolute)
    }

    pub(super) fn path_root_shadowed_at(&self, name: &str, byte: usize) -> bool {
        // A value binding does not shadow Rust's type/module path namespace:
        // `fn f(value: T) { value::Serializer::new() }` may still name an
        // imported `value` module. Item bindings remain namespace-relevant.
        !matches!(name, "crate" | "self" | "super" | "$crate")
            && self.path_item_shadows_target(name, byte)
    }

    fn path_item_shadows_target(&self, name: &str, byte: usize) -> bool {
        self.lexical_scope.item_bound_at(name, byte)
            && self.seeds.is_none_or(|seeds| {
                !usage_root_declaration_matches_at(
                    self.rust,
                    self.refs.token(),
                    self.file,
                    seeds,
                    name,
                    byte,
                ) && !usage_local_module_prefix_visible_at(
                    self.rust,
                    self.refs.token(),
                    self.file,
                    seeds,
                    name,
                    byte,
                )
            })
    }

    fn item_shadows_target(&self, name: &str, byte: usize) -> bool {
        self.lexical_scope.local_item_bound_at(name, byte)
            && self.seeds.is_none_or(|seeds| {
                !usage_root_declaration_matches_at(
                    self.rust,
                    self.refs.token(),
                    self.file,
                    seeds,
                    name,
                    byte,
                ) && !usage_local_module_prefix_visible_at(
                    self.rust,
                    self.refs.token(),
                    self.file,
                    seeds,
                    name,
                    byte,
                )
            })
    }

    fn reference_context_path_matches_target(
        &self,
        segments: &[&str],
        byte: usize,
        namespace: RustReferenceNamespace,
        leading_absolute: bool,
    ) -> bool {
        if leading_absolute || rust_path_root_is_rooted(segments) {
            return false;
        }
        let Some(fqn) = self.reference_context_path_fqn(segments, namespace) else {
            return false;
        };
        self.matches_resolved_target_path_in_namespace(&fqn, segments, byte, namespace)
    }

    fn reference_context_path_fqn(
        &self,
        segments: &[&str],
        namespace: RustReferenceNamespace,
    ) -> Option<String> {
        match namespace {
            RustReferenceNamespace::PathPrefix => {
                if let [name] = segments {
                    self.refs.resolve_bare(name)
                } else {
                    self.refs.resolve_scoped_owner(&segments.join("::"))
                }
            }
            RustReferenceNamespace::Macro => None,
            RustReferenceNamespace::Type
            | RustReferenceNamespace::Value
            | RustReferenceNamespace::Any => {
                let (name, prefix) = segments.split_last()?;
                if prefix.is_empty() {
                    self.refs.resolve_bare(name)
                } else {
                    self.refs.resolve_scoped(&prefix.join("::"), name)
                }
            }
        }
    }

    fn matches_unique_visible_resolved_fqn_in_namespace(
        &self,
        fqn: &str,
        byte: usize,
        namespace: RustReferenceNamespace,
    ) -> bool {
        self.matches_unique_visible_candidate_in_namespace(self.support.fqn(fqn), byte, namespace)
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_reference_at(
        &self,
        file: &ProjectFile,
        seeds: &RustBindingSeeds,
        segments: &[&str],
        byte: usize,
        namespace: RustReferenceNamespace,
        root_shadowed: bool,
        leading_absolute: bool,
    ) -> RustReferenceResolution {
        match self.usage_walks.as_ref() {
            Some(walks) => usage_reference_at_with_walks(
                self.rust,
                walks,
                file,
                seeds,
                segments,
                byte,
                namespace,
                root_shadowed,
                leading_absolute,
            ),
            None => usage_reference_at(
                self.rust,
                self.refs.token(),
                file,
                seeds,
                segments,
                byte,
                namespace,
                root_shadowed,
                leading_absolute,
            ),
        }
    }

    fn matches_resolved_target_path_in_namespace(
        &self,
        fqn: &str,
        segments: &[&str],
        byte: usize,
        namespace: RustReferenceNamespace,
    ) -> bool {
        self.authorize_exact_target_segments(segments, byte, namespace, false)
            && (self.matches_unique_visible_resolved_fqn_in_namespace(fqn, byte, namespace)
                // Shared Rust files can legitimately contribute the same analyzer
                // FQN through more than one Cargo target root (for example,
                // `src/error.rs` compiled into both the library and binary).
                // Once the ordinary reference-context route proves the written
                // path and the seed-aware exact resolver selects this target's
                // physical root, keep that exact hit instead of discarding it
                // merely because another target shares the same analyzer FQN.
                || fqn == self.target.fq_name())
    }

    fn authorize_exact_target_segments(
        &self,
        segments: &[&str],
        byte: usize,
        namespace: RustReferenceNamespace,
        leading_absolute: bool,
    ) -> bool {
        let roots = BTreeSet::from([self.target.clone()]);
        let seeds = usage_binding_seeds(self.rust, self.refs.token(), &roots);
        let resolution = self.resolve_reference_at(
            self.file,
            &seeds,
            segments,
            byte,
            namespace,
            false,
            leading_absolute,
        );
        let root = self
            .usage_walks
            .as_ref()
            .map(|walks| usage_exact_root_for_resolution_with_walks(walks, &resolution, &seeds))
            .unwrap_or_else(|| {
                usage_exact_root_for_resolution(self.rust, self.refs.token(), &resolution, &seeds)
            });
        root.as_ref() == Some(self.target)
    }
}

fn periodic_cancellation_requested(
    cancellation: Option<&CancellationToken>,
    checks_remaining: &mut usize,
) -> bool {
    if *checks_remaining > 0 {
        *checks_remaining -= 1;
        return false;
    }
    *checks_remaining = 255;
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn rust_path_root_is_rooted(segments: &[&str]) -> bool {
    matches!(
        segments.first().copied(),
        Some("crate" | "self" | "super" | "$crate")
    )
}

fn scan_node(root: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    walk_tree_iterative(
        root,
        ctx,
        |node, ctx| {
            if ctx.cancellation_requested() {
                return TreeWalkAction::Stop;
            }
            match node.kind() {
                "use_declaration" => {
                    if ctx.node_could_name_target(node) {
                        let started = RustScanPhaseTimings::start();
                        record_use_import_hits(node, token, ctx);
                        if let Some(started) = started
                            && started.elapsed().as_millis() >= 10
                        {
                            crate::profiling::note_with(|| {
                                format!(
                                    "rust_graph slow use resolution file={:?} byte={} elapsed_ms={:.1}",
                                    ctx.file,
                                    node.start_byte(),
                                    started.elapsed().as_secs_f64() * 1_000.0,
                                )
                            });
                        }
                    }
                    return TreeWalkAction::Skip;
                }
                "scoped_identifier" | "scoped_type_identifier" if !ctx.target_is_module => {
                    let Some(path) = rust_path_segments(node) else {
                        return TreeWalkAction::Descend;
                    };
                    if path.len() <= 1 {
                        return TreeWalkAction::Descend;
                    }
                    let segments = super::hits::path_segment_texts(&path, ctx.source);
                    let root = path[0];
                    // `matches_path` gates on the same condition; checking it here
                    // also skips the root-shadowing lookup. Interior nodes of a
                    // longer path are separate scoped nodes, so descending still
                    // reaches any segment that does name the target.
                    if !ctx.path_could_name_target(&segments) {
                        return TreeWalkAction::Descend;
                    }
                    let root_shadowed = ctx.path_root_shadowed_at(segments[0], root.start_byte());
                    let namespace = rust_reference_namespace(node);
                    if ctx.matches_path(
                        &segments,
                        node.start_byte(),
                        namespace,
                        root_shadowed,
                        crate::analyzer::usages::rust_graph::hits::rust_path_is_leading_absolute(
                            node,
                        ),
                    ) && let Some(name) = path.last()
                    {
                        record_hit(*name, ctx);
                    }
                }
                "macro_invocation" if ctx.target_is_macro => {
                    record_macro_invocation_hit(node, ctx);
                    // Macro arguments can themselves contain parsed invocations
                    // (`wrapper! { target!() }`). Keep walking after recording
                    // the outer path so nested invocations remain visible.
                    return TreeWalkAction::Descend;
                }
                "identifier" | "type_identifier" if !ctx.target_is_module => {
                    let text = node
                        .utf8_text(ctx.source.as_bytes())
                        .ok()
                        .map(str::trim)
                        .unwrap_or_default();
                    if !ctx.name_gate.admits(text) {
                        return TreeWalkAction::Descend;
                    }
                    if brokk_bifrost_rust::graph::ast::is_rust_declaration_name(node) {
                        return TreeWalkAction::Descend;
                    }
                    // `matches_identifier` gates on the same condition; checking it
                    // here also skips token-tree role classification and the
                    // whole-tree shadowing walk.
                    let resolution_started = RustScanPhaseTimings::start();
                    let matches = identifier_matches_target(node, root, text, ctx);
                    if let Some(started) = resolution_started
                        && started.elapsed().as_millis() >= 10
                    {
                        crate::profiling::note_with(|| {
                            format!(
                                "rust_graph slow identifier resolution file={:?} text={text:?} byte={} elapsed_ms={:.1}",
                                ctx.file,
                                node.start_byte(),
                                started.elapsed().as_secs_f64() * 1_000.0,
                            )
                        });
                    }
                    if matches {
                        record_hit(node, ctx);
                    }
                }
                _ => {}
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

/// The full identifier-reference decision, split out so `scan_node` can prove
/// (under `debug_assert`) that the name gate never hides one of these hits.
fn identifier_matches_target(
    node: Node<'_>,
    root: Node<'_>,
    text: &str,
    ctx: &mut ScanCtx<'_>,
) -> bool {
    let in_token_tree = token_tree_ancestor(node).is_some();
    let token_tree_role = ctx.token_tree_roles.role(node, ctx.source);
    let token_tree_candidate = token_tree_role.is_reference_candidate()
        || (token_tree_role == RustBareTokenTreeRole::Pattern && ctx.target_is_pattern_value);
    let token_tree_namespace = (in_token_tree && token_tree_candidate).then(|| {
        if ctx.target_is_macro
            && node
                .next_sibling()
                .is_some_and(|sibling| sibling.kind() == "!")
        {
            Some(RustReferenceNamespace::Macro)
        } else if node.next_sibling().is_some_and(|arguments| {
            arguments.kind() == "token_tree"
                && arguments.child(0).is_some_and(|open| open.kind() == "(")
        }) {
            Some(RustReferenceNamespace::Value)
        } else {
            rust_unique_nominal_reference_namespace(ctx.rust, ctx.support, &ctx.target.fq_name())
        }
    });
    let namespace = token_tree_namespace
        .flatten()
        .unwrap_or_else(|| rust_reference_namespace(node));
    let token_tree_role_matches = !in_token_tree
        || namespace != RustReferenceNamespace::Macro
        || node
            .next_sibling()
            .is_some_and(|sibling| sibling.kind() == "!");
    let matching_forward_token = token_tree_candidate
        && token_tree_namespace.flatten().is_some()
        && (namespace == RustReferenceNamespace::Macro
            || (!ctx.lexical_scope.name_bound_at(text, node.start_byte())
                && !lexical_scope::local_item_name_shadowed_in_tree(
                    root,
                    ctx.source,
                    text,
                    node.start_byte(),
                )))
        && ctx.matches_identifier(text, node.start_byte(), namespace)
        && ctx.matches_unique_visible_resolved_fqn_in_namespace(
            &ctx.target.fq_name(),
            node.start_byte(),
            namespace,
        );
    // `matches_identifier` has already applied lexical/item shadowing and
    // proven the exact seed identity. A second nearest-declaration veto can
    // mistake that same declaration for a shadow merely because its range
    // differs from this reference site.
    (!in_token_tree || token_tree_namespace.flatten().is_some())
        && token_tree_role_matches
        && !identifier_is_scoped_path_part(node)
        && if in_token_tree {
            matching_forward_token
        } else {
            ctx.matches_identifier(text, node.start_byte(), namespace)
        }
        && !lexical_scope::is_pattern_binding_identifier(node)
}

fn record_macro_invocation_hit(invocation: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(macro_path) = invocation.child_by_field_name("macro") else {
        return;
    };
    let Some(path) = rust_path_segments(macro_path) else {
        return;
    };
    let segments = path
        .iter()
        .map(|segment| {
            segment
                .utf8_text(ctx.source.as_bytes())
                .ok()
                .map(str::trim)
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return;
    }
    let matches = if segments.len() == 1 {
        ctx.matches_identifier(
            segments[0],
            macro_path.start_byte(),
            RustReferenceNamespace::Macro,
        )
    } else {
        ctx.matches_path(
            &segments,
            macro_path.start_byte(),
            RustReferenceNamespace::Macro,
            false,
            crate::analyzer::usages::rust_graph::hits::rust_path_is_leading_absolute(macro_path),
        )
    };
    if matches && let Some(name) = path.last() {
        record_hit(*name, ctx);
    }
}

fn identifier_is_scoped_path_part(node: Node<'_>) -> bool {
    rust_token_path_segment_is_qualified(node)
        || node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "scoped_identifier" | "scoped_type_identifier"
            )
        })
}

fn record_use_import_hits(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    let imports = brokk_bifrost_rust::imports::rust_imports_with_visibility_from_use_declaration(
        node, ctx.source,
    );
    let cfg_condition = brokk_bifrost_rust::lexical_scope::rust_cfg_condition(node, ctx.source);
    walk_tree_iterative(
        node,
        ctx,
        |current, ctx| {
            if matches!(current.kind(), "identifier" | "type_identifier" | "self")
                && is_local_use_binding_node(current)
            {
                if !use_as_clause_alias_node(current)
                    && let Some(path) =
                        crate::analyzer::rust::rust_focused_use_path(current, ctx.source)
                {
                    let segments = path.segments.iter().map(String::as_str).collect::<Vec<_>>();
                    let namespace = if current.kind() == "self" {
                        RustReferenceNamespace::PathPrefix
                    } else {
                        ctx.target_reference_namespace()
                    };
                    let could_name_target = ctx.path_could_name_target(&segments);
                    let exact_seed_import = could_name_target
                        && ctx.seeds.is_some_and(|seeds| {
                            imports.iter().any(|import| {
                                import.path == path.segments
                                    && usage_import_path_matches_seed(
                                        ctx.rust,
                                        ctx.refs.token(),
                                        ctx.file,
                                        seeds,
                                        &import.path,
                                        import.info.local_name().unwrap_or_default(),
                                        current.start_byte(),
                                        namespace,
                                        &cfg_condition,
                                    )
                            })
                        });
                    let root_name = path
                        .root
                        .utf8_text(ctx.source.as_bytes())
                        .ok()
                        .map(str::trim)
                        .map(|name| if name == "$crate" { "crate" } else { name })
                        .unwrap_or_default();
                    if exact_seed_import
                        || (could_name_target
                            && ctx.matches_path(
                                &segments,
                                current.start_byte(),
                                namespace,
                                ctx.path_root_shadowed_at(root_name, path.root.start_byte()),
                                crate::analyzer::usages::rust_graph::hits::rust_path_is_leading_absolute(
                                    path.root,
                                ),
                            ))
                        || rust_exported_macro_import_matches_target(node, token, current, ctx)
                    {
                        record_import_hit(current, ctx);
                    }
                    return TreeWalkAction::Descend;
                }
                let text = current
                    .utf8_text(ctx.source.as_bytes())
                    .ok()
                    .map(str::trim)
                    .unwrap_or_default();
                let matches_target_namespace = ctx.target_has_type_value_namespace_collision()
                    && crate::analyzer::rust::rust_focused_use_path(current, ctx.source)
                        .is_some_and(|path| {
                            let segments =
                                path.segments.iter().map(String::as_str).collect::<Vec<_>>();
                            let root_name = path
                                .root
                                .utf8_text(ctx.source.as_bytes())
                                .ok()
                                .map(str::trim)
                                .map(|name| if name == "$crate" { "crate" } else { name })
                                .unwrap_or_default();
                            ctx.matches_path(
                                &segments,
                                current.start_byte(),
                                ctx.target_reference_namespace(),
                                ctx.path_root_shadowed_at(root_name, path.root.start_byte()),
                                crate::analyzer::usages::rust_graph::hits::rust_path_is_leading_absolute(
                                    path.root,
                                ),
                            )
                        });
                if ctx.matches_identifier(text, current.start_byte(), RustReferenceNamespace::Any)
                    || matches_target_namespace
                    || rust_exported_macro_import_matches_target(node, token, current, ctx)
                {
                    record_import_hit(current, ctx);
                }
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

fn rust_exported_macro_import_matches_target(
    use_declaration: Node<'_>,
    token: QueryToken<'_>,
    binder: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> bool {
    if !ctx.target_is_macro || !is_rust_macro_export_declaration(ctx.rust.code_units(), ctx.target)
    {
        return false;
    }
    let Some(import) =
        brokk_bifrost_rust::imports::rust_imports_with_visibility_from_use_declaration(
            use_declaration,
            ctx.source,
        )
        .into_iter()
        .find(|import| {
            import.info.binder_span.is_some_and(|span| {
                span.start_byte <= binder.start_byte() && binder.end_byte() <= span.end_byte
            }) && import
                .path
                .last()
                .is_some_and(|name| name == ctx.target.identifier())
        })
    else {
        return false;
    };
    let Some((_, module_segments)) = import.path.split_last() else {
        return false;
    };
    if module_segments.is_empty() {
        return false;
    }
    let module_specifier = module_segments.join("::");
    resolve_module_package(ctx.rust, token, ctx.file, &module_specifier)
        .is_some_and(|package| package == rust_crate_root_package(ctx.target.source()))
}

fn is_local_use_binding_node(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "use_declaration" {
            return !use_path_leaf_is_prefix(node);
        }
        if parent.kind() == "scoped_use_list"
            && parent.child_by_field_name("path").is_some_and(|path| {
                path.start_byte() <= node.start_byte() && node.end_byte() <= path.end_byte()
            })
        {
            return false;
        }
        if parent.kind() == "use_list" {
            return !use_path_leaf_is_prefix(node);
        }
        if matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) && parent
            .child_by_field_name("path")
            .is_some_and(|path| same_node(path, node))
        {
            return false;
        }
        if parent.kind() == "use_as_clause" {
            return true;
        }
        current = parent.parent();
    }
    true
}

fn use_as_clause_alias_node(node: Node<'_>) -> bool {
    node.parent()
        .filter(|parent| parent.kind() == "use_as_clause")
        .and_then(|parent| parent.child_by_field_name("alias"))
        .is_some_and(|alias| same_node(alias, node))
}

fn use_path_leaf_is_prefix(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) && parent
            .child_by_field_name("path")
            .is_some_and(|path| same_node(path, node))
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_files_for_member_target(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    files: HashSet<ProjectFile>,
    target: &CodeUnit,
    requested_target: &CodeUnit,
    cancellation: Option<&CancellationToken>,
    max_usages: usize,
) -> RustMemberScanResult {
    let Some(owner) = rust
        .structural_parent_of(target)
        .or_else(|| rust.parent_of(target))
    else {
        return RustMemberScanResult::default();
    };
    let owner = canonical_member_owner(rust, token, owner);
    let owner_roots = BTreeSet::from([owner.clone()]);
    let owner_seeds = usage_binding_seeds(rust, token, &owner_roots);
    let member_name = target.identifier().to_string();
    let hits = Mutex::new(BTreeSet::new());
    let unproven_hits = Mutex::new(BTreeSet::new());
    let cap = UsageCapStop::new(max_usages);
    let constructor_support = AnalyzerRustDefinitionProvider::new(rust, true);
    let constructor_returns =
        self_like_constructor_returns(rust, token, &constructor_support, &owner);
    let self_like_constructors = self_like_constructor_seeds(rust, token, &constructor_returns);

    let files_vec = files.into_iter().collect::<Vec<_>>();
    let timings = RustScanPhaseTimings::default();
    // Parsing each file inside the scan, rather than prefetching every candidate
    // up front, keeps hits accumulating from the first file onward: a scan that
    // runs out of budget still reports the sites it proved.
    files_vec.par_iter().for_each_init(
        || AnalyzerRustDefinitionProvider::new(rust, true),
        |support, file| {
            if cap.reached() || cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            rust.note_scanned_candidate_file();
            let started = RustScanPhaseTimings::start();
            let Some(prepared) = rust.prepared_syntax(token, file) else {
                RustScanPhaseTimings::record(&timings.prepared_syntax_ns, started);
                return;
            };
            RustScanPhaseTimings::record(&timings.prepared_syntax_ns, started);
            let source = prepared.source();
            let tree = prepared.tree();
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            let line_starts = prepared.line_starts();
            let started = RustScanPhaseTimings::start();
            let lexical_scope_index = RustLexicalScopeIndex::new(tree.root_node(), source);
            RustScanPhaseTimings::record(&timings.lexical_scope_ns, started);
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            let started = RustScanPhaseTimings::start();
            let refs = rust.reference_context_of(token, file);
            RustScanPhaseTimings::record(&timings.reference_context_ns, started);
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            let mut owner_local_names: HashSet<String> = if file == target.source() {
                [owner.identifier().to_string()].into_iter().collect()
            } else {
                usage_binding_local_names(rust, token, file, &owner_seeds)
            };
            owner_local_names.extend(refs.bare_names_resolving_to(&owner.fq_name()));
            let trait_owner = is_trait_owner(rust, &owner);
            let receiver_type_names = if trait_owner {
                trait_implementer_names(rust, token, &owner, file)
            } else {
                owner_local_names.clone()
            };
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            if owner_local_names.is_empty()
                && receiver_type_names.is_empty()
                && !source.contains(&member_name)
            {
                return;
            }
            let visible_bare_constructors =
                visible_bare_constructor_names(rust, token, file, &self_like_constructors);
            let mut receiver_names = infer_receiver_names(
                tree.root_node(),
                source,
                &receiver_type_names,
                &constructor_returns,
                &visible_bare_constructors,
                cancellation,
            );
            receiver_names.extend(resolved_owner_receiver_names(
                tree.root_node(),
                token,
                source,
                analyzer,
                rust,
                support,
                file,
                &owner,
                cancellation,
            ));
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }
            receiver_names.sort();
            receiver_names.dedup();
            let static_owner_names = owner_local_names;
            // The raw-identifier escape sits between the path separator and the
            // name in source text (`Trait::r#type`), so the plain `::{member}`
            // substring check alone would miss a normalized raw-identifier member
            // name's escaped spelling; check both (#1128).
            let has_static_trait_call = trait_owner
                && (source.contains(&format!("::{member_name}"))
                    || source.contains(&format!("::r#{member_name}")));
            let record_unproven_receivers = !receiver_names.is_empty()
                || !static_owner_names.is_empty()
                || has_static_trait_call;
            let mut type_lookup_cache = RustTypeLookupCache::default();
            let mut token_tree_roles = RustTokenTreeRoleCache::default();
            let macro_candidate_names = [strip_raw_identifier_prefix(&member_name).to_string()]
                .into_iter()
                .collect::<HashSet<_>>();
            ingest_file_macro_matcher_roles(
                &mut token_tree_roles,
                token,
                analyzer,
                support,
                file,
                source,
                tree,
                RustMacroMatcherCandidateGate::Names(&macro_candidate_names),
                cancellation,
            );
            let mut local_hits = BTreeSet::new();
            let mut local_unproven_hits = BTreeSet::new();
            let target_is_enum_variant = requested_target.is_field()
                && rust
                    .structural_parent_of(requested_target)
                    .or_else(|| rust.parent_of(requested_target))
                    .is_some_and(|owner| is_rust_enum_declaration(rust, &owner));
            let mut ctx = MemberScanCtx {
                analyzer,
                rust,
                support,
                refs: &refs,
                file,
                source,
                root: tree.root_node(),
                line_starts,
                lexical_scope: &lexical_scope_index,
                owner: &owner,
                member_name: &member_name,
                scan_target: target,
                requested_target,
                owner_seeds: &owner_seeds,
                target_is_field: requested_target.is_field(),
                target_is_enum_variant,
                target_is_pattern_value: target_is_enum_variant
                    || is_rust_const_or_static_declaration(rust, requested_target),
                target_owner_is_trait: trait_owner,
                receiver_names: &receiver_names,
                receiver_type_names: &receiver_type_names,
                record_unproven_receivers,
                type_lookup_cache: &mut type_lookup_cache,
                token_tree_roles,
                cancellation,
                cancellation_checks_remaining: 0,
                hits: &mut local_hits,
                unproven_hits: &mut local_unproven_hits,
            };
            let started = RustScanPhaseTimings::start();
            scan_member_node(tree.root_node(), token, &mut ctx);
            RustScanPhaseTimings::record(&timings.ast_scan_ns, started);
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return;
            }

            let local_hits = classify_recursive_hits(analyzer, local_hits, requested_target);
            if !local_hits.is_empty() {
                cap.record(&local_hits);
                let mut sink = hits.lock().expect("poisoned Rust member collector");
                sink.extend(local_hits);
            }
            if !local_unproven_hits.is_empty() {
                let mut sink = unproven_hits
                    .lock()
                    .expect("poisoned Rust member unproven collector");
                sink.extend(local_unproven_hits);
            }
        },
    );

    timings.report(files_vec.len());

    RustMemberScanResult {
        hits: hits.into_inner().expect("poisoned Rust member collector"),
        unproven_hits: unproven_hits
            .into_inner()
            .expect("poisoned Rust member unproven collector"),
    }
}

#[derive(Default)]
pub(super) struct RustMemberScanResult {
    pub(super) hits: BTreeSet<UsageHit>,
    pub(super) unproven_hits: BTreeSet<UsageHit>,
}

struct MemberScanCtx<'a> {
    analyzer: &'a dyn IAnalyzer,
    rust: &'a RustAnalyzer,
    support: &'a dyn RustDefinitionProvider,
    refs: &'a RustReferenceContext<'a>,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'a>,
    line_starts: &'a [usize],
    lexical_scope: &'a RustLexicalScopeIndex,
    owner: &'a CodeUnit,
    member_name: &'a str,
    scan_target: &'a CodeUnit,
    requested_target: &'a CodeUnit,
    owner_seeds: &'a RustBindingSeeds,
    target_is_field: bool,
    target_is_enum_variant: bool,
    target_is_pattern_value: bool,
    target_owner_is_trait: bool,
    receiver_names: &'a Vec<String>,
    receiver_type_names: &'a HashSet<String>,
    record_unproven_receivers: bool,
    type_lookup_cache: &'a mut RustTypeLookupCache,
    token_tree_roles: RustTokenTreeRoleCache,
    cancellation: Option<&'a CancellationToken>,
    cancellation_checks_remaining: usize,
    hits: &'a mut BTreeSet<UsageHit>,
    unproven_hits: &'a mut BTreeSet<UsageHit>,
}

fn scan_member_node(root: Node<'_>, token: QueryToken<'_>, ctx: &mut MemberScanCtx<'_>) {
    walk_tree_iterative(
        root,
        ctx,
        |node, ctx| {
            if periodic_cancellation_requested(
                ctx.cancellation,
                &mut ctx.cancellation_checks_remaining,
            ) {
                return TreeWalkAction::Stop;
            }
            match node.kind() {
                "use_declaration" if ctx.target_is_field => {
                    record_member_use_import_hits(node, ctx);
                    return TreeWalkAction::Skip;
                }
                "field_expression" => record_instance_member_hit(node, token, ctx),
                "token_tree" => {
                    record_token_tree_instance_member_hits(node, token, ctx);
                    record_token_tree_static_member_hits(node, token, ctx);
                }
                "scoped_identifier" | "scoped_type_identifier" => {
                    record_static_member_hit(node, token, ctx)
                }
                "type_binding" | "associated_type_binding"
                    if ctx.target_is_field && ctx.target_owner_is_trait =>
                {
                    record_associated_type_binding_hit(node, token, ctx)
                }
                "type_item"
                    if ctx.target_is_field
                        && ctx.target_owner_is_trait
                        && !is_rust_trait_impl_member_declaration(
                            ctx.rust,
                            ctx.requested_target,
                        ) =>
                {
                    record_associated_type_declaration_hit(node, token, ctx)
                }
                "tuple_struct_pattern" if ctx.target_is_enum_variant => {
                    record_tuple_variant_pattern_hit(node, token, ctx)
                }
                "identifier" | "type_identifier"
                    if ctx.target_is_pattern_value
                        && node
                            .parent()
                            .is_some_and(|parent| parent.kind() == "token_tree") =>
                {
                    record_bare_token_tree_variant_pattern_hit(node, token, ctx)
                }
                "identifier" if ctx.target_is_enum_variant => {
                    record_bare_enum_variant_value_hit(node, token, ctx)
                }
                "struct_expression" | "struct_pattern" if ctx.target_is_field => {
                    record_struct_field_hits(node, ctx)
                }
                _ => {}
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

fn record_member_use_import_hits(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    let imports = brokk_bifrost_rust::imports::rust_imports_with_visibility_from_use_declaration(
        node, ctx.source,
    );
    for import in imports {
        let Some(span) = import.info.binder_span else {
            continue;
        };
        let Some(binder) = node_for_exact_range(ctx.root, span.start_byte, span.end_byte) else {
            continue;
        };
        let path = import.path.join("::");
        let Some(fqn) = resolve_rust_path_fqn(ctx.rust, ctx.refs, ctx.file, &path) else {
            continue;
        };
        if !ctx
            .support
            .fqn(&fqn)
            .into_iter()
            .any(|candidate| same_rust_declaration_identity(&candidate, ctx.requested_target))
        {
            continue;
        }
        let start = binder.start_byte();
        let end = binder.end_byte();
        let Some(enclosing) =
            member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
        else {
            continue;
        };
        push_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
        reclassify_import_hit_at(ctx.hits, ctx.file, start, end);
    }
}

fn record_associated_type_binding_hit(
    binding: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) {
    let Some(name) = binding.child_by_field_name("name") else {
        return;
    };
    if simple_node_text(name, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }

    let mut ancestor = binding.parent();
    let trait_type = loop {
        let Some(candidate) = ancestor else {
            return;
        };
        if candidate.kind() == "generic_type" {
            break candidate.child_by_field_name("type");
        }
        if matches!(candidate.kind(), "where_predicate" | "function_item") {
            return;
        }
        ancestor = candidate.parent();
    };
    let Some(trait_type) = trait_type else {
        return;
    };
    if !resolved_type_matches_owner(trait_type, token, ctx) {
        return;
    }

    let start = name.start_byte();
    let end = name.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
}

fn record_associated_type_declaration_hit(
    type_item: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) {
    let Some(name) = type_item.child_by_field_name("name") else {
        return;
    };
    if simple_node_text(name, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }
    let Some(impl_item) = enclosing_impl_item(type_item) else {
        return;
    };
    let Some(trait_type) = impl_item.child_by_field_name("trait") else {
        return;
    };
    if !resolved_type_matches_owner(trait_type, token, ctx) {
        return;
    }

    let start = name.start_byte();
    let end = name.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
}

fn record_tuple_variant_pattern_hit(
    pattern: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) {
    let Some(name) = pattern.child_by_field_name("type") else {
        return;
    };
    if name.kind() == "scoped_identifier" {
        record_qualified_tuple_variant_pattern_hit(name, token, ctx);
        return;
    }
    if name.kind() != "identifier"
        || simple_node_text(name, ctx.source).as_deref() != Some(ctx.member_name)
        || ctx
            .lexical_scope
            .name_bound_at(ctx.member_name, name.start_byte())
        || ctx
            .lexical_scope
            .item_bound_at(ctx.member_name, name.start_byte())
    {
        return;
    }

    if unqualified_enum_variant_matches(name, token, ctx) {
        record_static_member_name_hit(name, ctx);
    }
}

fn record_bare_token_tree_variant_pattern_hit(
    name: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) {
    let role = ctx.token_tree_roles.role(name, ctx.source);
    if simple_node_text(name, ctx.source).as_deref() != Some(ctx.member_name)
        || rust_token_path_segment_is_qualified(name)
        || !matches!(
            role,
            RustBareTokenTreeRole::Reference | RustBareTokenTreeRole::Pattern
        )
    {
        return;
    }
    let matches = if ctx.target_is_enum_variant {
        exact_forward_pattern_value_matches(name, token, ctx)
            || unqualified_enum_variant_matches(name, token, ctx)
    } else {
        exact_forward_pattern_value_matches(name, token, ctx)
    };
    if matches {
        record_static_member_name_hit(name, ctx);
    }
}

fn record_bare_enum_variant_value_hit(
    name: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) {
    let Some(written_name) = simple_node_text(name, ctx.source) else {
        return;
    };
    let pattern_binding = lexical_scope::is_pattern_binding_identifier(name);
    if brokk_bifrost_rust::graph::ast::is_rust_declaration_name(name)
        || token_tree_ancestor(name).is_some()
        || node_in_use_declaration(name)
        || identifier_is_scoped_path_part(name)
        || ctx
            .lexical_scope
            .name_bound_at(&written_name, name.start_byte())
        || ctx
            .lexical_scope
            .item_bound_at(&written_name, name.start_byte())
    {
        return;
    }
    if pattern_binding && !identifier_is_match_arm_pattern(name) {
        return;
    }
    let matches_variant = unqualified_enum_variant_matches(name, token, ctx);
    if pattern_binding && !matches_variant {
        return;
    }
    if matches_variant {
        record_static_member_name_hit(name, ctx);
    }
}

fn identifier_is_match_arm_pattern(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "match_arm" {
            return parent
                .child_by_field_name("pattern")
                .is_some_and(|pattern| {
                    pattern.start_byte() <= node.start_byte()
                        && node.end_byte() <= pattern.end_byte()
                });
        }
        current = parent;
    }
    false
}

fn exact_forward_pattern_value_matches(
    name: Node<'_>,
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    let roots = BTreeSet::from([ctx.requested_target.clone()]);
    let seeds = usage_binding_seeds(ctx.rust, token, &roots);
    let resolution = usage_reference_at(
        ctx.rust,
        token,
        ctx.file,
        &seeds,
        &[ctx.member_name],
        name.start_byte(),
        RustReferenceNamespace::Value,
        false,
        false,
    );
    let Some(root) = usage_exact_root_for_resolution(ctx.rust, token, &resolution, &seeds) else {
        return false;
    };
    same_rust_declaration_identity(&root, ctx.requested_target)
}

fn unqualified_enum_variant_matches(
    name: Node<'_>,
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    let Some(written_name) = simple_node_text(name, ctx.source) else {
        return false;
    };
    let binder =
        lexical_scope::visible_import_binder_in_tree(ctx.root, ctx.source, name.start_byte());
    let mut candidates = BTreeSet::new();
    if let Some(binding) = binder.bindings.get(&written_name) {
        // An explicit binding is authoritative over all glob imports. Only a
        // named enum-variant import can prove this unqualified pattern.
        if binding.kind != ImportKind::Named {
            return false;
        }
        let imported_name = binding.imported_name.as_deref().unwrap_or(&written_name);
        collect_enum_variant_candidates(
            &binding.module_specifier,
            imported_name,
            ctx,
            &mut candidates,
        );
    } else {
        // Only a written target name can resolve through a glob. A different
        // local name requires an explicit named import (possibly aliased).
        if written_name != ctx.member_name {
            return false;
        }
        // Ordinary module globs and re-export globs are already represented by
        // the import graph. Enum globs (`use Enum::*`) name a type rather than a
        // module, so resolve that owner through the same Rust reference context.
        for (target_file, target_name) in resolve_imported_export_from_binder_forward(
            ctx.rust,
            token,
            ctx.file,
            &binder,
            &written_name,
        ) {
            for candidate in ctx.support.file_identifier(&target_file, &target_name) {
                insert_enum_variant_candidate(candidate, ctx, &mut candidates);
            }
        }
        for binding in binder
            .bindings
            .values()
            .filter(|binding| binding.kind == ImportKind::Glob)
        {
            collect_enum_variant_candidates(
                &binding.module_specifier,
                &written_name,
                ctx,
                &mut candidates,
            );
        }
    }

    candidates.len() == 1
        && candidates.first().is_some_and(|candidate| {
            same_rust_declaration_identity(candidate, ctx.requested_target)
        })
}

fn record_qualified_tuple_variant_pattern_hit(
    variant_path: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) {
    let Some(name) = variant_path.child_by_field_name("name") else {
        return;
    };
    if simple_node_text(name, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }
    let Some(owner_path) = variant_path.child_by_field_name("path") else {
        return;
    };
    let Some(owner_segments) = rust_path_segments(owner_path) else {
        return;
    };
    let Some(resolved_owner) = exact_ast_owner(&owner_segments, token, ctx.owner_seeds, ctx) else {
        return;
    };
    let Some(requested_owner) = canonical_rust_hierarchy_type(ctx.rust, token, ctx.owner.clone())
    else {
        return;
    };
    if resolved_owner != requested_owner {
        return;
    }
    record_static_member_name_hit(name, ctx);
}

fn collect_enum_variant_candidates(
    owner_path: &str,
    variant_name: &str,
    ctx: &MemberScanCtx<'_>,
    candidates: &mut BTreeSet<CodeUnit>,
) {
    let Some(owner_fqn) = resolve_rust_path_fqn(ctx.rust, ctx.refs, ctx.file, owner_path) else {
        return;
    };
    for candidate in ctx.support.fqn(&format!("{owner_fqn}.{variant_name}")) {
        insert_enum_variant_candidate(candidate, ctx, candidates);
    }
}

fn insert_enum_variant_candidate(
    candidate: CodeUnit,
    ctx: &MemberScanCtx<'_>,
    candidates: &mut BTreeSet<CodeUnit>,
) {
    if candidate.is_field()
        && ctx
            .rust
            .parent_of(&candidate)
            .is_some_and(|owner| is_rust_enum_declaration(ctx.rust, &owner))
    {
        candidates.insert(candidate);
    }
}

fn record_instance_member_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut MemberScanCtx<'_>) {
    // A method target is referenced by a call (`receiver.method()`); a field target
    // is referenced by a read/write (`receiver.field`), never as the callee.
    if ctx.target_is_field {
        if field_expression_is_called(node) {
            return;
        }
    } else if !field_expression_is_called(node) {
        return;
    }
    let Some(field) = node.child_by_field_name("field") else {
        return;
    };
    if simple_node_text(field, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }
    let Some(receiver) = node.child_by_field_name("value") else {
        return;
    };
    let start = field.start_byte();
    let end = field.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    let receiver_name = simple_node_text(receiver, ctx.source);
    let inferred_match =
        match receiver_owner_proof(receiver, token, receiver_name.as_deref(), &enclosing, ctx) {
            ReceiverOwnerProof::Structured => false,
            ReceiverOwnerProof::Inferred => true,
            ReceiverOwnerProof::Mismatches => return,
            ReceiverOwnerProof::Unknown => {
                if ctx.record_unproven_receivers
                    && receiver_name.as_ref().is_some_and(|receiver_name| {
                        !receiver_name_explicitly_mismatched(receiver_name, &enclosing, ctx)
                    })
                {
                    push_unproven_member_hit(
                        ctx.file,
                        ctx.source,
                        ctx.line_starts,
                        start,
                        end,
                        enclosing,
                        ctx.unproven_hits,
                    );
                }
                return;
            }
        };

    // The explicit-mismatch guard only applies to a simple named receiver whose type
    // could be re-annotated in the enclosing scope; a resolved `self.field` receiver
    // already proved its type structurally.
    if inferred_match && let Some(receiver_name) = receiver_name.as_ref() {
        let receiver_mismatched = ctx
            .analyzer
            .get_source(&enclosing, false)
            .map(|enclosing_source| {
                receiver_explicitly_mismatched(
                    ctx.root,
                    ctx.source,
                    &enclosing_source,
                    ctx.receiver_type_names,
                    receiver_name,
                    ctx.cancellation,
                )
            })
            .unwrap_or(false);
        if receiver_mismatched {
            return;
        }
    }
    if !ctx.target_is_field && receiver_is_self_rooted(receiver, ctx.source) {
        push_self_receiver_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
    } else {
        push_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
    }
}

fn record_token_tree_instance_member_hits(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) {
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    for (index, window) in children.windows(3).enumerate() {
        let [receiver, dot, member] = window else {
            continue;
        };
        // Inside a macro token stream the receiver of `.member(...)` for an adapter
        // chain (`self.as_mut().member(...)`) is the adapter's call-parens token_tree,
        // not an identifier/self token; recognize that shape as a self-rooted receiver.
        let receiver_is_adapter_parens = receiver.kind() == "token_tree"
            && token_tree_receiver_is_self_rooted_adapter_chain(&children, index, ctx.source);
        if (!matches!(receiver.kind(), "identifier" | "self") && !receiver_is_adapter_parens)
            || dot.kind() != "."
        {
            continue;
        }
        if simple_node_text(*member, ctx.source).as_deref() != Some(ctx.member_name) {
            continue;
        }
        let is_call = children.get(index + 3).is_some_and(|call_args| {
            call_args.kind() == "token_tree"
                && call_args.child(0).is_some_and(|open| open.kind() == "(")
        });
        if ctx.target_is_field == is_call {
            continue;
        }
        let receiver_name = simple_node_text(*receiver, ctx.source);
        let start = member.start_byte();
        let end = member.end_byte();
        let Some(enclosing) =
            member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
        else {
            continue;
        };
        let proof = if receiver_is_adapter_parens {
            // No token-stream type inference is available for an adapter's call-parens
            // receiver; prove it by the enclosing impl's Self type, matching bare `self`.
            if enclosing_impl_type_matches_owner(*receiver, token, ctx) {
                ReceiverOwnerProof::Inferred
            } else {
                ReceiverOwnerProof::Unknown
            }
        } else {
            let receiver_types = token_tree_receiver_type_candidates(&children, token, index, ctx);
            if receiver_types.is_empty() {
                receiver_owner_proof(*receiver, token, receiver_name.as_deref(), &enclosing, ctx)
            } else {
                receiver_type_candidates_proof(&receiver_types, token, ctx)
            }
        };
        let inferred_match = match proof {
            ReceiverOwnerProof::Structured => false,
            ReceiverOwnerProof::Inferred => true,
            ReceiverOwnerProof::Mismatches => continue,
            ReceiverOwnerProof::Unknown => {
                if ctx.record_unproven_receivers
                    && receiver_name.as_ref().is_some_and(|receiver_name| {
                        !receiver_name_explicitly_mismatched(receiver_name, &enclosing, ctx)
                    })
                {
                    push_unproven_member_hit(
                        ctx.file,
                        ctx.source,
                        ctx.line_starts,
                        start,
                        end,
                        enclosing,
                        ctx.unproven_hits,
                    );
                }
                continue;
            }
        };
        if inferred_match && let Some(receiver_name) = receiver_name.as_ref() {
            let receiver_mismatched = ctx
                .analyzer
                .get_source(&enclosing, false)
                .map(|enclosing_source| {
                    receiver_explicitly_mismatched(
                        ctx.root,
                        ctx.source,
                        &enclosing_source,
                        ctx.receiver_type_names,
                        receiver_name,
                        ctx.cancellation,
                    )
                })
                .unwrap_or(false);
            if receiver_mismatched {
                continue;
            }
        }
        if !ctx.target_is_field
            && (receiver_is_adapter_parens || receiver_is_self_rooted(*receiver, ctx.source))
        {
            push_self_receiver_member_hit(
                ctx.file,
                ctx.source,
                ctx.line_starts,
                start,
                end,
                enclosing,
                ctx.hits,
            );
        } else {
            push_member_hit(
                ctx.file,
                ctx.source,
                ctx.line_starts,
                start,
                end,
                enclosing,
                ctx.hits,
            );
        }
    }
}

/// In a macro token stream, the receiver token that immediately precedes `.member(...)`
/// for an adapter chain like `self.as_mut().member(...)` is the adapter's empty
/// call-parens token_tree (`()`), preceded by `<adapter> . <inner>`. Recognize that
/// shape, walking back through nested adapter parens, bottoming out at `self`.
fn token_tree_receiver_is_self_rooted_adapter_chain(
    children: &[Node<'_>],
    receiver_index: usize,
    source: &str,
) -> bool {
    // The receiver token must be the adapter's empty call parens `()`.
    if children[receiver_index].kind() != "token_tree"
        || children[receiver_index].named_child_count() != 0
        || receiver_index < 3
    {
        return false;
    }
    let adapter = children[receiver_index - 1];
    let dot = children[receiver_index - 2];
    if adapter.kind() != "identifier"
        || dot.kind() != "."
        || simple_node_text(adapter, source)
            .is_none_or(|name| !is_self_preserving_receiver_adapter(&name))
    {
        return false;
    }
    token_tree_adapter_chain_root_is_self(children, receiver_index - 3, source)
}

/// Whether the token at `index` bottoms out at `self`, following any further
/// `<adapter>()` parens links back toward the chain root.
fn token_tree_adapter_chain_root_is_self(
    children: &[Node<'_>],
    index: usize,
    source: &str,
) -> bool {
    match children[index].kind() {
        "self" => true,
        "token_tree" => token_tree_receiver_is_self_rooted_adapter_chain(children, index, source),
        _ => false,
    }
}

fn token_tree_receiver_type_candidates(
    children: &[Node<'_>],
    token: QueryToken<'_>,
    receiver_index: usize,
    ctx: &mut MemberScanCtx<'_>,
) -> Vec<CodeUnit> {
    let mut root_index = receiver_index;
    while root_index >= 2 && children[root_index - 1].kind() == "." {
        let previous = children[root_index - 2];
        if !matches!(previous.kind(), "identifier" | "self") {
            break;
        }
        root_index -= 2;
    }
    let root = children[root_index];
    if !matches!(root.kind(), "identifier" | "self") {
        return Vec::new();
    }

    let mut receiver_types = rust_expression_type_definition_candidates_cached(
        ctx.analyzer,
        token,
        ctx.support,
        ctx.file,
        ctx.source,
        ctx.root,
        root,
        root.start_byte(),
        ctx.type_lookup_cache,
    );
    let mut segment_index = root_index + 2;
    while segment_index <= receiver_index && !receiver_types.is_empty() {
        let Some(field_name) = simple_node_text(children[segment_index], ctx.source) else {
            return Vec::new();
        };
        let mut fields = BTreeSet::new();
        for owner in &receiver_types {
            for candidate in ctx
                .support
                .fqn(&format!("{}.{}", owner.fq_name(), field_name))
            {
                if !candidate.is_field() {
                    continue;
                }
                if ctx
                    .rust
                    .parent_of(&candidate)
                    .is_some_and(|parent| same_rust_declaration_identity(&parent, owner))
                {
                    fields.insert(candidate);
                }
            }
        }
        receiver_types = fields
            .iter()
            .flat_map(|field| {
                rust_field_definition_type_candidates_cached(
                    ctx.analyzer,
                    token,
                    ctx.support,
                    field,
                    ctx.type_lookup_cache,
                )
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        segment_index += 2;
    }
    receiver_types
}

fn record_token_tree_static_member_hits(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) {
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    for member_index in 2..children.len() {
        let owner_index = member_index - 2;
        let owner = children[owner_index];
        let separator = children[member_index - 1];
        let member = children[member_index];
        if !rust_token_path_segment(owner)
            || separator.kind() != "::"
            || simple_node_text(member, ctx.source).as_deref() != Some(ctx.member_name)
        {
            continue;
        }
        let is_call = children.get(member_index + 1).is_some_and(|arguments| {
            arguments.kind() == "token_tree"
                && arguments.child(0).is_some_and(|open| open.kind() == "(")
        });
        if !static_member_role_matches_target(is_call, ctx) {
            continue;
        }
        let Some(owner_segments) = rust_token_owner_segments(&children, owner_index) else {
            continue;
        };
        if !structured_static_member_matches_target(owner, token, &owner_segments, ctx) {
            continue;
        }
        record_static_member_name_hit(member, ctx);
    }

    // A macro token tree can put the owner path inside `$crate` or a token
    // repetition. Resolve that structured path before the member scan's
    // local owner-name checks, which cannot represent those raw token nodes.
    //
    // A resolved fqn names the target only when the target is the sole
    // declaration that spells it. Two Cargo target roots can declare the same
    // crate-relative fqn, and this path has no owner node to select between
    // them, so an fqn that more than one declaration answers stays unproven
    // and the structured owner scan above decides the site instead.
    for segment in
        resolve_rust_token_tree_paths(ctx.rust, ctx.support, ctx.refs, ctx.file, ctx.source, node)
    {
        if !matches!(
            segment.role,
            RustTokenPathRole::Call | RustTokenPathRole::Value
        ) || simple_node_text(segment.node, ctx.source).as_deref() != Some(ctx.member_name)
            || segment.fqn != ctx.scan_target.fq_name()
        {
            continue;
        }
        let candidates =
            cargo_target_preferred_candidates(ctx.rust, ctx.file, ctx.support.fqn(&segment.fqn));
        if candidates.is_empty()
            || !candidates
                .iter()
                .all(|candidate| same_rust_declaration_identity(candidate, ctx.scan_target))
        {
            continue;
        }
        record_static_member_name_hit(segment.node, ctx);
    }
}

fn rust_token_owner_segments<'tree>(
    children: &[Node<'tree>],
    mut index: usize,
) -> Option<Vec<Node<'tree>>> {
    let mut segments = vec![children[index]];
    while index >= 2 && children[index - 1].kind() == "::" {
        let segment = children[index - 2];
        if !rust_token_path_segment(segment) {
            break;
        }
        segments.push(segment);
        index -= 2;
    }
    segments.reverse();
    Some(segments)
}

fn rust_token_path_segment(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "self" | "super" | "crate"
    )
}

fn receiver_name_explicitly_mismatched(
    receiver_name: &str,
    enclosing: &CodeUnit,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    ctx.analyzer
        .get_source(enclosing, false)
        .map(|enclosing_source| {
            receiver_explicitly_mismatched(
                ctx.root,
                ctx.source,
                &enclosing_source,
                ctx.receiver_type_names,
                receiver_name,
                ctx.cancellation,
            )
        })
        .unwrap_or(false)
}

/// Struct literal and destructuring labels reference fields on their resolved owner.
fn record_struct_field_hits(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    let Some((type_node, fields)) = rust_struct_field_references(node) else {
        return;
    };
    if !resolved_struct_field_owner_matches(type_node, ctx.refs.token(), ctx) {
        return;
    }
    for field in fields {
        if simple_node_text(field, ctx.source).as_deref() != Some(ctx.member_name) {
            continue;
        }
        let start = field.start_byte();
        let end = field.end_byte();
        let Some(enclosing) =
            member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
        else {
            continue;
        };
        push_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
    }
}

fn resolved_struct_field_owner_matches(
    type_node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    if !is_rust_enum_variant_declaration(ctx.rust, ctx.owner) {
        return resolved_type_matches_owner(type_node, token, ctx);
    }
    let Some(segments) = rust_path_segments(type_node) else {
        return false;
    };
    structured_owner_candidate_fqn(type_node, token, &segments, ctx)
        .is_some_and(|owner| owner == ctx.owner.fq_name())
}

enum ReceiverOwnerProof {
    Structured,
    Inferred,
    Mismatches,
    Unknown,
}

fn receiver_owner_proof(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    receiver_name: Option<&str>,
    enclosing: &CodeUnit,
    ctx: &mut MemberScanCtx<'_>,
) -> ReceiverOwnerProof {
    if receiver.kind() == "self"
        && enclosing_impl_item(receiver)
            .is_some_and(|impl_item| impl_item_contains_scan_target(impl_item, ctx))
    {
        return ReceiverOwnerProof::Structured;
    }

    let receiver_types = rust_expression_type_definition_candidates_cached(
        ctx.analyzer,
        token,
        ctx.support,
        ctx.file,
        ctx.source,
        ctx.root,
        receiver,
        receiver.start_byte(),
        ctx.type_lookup_cache,
    );
    if !receiver_types.is_empty() {
        match receiver_type_candidates_proof(&receiver_types, token, ctx) {
            ReceiverOwnerProof::Unknown => {}
            proof => return proof,
        }
    }
    if let Some(fqn) = rust_expression_type_definition_fqn_cached(
        ctx.analyzer,
        token,
        ctx.support,
        ctx.file,
        ctx.source,
        ctx.root,
        receiver,
        receiver.start_byte(),
        ctx.type_lookup_cache,
    ) {
        if !ctx.target_owner_is_trait
            && fqn_matches_owner(ctx.rust, token, ctx.support, &fqn, ctx.owner)
        {
            return ReceiverOwnerProof::Structured;
        }
        if let Some(matches) = receiver_type_matches_requested_dispatch(&fqn, ctx) {
            return if matches {
                ReceiverOwnerProof::Structured
            } else {
                ReceiverOwnerProof::Mismatches
            };
        }
        if !ctx.target_owner_is_trait
            && matches!(
                foreign_receiver_verdict(ctx.rust, &ctx.support.fqn(&fqn)),
                ReceiverOwnerProof::Mismatches
            )
        {
            return ReceiverOwnerProof::Mismatches;
        }
    }

    if receiver_name.is_some_and(|name| ctx.receiver_names.iter().any(|receiver| receiver == name))
    {
        return ReceiverOwnerProof::Inferred;
    }

    // Only reached once type inference above was inconclusive. A self-rooted chain of
    // Self-preserving adapters (`self.as_mut()`, …) dispatches to the enclosing type's
    // member, so prove it by the same enclosing-impl type identity as bare `self` —
    // this also covers the cross-impl case (a trait `impl` calling an inherent sibling),
    // because it matches on the impl's Self *type*, not on physical range containment.
    let matches = match receiver.kind() {
        "self" => enclosing_impl_type_matches_owner(receiver, token, ctx),
        "field_expression" => self_field_receiver_matches_owner(receiver, token, enclosing, ctx),
        "call_expression" | "parenthesized_expression"
            if receiver_is_self_rooted(receiver, ctx.source) =>
        {
            enclosing_impl_type_matches_owner(receiver, token, ctx)
        }
        _ => false,
    };
    if matches {
        ReceiverOwnerProof::Inferred
    } else {
        ReceiverOwnerProof::Unknown
    }
}

fn receiver_type_candidates_proof(
    receiver_types: &[CodeUnit],
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> ReceiverOwnerProof {
    if !ctx.target_owner_is_trait && type_candidates_match_owner(receiver_types, token, ctx) {
        return ReceiverOwnerProof::Structured;
    }
    if let Some(matches) = receiver_type_candidates_match_requested_dispatch(receiver_types, ctx) {
        return if matches {
            ReceiverOwnerProof::Structured
        } else {
            ReceiverOwnerProof::Mismatches
        };
    }
    if ctx.target_owner_is_trait {
        return ReceiverOwnerProof::Unknown;
    }
    foreign_receiver_verdict(ctx.rust, receiver_types)
}

/// Whether a receiver whose resolved type did not match the owner is *proof* of a
/// different owner. Only real evidence can refuse a call site: an alias hides the
/// declaration it stands for, and a type that resolved to no indexed declaration
/// proves nothing at all.
///
/// Claiming `Mismatches` on an empty resolution turned any FQN-identity blind spot
/// into a false `verified_absent` with zero unproven hits (issue #1750). Empty
/// evidence therefore stays `Unknown`, which reaches the unproven surface through
/// `record_unproven_receivers`.
fn foreign_receiver_verdict(rust: &RustAnalyzer, resolved: &[CodeUnit]) -> ReceiverOwnerProof {
    if resolved.is_empty() || resolved.iter().any(|unit| rust.is_type_alias(unit)) {
        ReceiverOwnerProof::Unknown
    } else {
        ReceiverOwnerProof::Mismatches
    }
}

fn type_candidates_match_owner(
    receiver_types: &[CodeUnit],
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    let canonical: Option<BTreeSet<_>> = receiver_types
        .iter()
        .cloned()
        .map(|unit| canonical_rust_hierarchy_type(ctx.rust, token, unit))
        .collect();
    let Some(canonical) = canonical else {
        return false;
    };
    canonical.len() == 1 && canonical.first().is_some_and(|unit| unit == ctx.owner)
}

fn receiver_type_candidates_match_requested_dispatch(
    receiver_types: &[CodeUnit],
    ctx: &MemberScanCtx<'_>,
) -> Option<bool> {
    let receiver_types: Vec<_> = receiver_types
        .iter()
        .filter(|unit| ctx.rust.supports_type_hierarchy(unit))
        .collect();
    if receiver_types.is_empty()
        || receiver_types
            .iter()
            .any(|unit| ctx.rust.is_type_alias(unit))
    {
        return None;
    }

    if ctx.requested_target != ctx.scan_target {
        let requested_owner = ctx.rust.parent_of(ctx.requested_target)?;
        return Some(receiver_types.into_iter().any(|receiver_type| {
            same_rust_declaration_identity(receiver_type, &requested_owner)
                && ctx
                    .rust
                    .get_ancestors(receiver_type)
                    .iter()
                    .any(|ancestor| same_rust_declaration_identity(ancestor, ctx.owner))
        }));
    }

    ctx.target_owner_is_trait.then(|| {
        receiver_types.into_iter().any(|receiver_type| {
            same_rust_declaration_identity(receiver_type, ctx.owner)
                || ctx
                    .rust
                    .get_ancestors(receiver_type)
                    .iter()
                    .any(|ancestor| same_rust_declaration_identity(ancestor, ctx.owner))
        })
    })
}

fn receiver_type_matches_requested_dispatch(fqn: &str, ctx: &MemberScanCtx<'_>) -> Option<bool> {
    let receiver_types: Vec<_> = ctx
        .support
        .fqn(fqn)
        .into_iter()
        .filter(|unit| ctx.rust.supports_type_hierarchy(unit))
        .collect();
    if receiver_types.is_empty()
        || receiver_types
            .iter()
            .any(|unit| ctx.rust.is_type_alias(unit))
    {
        return None;
    }

    if ctx.requested_target != ctx.scan_target {
        let requested_owner = ctx.rust.parent_of(ctx.requested_target)?;
        let result = receiver_types.into_iter().any(|receiver_type| {
            same_rust_declaration_identity(&receiver_type, &requested_owner)
                && ctx
                    .rust
                    .get_ancestors(&receiver_type)
                    .iter()
                    .any(|ancestor| same_rust_declaration_identity(ancestor, ctx.owner))
        });
        return Some(result);
    }

    ctx.target_owner_is_trait.then(|| {
        receiver_types.into_iter().any(|receiver_type| {
            same_rust_declaration_identity(&receiver_type, ctx.owner)
                || ctx
                    .rust
                    .get_ancestors(&receiver_type)
                    .iter()
                    .any(|ancestor| same_rust_declaration_identity(ancestor, ctx.owner))
        })
    })
}

fn same_rust_declaration_identity(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.fq_name() == right.fq_name()
        && left.source() == right.source()
        && left.kind() == right.kind()
}

/// Universally Self-preserving receiver adapters: calling one of these no-argument
/// methods on `self` yields a value of the *same nominal type* — `Self`, `&Self`,
/// `&mut Self`, or a smart-pointer re-borrow such as `Pin<&mut Self>` — so a method
/// invoked *through* the adapter still dispatches to the enclosing type's member.
///
/// The set is deliberately small and limited to the standard by-reference receiver
/// conversions (`AsMut`/`AsRef`/`Clone`/`Borrow`). Anything that can change the
/// nominal type (`into`, a user `AsRef<Other>`, `deref` to a different target, …)
/// is excluded so we never mistake a foreign owner's same-named method for a self
/// call. Type inference still runs first, so a receiver that inference resolves to a
/// concrete different owner is rejected before this allowlist is ever consulted.
const SELF_PRESERVING_RECEIVER_ADAPTERS: &[&str] =
    &["as_mut", "as_ref", "clone", "borrow", "borrow_mut"];

fn is_self_preserving_receiver_adapter(name: &str) -> bool {
    SELF_PRESERVING_RECEIVER_ADAPTERS.contains(&name)
}

/// Whether `receiver` is `self` (possibly parenthesized) or a chain of Self-preserving
/// adapter calls rooted at `self` — e.g. `self.as_mut()`, `(self).as_ref()`,
/// `self.as_ref().as_mut()`. Such a receiver dispatches to the enclosing type's member,
/// so a hit through it is classified as a self-receiver hit exactly like bare `self`.
fn receiver_is_self_rooted(receiver: Node<'_>, source: &str) -> bool {
    match receiver.kind() {
        "self" => true,
        "parenthesized_expression" => receiver
            .named_child(0)
            .is_some_and(|inner| receiver_is_self_rooted(inner, source)),
        "call_expression" => self_rooted_adapter_call(receiver, source),
        _ => false,
    }
}

/// `<inner>.<adapter>()` where `<adapter>` is a Self-preserving receiver adapter and
/// `<inner>` is itself self-rooted. Restricted to no-argument calls: every allowlisted
/// adapter is nullary, and requiring empty arguments keeps an unrelated same-named
/// method that happens to take arguments from being read as an adapter.
fn self_rooted_adapter_call(call: Node<'_>, source: &str) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "field_expression" {
        return false;
    }
    if call
        .child_by_field_name("arguments")
        .is_none_or(|args| args.named_child_count() != 0)
    {
        return false;
    }
    let adapter_matches = function
        .child_by_field_name("field")
        .and_then(|field| simple_node_text(field, source))
        .is_some_and(|name| is_self_preserving_receiver_adapter(&name));
    if !adapter_matches {
        return false;
    }
    function
        .child_by_field_name("value")
        .is_some_and(|value| receiver_is_self_rooted(value, source))
}

/// Whether `receiver` is direct `self` inside an inherent impl whose resolved
/// target type is the owner, so `self.member` resolves to that owner member.
fn enclosing_impl_type_matches_owner(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    let Some(impl_item) = enclosing_impl_item(receiver) else {
        return false;
    };
    let Some(type_node) = impl_item.child_by_field_name("type") else {
        return false;
    };
    resolved_type_matches_owner(type_node, token, ctx)
}

/// Whether `receiver` is `self.<field>` and that field's declared type on the
/// enclosing `impl` type is the owner type — so a `self.field.member` access
/// resolves without the receiver being a simple local of the owner type.
fn self_field_receiver_matches_owner(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    enclosing: &CodeUnit,
    ctx: &mut MemberScanCtx<'_>,
) -> bool {
    if receiver.kind() != "field_expression" {
        return false;
    }
    if receiver
        .child_by_field_name("value")
        .is_none_or(|value| value.kind() != "self")
    {
        return false;
    }
    let Some(field_name) = receiver
        .child_by_field_name("field")
        .and_then(|field| simple_node_text(field, ctx.source))
    else {
        return false;
    };
    let Some(self_type) = ctx.analyzer.parent_of(enclosing) else {
        return false;
    };
    for member in ctx.analyzer.get_members_in_class(&self_type) {
        if member.is_field()
            && member.identifier() == field_name
            && field_declared_type_matches_receiver(&member, token, ctx)
        {
            return true;
        }
    }
    false
}

fn enclosing_impl_item(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "impl_item" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn resolved_type_matches_owner(
    type_node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    if let Some(segments) = rust_path_segments(type_node)
        && exact_ast_owner(&segments, token, ctx.owner_seeds, ctx).as_ref() == Some(ctx.owner)
    {
        return true;
    }
    let Some(fqn) = rust_resolve_type_node_fqn(
        ctx.analyzer,
        token,
        ctx.support,
        ctx.file,
        ctx.source,
        type_node,
        Some(type_node.start_byte()),
    ) else {
        return false;
    };
    fqn_matches_owner(ctx.rust, token, ctx.support, &fqn, ctx.owner)
}

fn fqn_matches_owner(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    fqn: &str,
    owner: &CodeUnit,
) -> bool {
    let candidates = support.fqn(fqn);
    let canonical: Option<BTreeSet<_>> = candidates
        .into_iter()
        .map(|unit| canonical_rust_hierarchy_type(rust, token, unit))
        .collect();
    let Some(canonical) = canonical else {
        return false;
    };
    canonical.len() == 1 && canonical.first().is_some_and(|unit| unit == owner)
}

fn canonical_member_owner(rust: &RustAnalyzer, token: QueryToken<'_>, owner: CodeUnit) -> CodeUnit {
    let owner = canonical_imported_impl_target(rust, token, &owner).unwrap_or(owner);
    canonical_rust_hierarchy_type(rust, token, owner.clone()).unwrap_or(owner)
}

fn field_declared_type_matches_receiver(
    member: &CodeUnit,
    token: QueryToken<'_>,
    ctx: &mut MemberScanCtx<'_>,
) -> bool {
    let receiver_types = rust_field_definition_type_candidates_cached(
        ctx.analyzer,
        token,
        ctx.support,
        member,
        ctx.type_lookup_cache,
    );
    type_candidates_match_owner(&receiver_types, token, ctx)
}

fn node_for_exact_range(root: Node<'_>, start: usize, end: usize) -> Option<Node<'_>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() == start && node.end_byte() == end {
            return Some(node);
        }
        if node.start_byte() <= start && node.end_byte() >= end {
            let mut cursor = node.walk();
            let mut children: Vec<_> = node.named_children(&mut cursor).collect();
            children.reverse();
            stack.extend(children);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConstructorReturn {
    DirectReceiver,
    NeedsUnwrap,
}

#[derive(Clone, Debug)]
struct SelfLikeConstructor {
    declaration: CodeUnit,
    return_kind: ConstructorReturn,
}

fn field_expression_is_called(node: Node<'_>) -> bool {
    let mut expression = node;
    while let Some(parent) = expression.parent()
        && parent.kind() == "generic_function"
        && parent
            .child_by_field_name("function")
            .is_some_and(|function| same_node(function, expression))
    {
        expression = parent;
    }
    expression.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| same_node(function, expression))
    })
}

fn record_static_member_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut MemberScanCtx<'_>) {
    if node_in_use_declaration(node) {
        return;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if simple_node_text(name, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    if !static_member_role_matches_target(field_expression_is_called(node), ctx) {
        return;
    }
    if !ast_static_member_matches_target(path, token, ctx) {
        return;
    }

    record_static_member_name_hit(name, ctx);
}

fn record_static_member_name_hit(name: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    let start = name.start_byte();
    let end = name.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
}

fn static_member_role_matches_target(is_call: bool, ctx: &MemberScanCtx<'_>) -> bool {
    ctx.target_is_enum_variant || !ctx.target_is_field || !is_call
}

fn node_in_use_declaration(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "use_declaration" {
            return true;
        }
        node = parent;
    }
    false
}

fn ast_static_member_matches_target(
    owner_node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    let Some(segments) = rust_path_segments(owner_node) else {
        return false;
    };
    structured_static_member_matches_target(owner_node, token, &segments, ctx)
}

fn structured_static_member_matches_target(
    owner_node: Node<'_>,
    token: QueryToken<'_>,
    segments: &[Node<'_>],
    ctx: &MemberScanCtx<'_>,
) -> bool {
    if segments.len() == 1 && simple_node_text(segments[0], ctx.source).as_deref() == Some("Self") {
        return self_static_owner_matches_target(owner_node, token, ctx);
    }
    let item_matches = if ctx.target_is_field {
        CodeUnit::is_field
    } else {
        CodeUnit::is_function
    };
    let owner = exact_ast_owner(segments, token, ctx.owner_seeds, ctx)
        .or_else(|| exact_structured_static_owner(owner_node, token, segments, ctx))
        .or_else(|| {
            (!ctx.target_owner_is_trait)
                .then(|| exact_type_alias_owner(owner_node, token, segments, ctx))
                .flatten()
        });
    let Some(owner) = owner else {
        return ctx.target_owner_is_trait
            && trait_implementer_static_member_matches_target(
                owner_node,
                token,
                segments,
                item_matches,
                ctx,
            );
    };
    let exact_candidates = [ctx.requested_target, ctx.scan_target]
        .into_iter()
        .filter(|candidate| {
            if is_rust_trait_impl_member_declaration(ctx.rust, candidate) {
                return false;
            }
            let name_matches = candidate.identifier() == ctx.member_name;
            let role_matches = item_matches(candidate);
            let parent = ctx
                .rust
                .structural_parent_of(candidate)
                .or_else(|| ctx.rust.parent_of(candidate));
            let owner_matches = parent
                .map(|parent| canonical_member_owner(ctx.rust, token, parent))
                .as_ref()
                == Some(&owner);
            name_matches && role_matches && owner_matches
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let outcome = if !exact_candidates.is_empty() {
        ReceiverAnalysisOutcome::Precise(exact_candidates.into_iter().collect())
    } else if is_rust_trait_impl_member_declaration(ctx.rust, ctx.requested_target) {
        let candidates = ctx
            .support
            .fqn(&format!("{}.{}", owner.fq_name(), ctx.member_name))
            .into_iter()
            .filter(&item_matches)
            .filter(|candidate| {
                ctx.rust
                    .structural_parent_of(candidate)
                    .or_else(|| ctx.rust.parent_of(candidate))
                    .map(|parent| canonical_member_owner(ctx.rust, token, parent))
                    .as_ref()
                    == Some(&owner)
            })
            .collect();
        ReceiverAnalysisOutcome::Precise(candidates)
    } else {
        resolve_exact_owner_associated_item_matching(
            ctx.rust,
            ctx.support,
            ctx.refs,
            ctx.file,
            &owner,
            ctx.member_name,
            item_matches,
            owner_node.start_byte(),
        )
    };
    associated_candidates_match_target(outcome, token, owner_node, Some(&owner), ctx)
}

/// `candidates` narrowed to the declarations that `file`'s own Cargo target
/// root builds, when that root declares any of them.
///
/// A Rust fqn is a crate-relative module path, so a library root and a binary
/// root in one workspace spell the same fqn for two different declarations.
/// Equal fqns alone therefore admit a decoy from the other target; only the
/// route from the referring file selects between them.
fn cargo_target_preferred_candidates(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    match rust.candidates_in_same_cargo_target_root(file, candidates.clone()) {
        Some(physical) if !physical.is_empty() => physical,
        _ => candidates,
    }
}

fn exact_structured_static_owner(
    owner_node: Node<'_>,
    token: QueryToken<'_>,
    segments: &[Node<'_>],
    ctx: &MemberScanCtx<'_>,
) -> Option<CodeUnit> {
    let owner_fqn = structured_owner_candidate_fqn(owner_node, token, segments, ctx)?;
    let mut candidates = cargo_target_preferred_candidates(
        ctx.rust,
        ctx.file,
        ctx.support
            .fqn(&owner_fqn)
            .into_iter()
            .filter(|candidate| rust_is_type_definition(ctx.analyzer, candidate))
            .filter_map(|candidate| canonical_rust_hierarchy_type(ctx.rust, token, candidate))
            .collect(),
    );
    candidates.sort();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn exact_type_alias_owner(
    owner_node: Node<'_>,
    token: QueryToken<'_>,
    segments: &[Node<'_>],
    ctx: &MemberScanCtx<'_>,
) -> Option<CodeUnit> {
    let owner_fqn = structured_owner_candidate_fqn(owner_node, token, segments, ctx)?;
    let roots = ctx
        .support
        .fqn(&owner_fqn)
        .into_iter()
        .filter(|candidate| ctx.rust.is_type_alias(candidate))
        .collect::<BTreeSet<_>>();
    if roots.is_empty() {
        return None;
    }
    let seeds = usage_binding_seeds(ctx.rust, token, &roots);
    let alias_owner = exact_ast_owner(segments, token, &seeds, ctx)?;
    let target_owner = canonical_rust_hierarchy_type(ctx.rust, token, ctx.owner.clone())?;
    (alias_owner == target_owner).then_some(alias_owner)
}

fn exact_ast_owner(
    segments: &[Node<'_>],
    token: QueryToken<'_>,
    seeds: &RustBindingSeeds,
    ctx: &MemberScanCtx<'_>,
) -> Option<CodeUnit> {
    let segment_names = segments
        .iter()
        .map(|segment| simple_node_text(*segment, ctx.source))
        .collect::<Option<Vec<_>>>()?;
    let segment_refs = segment_names.iter().map(String::as_str).collect::<Vec<_>>();
    let root = *segments.first()?;
    let root_name = segment_names.first()?;
    let rooted = matches!(root_name.as_str(), "crate" | "self" | "super");
    let root_shadowed = !rooted
        && if segments.len() > 1 {
            ctx.lexical_scope
                .item_bound_at(root_name, root.start_byte())
        } else {
            ctx.lexical_scope
                .local_item_bound_at(root_name, root.start_byte())
        }
        && !usage_root_declaration_matches_at(
            ctx.rust,
            token,
            ctx.file,
            seeds,
            root_name,
            root.start_byte(),
        )
        && !usage_local_module_prefix_visible_at(
            ctx.rust,
            token,
            ctx.file,
            seeds,
            root_name,
            root.start_byte(),
        );
    let resolution = usage_reference_at(
        ctx.rust,
        token,
        ctx.file,
        seeds,
        &segment_refs,
        segments.last()?.start_byte(),
        RustReferenceNamespace::Type,
        root_shadowed,
        crate::analyzer::usages::rust_graph::hits::rust_path_is_leading_absolute(*segments.last()?),
    );
    let root = usage_exact_root_for_resolution(ctx.rust, token, &resolution, seeds)?;
    canonical_rust_hierarchy_type(ctx.rust, token, root)
}

fn trait_implementer_static_member_matches_target(
    owner_node: Node<'_>,
    token: QueryToken<'_>,
    segments: &[Node<'_>],
    item_matches: fn(&CodeUnit) -> bool,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    let Some(owner_fqn) = structured_owner_candidate_fqn(owner_node, token, segments, ctx) else {
        return false;
    };
    let mut roots = ctx
        .support
        .fqn(&owner_fqn)
        .into_iter()
        .filter(|candidate| rust_is_type_definition(ctx.analyzer, candidate))
        .filter(|candidate| !is_rust_trait_declaration(ctx.rust, candidate))
        .collect::<BTreeSet<_>>();
    if is_rust_trait_impl_member_declaration(ctx.rust, ctx.requested_target)
        && let Some(owner) = ctx.rust.parent_of(ctx.requested_target)
    {
        roots.insert(canonical_member_owner(ctx.rust, token, owner));
    }
    if roots.is_empty() {
        return false;
    }
    let seeds = usage_binding_seeds(ctx.rust, token, &roots);
    let Some(owner) = exact_ast_owner(segments, token, &seeds, ctx) else {
        return false;
    };
    let outcome = resolve_exact_owner_associated_item_matching(
        ctx.rust,
        ctx.support,
        ctx.refs,
        ctx.file,
        &owner,
        ctx.member_name,
        item_matches,
        owner_node.start_byte(),
    );
    associated_candidates_match_target(outcome, token, owner_node, None, ctx)
}

fn structured_owner_candidate_fqn(
    owner_node: Node<'_>,
    token: QueryToken<'_>,
    segments: &[Node<'_>],
    ctx: &MemberScanCtx<'_>,
) -> Option<String> {
    let names = segments
        .iter()
        .map(|segment| simple_node_text(*segment, ctx.source))
        .collect::<Option<Vec<_>>>()?;
    let (name, prefix) = names.split_last()?;
    let resolved = if prefix.is_empty() {
        ctx.refs.resolve_bare(name)
    } else {
        let path = prefix.join("::");
        ctx.refs.resolve_scoped(&path, name)
    };
    resolved.or_else(|| {
        rust_resolve_type_node_fqn(
            ctx.analyzer,
            token,
            ctx.support,
            ctx.file,
            ctx.source,
            owner_node,
            Some(owner_node.start_byte()),
        )
    })
}

fn associated_candidates_match_target(
    outcome: ReceiverAnalysisOutcome<CodeUnit>,
    token: QueryToken<'_>,
    owner_node: Node<'_>,
    expected_owner: Option<&CodeUnit>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    match outcome {
        ReceiverAnalysisOutcome::Precise(candidates) => {
            let applicable = is_rust_trait_impl_member_declaration(ctx.rust, ctx.requested_target)
                .then(|| {
                    owner_node
                        .parent()
                        .filter(|scoped| {
                            matches!(
                                scoped.kind(),
                                "scoped_identifier" | "scoped_type_identifier"
                            )
                        })
                        .and_then(|scoped| {
                            rust_associated_call_applicable_candidates(
                                ctx.analyzer,
                                ctx.support,
                                ctx.source,
                                ctx.root,
                                scoped,
                                candidates.clone(),
                            )
                        })
                })
                .flatten();
            if applicable.as_ref().is_some_and(|applicable| {
                applicable.len() != 1 && !(applicable.is_empty() && candidates.len() == 1)
            }) {
                return false;
            }
            // An empty applicability result means that the argument shape did
            // not provide positive type evidence. Keep a unique resolver
            // candidate in that case; with multiple candidates the call stays
            // ambiguous and was rejected above.
            let applicability_selected = applicable.as_ref().is_some_and(|items| !items.is_empty());
            let candidates = if applicability_selected {
                applicable.expect("selected applicability candidates")
            } else {
                candidates
            };
            candidates.into_iter().any(|candidate| {
                let parent = ctx
                    .rust
                    .structural_parent_of(&candidate)
                    .or_else(|| ctx.rust.parent_of(&candidate));
                let owner_matches = expected_owner.is_none_or(|expected| {
                    parent.as_ref().is_some_and(|parent| {
                        is_rust_trait_declaration(ctx.rust, parent)
                            || canonical_member_owner(ctx.rust, token, parent.clone()) == *expected
                    })
                });
                let mapped_trait = is_rust_trait_impl_member_declaration(ctx.rust, &candidate)
                    .then(|| trait_member_for_impl_member(ctx.rust, token, &candidate))
                    .flatten();
                let enum_parent = ctx
                    .target_is_enum_variant
                    .then_some(parent.as_ref())
                    .flatten()
                    .filter(|parent| is_rust_enum_declaration(ctx.rust, parent));
                let visibility_declaration =
                    mapped_trait.as_ref().or(enum_parent).unwrap_or(&candidate);
                let directly_visible = if mapped_trait.is_some() || enum_parent.is_some() {
                    usage_declaration_visible_at(
                        ctx.rust,
                        token,
                        visibility_declaration,
                        ctx.file,
                        owner_node.start_byte(),
                    )
                } else {
                    usage_identity_visible_at(
                        ctx.rust,
                        token,
                        visibility_declaration,
                        ctx.file,
                        owner_node.start_byte(),
                    )
                };
                let unindexed_trait_impl_visible_through_owner = mapped_trait.is_none()
                    && is_rust_trait_impl_member_declaration(ctx.rust, &candidate)
                    && is_graph_visible_member_target(ctx.rust, &candidate);
                let public_trait_visible_through_owner =
                    mapped_trait.as_ref().is_some_and(|member| {
                        ctx.rust.parent_of(member).is_some_and(|trait_owner| {
                            matches!(
                                brokk_bifrost_rust::graph_support::rust_declaration_visibility(
                                    ctx.rust,
                                    token,
                                    &trait_owner,
                                ),
                                brokk_bifrost_rust::imports::RustVisibility::Public
                            )
                        })
                    });
                let identity_matches = if applicability_selected {
                    candidate == *ctx.requested_target
                        || mapped_trait
                            .as_ref()
                            .is_some_and(|trait_member| trait_member == ctx.requested_target)
                } else {
                    same_rust_declaration_identity(&candidate, ctx.requested_target)
                        || mapped_trait.as_ref().is_some_and(|trait_member| {
                            same_rust_declaration_identity(trait_member, ctx.requested_target)
                        })
                };
                (applicability_selected
                    || directly_visible
                    || unindexed_trait_impl_visible_through_owner
                    || public_trait_visible_through_owner)
                    && owner_matches
                    && identity_matches
            })
        }
        ReceiverAnalysisOutcome::Ambiguous(_)
        | ReceiverAnalysisOutcome::Unknown
        | ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. } => false,
    }
}

fn self_static_owner_matches_target(
    owner_node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    let mut current = Some(owner_node);
    while let Some(node) = current {
        match node.kind() {
            "impl_item" => {
                if impl_item_contains_requested_target(node, ctx)
                    || impl_item_contains_scan_target(node, ctx)
                {
                    return true;
                }
                if ctx.scan_target != ctx.requested_target
                    && let Some(requested_owner) = ctx.rust.parent_of(ctx.requested_target)
                    && !is_rust_trait_declaration(ctx.rust, &requested_owner)
                {
                    return node.child_by_field_name("type").is_some_and(|type_node| {
                        rust_resolve_type_node_fqn(
                            ctx.analyzer,
                            token,
                            ctx.support,
                            ctx.file,
                            ctx.source,
                            type_node,
                            Some(type_node.start_byte()),
                        )
                        .is_some_and(|fqn| {
                            fqn_matches_owner(ctx.rust, token, ctx.support, &fqn, &requested_owner)
                        })
                    });
                }
                let owner = if ctx.target_owner_is_trait {
                    node.child_by_field_name("trait")
                } else {
                    node.child_by_field_name("type")
                };
                return owner.is_some_and(|owner| resolved_type_matches_owner(owner, token, ctx));
            }
            "trait_item" => {
                return node
                    .child_by_field_name("name")
                    .is_some_and(|name| resolved_type_matches_owner(name, token, ctx));
            }
            _ => current = node.parent(),
        }
    }
    false
}

fn impl_item_contains_requested_target(node: Node<'_>, ctx: &MemberScanCtx<'_>) -> bool {
    impl_item_contains_target(node, ctx.requested_target, ctx)
}

fn impl_item_contains_scan_target(node: Node<'_>, ctx: &MemberScanCtx<'_>) -> bool {
    impl_item_contains_target(node, ctx.scan_target, ctx)
}

fn impl_item_contains_target(node: Node<'_>, target: &CodeUnit, ctx: &MemberScanCtx<'_>) -> bool {
    ctx.file == target.source()
        && ctx
            .rust
            .ranges(target)
            .into_iter()
            .any(|range| node.start_byte() <= range.start_byte && range.end_byte <= node.end_byte())
}

fn self_like_constructor_returns(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    owner: &CodeUnit,
) -> HashMap<String, SelfLikeConstructor> {
    let Ok(source) = owner.source().read_to_string() else {
        return HashMap::default();
    };
    let Some(tree) = parse_rust_source(&source) else {
        return HashMap::default();
    };

    rust.get_all_declarations()
        .into_iter()
        .filter(|code_unit| code_unit.source() == owner.source())
        .filter(|code_unit| code_unit.is_function())
        .filter(|code_unit| {
            // Associated constructors of the owner (`Owner::new`) and free functions
            // in the same module (`build_owner`) both return the owner type; a method
            // on a different type is excluded by the return-type check below.
            match rust.parent_of(code_unit) {
                None => true,
                Some(parent) => parent.is_module() || parent == *owner,
            }
        })
        .filter_map(|code_unit| {
            let range = rust.ranges(&code_unit).into_iter().next()?;
            let function =
                node_for_exact_range(tree.root_node(), range.start_byte, range.end_byte)?;
            let return_type = function_return_type_node(function)?;
            let ctx = ConstructorReturnCtx {
                rust,
                token,
                support,
                file: code_unit.source(),
                source: &source,
                owner,
            };
            constructor_return_kind_from_type_node(return_type, &ctx).map(|return_kind| {
                (
                    code_unit.identifier().to_string(),
                    SelfLikeConstructor {
                        declaration: code_unit,
                        return_kind,
                    },
                )
            })
        })
        .collect()
}

struct ConstructorReturnCtx<'a> {
    rust: &'a RustAnalyzer,
    token: QueryToken<'a>,
    support: &'a dyn RustDefinitionProvider,
    file: &'a ProjectFile,
    source: &'a str,
    owner: &'a CodeUnit,
}

/// Whether a function's return type produces the owner type either directly as a
/// method receiver (`Self`, owner, `Box`/`Arc`/`Rc`) or behind an explicit
/// `Option`/`Result` unwrap. This inspects tree-sitter type nodes instead of
/// reparsing Rust type syntax from source text.
fn constructor_return_kind_from_type_node(
    type_node: Node<'_>,
    ctx: &ConstructorReturnCtx<'_>,
) -> Option<ConstructorReturn> {
    match type_node.kind() {
        "type_identifier" | "identifier" | "scoped_type_identifier" | "scoped_identifier" => {
            type_node_matches_constructor_owner(type_node, ctx)
                .then_some(ConstructorReturn::DirectReceiver)
        }
        "generic_type" => {
            let base = type_node.child_by_field_name("type").or_else(|| {
                let mut cursor = type_node.walk();
                type_node.named_children(&mut cursor).next()
            })?;
            let base_name = type_node_last_segment(base, ctx.source)?;
            if matches!(base_name.as_str(), "Box" | "Arc" | "Rc") {
                return first_generic_type_argument(type_node)
                    .and_then(|inner| constructor_return_kind_from_type_node(inner, ctx))
                    .filter(|kind| *kind == ConstructorReturn::DirectReceiver);
            }
            if matches!(base_name.as_str(), "Result" | "Option") {
                return first_generic_type_argument(type_node)
                    .and_then(|inner| constructor_return_kind_from_type_node(inner, ctx))
                    .map(|_| ConstructorReturn::NeedsUnwrap);
            }
            type_node_matches_constructor_owner(base, ctx)
                .then_some(ConstructorReturn::DirectReceiver)
        }
        "reference_type" | "pointer_type" => {
            let mut cursor = type_node.walk();
            type_node
                .named_children(&mut cursor)
                .find_map(|child| constructor_return_kind_from_type_node(child, ctx))
        }
        _ => None,
    }
}

fn function_return_type_node(function: Node<'_>) -> Option<Node<'_>> {
    if let Some(return_type) = function.child_by_field_name("return_type") {
        return Some(return_type);
    }

    let parameters = function.child_by_field_name("parameters")?;
    let body = function.child_by_field_name("body");
    let mut cursor = function.walk();
    function
        .named_children(&mut cursor)
        .filter(|child| child.start_byte() >= parameters.end_byte())
        .filter(|child| body.is_none_or(|body| !same_node(*child, body)))
        .find(|child| is_rust_type_node(*child))
}

fn type_node_matches_constructor_owner(
    type_node: Node<'_>,
    ctx: &ConstructorReturnCtx<'_>,
) -> bool {
    if simple_node_text(type_node, ctx.source).as_deref() == Some("Self") {
        return true;
    }
    constructor_type_node_fqn(type_node, ctx)
        .as_deref()
        .is_some_and(|fqn| fqn_matches_owner(ctx.rust, ctx.token, ctx.support, fqn, ctx.owner))
}

fn constructor_type_node_fqn(
    type_node: Node<'_>,
    ctx: &ConstructorReturnCtx<'_>,
) -> Option<String> {
    let refs = ctx.rust.reference_context_of(ctx.token, ctx.file);

    match type_node.kind() {
        "type_identifier" | "identifier" => {
            let name = simple_node_text(type_node, ctx.source)?;
            refs.resolve_bare(&name)
        }
        "scoped_type_identifier" | "scoped_identifier" => {
            let path = type_node
                .child_by_field_name("path")
                .and_then(|path| simple_node_text(path, ctx.source))?;
            let name = type_node
                .child_by_field_name("name")
                .and_then(|name| simple_node_text(name, ctx.source))?;
            refs.resolve_scoped(&path, &name)
        }
        "generic_type" => type_node
            .child_by_field_name("type")
            .and_then(|base| constructor_type_node_fqn(base, ctx)),
        "reference_type" | "pointer_type" => {
            let mut cursor = type_node.walk();
            type_node
                .named_children(&mut cursor)
                .find_map(|child| constructor_type_node_fqn(child, ctx))
        }
        _ => None,
    }
}

fn self_like_constructor_seeds(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    constructor_returns: &HashMap<String, SelfLikeConstructor>,
) -> HashMap<String, RustBindingSeeds> {
    constructor_returns
        .iter()
        .map(|(name, constructor)| {
            let roots = BTreeSet::from([constructor.declaration.clone()]);
            let seeds = usage_binding_seeds(rust, token, &roots);
            (name.clone(), seeds)
        })
        .collect()
}

fn visible_bare_constructor_names(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    constructors: &HashMap<String, RustBindingSeeds>,
) -> HashSet<String> {
    let mut visible = HashSet::default();
    for (constructor, seeds) in constructors {
        let (direct_names, _) = usage_binding_names(rust, token, file, seeds);
        if direct_names.contains(constructor)
            || seeds
                .identities_in_file(file)
                .any(|identity| identity.name() == constructor)
        {
            visible.insert(constructor.clone());
        }
    }
    visible
}

fn expanded_receiver_type_names(
    root: Node<'_>,
    source: &str,
    owner_local_names: &HashSet<String>,
    cancellation: Option<&CancellationToken>,
) -> HashSet<String> {
    let mut owner_type_names = owner_local_names.clone();
    let aliases = collect_type_aliases(root, source, cancellation);

    loop {
        let mut changed = false;
        for (alias, target) in &aliases {
            if owner_type_names.contains(target) && owner_type_names.insert(alias.clone()) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    owner_type_names
}

fn receiver_explicitly_mismatched(
    file_root: Node<'_>,
    file_source: &str,
    enclosing_source: &str,
    owner_local_names: &HashSet<String>,
    receiver_name: &str,
    cancellation: Option<&CancellationToken>,
) -> bool {
    let owner_type_names =
        expanded_receiver_type_names(file_root, file_source, owner_local_names, cancellation);
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return false;
    }
    let Some(tree) = parse_rust_source(enclosing_source) else {
        return false;
    };

    for (name, ty) in
        collect_explicit_receiver_annotations(tree.root_node(), enclosing_source, cancellation)
    {
        if name == receiver_name {
            return ty.as_ref().is_none_or(|ty| !owner_type_names.contains(ty));
        }
    }

    false
}

fn infer_receiver_names(
    root: Node<'_>,
    source: &str,
    owner_local_names: &HashSet<String>,
    self_like_constructors: &HashMap<String, SelfLikeConstructor>,
    visible_bare_constructors: &HashSet<String>,
    cancellation: Option<&CancellationToken>,
) -> Vec<String> {
    let owner_type_names =
        expanded_receiver_type_names(root, source, owner_local_names, cancellation);
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Vec::new();
    }
    let bindings = collect_receiver_bindings(
        root,
        source,
        &owner_type_names,
        self_like_constructors,
        visible_bare_constructors,
        cancellation,
    );
    let mut receivers: Vec<_> = bindings
        .snapshot()
        .matching_symbols(|target| owner_type_names.contains(target))
        .into_iter()
        .collect();
    receivers.sort();
    receivers
}

#[allow(clippy::too_many_arguments)]
fn resolved_owner_receiver_names(
    root: Node<'_>,
    token: QueryToken<'_>,
    source: &str,
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    owner: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> Vec<String> {
    let mut receivers = Vec::new();
    let mut stack = vec![root];
    let mut cancellation_checks_remaining = 0;
    while let Some(node) = stack.pop() {
        if periodic_cancellation_requested(cancellation, &mut cancellation_checks_remaining) {
            break;
        }
        if matches!(node.kind(), "parameter" | "let_declaration")
            && let Some(pattern) = node.child_by_field_name("pattern")
            && let Some(name) = simple_pattern_name(pattern, source)
            && let Some(type_node) = node.child_by_field_name("type")
            && rust_resolve_type_node_fqn(
                analyzer,
                token,
                support,
                file,
                source,
                type_node,
                Some(type_node.start_byte()),
            )
            .is_some_and(|fqn| fqn_matches_owner(rust, token, support, &fqn, owner))
        {
            receivers.push(name);
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    receivers
}

fn collect_receiver_bindings(
    root: Node<'_>,
    source: &str,
    owner_type_names: &HashSet<String>,
    self_like_constructors: &HashMap<String, SelfLikeConstructor>,
    visible_bare_constructors: &HashSet<String>,
    cancellation: Option<&CancellationToken>,
) -> LocalInferenceEngine<String> {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());

    // A stable owner-type name to seed receivers whose owner type is known only
    // indirectly (a function whose return type is the owner). Any element of
    // `owner_type_names` matches in `infer_receiver_names`, so pick deterministically.
    let owner_repr = owner_type_names.iter().min().cloned();

    let option_field_types = collect_option_field_types(root, source, cancellation);
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return engine;
    }
    let mut aliases = Vec::new();
    for event in collect_receiver_events(root, source, &option_field_types, cancellation) {
        match event {
            ReceiverEvent::TypedBinding { name, ty } => {
                if owner_type_names.contains(&ty) {
                    engine.seed_symbol(name, ty);
                }
            }
            ReceiverEvent::Constructed {
                name,
                ty,
                constructor,
                unwrapped,
            } => match constructor {
                // `Owner::new(...)` / tuple-struct `Owner(...)`: the path text is the
                // owner type and (for the scoped form) the associated fn must return it.
                Some(ctor) => {
                    if owner_type_names.contains(&ty)
                        && self_like_constructors
                            .get(&ctor)
                            .is_some_and(|constructor| {
                                constructor_return_can_seed(constructor.return_kind, unwrapped)
                            })
                    {
                        engine.seed_symbol(name, ty);
                    }
                }
                None if owner_type_names.contains(&ty) => {
                    engine.seed_symbol(name, ty);
                }
                // `let x = build_owner();` — a bare call to a free or associated
                // function whose return type is the owner. Seed the receiver's type so
                // method/field accesses on it resolve.
                None if visible_bare_constructors.contains(&ty)
                    && self_like_constructors.get(&ty).is_some_and(|constructor| {
                        constructor_return_can_seed(constructor.return_kind, unwrapped)
                    }) =>
                {
                    if let Some(owner_repr) = owner_repr.clone() {
                        engine.seed_symbol(name, owner_repr);
                    }
                }
                None => {}
            },
            ReceiverEvent::Alias { name, source } => aliases.push((name, source)),
        }
    }
    engine.apply_aliases_until_stable(aliases);

    engine
}

fn constructor_return_can_seed(kind: ConstructorReturn, unwrapped: bool) -> bool {
    kind == ConstructorReturn::DirectReceiver || unwrapped
}

enum ReceiverEvent {
    TypedBinding {
        name: String,
        ty: String,
    },
    Constructed {
        name: String,
        ty: String,
        constructor: Option<String>,
        unwrapped: bool,
    },
    Alias {
        name: String,
        source: String,
    },
}

fn parse_rust_source(source: &str) -> Option<Tree> {
    if source.trim().is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn collect_type_aliases(
    root: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Vec<(String, String)> {
    let mut aliases = Vec::new();
    let mut stack = vec![root];
    let mut cancellation_checks_remaining = 0;
    while let Some(node) = stack.pop() {
        if periodic_cancellation_requested(cancellation, &mut cancellation_checks_remaining) {
            break;
        }
        if node.kind() == "type_item"
            && let (Some(alias), Some(target)) = (
                node.child_by_field_name("name")
                    .and_then(|name| simple_node_text(name, source)),
                node.child_by_field_name("type")
                    .and_then(|ty| simple_type_name(ty, source)),
            )
        {
            aliases.push((alias, target));
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    aliases
}

fn collect_explicit_receiver_annotations(
    root: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Vec<(String, Option<String>)> {
    let mut bindings = Vec::new();
    let mut stack = vec![root];
    let mut cancellation_checks_remaining = 0;
    while let Some(node) = stack.pop() {
        if periodic_cancellation_requested(cancellation, &mut cancellation_checks_remaining) {
            break;
        }
        match node.kind() {
            "parameter" | "let_declaration" => {
                if let Some((name, ty)) = explicit_receiver_annotation(node, source) {
                    bindings.push((name, ty));
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    bindings
}

fn collect_option_field_types(
    root: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> HashMap<String, String> {
    let mut fields = HashMap::default();
    let mut stack = vec![root];
    let mut cancellation_checks_remaining = 0;
    while let Some(node) = stack.pop() {
        if periodic_cancellation_requested(cancellation, &mut cancellation_checks_remaining) {
            break;
        }
        if node.kind() == "field_declaration"
            && let (Some(name), Some(ty)) = (
                node.child_by_field_name("name")
                    .and_then(|name| simple_node_text(name, source)),
                node.child_by_field_name("type")
                    .and_then(|ty| option_inner_type_name(ty, source)),
            )
        {
            fields.insert(name, ty);
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    fields
}

fn collect_receiver_events(
    root: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
    cancellation: Option<&CancellationToken>,
) -> Vec<ReceiverEvent> {
    let mut events = Vec::new();
    let mut stack = vec![root];
    let mut cancellation_checks_remaining = 0;
    while let Some(node) = stack.pop() {
        if periodic_cancellation_requested(cancellation, &mut cancellation_checks_remaining) {
            break;
        }
        match node.kind() {
            "parameter" => {
                if let Some((name, ty)) = typed_parameter_binding(node, source) {
                    events.push(ReceiverEvent::TypedBinding { name, ty });
                }
            }
            "let_declaration" => {
                collect_let_receiver_event(node, source, option_field_types, &mut events)
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    events
}

fn collect_let_receiver_event(
    node: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
    events: &mut Vec<ReceiverEvent>,
) {
    if let Some((name, ty)) = typed_let_binding(node, source) {
        events.push(ReceiverEvent::TypedBinding { name, ty });
        return;
    }

    if let Some((name, ty)) = self_field_as_ref_let_else_binding(node, source, option_field_types) {
        events.push(ReceiverEvent::TypedBinding { name, ty });
        return;
    }

    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(name) = simple_pattern_name(pattern, source) else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };

    if let Some((ty, constructor, unwrapped)) = constructed_receiver_type(value, source) {
        events.push(ReceiverEvent::Constructed {
            name,
            ty,
            constructor,
            unwrapped,
        });
    } else if let Some(source) = simple_node_text(value, source) {
        events.push(ReceiverEvent::Alias { name, source });
    }
}

fn typed_parameter_binding(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let name = node
        .child_by_field_name("pattern")
        .and_then(|pattern| simple_pattern_name(pattern, source))?;
    let ty = node
        .child_by_field_name("type")
        .and_then(|ty| simple_type_name(ty, source))?;
    Some((name, ty))
}

fn typed_let_binding(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let name = node
        .child_by_field_name("pattern")
        .and_then(|pattern| simple_pattern_name(pattern, source))?;
    let ty = node
        .child_by_field_name("type")
        .and_then(|ty| simple_type_name(ty, source))?;
    Some((name, ty))
}

fn explicit_receiver_annotation(node: Node<'_>, source: &str) -> Option<(String, Option<String>)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = simple_pattern_name(pattern, source)?;
    let ty = node.child_by_field_name("type")?;
    Some((name, direct_receiver_type_name(ty, source)))
}

fn direct_receiver_type_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = simple_type_name(node, source) {
        return Some(name);
    }
    if node.kind() != "reference_type" {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(|child| direct_receiver_type_name(child, source))
}

fn self_field_as_ref_let_else_binding(
    node: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
) -> Option<(String, String)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = some_tuple_pattern_name(pattern, source)?;
    let value = node.child_by_field_name("value")?;
    let field_name = self_field_as_ref_field_name(value, source)?;
    let ty = option_field_types.get(&field_name)?.clone();
    Some((name, ty))
}

fn some_tuple_pattern_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "tuple_struct_pattern" {
        return None;
    }
    let type_name = node
        .child_by_field_name("type")
        .and_then(|ty| simple_node_text(ty, source))?;
    if type_name != "Some" {
        return None;
    }
    let type_id = node.child_by_field_name("type").map(|ty| ty.id());
    let mut cursor = node.walk();
    let identifiers: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier" && Some(child.id()) != type_id)
        .filter_map(|child| simple_node_text(child, source))
        .collect();
    (identifiers.len() == 1).then(|| identifiers[0].clone())
}

fn self_field_as_ref_field_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "field_expression" {
        return None;
    }
    if function
        .child_by_field_name("field")
        .and_then(|field| simple_node_text(field, source))
        .as_deref()
        != Some("as_ref")
    {
        return None;
    }
    let receiver = function.child_by_field_name("value")?;
    if receiver.kind() != "field_expression" {
        return None;
    }
    if receiver
        .child_by_field_name("value")
        .is_some_and(|value| value.kind() == "self")
    {
        receiver
            .child_by_field_name("field")
            .and_then(|field| simple_node_text(field, source))
    } else {
        None
    }
}

fn constructed_receiver_type(
    node: Node<'_>,
    source: &str,
) -> Option<(String, Option<String>, bool)> {
    match node.kind() {
        "struct_expression" => node
            .child_by_field_name("name")
            .and_then(|name| simple_type_name(name, source))
            .map(|name| (name, None, false)),
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "identifier" | "type_identifier" => {
                    simple_node_text(function, source).map(|name| (name, None, false))
                }
                "scoped_identifier" => {
                    let ty = function
                        .child_by_field_name("path")
                        .and_then(|path| simple_type_name(path, source))?;
                    let constructor = function
                        .child_by_field_name("name")
                        .and_then(|name| simple_node_text(name, source));
                    Some((ty, constructor, false))
                }
                "field_expression" => {
                    let method = function
                        .child_by_field_name("field")
                        .and_then(|field| simple_node_text(field, source));
                    let unwrapped = matches!(method.as_deref(), Some("unwrap" | "expect"));
                    function
                        .child_by_field_name("value")
                        .and_then(|value| constructed_receiver_type(value, source))
                        .map(|(ty, constructor, inner_unwrapped)| {
                            (ty, constructor, inner_unwrapped || unwrapped)
                        })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn option_inner_type_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "generic_type" {
        return None;
    }
    if node
        .child_by_field_name("type")
        .and_then(|ty| simple_node_text(ty, source))
        .as_deref()
        != Some("Option")
    {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() != "type_identifier")
        .find_map(|child| first_simple_type_name(child, source))
}

fn first_simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = simple_type_name(node, source) {
        return Some(name);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(|child| first_simple_type_name(child, source))
}

fn simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    matches!(node.kind(), "type_identifier" | "identifier")
        .then(|| simple_node_text(node, source))
        .flatten()
}

fn simple_pattern_name(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "identifier")
        .then(|| simple_node_text(node, source))
        .flatten()
}

/// Same identifier-kind-gated `r#` stripping as `rust_graph::hits::node_text`
/// (#1128): usage-side member/reference text must agree with normalized
/// declaration names.
fn simple_node_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = crate::analyzer::common::node_ident_text(
        node,
        source,
        true,
        &crate::analyzer::common::RUST_IDENTIFIER_SIGIL,
    );
    (!text.is_empty()).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::QueryScope;
    use crate::analyzer::{AnalyzerQueryScope, Language, TestProject};
    use std::sync::Arc;

    // Issue #1750: `Mismatches` refuses a call site outright: it records nothing, not
    // even an unproven candidate, so `scan_usages` reports `verified_absent`. That
    // certainty must rest on evidence. A receiver type that resolved to no indexed
    // declaration is an unresolved name, not a proven foreign owner.
    #[test]
    fn issue_1750_receiver_verdict_needs_evidence_to_refuse_a_site() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(
            root.join("lib.rs"),
            "pub struct Other;\npub type Alias = Other;\n",
        )
        .unwrap();
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let unit = |fq_name: &str| {
            analyzer
                .get_definitions(fq_name)
                .into_iter()
                .next()
                .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
        };

        assert!(
            matches!(
                foreign_receiver_verdict(&analyzer, &[unit("Other")]),
                ReceiverOwnerProof::Mismatches
            ),
            "a receiver resolved to a real foreign declaration refuses the site"
        );
        assert!(
            matches!(
                foreign_receiver_verdict(&analyzer, &[unit("Alias")]),
                ReceiverOwnerProof::Unknown
            ),
            "an alias hides the declaration it stands for, so it cannot refuse the site"
        );
        assert!(
            matches!(
                foreign_receiver_verdict(&analyzer, &[]),
                ReceiverOwnerProof::Unknown
            ),
            "an empty resolution is no evidence at all and must not refuse the site"
        );
    }

    #[test]
    fn scan_parses_each_candidate_once_within_query_scope() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("lib.rs"), "pub fn target() {}\n").unwrap();
        let file = ProjectFile::new(root.clone(), "lib.rs");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let scope = AnalyzerQueryScope::new(&analyzer);

        let first = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("first prepared syntax");
        let second = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("reused prepared syntax");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    #[test]
    fn issue_1228_receiver_event_walk_stops_before_late_bindings_after_cancellation() {
        let mut source = String::from("struct Owner;\nfn scan() {\n");
        for index in 0..400 {
            source.push_str(&format!("let filler_{index} = {index};\n"));
        }
        source.push_str("let late: Owner = Owner;\n}\n");
        let tree = parse_rust_source(&source).expect("parse receiver fixture");
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);

        let events = collect_receiver_events(
            tree.root_node(),
            &source,
            &HashMap::default(),
            Some(&cancellation),
        );

        assert!(cancellation.is_cancelled());
        assert!(
            !events.iter().any(
                |event| matches!(event, ReceiverEvent::TypedBinding { name, .. } if name == "late")
            ),
            "nodes after cancellation must not participate in receiver inference"
        );
    }
}
