//! The analysis-side half of the JS/TS export-usage reference graph.
//!
//! The scan itself -- the per-file forward walk, the resolution index, the
//! receiver-facts index and the per-file inverted walks -- moved to
//! [`brokk_bifrost_js_ts::graph`]. What stays here is everything that needs an
//! analyzer handle:
//!
//! - the two `resolve_analyzer::<{Typescript,Javascript}Analyzer>` downcasts
//!   ([`cached_jsts_index`], [`prewarm_cached_jsts_index`]) and the `JsTsHosts`
//!   view the whole-workspace builders are handed;
//! - the inverted pass's fan-out -- `build_edge_output`, `build_edge_weights`,
//!   `parse_and_collect` and `collect_file_edges`, which are analysis-owned --
//!   driving the crate's per-file scans;
//! - the SPI surface: `UsageQueryResolver`, `GraphUsageAnalyzer` and
//!   `UsageAnalyzer` on [`JsTsExportUsageGraphStrategy`].
//!
//! Both dialects run through one strategy and one `EdgePassId`: the builders
//! below walk TypeScript and JavaScript in one pass and merge, which is why they
//! take the host view rather than a single host.

/// The receiver-facts factory the registry hands the receiver query, and the
/// resolution/receiver indices, re-exported at the paths their framework callers
/// already use.
pub(crate) use crate::analyzer::js_ts::receiver_facts::JsTsReceiverFacts;
pub(in crate::analyzer::usages) use brokk_bifrost_js_ts::graph::receiver_analysis::{
    JsTsReceiverFactProvider, JsTsReceiverSyntaxIndex, build_js_ts_receiver_syntax_index,
};
pub(crate) use brokk_bifrost_js_ts::graph::resolver::JsTsUsageIndex;
pub(in crate::analyzer::usages) use brokk_bifrost_js_ts::graph::resolver::{
    browser_global_property_shape, unbound_browser_global_property,
};
pub(in crate::analyzer::usages) use brokk_bifrost_js_ts::syntax::compute_import_binder as compute_jsts_import_binder;

use crate::analyzer::js_ts::providers::resolve_js_ts_source;
use crate::analyzer::usages::common::analyzed_files_for_language;
use crate::analyzer::usages::inverted_edges::{
    CallSite, JsTsScopedNodeStatus, JsTsScopedUsageEdges, UsageEdgeBuildOutput, UsageEdgeWeights,
    UsageEdges, UsageNodeKey, build_edge_output, build_edge_weights, collect_file_edges,
    parse_and_collect,
};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{
    CandidateUsageHits, GraphFailureReason, GraphUsageOutcome, union_candidate_usages,
};
use crate::analyzer::usages::parsed_tree::parse_tree_sitter_file;
use crate::analyzer::usages::traits::{
    GraphUsageAnalyzer, UsageAnalyzer, UsageQueryResolver, UsageScanScope,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, JavascriptAnalyzer, Language, ProjectFile, TypescriptAnalyzer,
    resolve_analyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use brokk_bifrost_js_ts::graph::resolver::{combine_jsts_usage_indices, target_language};
use brokk_bifrost_js_ts::graph::{JsTsHosts, inverted, scan_js_ts_target_usages};
use brokk_bifrost_js_ts::parse::{js_ts_tree_sitter_language_for_file, tree_sitter_language_for};
use brokk_bifrost_js_ts::providers::JsTsSource;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The two dialects, in the order every whole-workspace pass walks them.
const JS_TS_LANGUAGES: [Language; 2] = [Language::TypeScript, Language::JavaScript];

/// The strategy name every JS/TS usage diagnostic reports.
const JS_TS_STRATEGY: &str = "JsTsExportUsageGraphStrategy";

/// Resolve both dialects' analyzers once for a whole-workspace pass.
///
/// The crate cannot name `JavascriptAnalyzer` or `TypescriptAnalyzer`, so the
/// downcasts happen here and the resulting view crosses -- the `JvmSourceRealm`
/// shape.
fn js_ts_hosts(analyzer: &dyn IAnalyzer) -> JsTsHosts<'_> {
    JsTsHosts::new(
        JS_TS_LANGUAGES
            .into_iter()
            .filter_map(|language| {
                resolve_js_ts_source(analyzer, language)
                    .map(|host| (language, host as &dyn JsTsSource))
            })
            .collect(),
    )
}

/// Build the whole JS/TS `caller -> callee` edge set in a single inverted pass per
/// language present, merging TypeScript and JavaScript. Returns `None` when the
/// workspace has no JS/TS files. `nodes`/`keep_file` mirror the Go builder.
pub(crate) fn build_jsts_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = JsTsEdgeResolver::try_new(analyzer)?;
    for language in JS_TS_LANGUAGES {
        if !analyzed_files_for_language(analyzer, language).is_empty() {
            let _ = prewarm_cached_jsts_index(analyzer, language);
        }
    }
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

/// Borrow the analyzer-cached [`JsTsUsageIndex`] for `language` off the concrete TS/JS
/// analyzer behind `analyzer`, building it on first use. `None` when the analyzer does
/// not expose the matching JS/TS analyzer, or when a cancellation token fires mid-build.
///
/// The downcasting half of the pair: framework callers that hold only a
/// `&dyn IAnalyzer` (the definition trace, the dead-code pass, the edge builders)
/// come through here. Everything already holding a `JsTsSource` calls
/// `JsTsSource::usage_index` directly.
pub(crate) fn cached_jsts_index(
    analyzer: &dyn IAnalyzer,
    language: Language,
    cancellation: Option<&CancellationToken>,
) -> Option<Arc<JsTsUsageIndex>> {
    resolve_js_ts_source(analyzer, language)?.usage_index(cancellation)
}

pub(in crate::analyzer::usages) fn prewarm_cached_jsts_index(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Option<Arc<JsTsUsageIndex>> {
    match language {
        Language::TypeScript => {
            Some(resolve_analyzer::<TypescriptAnalyzer>(analyzer)?.prewarm_jsts_usage_index())
        }
        Language::JavaScript => {
            Some(resolve_analyzer::<JavascriptAnalyzer>(analyzer)?.prewarm_jsts_usage_index())
        }
        _ => None,
    }
}

/// JS/TS resolves usages off the project file set rather than a single concrete
/// analyzer — it spans the TypeScript and JavaScript analyzers — so these resolvers
/// hold no borrowed analyzer in this form.
pub(crate) struct JsTsQueryResolver;

impl<'a> UsageQueryResolver<'a> for JsTsQueryResolver {
    fn try_new(_analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self)
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let cancellation = scan_scope.cancellation();
        // One host and resolution index per dialect, resolved the first time a
        // candidate needs it: a target group can hold a TypeScript and a
        // JavaScript declaration of the same name, and each is scanned against
        // its own dialect's index. The index itself is analyzer-cached, so the
        // repeat lookups a multi-candidate group makes are map hits.
        let mut hosts: Vec<(Language, &dyn JsTsSource, Arc<JsTsUsageIndex>)> = Vec::new();
        union_candidate_usages(overloads, max_usages, |target| {
            let language = target_language(target);
            if language == Language::None {
                return Err(
                    GraphFailureReason::UnsupportedTargetLanguage("target is not JS/TS")
                        .diagnostic(target.fq_name(), JS_TS_STRATEGY),
                );
            }
            if !hosts.iter().any(|(dialect, _, _)| *dialect == language) {
                let resolved = resolve_js_ts_source(analyzer, language)
                    .and_then(|host| host.usage_index(cancellation).map(|index| (host, index)));
                let Some((host, index)) = resolved else {
                    if cancellation.is_some_and(CancellationToken::is_cancelled) {
                        // The scan stopped mid-flight; the group keeps whatever
                        // the candidates scanned before the token tripped.
                        return Ok(CandidateUsageHits::default());
                    }
                    return Err(GraphFailureReason::MissingAnalyzerCapability(
                        "analyzer does not expose a JS/TS analyzer",
                    )
                    .diagnostic(target.fq_name(), JS_TS_STRATEGY));
                };
                hosts.push((language, host, index));
            }
            let (_, host, index) = hosts
                .iter()
                .find(|(dialect, _, _)| *dialect == language)
                .expect("host for this dialect was just resolved");
            Ok(scan_js_ts_target_usages(
                *host,
                analyzer,
                index.as_ref(),
                target,
                scan_scope,
                language,
            ))
        })
    }
}

pub(crate) struct JsTsEdgeResolver;

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzers once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl JsTsEdgeResolver {
    pub(crate) fn try_new(analyzer: &dyn IAnalyzer) -> Option<Self> {
        let has_jsts = JS_TS_LANGUAGES
            .iter()
            .any(|language| !analyzed_files_for_language(analyzer, *language).is_empty());
        has_jsts.then_some(Self)
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
        let hosts = js_ts_hosts(analyzer);
        let mut edges: BTreeMap<(String, String), Vec<CallSite>> = BTreeMap::new();
        let mut truncated: BTreeMap<String, usize> = BTreeMap::new();
        let mut unproven_inbound: BTreeMap<String, usize> = BTreeMap::new();

        for language in JS_TS_LANGUAGES {
            if analyzed_files_for_language(analyzer, language).is_empty() {
                continue;
            }
            let result: UsageEdges =
                build_jsts_edges(analyzer, &hosts, language, nodes, &keep_file);
            for (key, sites) in result.edges {
                edges.entry(key).or_default().extend(sites);
            }
            for (callee, total) in result.truncated {
                *truncated.entry(callee).or_insert(0) += total;
            }
            for (callee, total) in result.unproven_inbound {
                *unproven_inbound.entry(callee).or_insert(0) += total;
            }
        }

        // TS and JS are distinct files, so per-language sites for a shared edge key
        // never overlap; re-sort after concatenating the two runs for determinism.
        for sites in edges.values_mut() {
            sites.sort();
        }

        UsageEdges {
            edges,
            truncated,
            unproven_inbound,
        }
    }
}

/// The non-scoped inverted pass for one dialect: the analysis-owned parallel
/// fan-out over files, driving [`inverted::scan_file`] per file.
fn build_jsts_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    hosts: &JsTsHosts<'_>,
    language: Language,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String> + Default,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    if tree_sitter_language_for(language).is_none() {
        return Output::default();
    }
    let _index = cached_jsts_index(analyzer, language, None);
    // Resolved once for the whole scan; the per-file receiver provider is on the
    // JS/TS host. No analyzer for `language` means no JS/TS files to scan either.
    let Some(host) = hosts.get(language) else {
        return Output::default();
    };
    let files = analyzed_files_for_language(analyzer, language);
    build_edge_output(&files, keep_file, |file| {
        // The non-scoped scan needs only the file's own tree for its main binder +
        // declaration pass. Receiver analysis can consult the analyzer-cached
        // resolution index, so it is pre-materialized before this parallel scan.
        let parser_language = js_ts_tree_sitter_language_for_file(file, language)?;
        parse_and_collect(analyzer, file, nodes, &parser_language, |input| {
            inverted::scan_file(host, analyzer, language, file, nodes, input)
        })
    })
}

/// Build the whole JS/TS `caller -> callee` edge set using file-scoped node
/// identity, so same-name exports in different files do not cross-match.
pub(crate) fn build_jsts_scoped_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<UsageNodeKey>,
    keep_file: F,
) -> Option<JsTsScopedUsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync + Copy,
{
    let hosts = js_ts_hosts(analyzer);
    let mut edges = BTreeMap::new();
    let mut truncated: BTreeMap<UsageNodeKey, usize> = BTreeMap::new();
    let mut unproven_inbound: BTreeMap<UsageNodeKey, usize> = BTreeMap::new();
    let mut node_status: BTreeMap<UsageNodeKey, JsTsScopedNodeStatus> = BTreeMap::new();
    let mut any = false;

    let mut cached_indices = Vec::new();
    for language in JS_TS_LANGUAGES {
        if let Some(index) = cached_jsts_index(analyzer, language, None) {
            cached_indices.push(index);
        }
    }
    // No JS/TS analyzer means no analyzed files for either dialect either, so
    // `any` would stay false and this would return `None` regardless.
    let aliases = hosts.alias_resolver()?;
    let combined_index = combine_jsts_usage_indices(
        aliases,
        cached_indices.iter().map(std::convert::AsRef::as_ref),
    );

    for language in JS_TS_LANGUAGES {
        if analyzed_files_for_language(analyzer, language).is_empty() {
            continue;
        }
        any = true;
        if nodes.is_empty() {
            continue;
        }
        let result = build_jsts_scoped_edges(
            analyzer,
            &hosts,
            &combined_index,
            language,
            nodes,
            keep_file,
        );
        for (key, weight) in result.edges.edges {
            *edges.entry(key).or_default() += weight;
        }
        for (callee, total) in result.edges.truncated {
            *truncated.entry(callee).or_insert(0) += total;
        }
        for (callee, total) in result.edges.unproven_inbound {
            *unproven_inbound.entry(callee).or_insert(0) += total;
        }
        node_status.extend(result.node_status);
    }

    any.then_some(JsTsScopedUsageEdges {
        edges: UsageEdgeWeights {
            edges,
            truncated,
            unproven_inbound,
        },
        node_status,
    })
}

/// The scoped inverted pass for one dialect, with the fan-out on this side.
fn build_jsts_scoped_edges<F>(
    analyzer: &dyn IAnalyzer,
    hosts: &JsTsHosts<'_>,
    index: &JsTsUsageIndex,
    language: Language,
    nodes: &HashSet<UsageNodeKey>,
    keep_file: F,
) -> JsTsScopedUsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let empty = || JsTsScopedUsageEdges {
        edges: UsageEdgeWeights::default(),
        node_status: BTreeMap::new(),
    };
    if tree_sitter_language_for(language).is_none() {
        return empty();
    }
    // Resolved once for the whole scan; see `build_jsts_edges` above.
    let Some(host) = hosts.get(language) else {
        return empty();
    };
    let files = analyzed_files_for_language(analyzer, language);
    // The declaration map spans both dialects: a scoped edge set merges TypeScript
    // and JavaScript, and a JS file can import a name a TS file declares.
    let prep = inverted::prepare_scoped_scan(analyzer, index, nodes);
    let edges = build_edge_weights(&files, keep_file, |file| {
        // Parse on demand and drop the tree when this closure returns; cross-file
        // resolution comes from the analyzer-cached `index`, not retained trees.
        let parser_language = js_ts_tree_sitter_language_for_file(file, language)?;
        let parsed = parse_tree_sitter_file(file, &parser_language)?;
        let file_prep = inverted::prepare_scoped_file(
            &prep,
            analyzer,
            file,
            language,
            parsed.tree.root_node(),
            parsed.source.as_str(),
        );
        Some(collect_file_edges(
            analyzer,
            file,
            nodes,
            &parsed,
            |input| {
                inverted::scan_scoped_file(host, index, &prep, file_prep, language, file, input)
            },
        ))
    });
    JsTsScopedUsageEdges {
        edges,
        node_status: prep.node_status,
    }
}

/// JS/TS export-graph usage analyzer. Resolves usages of a JavaScript or TypeScript
/// `CodeUnit` by walking the export/import graph rather than scanning text.
///
/// Stateless: rebuilds its project graph per query.
#[derive(Default)]
pub struct JsTsExportUsageGraphStrategy;

impl JsTsExportUsageGraphStrategy {
    pub const fn new() -> Self {
        Self
    }

    /// Returns true when the target is a JavaScript or TypeScript code unit and lives in
    /// a file the graph can analyze.
    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) != Language::None
    }
}

impl GraphUsageAnalyzer for JsTsExportUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(resolver) = JsTsQueryResolver::try_new(analyzer) else {
            let fq_name = overloads.first().map(CodeUnit::fq_name).unwrap_or_default();
            return GraphUsageOutcome::fallback_safe(
                fq_name,
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose a JS/TS analyzer",
                ),
                JS_TS_STRATEGY,
            );
        };
        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

impl UsageAnalyzer for JsTsExportUsageGraphStrategy {
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
