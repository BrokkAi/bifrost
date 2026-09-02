//! `score_diff`: a deterministic maintainability feature vector for a revision
//! range.
//!
//! [`diff_analysis`](crate::diff_analysis) answers *what changed*. This module
//! answers *how hard the change is to live with*, from four groups of raw,
//! unweighted features derived from that same change model:
//!
//! - **geometry** -- how many symbols moved and how far apart the edits sit,
//! - **coordination** -- how much untouched code has to agree with the change,
//! - **verification** -- which changed production symbols no test references,
//! - **baseline** -- cognitive complexity before and after, for comparison.
//!
//! There is deliberately no weighting and no scalar score. No validated
//! weighting exists yet, and shipping an invented one would repeat the mistake
//! the cognitive-complexity metric made. A consumer weights these itself.
//!
//! Every degradation is counted rather than dropped: binary and unparseable
//! files land in [`ExcludedFiles`], and a symbol whose references could not be
//! resolved lands in [`VerificationFeatures::unresolved_symbols`].

use crate::analyzer::{DispatchExtensibility, IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::diff_analysis::{
    AnalyzedDiff, CommitSymbol, DiffAnalysisOptions, DiffEndpointParams, DiffEndpoints,
    EndpointAnalysis, FileChange, ImportExpansionTarget, PatchSymbols, PreparedDiff,
    analyze_prepared_diff_with_endpoints, path_language, path_string, primary_range,
    resolved_imports_of,
};
use crate::searchtools::{
    ScanUsagesByLocationParams, ScanUsagesEntry, ScanUsagesInput, ScanUsagesStatus,
    ScanUsagesTarget, is_test_like_file, scan_usages_by_location_with_cancellation,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Parameters for `score_diff`.
///
/// The endpoint resolution table is [`AnalyzeDiffParams`]', which this delegates
/// to unchanged: `{}` is HEAD against the working tree, `{target: X}` is a
/// commit against its first parent, and both spelled out is the plain range.
///
/// There is no `include_tests` knob. Verification asks whether a test
/// references a changed symbol, which is only answerable when test files are in
/// scope, so excluding them would silently turn every symbol untested.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScoreDiffParams {
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffScoreResult {
    pub endpoints: DiffEndpoints,
    pub geometry: GeometryFeatures,
    pub coordination: CoordinationFeatures,
    pub verification: VerificationFeatures,
    pub baseline: BaselineFeatures,
    pub excluded: ExcludedFiles,
}

/// How much of the codebase the patch touches, and how spread out those touches
/// are.
#[derive(Debug, Clone, Serialize)]
pub struct GeometryFeatures {
    pub edited_symbols: usize,
    pub introduced_symbols: usize,
    pub deleted_symbols: usize,
    pub moved_symbols: usize,
    pub signature_changes: usize,
    pub production_files_changed: usize,
    pub test_files_changed: usize,
    pub directories_changed: usize,
    /// Connected components over the changed production files, where two files
    /// are connected when they share a directory or one imports the other in
    /// the target revision. One cluster means the patch is locally contained;
    /// several mean it is several separate edits that must land together.
    pub edit_clusters: usize,
    /// Mean pairwise directory distance between changed production files:
    /// components up plus components down between their two directories. Zero
    /// when fewer than two production files changed.
    pub mean_directory_distance: f64,
    pub max_directory_distance: usize,
    pub insertions: usize,
    pub deletions: usize,
}

/// What untouched code has to agree with for the patch to be correct.
#[derive(Debug, Clone, Serialize)]
pub struct CoordinationFeatures {
    /// Reference sites, across the whole target revision, for symbols whose
    /// signature changed, counting only sites in files the diff did not touch.
    pub signature_change_external_caller_sites: usize,
    pub max_external_callers_per_signature_change: usize,
    /// Per signature change, complete rather than summarized: a consumer
    /// deciding whether a change is safe needs to see which callers, not only
    /// how many.
    pub external_callers_by_signature_change: Vec<SignatureChangeCallers>,
    /// Total weight of call edges patch symbols gained, over the edited, moved
    /// and introduced records.
    pub added_call_weight: usize,
    /// Total weight of call edges patch symbols lost, over the edited, moved
    /// and deleted records.
    pub removed_call_weight: usize,
    /// Call-edge changes `analyze_diff` could not attribute to any patch
    /// symbol. High values mean the patch moved resolution under untouched
    /// code, which is an opacity signal, not a size signal.
    pub unattributed_call_edge_changes: usize,
    /// Edited symbols whose signature metadata publishes `dispatch_extensibility:
    /// open`, so an unseen override may exist. A language that publishes
    /// nothing is not counted, because absence is not evidence of closedness.
    pub dispatch_extensible_edited_symbols: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureChangeCallers {
    pub fqn: String,
    pub path: String,
    pub start_line: usize,
    pub external_caller_sites: usize,
    /// Every unchanged file holding at least one reference, in path order.
    pub external_caller_files: Vec<String>,
    /// Set when the underlying scan did not resolve or did not complete for
    /// this symbol, so the counts above are a floor rather than a total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<String>,
}

/// Which changed production symbols no test distinguishes.
///
/// This is symbol-level and direct: a symbol counts as referenced by a test
/// only when a reference site for that exact symbol lies in a test file or a
/// test region of the target revision. It is NOT transitive -- a symbol reached
/// only through an intermediate that a test does call is reported here as
/// having no direct test reference.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationFeatures {
    pub changed_production_symbols: usize,
    pub without_direct_test_reference: Vec<UntestedSymbol>,
    /// `without_direct_test_reference.len() / changed_production_symbols`, or
    /// 0.0 when the patch changed no production symbol.
    pub untested_fraction: f64,
    /// Symbols the question could not be answered for: the reference scan did
    /// not resolve them, did not complete, or answered with sites that cannot
    /// be placed on either side of the test boundary. They are excluded from
    /// both counts above rather than assumed untested.
    pub unresolved_symbols: Vec<UnresolvedSymbol>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UntestedSymbol {
    pub fqn: String,
    pub kind: String,
    pub path: String,
    pub start_line: usize,
    pub language: String,
    /// How the patch changed it: `edited`, `introduced`, or `moved`. A symbol
    /// that both moved and was edited reports `edited`, which never suggests
    /// its body is unchanged; `geometry.moved_symbols` still counts the
    /// relocation.
    pub change: String,
    /// Reference sites the symbol does have, all of them outside tests.
    pub non_test_reference_sites: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnresolvedSymbol {
    pub fqn: String,
    pub path: String,
    pub start_line: usize,
    /// The scan status, incompleteness, or unclassifiable reference file that
    /// kept this symbol out of the verification counts.
    pub reason: String,
}

/// SonarSource cognitive complexity over the edited symbol pairs, as the
/// established metric to compare the features above against.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineFeatures {
    pub cognitive_before: u64,
    pub cognitive_after: u64,
    pub cognitive_delta: i64,
    pub max_cognitive_after: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExcludedFiles {
    pub binary_files: usize,
    pub unparseable_files: usize,
    /// Complete lists, not samples: a consumer reading a low symbol count needs
    /// to see exactly which files never reached the analyzer.
    pub binary_paths: Vec<String>,
    pub unparseable_paths: Vec<String>,
}

/// The whole tool: `base..target` in, feature vector out.
///
/// `cancellation` is the caller's token, not a fresh one. The reference scan
/// this runs over the whole target revision is the expensive step, and a client
/// that gave up on the tool call must be able to stop it.
pub fn score_diff_at_root(
    root: &Path,
    params: ScoreDiffParams,
    options: &DiffAnalysisOptions,
    cancellation: &CancellationToken,
) -> Result<DiffScoreResult, String> {
    let prepared = PreparedDiff::at_root(
        root,
        DiffEndpointParams {
            base: params.base,
            target: params.target,
        },
        options,
    )?;
    // Test symbols and edges are always in scope: verification asks whether a
    // changed production symbol has any test reference at all.
    let analyzed = analyze_prepared_diff_with_endpoints(&prepared, true)?;
    let whole_target = prepared.whole_target_analysis()?;

    let changed_paths: BTreeSet<String> = analyzed
        .result
        .file_changes
        .iter()
        .flat_map(|change| [change.path.clone(), change.old_path.clone()])
        .flatten()
        .collect();

    let geometry = geometry_features(
        &analyzed.result.file_changes,
        &analyzed.result.patch_symbols,
        &whole_target,
    );
    let references =
        resolve_reference_sites(&analyzed.result.patch_symbols, &whole_target, cancellation);
    let coordination = coordination_features(&analyzed, &references, &changed_paths);
    let verification = verification_features(
        &analyzed.result.patch_symbols,
        &references,
        whole_target.analyzer(),
    );
    let baseline = baseline_features(&analyzed);
    let excluded = excluded_files(&analyzed.result.file_changes);

    Ok(DiffScoreResult {
        endpoints: analyzed.result.endpoints.clone(),
        geometry,
        coordination,
        verification,
        baseline,
        excluded,
    })
}

// ---------------------------------------------------------------- geometry

fn geometry_features(
    file_changes: &[FileChange],
    patch_symbols: &PatchSymbols,
    target: &EndpointAnalysis,
) -> GeometryFeatures {
    let measured = MeasuredFiles::of(file_changes);
    let (mean_directory_distance, max_directory_distance) = measured.dispersion();

    GeometryFeatures {
        edited_symbols: patch_symbols.edited.len(),
        introduced_symbols: patch_symbols.introduced.len(),
        deleted_symbols: patch_symbols.deleted.len(),
        moved_symbols: patch_symbols.moved.len(),
        signature_changes: patch_symbols.signature_changes.len(),
        production_files_changed: measured.paths.len(),
        test_files_changed: file_changes.iter().filter(|change| change.is_test).count(),
        directories_changed: measured.directories.iter().collect::<BTreeSet<_>>().len(),
        edit_clusters: measured.edit_clusters(target),
        mean_directory_distance,
        max_directory_distance,
        insertions: file_changes.iter().map(|change| change.insertions).sum(),
        deletions: file_changes.iter().map(|change| change.deletions).sum(),
    }
}

/// The changed files every shape feature is computed over: production, and
/// something the analyzer can actually read.
///
/// A binary or unparseable file has no symbols, no imports, and no measurable
/// relationship to any other file, so counting it as a changed production file
/// would inflate the cluster and dispersion features with edits whose structure
/// was never examined -- a vendored image next to a source file would read as a
/// second, unrelated cluster. Those files are reported in [`ExcludedFiles`]
/// instead, and the raw `insertions`/`deletions` line counts still cover every
/// changed file, because those are Git's numbers and need no analyzer.
struct MeasuredFiles {
    paths: Vec<String>,
    directories: Vec<PathBuf>,
    /// Each directory's components, hoisted out of the pairwise distance loop
    /// so an O(n^2) comparison does not re-split every path O(n) times.
    /// `OsString` rather than `String`: a path component that is not UTF-8 must
    /// still compare exactly rather than be dropped or replaced.
    components: Vec<Vec<OsString>>,
}

impl MeasuredFiles {
    fn of(file_changes: &[FileChange]) -> Self {
        let paths: Vec<String> = file_changes
            .iter()
            .filter(|change| !change.is_test && change.is_parseable && !change.is_binary)
            .filter_map(|change| change.path.clone().or_else(|| change.old_path.clone()))
            .collect();
        let directories: Vec<PathBuf> = paths
            .iter()
            .map(|path| {
                Path::new(path)
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .to_path_buf()
            })
            .collect();
        let components = directories
            .iter()
            .map(|dir| {
                dir.components()
                    .map(|component| component.as_os_str().to_os_string())
                    .collect()
            })
            .collect();
        Self {
            paths,
            directories,
            components,
        }
    }

    /// Mean and maximum pairwise directory distance: components up plus
    /// components down between two directories, the length of the shortest path
    /// through the directory tree that joins them.
    fn dispersion(&self) -> (f64, usize) {
        let mut total = 0usize;
        let mut pairs = 0usize;
        let mut max = 0usize;
        for (index, left) in self.components.iter().enumerate() {
            for right in &self.components[index + 1..] {
                let shared = left
                    .iter()
                    .zip(right.iter())
                    .take_while(|(a, b)| a == b)
                    .count();
                let distance = (left.len() - shared) + (right.len() - shared);
                total += distance;
                pairs += 1;
                max = max.max(distance);
            }
        }
        if pairs == 0 {
            return (0.0, 0);
        }
        let mean = total as f64 / pairs as f64;
        ((mean * 100.0).round() / 100.0, max)
    }

    /// Connected components over the measured files under
    /// same-directory-or-import adjacency in the target revision.
    ///
    /// Union-find rather than a graph walk: the relation is symmetric and the
    /// only question asked of it is component count, so there is nothing to
    /// traverse.
    fn edit_clusters(&self, target: &EndpointAnalysis) -> usize {
        if self.paths.len() < 2 {
            return self.paths.len();
        }
        let mut parent: Vec<usize> = (0..self.paths.len()).collect();

        fn find(parent: &mut [usize], mut node: usize) -> usize {
            while parent[node] != node {
                parent[node] = parent[parent[node]];
                node = parent[node];
            }
            node
        }
        fn union(parent: &mut [usize], left: usize, right: usize) {
            let left = find(parent, left);
            let right = find(parent, right);
            if left != right {
                parent[left] = right;
            }
        }

        // Same-directory adjacency by grouping, not by comparing every pair:
        // union each file with the first file seen in its directory, which is
        // the same partition in one pass instead of n^2 comparisons.
        let mut first_in_directory: HashMap<&Path, usize> = HashMap::new();
        for (index, directory) in self.directories.iter().enumerate() {
            match first_in_directory.get(directory.as_path()) {
                Some(first) => union(&mut parent, index, *first),
                None => {
                    first_in_directory.insert(directory.as_path(), index);
                }
            }
        }

        for (left, right) in self.import_adjacency(target) {
            union(&mut parent, left, right);
        }

        (0..self.paths.len())
            .map(|index| find(&mut parent, index))
            .collect::<HashSet<_>>()
            .len()
    }

    /// Index pairs `(a, b)` where `a` imports `b` in the target revision.
    fn import_adjacency(&self, target: &EndpointAnalysis) -> Vec<(usize, usize)> {
        let index_by_path: HashMap<&str, usize> = self
            .paths
            .iter()
            .enumerate()
            .map(|(index, path)| (path.as_str(), index))
            .collect();
        let mut edges = Vec::new();
        for (index, path) in self.paths.iter().enumerate() {
            for import in resolved_imports_of(target.analyzer(), target.root(), Path::new(path)) {
                match import {
                    ImportExpansionTarget::File(file) => {
                        if let Some(other) = index_by_path.get(path_string(&file).as_str())
                            && *other != index
                        {
                            edges.push((index, *other));
                        }
                    }
                    ImportExpansionTarget::Directory(package) => {
                        // A directory import names a package, and a package's
                        // members are the files directly inside it. Treating
                        // the whole subtree as imported would connect a file to
                        // every changed file under a distant ancestor -- a
                        // `crates/` import would swallow the repository.
                        for (other, directory) in self.directories.iter().enumerate() {
                            if other != index && directory == &package {
                                edges.push((index, other));
                            }
                        }
                    }
                }
            }
        }
        edges
    }
}

// ------------------------------------------------------------ coordination

/// Why a symbol's counts are a floor rather than a total when the scan returned
/// no entry for it at all.
///
/// Shared by both consumers of the scan, because the two must not disagree
/// about what an absent entry means: coordination reports it as an
/// incompleteness on the signature change, verification refuses to call the
/// symbol untested on the strength of it.
const MISSING_SCAN_RESULT: &str = "no reference scan result for this declaration";

fn coordination_features(
    analyzed: &AnalyzedDiff,
    references: &ReferenceSites,
    changed_paths: &BTreeSet<String>,
) -> CoordinationFeatures {
    let patch_symbols = &analyzed.result.patch_symbols;
    let mut external_callers_by_signature_change = Vec::new();
    for change in &patch_symbols.signature_changes {
        let sites = references.get(&symbol_key(&change.after));
        let mut external_caller_files = Vec::new();
        let mut external_caller_sites = 0usize;
        for site in sites
            .map(|sites| sites.files.as_slice())
            .unwrap_or_default()
        {
            if changed_paths.contains(&site.path) {
                continue;
            }
            external_caller_sites += site.hits;
            external_caller_files.push(site.path.clone());
        }
        external_callers_by_signature_change.push(SignatureChangeCallers {
            fqn: change.after.fqn.clone(),
            path: change.after.path.clone(),
            start_line: change.after.start_line,
            external_caller_sites,
            external_caller_files,
            // A missing scan result is itself an incompleteness. Without this
            // the entry would report a confident zero external callers for a
            // symbol nothing ever scanned, which reads exactly like a verified
            // "safe to change".
            incomplete_reason: match sites {
                Some(sites) => sites.incomplete_reason.clone(),
                None => Some(MISSING_SCAN_RESULT.to_string()),
            },
        });
    }
    external_callers_by_signature_change.sort_by(|a, b| {
        b.external_caller_sites
            .cmp(&a.external_caller_sites)
            .then_with(|| a.fqn.cmp(&b.fqn))
    });

    let added_call_weight = patch_symbols
        .edited
        .iter()
        .flat_map(|pair| pair.added_calls.iter())
        .chain(
            patch_symbols
                .moved
                .iter()
                .flat_map(|record| record.added_calls.iter()),
        )
        .chain(
            patch_symbols
                .introduced
                .iter()
                .flat_map(|record| record.calls.iter()),
        )
        .map(|call| call.weight)
        .sum();
    let removed_call_weight = patch_symbols
        .edited
        .iter()
        .flat_map(|pair| pair.removed_calls.iter())
        .chain(
            patch_symbols
                .moved
                .iter()
                .flat_map(|record| record.removed_calls.iter()),
        )
        .chain(
            patch_symbols
                .deleted
                .iter()
                .flat_map(|record| record.called.iter()),
        )
        .map(|call| call.weight)
        .sum();

    CoordinationFeatures {
        signature_change_external_caller_sites: external_callers_by_signature_change
            .iter()
            .map(|entry| entry.external_caller_sites)
            .sum(),
        max_external_callers_per_signature_change: external_callers_by_signature_change
            .iter()
            .map(|entry| entry.external_caller_sites)
            .max()
            .unwrap_or(0),
        external_callers_by_signature_change,
        added_call_weight,
        removed_call_weight,
        unattributed_call_edge_changes: analyzed.result.unattributed_call_edge_changes.len(),
        dispatch_extensible_edited_symbols: dispatch_extensible_edited_symbols(analyzed),
    }
}

/// Edited symbols an unseen override may exist for.
///
/// A patch symbol is a serialized description, not a handle, so the declaration
/// has to be recovered before the analyzer can be asked anything about it. The
/// symbol's own line span is what recovers it: `enclosing_code_unit_for_lines`
/// is the indexed innermost-declaration lookup every other consumer of a line
/// position uses, so this asks the same question the same way instead of
/// reading and re-ranging every declaration of every touched file.
fn dispatch_extensible_edited_symbols(analyzed: &AnalyzedDiff) -> usize {
    let analyzer = analyzed.target.analyzer();
    analyzed
        .result
        .patch_symbols
        .edited
        .iter()
        .filter(|pair| {
            let Some(file) = analyzer
                .project()
                .file_by_rel_path(Path::new(&pair.after.path))
            else {
                return false;
            };
            analyzer
                .enclosing_code_unit_for_lines(&file, pair.after.start_line, pair.after.end_line)
                .is_some_and(|unit| {
                    analyzer.signature_metadata(&unit).iter().any(|metadata| {
                        metadata.dispatch_extensibility() == Some(DispatchExtensibility::Open)
                    })
                })
        })
        .count()
}

// -------------------------------------------------------------- references

/// One file's reference sites for one symbol.
#[derive(Debug, Clone)]
struct ReferenceFile {
    path: String,
    hits: usize,
    /// Reference lines, when the scan rendered them. A scan that summarized a
    /// very hot symbol reports per-file counts only, which is why this can be
    /// empty while `hits` is not.
    lines: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
struct SymbolReferences {
    files: Vec<ReferenceFile>,
    /// Set when the scan could not answer completely for this symbol; the
    /// verification pass refuses to call such a symbol untested.
    incomplete_reason: Option<String>,
}

/// Every scanned symbol's reference sites, keyed by where the symbol sits at
/// the target endpoint -- the same key [`symbol_key`] derives from a patch
/// symbol and the by-location scan echoes back in its input.
type ReferenceSites = HashMap<SymbolKey, SymbolReferences>;

/// A declaration's target-endpoint `(path, start_line)`.
type SymbolKey = (String, usize);

fn symbol_key(symbol: &CommitSymbol) -> SymbolKey {
    (symbol.path.clone(), symbol.start_line)
}

/// Every symbol the patch leaves behind at the target endpoint, each labelled
/// with how it got there.
///
/// One definition serves both consumers on purpose. The scan resolves exactly
/// these symbols and verification judges exactly these symbols, so a symbol
/// class present in one list and missing from the other would report itself as
/// unresolved forever. `moved` is the case that makes the point: a renamed or
/// relocated function is still a changed production symbol a test should
/// reference, and its `after` identity is the only one the target revision
/// knows it by.
///
/// The three lists are not disjoint -- a symbol whose file was renamed *and*
/// whose body was edited is both `moved` and `edited` -- so each target
/// position is yielded once, under the first label that claims it. Without
/// that, such a symbol would be counted twice and reported twice.
fn changed_target_symbols(
    patch_symbols: &PatchSymbols,
) -> impl Iterator<Item = (&CommitSymbol, &'static str)> {
    let mut seen: HashSet<SymbolKey> = HashSet::new();
    patch_symbols
        .edited
        .iter()
        .map(|pair| (&pair.after, "edited"))
        .chain(
            patch_symbols
                .introduced
                .iter()
                .map(|record| (&record.after, "introduced")),
        )
        .chain(
            patch_symbols
                .moved
                .iter()
                .map(|record| (&record.after, "moved")),
        )
        .filter(move |(symbol, _)| seen.insert(symbol_key(symbol)))
}

/// Resolve, in one scan over the whole target revision, every reference site of
/// every symbol the patch edited, introduced, moved, or resignatured.
///
/// Targeting by location rather than by name is what makes this exact: a
/// patch symbol already knows where it is at the target endpoint, so the scan
/// never has to guess between overloads or same-named declarations.
fn resolve_reference_sites(
    patch_symbols: &PatchSymbols,
    whole_target: &EndpointAnalysis,
    cancellation: &CancellationToken,
) -> ReferenceSites {
    let mut wanted: BTreeMap<SymbolKey, String> = BTreeMap::new();
    for symbol in changed_target_symbols(patch_symbols)
        .map(|(symbol, _)| symbol)
        .chain(patch_symbols.signature_changes.iter().map(|c| &c.after))
    {
        wanted.insert(symbol_key(symbol), symbol.fqn.clone());
    }
    if wanted.is_empty() {
        return ReferenceSites::default();
    }

    let targets: Vec<ScanUsagesTarget> = wanted
        .iter()
        .map(|((path, line), fqn)| ScanUsagesTarget {
            path: path.clone(),
            line: *line,
            column: None,
            symbol: Some(fqn.clone()),
        })
        .collect();
    let scanned = scan_usages_by_location_with_cancellation(
        whole_target.analyzer(),
        ScanUsagesByLocationParams {
            targets,
            include_tests: true,
            paths: None,
            include_same_owner: false,
        },
        // A scan carries no wall-clock budget of its own; the caller's token is
        // the only thing that can stop it. That suits this scan, which runs
        // once per revision range over a whole revision rather than serving
        // keystrokes: a fixed interactive budget would fail every symbol in a
        // real repository and leave the verification group reporting nothing.
        // A symbol whose scan the caller cancels lands in
        // `verification.unresolved_symbols` instead of being read as a
        // confident negative.
        cancellation.clone(),
    );

    scanned
        .results
        .iter()
        .map(|entry| (entry_key(entry), symbol_references(entry)))
        .collect()
}

/// The scanned entry's symbol key.
///
/// Every request above is a [`ScanUsagesTarget`], and the scan echoes each
/// request's own input back on its entry, so a symbol input here would mean the
/// by-location scan answered a question nobody asked. Skipping such an entry
/// would silently drop a symbol from verification; there is no recovery, so
/// this is an assertion rather than an `Option`.
fn entry_key(entry: &ScanUsagesEntry) -> SymbolKey {
    match &entry.input {
        ScanUsagesInput::Target(target) => (target.path.clone(), target.line),
        ScanUsagesInput::Symbol(symbol) => {
            unreachable!("by-location scan echoed a symbol input: {symbol}")
        }
    }
}

fn symbol_references(entry: &ScanUsagesEntry) -> SymbolReferences {
    let incomplete_reason = match entry.status {
        ScanUsagesStatus::Found
        | ScanUsagesStatus::VerifiedAbsent
        | ScanUsagesStatus::NoExternalUsages => entry
            .incomplete_reason
            .map(|reason| format!("{reason:?}"))
            .or_else(|| {
                entry
                    .files_truncated
                    .map(|count| format!("{count} reference files omitted"))
            }),
        // Report the scan's own explanation, not just its verdict: a bare
        // status leaves a consumer unable to tell a symbol the scan refused
        // from one it could not resolve.
        other => Some(match entry.message.as_deref() {
            Some(message) => format!("scan status {other:?}: {message}"),
            None => format!("scan status {other:?}"),
        }),
    };
    let files = entry
        .files
        .iter()
        .map(|group| ReferenceFile {
            path: group.path.clone(),
            hits: group.hit_count.unwrap_or(group.hits.len()),
            lines: group.hits.iter().map(|hit| hit.line).collect(),
        })
        .collect();
    SymbolReferences {
        files,
        incomplete_reason,
    }
}

// ------------------------------------------------------------ verification

fn verification_features(
    patch_symbols: &PatchSymbols,
    references: &ReferenceSites,
    analyzer: &dyn IAnalyzer,
) -> VerificationFeatures {
    let mut classifier = TestFileClassifier::default();
    let mut without_direct_test_reference = Vec::new();
    let mut unresolved_symbols = Vec::new();
    let mut changed_production_symbols = 0usize;

    for (symbol, change) in changed_target_symbols(patch_symbols) {
        if symbol.is_test {
            continue;
        }
        let unresolved = |reason: String| UnresolvedSymbol {
            fqn: symbol.fqn.clone(),
            path: symbol.path.clone(),
            start_line: symbol.start_line,
            reason,
        };
        let Some(sites) = references.get(&symbol_key(symbol)) else {
            unresolved_symbols.push(unresolved(MISSING_SCAN_RESULT.to_string()));
            continue;
        };
        if let Some(reason) = &sites.incomplete_reason {
            unresolved_symbols.push(unresolved(reason.clone()));
            continue;
        }

        let mut non_test_reference_sites = 0usize;
        let mut has_test_reference = false;
        let mut undecidable: Option<String> = None;
        for site in &sites.files {
            match classifier.classify(analyzer, site) {
                TestReference::Test => has_test_reference = true,
                TestReference::NonTest => non_test_reference_sites += site.hits,
                // Not counted on either side: a site that cannot be placed is
                // not evidence of a test reference, and calling it a
                // non-test reference would be the same guess in the other
                // direction.
                TestReference::Undecidable(why) => {
                    undecidable.get_or_insert_with(|| format!("{why}: {}", site.path));
                }
            }
        }
        // An undecidable file only matters when nothing else settled the
        // question. With a test reference already found the symbol is tested
        // whatever that file holds.
        if !has_test_reference && let Some(why) = undecidable {
            unresolved_symbols.push(unresolved(why));
            continue;
        }

        changed_production_symbols += 1;
        if !has_test_reference {
            without_direct_test_reference.push(UntestedSymbol {
                fqn: symbol.fqn.clone(),
                kind: symbol.kind.clone(),
                path: symbol.path.clone(),
                start_line: symbol.start_line,
                language: symbol.language.clone(),
                change: change.to_string(),
                non_test_reference_sites,
            });
        }
    }

    without_direct_test_reference.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.start_line.cmp(&b.start_line))
    });
    unresolved_symbols.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.start_line.cmp(&b.start_line))
    });
    let untested_fraction = if changed_production_symbols == 0 {
        0.0
    } else {
        let raw = without_direct_test_reference.len() as f64 / changed_production_symbols as f64;
        (raw * 100.0).round() / 100.0
    };
    VerificationFeatures {
        changed_production_symbols,
        without_direct_test_reference,
        untested_fraction,
        unresolved_symbols,
    }
}

/// Which side of the test boundary one file's reference sites fall on.
#[derive(Debug, Clone, Copy)]
enum TestReference {
    Test,
    NonTest,
    /// Neither answer is available. The reason is a phrase the call site
    /// completes with the file it is about.
    Undecidable(&'static str),
}

/// Which side of the test boundary a file's reference sites fall on, memoized
/// per file because one file holds sites for many of the patch's symbols.
///
/// A test-like file settles it outright, by exactly the predicate a usage scan
/// uses ([`is_test_like_file`]) rather than a private path rule: a Rust sibling
/// `#[cfg(test)] mod tests` file matches no path convention at all, and only
/// that predicate's `file_is_test_only` disjunct sees it. Otherwise the file may
/// still hold an inline test region, and only the sites inside it count, so
/// each site's enclosing declaration decides.
#[derive(Default)]
struct TestFileClassifier {
    files: HashMap<String, FileTestKind>,
}

enum FileTestKind {
    /// The whole file is test code or test support: every site in it is a test
    /// reference.
    TestLike,
    /// Production by path and module structure, but holding test regions, so
    /// the site's own position decides. Carries the file the decision needs.
    InlineTests(ProjectFile),
    /// Production, with no test region for a site to be inside.
    Production,
    /// Not a file of the target revision's project, so nothing can be asked
    /// about it.
    Unknown,
}

impl TestFileClassifier {
    fn classify(&mut self, analyzer: &dyn IAnalyzer, site: &ReferenceFile) -> TestReference {
        let path = Path::new(site.path.as_str());
        let kind = self.files.entry(site.path.clone()).or_insert_with(|| {
            let Some(file) = analyzer.project().file_by_rel_path(path) else {
                return FileTestKind::Unknown;
            };
            if is_test_like_file(analyzer, &file, &site.path, path_language(path)) {
                FileTestKind::TestLike
            } else if analyzer.contains_tests(&file) {
                FileTestKind::InlineTests(file)
            } else {
                FileTestKind::Production
            }
        });
        match kind {
            FileTestKind::TestLike => TestReference::Test,
            FileTestKind::Production => TestReference::NonTest,
            FileTestKind::Unknown => TestReference::Undecidable(
                "the target revision's project has no such file, so its references cannot be \
                 classified",
            ),
            // A summarized scan reports this file's hit count without lines,
            // and those hits can be on either side of the file's own test
            // boundary. Crediting a test reference here would turn "the symbol
            // was hot enough for the scan to summarize it" into "the symbol is
            // tested", the one way this feature could be silently wrong in the
            // reassuring direction.
            FileTestKind::InlineTests(_) if site.lines.is_empty() => TestReference::Undecidable(
                "the scan summarized this file's hits without lines, so they cannot be placed \
                 inside or outside its test region",
            ),
            FileTestKind::InlineTests(file) => {
                if site
                    .lines
                    .iter()
                    .any(|line| enclosing_is_test_region(analyzer, file, *line))
                {
                    TestReference::Test
                } else {
                    TestReference::NonTest
                }
            }
        }
    }
}

fn enclosing_is_test_region(analyzer: &dyn IAnalyzer, file: &ProjectFile, line: usize) -> bool {
    analyzer
        .get_declarations(file)
        .into_iter()
        .filter(|unit| {
            primary_range(analyzer, unit)
                .is_some_and(|range| range.start_line <= line && line <= range.end_line)
        })
        .any(|unit| analyzer.in_test_region(&unit))
}

// ---------------------------------------------------------------- baseline

fn baseline_features(analyzed: &AnalyzedDiff) -> BaselineFeatures {
    let before = cognitive_totals(
        &analyzed.base,
        analyzed
            .result
            .patch_symbols
            .edited
            .iter()
            .map(|pair| &pair.before),
    );
    let after = cognitive_totals(
        &analyzed.target,
        analyzed
            .result
            .patch_symbols
            .edited
            .iter()
            .map(|pair| &pair.after),
    );
    BaselineFeatures {
        cognitive_before: before.total,
        cognitive_after: after.total,
        cognitive_delta: after.total as i64 - before.total as i64,
        max_cognitive_after: after.max,
    }
}

struct CognitiveTotals {
    total: u64,
    max: u32,
}

/// Cognitive complexity of one endpoint's side of the edited pairs.
///
/// The walker reports per function, while an edited symbol may be a class or a
/// module, so each measured function is attributed to the innermost edited
/// symbol whose range contains it. Innermost, not every container, is what
/// keeps a method's score from being counted again for its class.
fn cognitive_totals<'a>(
    endpoint: &EndpointAnalysis,
    symbols: impl Iterator<Item = &'a CommitSymbol>,
) -> CognitiveTotals {
    let analyzer = endpoint.analyzer();
    let mut by_path: BTreeMap<&str, Vec<&CommitSymbol>> = BTreeMap::new();
    for symbol in symbols {
        by_path
            .entry(symbol.path.as_str())
            .or_default()
            .push(symbol);
    }

    let mut per_symbol: HashMap<(&str, usize), u32> = HashMap::new();
    for (path, symbols) in &by_path {
        let Some(file) = analyzer.project().file_by_rel_path(Path::new(path)) else {
            continue;
        };
        for (unit, complexity) in analyzer.compute_cognitive_complexities(&file) {
            if unit.is_synthetic() {
                continue;
            }
            let Some(range) = primary_range(analyzer, &unit) else {
                continue;
            };
            let innermost = symbols
                .iter()
                .filter(|symbol| {
                    symbol.start_line <= range.start_line && range.end_line <= symbol.end_line
                })
                .min_by_key(|symbol| symbol.end_line - symbol.start_line);
            if let Some(symbol) = innermost {
                *per_symbol.entry((path, symbol.start_line)).or_default() += complexity;
            }
        }
    }
    CognitiveTotals {
        total: per_symbol.values().map(|value| u64::from(*value)).sum(),
        max: per_symbol.values().copied().max().unwrap_or(0),
    }
}

// ---------------------------------------------------------------- excluded

fn excluded_files(file_changes: &[FileChange]) -> ExcludedFiles {
    let mut binary_paths = Vec::new();
    let mut unparseable_paths = Vec::new();
    for change in file_changes {
        let Some(path) = change.path.clone().or_else(|| change.old_path.clone()) else {
            continue;
        };
        if change.is_binary {
            binary_paths.push(path);
        } else if !change.is_parseable {
            unparseable_paths.push(path);
        }
    }
    ExcludedFiles {
        binary_files: binary_paths.len(),
        unparseable_files: unparseable_paths.len(),
        binary_paths,
        unparseable_paths,
    }
}

#[cfg(test)]
mod tests {
    use super::{DiffScoreResult, ScoreDiffParams, score_diff_at_root};
    use crate::cancellation::CancellationToken;
    use crate::diff_analysis::DiffAnalysisOptions;
    use crate::gitblob::test_repo;
    use std::fs;
    use std::path::Path;

    const MANIFEST: &str = "[package]\nname = \"repro\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("a relative file has a parent")).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// Score the range `HEAD~1..HEAD` of a repository built by `build`, which
    /// receives the root and commits twice through `test_repo`.
    fn score_two_commits(build: impl FnOnce(&Path, &git2::Repository)) -> DiffScoreResult {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        build(dir.path(), &repo);
        drop(repo);
        score_diff_at_root(
            dir.path(),
            ScoreDiffParams {
                base: Some("HEAD~1".to_string()),
                target: Some("HEAD".to_string()),
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("score_diff failed")
    }

    /// The same three-module crate edited two ways: once in three sibling
    /// directories, once in a single file. Every geometry feature that claims
    /// to measure dispersion must separate the two, or it measures nothing --
    /// a patch's difficulty is supposed to be the thing these numbers track.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn dispersed_edit_reports_more_clusters_and_distance_than_a_single_file_edit() {
        fn seed(root: &Path, repo: &git2::Repository) {
            write(root, "Cargo.toml", MANIFEST);
            write(
                root,
                "src/lib.rs",
                "pub mod alpha;\npub mod beta;\npub mod gamma;\n",
            );
            for module in ["alpha", "beta", "gamma"] {
                write(
                    root,
                    &format!("src/{module}/mod.rs"),
                    &format!("pub fn {module}_value() -> i32 {{\n    1\n}}\n"),
                );
            }
            test_repo::commit_all(repo, "commit 1");
        }

        let dispersed = score_two_commits(|root, repo| {
            seed(root, repo);
            for module in ["alpha", "beta", "gamma"] {
                write(
                    root,
                    &format!("src/{module}/mod.rs"),
                    &format!("pub fn {module}_value() -> i32 {{\n    2\n}}\n"),
                );
            }
            test_repo::commit_all(repo, "commit 2");
        });
        let single = score_two_commits(|root, repo| {
            seed(root, repo);
            write(
                root,
                "src/alpha/mod.rs",
                "pub fn alpha_value() -> i32 {\n    2\n}\n",
            );
            test_repo::commit_all(repo, "commit 2");
        });

        assert_eq!(
            single.geometry.production_files_changed, 1,
            "control: the single-file edit must touch one production file, got {:?}",
            single.geometry
        );
        assert_eq!(
            single.geometry.edit_clusters, 1,
            "one changed file is one cluster, got {:?}",
            single.geometry
        );
        assert_eq!(
            single.geometry.mean_directory_distance, 0.0,
            "a lone file has no pair to be distant from, got {:?}",
            single.geometry
        );
        assert_eq!(single.geometry.max_directory_distance, 0);

        assert_eq!(
            dispersed.geometry.production_files_changed, 3,
            "control: the dispersed edit must touch three production files, got {:?}",
            dispersed.geometry
        );
        assert_eq!(
            dispersed.geometry.directories_changed, 3,
            "three sibling module directories, got {:?}",
            dispersed.geometry
        );
        assert_eq!(
            dispersed.geometry.edit_clusters, 3,
            "the three files share no directory and import nothing of each \
             other, so each is its own cluster, got {:?}",
            dispersed.geometry
        );
        assert_eq!(
            dispersed.geometry.mean_directory_distance, 2.0,
            "sibling directories under src/ are one up and one down apart, got {:?}",
            dispersed.geometry
        );
        assert_eq!(dispersed.geometry.max_directory_distance, 2);
        assert!(
            dispersed.geometry.edit_clusters > single.geometry.edit_clusters
                && dispersed.geometry.mean_directory_distance
                    > single.geometry.mean_directory_distance,
            "the dispersed edit must score higher on both dispersion features: \
             dispersed {:?} vs single {:?}",
            dispersed.geometry,
            single.geometry
        );
    }

    /// A signature change whose only caller sits in a file the patch never
    /// touched. This is the feature that cannot be computed from the diff's own
    /// files, so it is also the proof that the whole-target-revision analyzer
    /// is doing its job.
    #[test]
    fn signature_change_reports_a_caller_in_an_unchanged_file() {
        let score = score_two_commits(|root, repo| {
            write(root, "Cargo.toml", MANIFEST);
            write(root, "src/lib.rs", "pub mod core_ops;\npub mod client;\n");
            write(
                root,
                "src/core_ops.rs",
                "pub fn compute(x: i32) -> i32 {\n    x + 1\n}\n",
            );
            write(
                root,
                "src/client.rs",
                "use crate::core_ops::compute;\n\npub fn run() -> i32 {\n    compute(1)\n}\n",
            );
            test_repo::commit_all(repo, "commit 1");

            write(
                root,
                "src/core_ops.rs",
                "pub fn compute(x: i32, y: i32) -> i32 {\n    x + y\n}\n",
            );
            test_repo::commit_all(repo, "commit 2");
        });

        assert_eq!(
            score.geometry.signature_changes, 1,
            "control: adding a parameter is one signature change, got {:?}",
            score.geometry
        );
        let entry = score
            .coordination
            .external_callers_by_signature_change
            .iter()
            .find(|entry| entry.fqn.contains("compute"))
            .unwrap_or_else(|| {
                panic!(
                    "no signature-change entry for compute in {:?}",
                    score.coordination.external_callers_by_signature_change
                )
            });
        assert!(
            entry
                .external_caller_files
                .contains(&"src/client.rs".to_string()),
            "the unchanged caller file must be reported, got {entry:?}"
        );
        assert!(
            entry.external_caller_sites >= 1,
            "the unchanged caller's call site must be counted, got {entry:?}"
        );
        assert!(
            score.coordination.signature_change_external_caller_sites >= 1
                && score.coordination.max_external_callers_per_signature_change >= 1,
            "the totals must reflect the per-change entry, got {:?}",
            score.coordination
        );
    }

    /// Two edited production functions in the same crate, one of which a test
    /// calls. Only the other may be reported as lacking a direct test
    /// reference; reporting both would make the feature a restatement of "this
    /// symbol was edited".
    #[test]
    fn only_the_symbol_without_a_test_reference_is_reported_untested() {
        // The two names must not share a substring: an earlier revision of
        // this test called them `tested_fn` and `untested_fn` and passed its
        // "must not be reported" assertion for the wrong reason, because
        // `"untested_fn".contains("tested_fn")`.
        let covered = "pub fn covered() -> i32 {\n    VALUE\n}\n\n\
                       #[cfg(test)]\nmod tests {\n    use super::covered;\n\n    \
                       #[test]\n    fn exercises_it() {\n        \
                       assert_eq!(covered(), VALUE);\n    }\n}\n";
        let score = score_two_commits(|root, repo| {
            write(root, "Cargo.toml", MANIFEST);
            write(root, "src/lib.rs", "pub mod covered;\npub mod bare;\n");
            write(root, "src/covered.rs", &covered.replace("VALUE", "1"));
            write(root, "src/bare.rs", "pub fn bare() -> i32 {\n    1\n}\n");
            test_repo::commit_all(repo, "commit 1");

            write(root, "src/covered.rs", &covered.replace("VALUE", "2"));
            write(root, "src/bare.rs", "pub fn bare() -> i32 {\n    2\n}\n");
            test_repo::commit_all(repo, "commit 2");
        });

        let untested: Vec<&str> = score
            .verification
            .without_direct_test_reference
            .iter()
            .map(|symbol| symbol.fqn.as_str())
            .collect();
        assert!(
            score.verification.unresolved_symbols.is_empty(),
            "both symbols must resolve, got {:?}",
            score.verification.unresolved_symbols
        );
        assert_eq!(
            score.verification.changed_production_symbols, 2,
            "control: both edited functions are production symbols, got {:?}",
            score.verification
        );
        assert!(
            untested.iter().any(|fqn| fqn.ends_with("bare")),
            "the function no test calls must be reported, got {untested:?} from {:?}",
            score.verification
        );
        assert!(
            !untested.iter().any(|fqn| fqn.ends_with("covered")),
            "the function a test calls must NOT be reported, got {untested:?} from {:?}",
            score.verification
        );
        assert!(
            score.verification.untested_fraction > 0.0
                && score.verification.untested_fraction < 1.0,
            "one of two changed production symbols is untested, got {:?}",
            score.verification
        );
    }

    /// A function carried to a renamed module, once with its body untouched and
    /// once with its body edited too.
    ///
    /// The pure rename is the discriminating case: no hunk touches the
    /// function's own lines, so `analyze_diff` reports it under `moved` and
    /// nowhere else. It is still a changed production symbol -- a rename is one
    /// of the changes most likely to leave a test behind -- so judging only the
    /// `edited` and `introduced` lists would drop it from verification
    /// entirely, neither reported untested nor reported unresolved, simply
    /// absent. The second case is why the three lists must be merged rather
    /// than concatenated: a relocated symbol whose body also changed is in two
    /// of them and must still be judged once.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn a_relocated_symbol_is_judged_by_verification_exactly_once() {
        fn seed(root: &Path, repo: &git2::Repository) {
            write(root, "Cargo.toml", MANIFEST);
            write(root, "src/lib.rs", "pub mod shipping;\n");
            write(
                root,
                "src/shipping.rs",
                "pub fn compute_rate(units: i32) -> i32 {\n    units * 2\n}\n",
            );
            test_repo::commit_all(repo, "commit 1");
        }
        fn rename_to_billing(root: &Path, repo: &git2::Repository, body: &str) {
            fs::remove_file(root.join("src/shipping.rs")).unwrap();
            write(root, "src/lib.rs", "pub mod billing;\n");
            write(root, "src/billing.rs", body);
            test_repo::commit_all(repo, "commit 2");
        }
        let untested_rates = |score: &DiffScoreResult| -> Vec<(String, String)> {
            score
                .verification
                .without_direct_test_reference
                .iter()
                .filter(|symbol| symbol.fqn.ends_with("compute_rate"))
                .map(|symbol| (symbol.fqn.clone(), symbol.change.clone()))
                .collect()
        };

        let renamed = score_two_commits(|root, repo| {
            seed(root, repo);
            rename_to_billing(
                root,
                repo,
                "pub fn compute_rate(units: i32) -> i32 {\n    units * 2\n}\n",
            );
        });
        assert!(
            renamed.geometry.moved_symbols >= 1,
            "control: renaming the module relocates compute_rate, got {:?}",
            renamed.geometry
        );
        assert!(
            renamed.verification.unresolved_symbols.is_empty(),
            "the relocated symbol resolves at its new location, got {:?}",
            renamed.verification
        );
        assert_eq!(
            untested_rates(&renamed),
            vec![(
                "repro.billing.compute_rate".to_string(),
                "moved".to_string()
            )],
            "the relocated symbol must be judged, under the label that explains \
             why it is here: only the moved list holds it, because no hunk \
             touched its body. Got {:?}",
            renamed.verification
        );

        let renamed_and_edited = score_two_commits(|root, repo| {
            seed(root, repo);
            rename_to_billing(
                root,
                repo,
                "pub fn compute_rate(units: i32) -> i32 {\n    units * 3\n}\n",
            );
        });
        assert_eq!(
            untested_rates(&renamed_and_edited),
            vec![(
                "repro.billing.compute_rate".to_string(),
                "edited".to_string()
            )],
            "a symbol that both moved and was edited is in two patch-symbol \
             lists and must be reported once, under the first label that claims \
             it. Got {:?}",
            renamed_and_edited.verification
        );
        assert_eq!(
            renamed_and_edited.verification.changed_production_symbols,
            renamed.verification.changed_production_symbols,
            "and must be counted once: editing the relocated body cannot add a \
             production symbol. Got {:?} vs {:?}",
            renamed_and_edited.verification,
            renamed.verification
        );
    }

    /// A binary file and a file no analyzer can read, changed alongside one
    /// source file. Neither has symbols, imports, or any measurable
    /// relationship to the source file, so counting them as changed production
    /// files would report a one-file edit as three unrelated clusters spread
    /// across the tree. They must be reported as excluded instead.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn binary_and_unparseable_changes_are_excluded_from_the_shape_features() {
        let score = score_two_commits(|root, repo| {
            write(root, "Cargo.toml", MANIFEST);
            write(root, "src/lib.rs", "pub fn only() -> i32 {\n    1\n}\n");
            test_repo::commit_all(repo, "commit 1");

            write(root, "src/lib.rs", "pub fn only() -> i32 {\n    2\n}\n");
            write(root, "docs/notes.md", "# notes\n");
            write(root, "assets/logo.bin", "\u{0}\u{1}\u{0}\u{2}binary\u{0}");
            test_repo::commit_all(repo, "commit 2");
        });

        assert_eq!(
            score.excluded.binary_paths,
            vec!["assets/logo.bin".to_string()],
            "control: git must see the NUL bytes as binary content, got {:?}",
            score.excluded
        );
        assert_eq!(
            score.excluded.unparseable_paths,
            vec!["docs/notes.md".to_string()],
            "control: no analyzer claims .md, got {:?}",
            score.excluded
        );
        assert_eq!(
            score.geometry.production_files_changed, 1,
            "only the source file can be measured, got {:?}",
            score.geometry
        );
        assert_eq!(
            score.geometry.directories_changed, 1,
            "the excluded files' directories are not changed production \
             directories, got {:?}",
            score.geometry
        );
        assert_eq!(
            score.geometry.edit_clusters, 1,
            "one measurable file is one cluster, got {:?}",
            score.geometry
        );
        assert_eq!(
            (
                score.geometry.mean_directory_distance,
                score.geometry.max_directory_distance
            ),
            (0.0, 0),
            "an unmeasurable file is not a place the edit is dispersed to, got {:?}",
            score.geometry
        );
        assert!(
            score.geometry.insertions > 0,
            "line counts are Git's and still cover every changed file, got {:?}",
            score.geometry
        );
    }

    /// A body that gains nested branching must move the baseline metric, and
    /// must move it upward. The delta is what a consumer compares the geometry
    /// features against, so a flat zero here would make the comparison vacuous.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn added_branching_raises_the_cognitive_baseline() {
        let score = score_two_commits(|root, repo| {
            write(root, "Cargo.toml", MANIFEST);
            write(
                root,
                "src/lib.rs",
                "pub fn classify(x: i32) -> i32 {\n    x\n}\n",
            );
            test_repo::commit_all(repo, "commit 1");

            write(
                root,
                "src/lib.rs",
                "pub fn classify(x: i32) -> i32 {\n    \
                 if x > 0 {\n        \
                 if x > 10 {\n            return 2;\n        }\n        \
                 return 1;\n    } else if x < -10 {\n        \
                 return -2;\n    }\n    -1\n}\n",
            );
            test_repo::commit_all(repo, "commit 2");
        });

        assert_eq!(
            score.geometry.edited_symbols, 1,
            "control: one function was edited, got {:?}",
            score.geometry
        );
        assert_eq!(
            score.baseline.cognitive_before, 0,
            "the original body has no branching, got {:?}",
            score.baseline
        );
        assert!(
            score.baseline.cognitive_after > 0 && score.baseline.cognitive_delta > 0,
            "nested branching must raise the score, got {:?}",
            score.baseline
        );
        assert_eq!(
            score.baseline.max_cognitive_after as u64, score.baseline.cognitive_after,
            "one edited symbol makes the maximum and the total the same, got {:?}",
            score.baseline
        );
    }
}
