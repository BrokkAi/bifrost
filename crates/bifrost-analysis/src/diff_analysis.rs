use crate::analyzer::test_paths;
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, DependencyPackEcosystem, IAnalyzer, Language,
    ProjectFile,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{RevisionBlobIdentities, RevisionWorkspaceProjection, SharedAnalyzerCache};
use crate::gitblob::resolve_default_branch_ref;
use crate::profiling;
use crate::searchtools::{
    UsageGraphCallSite, UsageGraphEdge, UsageGraphParams, UsageGraphTruncatedSymbol, usage_graph,
};
use crate::{FileSetProject, FilesystemProject, ImportInfo, Project, WorkspaceAnalyzer};
use git2::{
    Delta, DiffFormat, DiffOptions, FileMode, ObjectType, Oid, Repository, TreeWalkMode,
    TreeWalkResult,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Endpoint label reported for the uncommitted working tree.
pub const WORKTREE_ENDPOINT: &str = "worktree";

/// Parameters for `analyze_diff`.
///
/// Both endpoints are optional; see [`resolve_endpoints`] for the resolution
/// table. `{}` means "merge base of HEAD and the default branch vs the working
/// tree".
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AnalyzeDiffParams {
    /// Revspec of the "before" endpoint. Defaults to the first parent of
    /// `target` when `target` is a commit. For the implicit working-tree target,
    /// it defaults to the merge base of `HEAD` and the default branch advertised
    /// by `refs/remotes/origin/HEAD`, falling back to `HEAD` when unavailable.
    #[serde(default)]
    pub base: Option<String>,
    /// Revspec of the "after" endpoint. Omitted means the working tree.
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default = "default_include_tests")]
    pub include_tests: bool,
}

/// Endpoint selectors shared by diff-derived tools.
#[derive(Debug, Clone, Default)]
pub struct DiffEndpointParams {
    pub base: Option<String>,
    pub target: Option<String>,
}

impl From<&AnalyzeDiffParams> for DiffEndpointParams {
    fn from(params: &AnalyzeDiffParams) -> Self {
        Self {
            base: params.base.clone(),
            target: params.target.clone(),
        }
    }
}

/// Trusted host configuration for immutable `analyze_diff` endpoints.
///
/// This deliberately is not deserializable from tool arguments: the directory
/// is a Git object database selected by the process host, not by an MCP caller.
#[derive(Debug, Clone, Default)]
pub struct DiffAnalysisOptions {
    pub snapshot_object_dir: Option<PathBuf>,
}

fn default_include_tests() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffAnalysisResult {
    pub endpoints: DiffEndpoints,
    pub file_changes: Vec<FileChange>,
    pub patch_symbols: PatchSymbols,
    pub dependency_symbols: Vec<CommitSymbol>,
    pub import_changes: Vec<ImportChange>,
    /// The call-edge changes left over after every patch symbol took the edges
    /// it calls, such as an untouched function in a changed file whose callee
    /// resolution moved under it. A caller that appears anywhere in
    /// `patch_symbols` reports its callee deltas there instead.
    pub unattributed_call_edge_changes: Vec<CallEdgeChange>,
    pub large_callsite_symbols: Vec<LargeCallsiteSymbol>,
}

/// Resolved diff endpoints. Fields are a full commit hash, `tree:<full hash>`,
/// or the literal [`WORKTREE_ENDPOINT`].
#[derive(Debug, Clone, Serialize)]
pub struct DiffEndpoints {
    pub base: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileChange {
    /// Preimage path, present only when it differs from `path` (a rename or a
    /// copy). Absent for a deletion, whose only path is `path`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Closed set, produced by [`delta_status`]: `added`, `deleted`,
    /// `modified`, `renamed`, `copied`, `typechange`, `conflicted`, `unknown`.
    /// A never-committed file in a working-tree diff reports `added`.
    pub status: String,
    /// Added lines, with `git diff --numstat` semantics: the count of `+` lines
    /// in the patch, so a pure rename reports 0 and `is_binary` reports 0.
    pub insertions: usize,
    /// Removed lines, with `git diff --numstat` semantics; see `insertions`.
    pub deletions: usize,
    /// Git treated the content as binary, so it emitted no line-level hunks.
    /// `insertions` and `deletions` are then both 0 -- the same information
    /// `git diff --numstat` spells as `-  -`.
    pub is_binary: bool,
    pub is_test: bool,
    pub is_parseable: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CommitSymbol {
    pub fqn: String,
    pub name: String,
    pub kind: String,
    pub signature: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub language: String,
    pub is_test: bool,
}

/// Symbol-level effects of the patch, partitioned by which endpoints hold the
/// symbol: `edited` for the two-endpoint case, `introduced` and `deleted` for
/// the one-endpoint cases. A symbol appears in at most one of the three.
#[derive(Debug, Clone, Serialize)]
pub struct PatchSymbols {
    pub edited: Vec<EditedSymbolPair>,
    pub introduced: Vec<IntroducedSymbol>,
    pub deleted: Vec<DeletedSymbol>,
    pub moved: Vec<MovedSymbol>,
    pub signature_changes: Vec<SignatureChange>,
}

/// Symbol endpoint pairing and patch tags before exact call-edge analysis.
///
/// This crate-private shape deliberately has no call collections. It is the
/// shared boundary consumed directly by `blast_radius`; only `analyze_diff`
/// converts it into [`PatchSymbols`] and enriches the records with exact call
/// deltas.
pub(crate) struct PairedSymbolChanges {
    pub(crate) edited: Vec<PairedEditedSymbol>,
    pub(crate) introduced: Vec<PairedIntroducedSymbol>,
    pub(crate) deleted: Vec<PairedDeletedSymbol>,
    pub(crate) moved: Vec<PairedMovedSymbol>,
    pub(crate) signature_changes: Vec<SignatureChange>,
}

pub(crate) struct PairedEditedSymbol {
    pub(crate) before: CommitSymbol,
    pub(crate) after: CommitSymbol,
    touched_old_lines: Vec<usize>,
    touched_new_lines: Vec<usize>,
}

pub(crate) struct PairedIntroducedSymbol {
    pub(crate) after: CommitSymbol,
    touched_new_lines: Vec<usize>,
}

pub(crate) struct PairedDeletedSymbol {
    pub(crate) before: CommitSymbol,
    touched_old_lines: Vec<usize>,
}

pub(crate) struct PairedMovedSymbol {
    pub(crate) before: CommitSymbol,
    pub(crate) after: CommitSymbol,
    similarity: Option<f64>,
}

impl PairedSymbolChanges {
    fn into_patch_symbols(self) -> PatchSymbols {
        PatchSymbols {
            edited: self
                .edited
                .into_iter()
                .map(|pair| EditedSymbolPair {
                    before: pair.before,
                    after: pair.after,
                    touched_old_lines: pair.touched_old_lines,
                    touched_new_lines: pair.touched_new_lines,
                    added_calls: Vec::new(),
                    removed_calls: Vec::new(),
                })
                .collect(),
            introduced: self
                .introduced
                .into_iter()
                .map(|record| IntroducedSymbol {
                    after: record.after,
                    touched_new_lines: record.touched_new_lines,
                    calls: Vec::new(),
                })
                .collect(),
            deleted: self
                .deleted
                .into_iter()
                .map(|record| DeletedSymbol {
                    before: record.before,
                    touched_old_lines: record.touched_old_lines,
                    called: Vec::new(),
                })
                .collect(),
            moved: self
                .moved
                .into_iter()
                .map(|record| MovedSymbol {
                    before: record.before,
                    after: record.after,
                    added_calls: Vec::new(),
                    removed_calls: Vec::new(),
                    similarity: record.similarity,
                })
                .collect(),
            signature_changes: self.signature_changes,
        }
    }
}

/// One outgoing call edge a patch symbol gained or lost.
///
/// This is [`CallEdgeChange`] without `from` and `change`, because both are
/// implied by position: the caller is the record holding the list, and the
/// direction is which of the record's two lists it lands in.
#[derive(Debug, Clone, Serialize)]
pub struct CalleeChange {
    pub to: String,
    pub language: String,
    pub weight: usize,
    pub sites: Vec<UsageGraphCallSite>,
}

/// A symbol present at both endpoints that some hunk touched.
///
/// The two line lists are the whole story about *how* it was touched, which is
/// why no separate reason field exists: an empty `touched_old_lines` means the
/// hunk only inserted, an empty `touched_new_lines` means it only deleted, and
/// both non-empty means it replaced. At least one is always non-empty -- an
/// untouched matched symbol is not reported here at all.
#[derive(Debug, Clone, Serialize)]
pub struct EditedSymbolPair {
    pub before: CommitSymbol,
    pub after: CommitSymbol,
    pub touched_old_lines: Vec<usize>,
    pub touched_new_lines: Vec<usize>,
    /// Callees this symbol reaches in the postimage and did not reach in the
    /// preimage.
    pub added_calls: Vec<CalleeChange>,
    /// Callees this symbol reached in the preimage and no longer reaches.
    pub removed_calls: Vec<CalleeChange>,
}

/// A symbol the postimage has and the preimage does not.
#[derive(Debug, Clone, Serialize)]
pub struct IntroducedSymbol {
    pub after: CommitSymbol,
    pub touched_new_lines: Vec<usize>,
    /// Everything the new symbol calls. One list rather than a pair, because a
    /// symbol the preimage does not have can only add edges.
    pub calls: Vec<CalleeChange>,
}

/// A symbol the preimage has and the postimage does not.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedSymbol {
    pub before: CommitSymbol,
    pub touched_old_lines: Vec<usize>,
    /// Everything the symbol used to call. One list rather than a pair, for the
    /// mirror of [`IntroducedSymbol::calls`]'s reason.
    pub called: Vec<CalleeChange>,
}

/// A symbol both endpoints hold at different locations, or under different
/// fully-qualified names because its file moved.
///
/// A pure move reports both call lists empty: the preimage graph is rewritten
/// through these very pairs before the two graphs are compared, so relocating a
/// symbol is not by itself a call-edge change. See [`fqn_renames`].
#[derive(Debug, Clone, Serialize)]
pub struct MovedSymbol {
    pub before: CommitSymbol,
    pub after: CommitSymbol,
    /// See [`EditedSymbolPair::added_calls`].
    pub added_calls: Vec<CalleeChange>,
    /// See [`EditedSymbolPair::removed_calls`].
    pub removed_calls: Vec<CalleeChange>,
    /// Present only when the pairing was *inferred* by body similarity (the
    /// fuzzy third rule of [`pair_endpoints`]) rather than established by an
    /// identity key or a Git-reported rename: the diff-local-IDF-weighted
    /// token-similarity score in `[threshold, 1.0]` (see [`body_similarity`]),
    /// rounded to two decimals. A consumer can use it to weigh these
    /// lower-confidence relocations accordingly. Identity and rename-bucket
    /// moves omit the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureChange {
    pub before: CommitSymbol,
    pub after: CommitSymbol,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportChange {
    pub path: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// A call edge the patch added or removed whose caller no patch symbol claims.
#[derive(Debug, Clone, Serialize)]
pub struct CallEdgeChange {
    /// Closed set, produced by [`diff_call_edges`]: `added` for an edge only the
    /// postimage graph has, `removed` for one only the preimage graph has. An
    /// edge present in both is not reported.
    pub change: String,
    pub from: String,
    pub to: String,
    pub language: String,
    pub weight: usize,
    pub sites: Vec<UsageGraphCallSite>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LargeCallsiteSymbol {
    pub fqn: String,
    pub language: String,
    pub total_callsites: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Default)]
struct ChangedLines {
    old: BTreeSet<usize>,
    new: BTreeSet<usize>,
}

/// Per-file `git diff --numstat` counters accumulated during the patch walk.
#[derive(Debug, Clone, Default)]
struct FileLineCounts {
    insertions: usize,
    deletions: usize,
    is_binary: bool,
}

#[derive(Debug, Clone)]
struct SymbolSnapshot {
    symbol: CommitSymbol,
    key: SymbolKey,
    /// Normalized token sequence of the symbol's body, or `None` when the body
    /// is too trivial to identify a move by content alone. Used only to pair
    /// leftovers that shared no identity key, by token similarity -- see
    /// [`pair_endpoints`] and [`body_similarity`].
    token_sig: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SymbolKey {
    fqn: String,
    kind: String,
    language: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    from: String,
    to: String,
    language: String,
}

/// One end of a diff: a commit, a bare tree, or the live working tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Snapshot {
    Commit(Oid),
    Tree(Oid),
    Worktree,
}

impl Snapshot {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Commit(oid) => oid.to_string(),
            Self::Tree(oid) => format!("tree:{oid}"),
            Self::Worktree => WORKTREE_ENDPOINT.to_string(),
        }
    }

    pub(crate) fn is_immutable(self) -> bool {
        !matches!(self, Self::Worktree)
    }
}

/// Resolve `params` into `(base, target)` snapshots.
///
/// | params                     | base                | target      |
/// |----------------------------|---------------------|-------------|
/// | `{}`                       | merge base of `HEAD` and default branch | working tree|
/// | `{target: X}`              | first parent of `X` | `X`         |
/// | `{base: A, target: B}`     | `A`                 | `B`         |
/// | `{base: A}`                | `A`                 | working tree|
///
fn resolve_endpoints(
    repo: &Repository,
    params: &DiffEndpointParams,
) -> Result<(Snapshot, Snapshot), String> {
    let target = match params.target.as_deref().map(str::trim) {
        Some(revision) if !revision.is_empty() => resolve_snapshot(repo, revision)?,
        _ => Snapshot::Worktree,
    };

    let base = match params.base.as_deref().map(str::trim) {
        Some(revision) if !revision.is_empty() => resolve_snapshot(repo, revision)?,
        _ => default_base(repo, target, params.target.as_deref())?,
    };

    Ok((base, target))
}

fn resolve_snapshot(repo: &Repository, revision: &str) -> Result<Snapshot, String> {
    let object = repo
        .revparse_single(revision)
        .map_err(|err| format!("unable to resolve revision `{revision}`: {err}"))?;
    if let Ok(commit) = object.peel_to_commit() {
        return Ok(Snapshot::Commit(commit.id()));
    }
    if let Ok(tree) = object.peel(ObjectType::Tree) {
        return Ok(Snapshot::Tree(tree.id()));
    }
    Err(format!(
        "revision `{revision}` resolves to {}, not a commit or tree",
        object
            .kind()
            .map_or("an unknown object type", |kind| match kind {
                ObjectType::Any => "an unspecified object",
                ObjectType::Commit => "a commit",
                ObjectType::Tree => "a tree",
                ObjectType::Blob => "a blob",
                ObjectType::Tag => "a tag",
            })
    ))
}

fn resolve_commit(repo: &Repository, revision: &str) -> Result<Oid, String> {
    match resolve_snapshot(repo, revision)? {
        Snapshot::Commit(oid) => Ok(oid),
        Snapshot::Tree(_) => Err(format!("revision `{revision}` is a tree, not a commit")),
        Snapshot::Worktree => unreachable!("explicit revisions never resolve to worktree"),
    }
}

/// Pick the implicit base when the caller omitted `base`.
fn default_base(
    repo: &Repository,
    target: Snapshot,
    target_revision: Option<&str>,
) -> Result<Snapshot, String> {
    match target {
        Snapshot::Worktree => default_worktree_base(repo).map(Snapshot::Commit),
        Snapshot::Commit(oid) => {
            let commit = repo
                .find_commit(oid)
                .map_err(|err| format!("unable to read commit {oid}: {err}"))?;
            // `resolve_endpoints` only produces a commit target from a revision
            // the caller spelled out, so the spelling echoed back in these
            // messages is always available.
            let spelling = target_revision.map(str::trim).unwrap_or_default();
            assert!(
                !spelling.is_empty(),
                "commit target {oid} resolved from an empty revision spelling"
            );
            match commit.parent_count() {
                0 => Err(format!(
                    "analyze_diff cannot default `base` for root commit `{spelling}`; \
                     root commits have no parent, so pass an explicit `base`"
                )),
                1 => commit
                    .parent_id(0)
                    .map(Snapshot::Commit)
                    .map_err(|err| format!("unable to read parent commit: {err}")),
                n => Err(format!(
                    "analyze_diff cannot default `base` for merge commit `{spelling}` \
                     ({n} parents); pass an explicit base such as `base: \"{spelling}^1\"`"
                )),
            }
        }
        Snapshot::Tree(_) => Err(format!(
            "analyze_diff cannot default `base` for tree endpoint `{}`; trees have no parent, so pass an explicit `base`",
            target_revision.map(str::trim).unwrap_or_default()
        )),
    }
}

fn default_worktree_base(repo: &Repository) -> Result<Oid, String> {
    let head = resolve_commit(repo, "HEAD").map_err(|err| {
        format!("unable to resolve HEAD while defaulting `base` for a working-tree diff: {err}")
    })?;
    let default_branch = resolve_default_branch_ref(repo);
    let default_head = resolve_commit(repo, &default_branch.ref_name).map_err(|err| {
        format!(
            "unable to resolve default branch `{}` while defaulting `base` for a working-tree diff: {err}",
            default_branch.display_name
        )
    })?;
    repo.merge_base(head, default_head).map_err(|err| {
        format!(
            "unable to find a merge base between HEAD and default branch `{}`: {err}",
            default_branch.display_name
        )
    })
}

pub fn analyze_diff(
    analyzer: &dyn IAnalyzer,
    params: AnalyzeDiffParams,
    options: &DiffAnalysisOptions,
) -> Result<DiffAnalysisResult, String> {
    analyze_diff_at_root(analyzer.project().root(), params, options)
}

pub fn analyze_diff_at_root(
    root: &Path,
    params: AnalyzeDiffParams,
    options: &DiffAnalysisOptions,
) -> Result<DiffAnalysisResult, String> {
    let prepared = PreparedDiff::at_root(root, DiffEndpointParams::from(&params), options)?;
    analyze_prepared_diff(&prepared, params.include_tests)
}

/// A resolved diff and its Git metadata, shared by tools derived from a diff.
///
/// The repository owner remains attached because immutable comparisons may use
/// a private bare repository whose lifetime must cover subsequent exports.
pub(crate) struct PreparedDiff {
    repository: DiffRepository,
    /// The repository's persisted analyzer cache, opened once for this request
    /// when either endpoint is immutable. `None` means only that both endpoints
    /// are mutable, so this request builds no revision image and needs no
    /// shared cache; a cache that exists but cannot be opened fails the request
    /// instead of downgrading it.
    shared_cache: Option<SharedAnalyzerCache>,
    pub(crate) base: Snapshot,
    pub(crate) target: Snapshot,
    pub(crate) file_changes: Vec<FileChange>,
    changed_lines: BTreeMap<String, ChangedLines>,
}

impl PreparedDiff {
    pub(crate) fn at_root(
        root: &Path,
        params: DiffEndpointParams,
        options: &DiffAnalysisOptions,
    ) -> Result<Self, String> {
        let resolution_repo = open_repository(root, options, false)?;
        let (base, target) = resolve_endpoints(&resolution_repo.repo, &params)?;
        let repository = if base.is_immutable() && target.is_immutable() {
            open_repository(root, options, true)?
        } else {
            resolution_repo
        };
        let (file_changes, changed_lines) = diff_metadata(&repository.repo, base, target)?;
        // Resolve the cache from the caller's root, never from an export
        // directory: `cache_dir_path` walks up to the primary repository, and a
        // temp export has no repository to walk up to.
        let shared_cache = if base.is_immutable() || target.is_immutable() {
            Some(SharedAnalyzerCache::open(root).map_err(|error| error.to_string())?)
        } else {
            None
        };
        Ok(Self {
            repository,
            shared_cache,
            base,
            target,
            file_changes,
            changed_lines,
        })
    }

    /// The persisted cache immutable images of this diff publish into.
    pub(crate) fn shared_cache(&self) -> Option<&SharedAnalyzerCache> {
        self.shared_cache.as_ref()
    }

    /// Build an analyzer over the *whole* target revision.
    ///
    /// An analyzed diff's own target endpoint carries only the diff's files
    /// plus what name resolution needs, which is everything the patch-symbol
    /// model reads. A question about the rest of the revision -- who calls a
    /// changed symbol, whether any test references it -- has no answer in that
    /// image, because the files that would hold the answer were never
    /// exported. This pays the whole-revision export and parse to get one. An
    /// immutable target reads the request's shared content-addressed cache, so
    /// it parses only the blobs no earlier request already published.
    pub(crate) fn whole_target_analysis(&self) -> Result<EndpointAnalysis, String> {
        let image = RevisionImage::materialize(
            &self.repository.repo,
            self.target,
            None,
            &self.repository.alternate_object_dirs,
            self.shared_cache(),
        )?;
        let analyzer = build_revision_analyzer(&image, self.shared_cache())?;
        Ok(EndpointAnalysis { analyzer, image })
    }

    /// Materialize the source and dependency-input files that can contribute
    /// to a file-dependency graph in `languages`.
    ///
    /// This is deliberately a separate seam from [`Self::materialize`]. The
    /// latter's `None` form means a complete immutable revision and is used by
    /// callers whose answer depends on every file. Blast-radius only needs the
    /// selected usage ecosystems, so exporting their source files avoids
    /// inflating unrelated language trees while retaining the manifests and
    /// build inputs that give those sources their identity.
    pub(crate) fn materialize_file_dependencies(
        &self,
        snapshot: Snapshot,
        languages: &BTreeSet<Language>,
    ) -> Result<RevisionImage, String> {
        RevisionImage::materialize_file_dependencies(
            &self.repository.repo,
            snapshot,
            languages,
            &self.repository.alternate_object_dirs,
        )
    }
}

pub(crate) struct PreparedSymbolChanges {
    symbol_changes: PairedSymbolChanges,
    context: SymbolChangesContext,
}

impl PreparedSymbolChanges {
    pub(crate) fn symbol_changes(&self) -> &PairedSymbolChanges {
        &self.symbol_changes
    }

    pub(crate) fn endpoint_analyzers(&self) -> (&dyn IAnalyzer, &dyn IAnalyzer) {
        (
            self.context.base_analyzer.analyzer(),
            self.context.target_analyzer.analyzer(),
        )
    }

    /// Consume the lightweight result without retaining endpoint analyzers that
    /// exist only so full diff analysis can continue into exact call edges.
    pub(crate) fn into_symbol_changes(self) -> PairedSymbolChanges {
        self.symbol_changes
    }
}

struct SymbolChangesContext {
    base_analyzer: RevisionAnalyzer,
    target_analyzer: RevisionAnalyzer,
    // Declared after the analyzers so the export directories outlive every
    // query that reads their files.
    _base_image: RevisionImage,
    _target_image: RevisionImage,
    after: BTreeMap<SymbolKey, SymbolSnapshot>,
    changed_paths: Vec<String>,
}

pub(crate) fn analyze_prepared_symbol_changes(
    prepared: &PreparedDiff,
    include_tests: bool,
) -> Result<PreparedSymbolChanges, String> {
    let (changed_paths, base_paths, target_paths) = symbol_change_paths(prepared);
    let repo = &prepared.repository.repo;
    let base_image = {
        let _scope = profiling::scope("diff_symbols.materialize_base");
        RevisionImage::materialize_symbols(
            repo,
            prepared.base,
            &base_paths,
            &prepared.repository.alternate_object_dirs,
        )?
    };
    let target_image = {
        let _scope = profiling::scope("diff_symbols.materialize_target");
        RevisionImage::materialize_symbols(
            repo,
            prepared.target,
            &target_paths,
            &prepared.repository.alternate_object_dirs,
        )?
    };
    analyze_prepared_symbol_changes_from_images(
        prepared,
        include_tests,
        base_image,
        target_image,
        changed_paths,
    )
}

fn symbol_change_paths(prepared: &PreparedDiff) -> (Vec<String>, Vec<String>, Vec<String>) {
    let file_changes = &prepared.file_changes;
    let changed_paths: Vec<String> = file_changes
        .iter()
        .flat_map(|change| [change.old_path.clone(), change.path.clone()])
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let base_paths: Vec<String> = file_changes
        .iter()
        .filter_map(|change| change.old_path.as_ref().or(change.path.as_ref()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let target_paths: Vec<String> = file_changes
        .iter()
        .filter_map(|change| change.path.as_ref())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    (changed_paths, base_paths, target_paths)
}

fn analyze_prepared_symbol_changes_from_images(
    prepared: &PreparedDiff,
    include_tests: bool,
    base_image: RevisionImage,
    target_image: RevisionImage,
    changed_paths: Vec<String>,
) -> Result<PreparedSymbolChanges, String> {
    let file_changes = &prepared.file_changes;
    let changed_lines = &prepared.changed_lines;
    let base_analyzer = {
        let _scope = profiling::scope("diff_symbols.build_base_analyzer");
        build_revision_analyzer(&base_image, prepared.shared_cache())?
    };
    let target_analyzer = {
        let _scope = profiling::scope("diff_symbols.build_target_analyzer");
        build_revision_analyzer(&target_image, prepared.shared_cache())?
    };

    let before = {
        let _scope = profiling::scope("diff_symbols.snapshot_base");
        symbol_snapshot_map(base_analyzer.analyzer(), include_tests)
    };
    let after = {
        let _scope = profiling::scope("diff_symbols.snapshot_target");
        symbol_snapshot_map(target_analyzer.analyzer(), include_tests)
    };

    let mut introduced = Vec::new();
    let mut edited = Vec::new();
    let mut deleted = Vec::new();
    let mut moved = Vec::new();
    let mut signature_changes = Vec::new();

    // A pair yields at most one `edited` record, which carries both endpoint
    // descriptors and both line lists. A hunk touching either side edits the
    // symbol, so the record exists whenever either overlap is non-empty; a
    // lopsided hunk simply leaves the untouched side's list empty. `introduced`
    // and `deleted` stay one-sided because only one endpoint has the symbol.
    //
    // Boundary, deliberately left as is: a paired symbol whose own lines see no
    // hunk is not reported edited even when the patch changed its meaning from
    // above (an enclosing scope or an import shifting parse context), and an
    // unpaired symbol with no overlap is likewise dropped rather than reported.
    let endpoint_pairing = {
        let _scope = profiling::scope("diff_symbols.pair_endpoints");
        pair_endpoints(&before, &after, file_changes)
    };
    for (pre, post) in &endpoint_pairing.pairs {
        // A paired symbol is only *moved* when it genuinely relocated -- its
        // name changed (body-identity pairing matched it under a new fqn), its
        // file changed, or its position changed by more than the patch's own
        // line offset accounts for. A symbol whose start line merely shifted
        // because lines were inserted/deleted ELSEWHERE in the file has not
        // moved; reporting it as such floods the result with one entry per
        // symbol below any early edit (a single insert near the top of a large
        // file otherwise yields hundreds of spurious "moved" rows).
        let relocated = pre.symbol.fqn != post.symbol.fqn
            || pre.symbol.path != post.symbol.path
            || (pre.symbol.start_line != post.symbol.start_line
                && !is_pure_line_shift(&pre.symbol, &post.symbol, changed_lines));
        let fallback_score = endpoint_pairing.fallback_paired.get(&pre.key).copied();
        if relocated {
            moved.push(PairedMovedSymbol {
                before: pre.symbol.clone(),
                after: post.symbol.clone(),
                similarity: fallback_score.map(|score| (score * 100.0).round() / 100.0),
            });
        }
        // A pair matched by the body-similarity rule (rather than by identity or
        // a Git rename) relocated -- and may have been renamed or lightly
        // edited -- but its touched lines are dominated by the relocation, not a
        // real edit. The `moved` entry above already carries the full before and
        // after symbols, so also reporting it as an edit -- with every cut line
        // "deleted" and every pasted line "inserted" -- or as a signature change
        // would be double-counting noise. Suppress both for those pairs.
        let relocated_by_body = fallback_score.is_some();
        if !relocated_by_body && pre.symbol.signature != post.symbol.signature {
            signature_changes.push(SignatureChange {
                before: pre.symbol.clone(),
                after: post.symbol.clone(),
            });
        }
        let touched_old_lines = old_overlap(&pre.symbol, changed_lines);
        let touched_new_lines = new_overlap(&post.symbol, changed_lines);
        if relocated_by_body || (touched_old_lines.is_empty() && touched_new_lines.is_empty()) {
            continue;
        }
        edited.push(PairedEditedSymbol {
            before: pre.symbol.clone(),
            after: post.symbol.clone(),
            touched_old_lines,
            touched_new_lines,
        });
    }
    for post in &endpoint_pairing.postimage_only {
        let touched_new_lines = new_overlap(&post.symbol, changed_lines);
        if !touched_new_lines.is_empty() {
            introduced.push(PairedIntroducedSymbol {
                after: post.symbol.clone(),
                touched_new_lines,
            });
        }
    }
    for pre in &endpoint_pairing.preimage_only {
        let touched_old_lines = old_overlap(&pre.symbol, changed_lines);
        if !touched_old_lines.is_empty() {
            deleted.push(PairedDeletedSymbol {
                before: pre.symbol.clone(),
                touched_old_lines,
            });
        }
    }

    edited.sort_by(|a, b| a.after.cmp(&b.after));
    introduced.sort_by(|a, b| a.after.cmp(&b.after));
    deleted.sort_by(|a, b| a.before.cmp(&b.before));
    moved.sort_by(|a, b| a.after.cmp(&b.after));
    signature_changes.sort_by(|a, b| a.after.cmp(&b.after));

    Ok(PreparedSymbolChanges {
        symbol_changes: PairedSymbolChanges {
            edited,
            introduced,
            deleted,
            moved,
            signature_changes,
        },
        context: SymbolChangesContext {
            base_analyzer,
            target_analyzer,
            _base_image: base_image,
            _target_image: target_image,
            after,
            changed_paths,
        },
    })
}

/// One diff endpoint's on-disk image and the analyzer built over it.
///
/// Declaration order is drop order: the analyzer releases the export before the
/// temporary directory holding it is removed.
pub(crate) struct EndpointAnalysis {
    analyzer: RevisionAnalyzer,
    image: RevisionImage,
}

impl EndpointAnalysis {
    pub(crate) fn analyzer(&self) -> &dyn IAnalyzer {
        self.analyzer.analyzer()
    }

    /// Directory the endpoint's files live in: a private export for a committed
    /// endpoint, the project root itself for the working tree.
    pub(crate) fn root(&self) -> &Path {
        self.image.root()
    }
}

/// [`analyze_prepared_diff`]'s result together with the endpoint analyses that
/// produced it, so a derived analysis can ask further questions of the very
/// same two revision images instead of exporting and re-parsing them.
pub(crate) struct AnalyzedDiff {
    pub(crate) result: DiffAnalysisResult,
    pub(crate) base: EndpointAnalysis,
    pub(crate) target: EndpointAnalysis,
}

pub(crate) fn analyze_prepared_diff(
    prepared: &PreparedDiff,
    include_tests: bool,
) -> Result<DiffAnalysisResult, String> {
    analyze_prepared_diff_with_endpoints(prepared, include_tests).map(|analyzed| analyzed.result)
}

pub(crate) fn analyze_prepared_diff_with_endpoints(
    prepared: &PreparedDiff,
    include_tests: bool,
) -> Result<AnalyzedDiff, String> {
    let (changed_paths, base_paths, target_paths) = symbol_change_paths(prepared);
    let repo = &prepared.repository.repo;
    let base_image = {
        let _scope = profiling::scope("diff_exact.materialize_base");
        RevisionImage::materialize(
            repo,
            prepared.base,
            Some(&base_paths),
            &prepared.repository.alternate_object_dirs,
            prepared.shared_cache(),
        )?
    };
    let target_image = {
        let _scope = profiling::scope("diff_exact.materialize_target");
        RevisionImage::materialize(
            repo,
            prepared.target,
            Some(&target_paths),
            &prepared.repository.alternate_object_dirs,
            prepared.shared_cache(),
        )?
    };
    let PreparedSymbolChanges {
        symbol_changes,
        context,
    } = analyze_prepared_symbol_changes_from_images(
        prepared,
        include_tests,
        base_image,
        target_image,
        changed_paths,
    )?;
    let PatchSymbols {
        mut edited,
        mut introduced,
        mut deleted,
        mut moved,
        signature_changes,
    } = symbol_changes.into_patch_symbols();
    // Each image is rejoined to the analyzer built over it, and
    // `EndpointAnalysis` declares the analyzer first so the analyzer drops
    // before the export directory it reads files out of.
    let SymbolChangesContext {
        _base_image: base_image,
        _target_image: target_image,
        base_analyzer,
        target_analyzer,
        after,
        changed_paths,
    } = context;
    let base = prepared.base;
    let target = prepared.target;
    let file_changes = &prepared.file_changes;

    let import_changes = import_changes(
        base_analyzer.analyzer(),
        target_analyzer.analyzer(),
        &changed_paths,
    );
    let graph_before = usage_graph(
        base_analyzer.analyzer(),
        UsageGraphParams {
            include_tests,
            paths: Some(changed_paths.clone()),
            depth: 1,
        },
    );
    let graph_after = usage_graph(
        target_analyzer.analyzer(),
        UsageGraphParams {
            include_tests,
            paths: Some(changed_paths),
            depth: 1,
        },
    );
    let CallEdgeDiff {
        deltas,
        dependency_symbols,
    } = diff_call_edges(
        &graph_before.edges,
        &graph_after.edges,
        &fqn_renames(&moved),
        &after,
    );

    // Hand each patch symbol the callee delta recorded under its name, so the
    // consumer never has to join a flat edge list against the symbol lists. A
    // symbol that was both edited and moved appears in two lists and takes the
    // same delta twice, which is why this reads the map instead of draining it.
    //
    // Claims are per direction, not per symbol: a one-sided record claims only
    // the direction it can express. An fqn that names a function at one endpoint
    // and a class at the other is introduced and deleted at once, and each
    // record then still reports its own half rather than swallowing both.
    let mut claimed_added: HashSet<CallerKey> = HashSet::new();
    let mut claimed_removed: HashSet<CallerKey> = HashSet::new();
    for pair in &mut edited {
        let key = symbol_edge_key(&pair.after);
        if let Some(delta) = deltas.get(&key) {
            pair.added_calls.clone_from(&delta.added);
            pair.removed_calls.clone_from(&delta.removed);
        }
        claimed_added.insert(key.clone());
        claimed_removed.insert(key);
    }
    for record in &mut moved {
        let key = symbol_edge_key(&record.after);
        if let Some(delta) = deltas.get(&key) {
            record.added_calls.clone_from(&delta.added);
            record.removed_calls.clone_from(&delta.removed);
        }
        claimed_added.insert(key.clone());
        claimed_removed.insert(key);
    }
    for record in &mut introduced {
        let key = symbol_edge_key(&record.after);
        if let Some(delta) = deltas.get(&key) {
            record.calls.clone_from(&delta.added);
        }
        claimed_added.insert(key);
    }
    for record in &mut deleted {
        let key = symbol_edge_key(&record.before);
        if let Some(delta) = deltas.get(&key) {
            record.called.clone_from(&delta.removed);
        }
        claimed_removed.insert(key);
    }
    let unattributed_call_edge_changes =
        flatten_unattributed(deltas, &claimed_added, &claimed_removed);

    let patch_symbols = PatchSymbols {
        edited,
        introduced,
        deleted,
        moved,
        signature_changes,
    };
    let large_callsite_symbols = large_callsite_symbols(
        graph_before.truncated_symbols,
        graph_after.truncated_symbols,
    );

    Ok(AnalyzedDiff {
        result: DiffAnalysisResult {
            endpoints: DiffEndpoints {
                base: base.label(),
                target: target.label(),
            },
            file_changes: file_changes.clone(),
            patch_symbols,
            dependency_symbols,
            import_changes,
            unattributed_call_edge_changes,
            large_callsite_symbols,
        },
        base: EndpointAnalysis {
            analyzer: base_analyzer,
            image: base_image,
        },
        target: EndpointAnalysis {
            analyzer: target_analyzer,
            image: target_image,
        },
    })
}

struct DiffRepository {
    repo: Repository,
    /// Object directories explicitly trusted by the host for this request.
    /// libgit2 attaches them in memory; Git subprocesses receive the identical
    /// closed set through `GIT_ALTERNATE_OBJECT_DIRECTORIES`.
    alternate_object_dirs: Vec<PathBuf>,
    // Must outlive `repo`: it owns the private bare repository backing an
    // immutable comparison.
    _temp: Option<RevisionTempDir>,
}

fn open_repository(
    root: &Path,
    options: &DiffAnalysisOptions,
    bare: bool,
) -> Result<DiffRepository, String> {
    let repo = if bare {
        let discovered = Repository::open(root)
            .map_err(|err| format!("not a git repository at project root: {err}"))?;
        let source_objects = discovered.commondir().join("objects");
        let temp = RevisionTempDir::new("immutable-odb")?;
        let repo = Repository::init_bare(temp.path()).map_err(|err| {
            format!(
                "unable to create isolated immutable diff repository {}: {err}",
                temp.path().display()
            )
        })?;
        add_odb_alternate(&repo, &source_objects, "repository object directory")?;
        let mut alternate_object_dirs = vec![source_objects];
        let repo = attach_snapshot_alternate(repo, options, &mut alternate_object_dirs)?;
        return Ok(DiffRepository {
            repo,
            alternate_object_dirs,
            _temp: Some(temp),
        });
    } else {
        Repository::open(root)
    }
    .map_err(|err| format!("not a git repository at project root: {err}"))?;
    let mut alternate_object_dirs = Vec::new();
    attach_snapshot_alternate(repo, options, &mut alternate_object_dirs).map(|repo| {
        DiffRepository {
            repo,
            alternate_object_dirs,
            _temp: None,
        }
    })
}

fn attach_snapshot_alternate(
    repo: Repository,
    options: &DiffAnalysisOptions,
    alternate_object_dirs: &mut Vec<PathBuf>,
) -> Result<Repository, String> {
    if let Some(path) = options.snapshot_object_dir.as_deref() {
        add_odb_alternate(&repo, path, "configured diff snapshot object directory")?;
        alternate_object_dirs.push(path.to_path_buf());
    }
    Ok(repo)
}

fn add_odb_alternate(repo: &Repository, path: &Path, description: &str) -> Result<(), String> {
    if !path.is_dir() {
        return Err(format!(
            "{description} {} does not exist or is not a directory",
            path.display()
        ));
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| format!("{description} {} is not valid UTF-8", path.display()))?;
    repo.odb()
        .and_then(|odb| odb.add_disk_alternate(path_str))
        .map_err(|err| format!("unable to attach {description} {}: {err}", path.display()))
}

fn diff_metadata(
    repo: &Repository,
    base: Snapshot,
    target: Snapshot,
) -> Result<(Vec<FileChange>, BTreeMap<String, ChangedLines>), String> {
    let base_tree = snapshot_tree(repo, base)?;
    let mut opts = DiffOptions::new();
    let mut diff = match target {
        Snapshot::Commit(_) | Snapshot::Tree(_) => {
            let target_tree = snapshot_tree(repo, target)?;
            repo.diff_tree_to_tree(Some(&base_tree), Some(&target_tree), Some(&mut opts))
        }
        Snapshot::Worktree => {
            // `git diff <base>` semantics: staged and unstaged changes combined,
            // plus brand-new files as `added` (ignored files stay excluded).
            // `show_untracked_content` is what makes an untracked file's lines
            // appear as `+` hunks, which is how its symbols get attributed.
            opts.include_untracked(true)
                .recurse_untracked_dirs(true)
                .show_untracked_content(true);
            repo.diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut opts))
        }
    }
    .map_err(|err| format!("diff failed: {err}"))?;
    let _ = diff.find_similar(None);

    let mut changes = Vec::new();
    for delta in diff.deltas() {
        let old_path = delta.old_file().path().map(path_string);
        let new_path = delta.new_file().path().map(path_string);
        let display_path = new_path
            .clone()
            .or_else(|| old_path.clone())
            .unwrap_or_default();
        changes.push(FileChange {
            old_path: old_path.filter(|old| Some(old) != new_path.as_ref()),
            path: new_path,
            status: delta_status(delta.status()).to_string(),
            insertions: 0,
            deletions: 0,
            is_binary: false,
            is_test: test_paths::is_test_like_path(
                &display_path,
                path_language(Path::new(&display_path)),
            ),
            is_parseable: is_parseable_path(&display_path),
        });
    }

    // One walk feeds two consumers keyed differently on purpose. `changed_lines`
    // is keyed per side -- `+` lines under the postimage path and `-` lines
    // under the preimage path -- because symbol ranges resolve against the
    // endpoint they came from, so a rename must not cross-contaminate. The
    // per-file counts are keyed by the delta's display path, matching how
    // `changes` is looked up below, and cover every file the diff touches
    // rather than only the parseable ones.
    let mut changed_lines: BTreeMap<String, ChangedLines> = BTreeMap::new();
    let mut counts: BTreeMap<String, FileLineCounts> = BTreeMap::new();
    diff.print(DiffFormat::Patch, |delta, _hunk, line| {
        // A delta always names at least one side; a hypothetical pathless one
        // accumulates under the empty key, which no `FileChange` ever looks up.
        let display_path = delta
            .new_file()
            .path()
            .or_else(|| delta.old_file().path())
            .map(path_string)
            .unwrap_or_default();
        let counts = counts.entry(display_path).or_default();
        // Git emits no line hunks for binary content, so a binary delta reaches
        // this callback only as a `Binary files ... differ` marker; that plus
        // the flag libgit2 sets once it has inspected the content is what makes
        // `is_binary` true with both counts left at 0.
        if delta.flags().contains(git2::DiffFlags::BINARY) || line.origin() == 'B' {
            counts.is_binary = true;
        }
        match line.origin() {
            '+' => {
                counts.insertions += 1;
                if let (Some(path), Some(line_no)) =
                    (delta.new_file().path().map(path_string), line.new_lineno())
                {
                    changed_lines
                        .entry(path)
                        .or_default()
                        .new
                        .insert(line_no as usize);
                }
            }
            '-' => {
                counts.deletions += 1;
                if let (Some(path), Some(line_no)) =
                    (delta.old_file().path().map(path_string), line.old_lineno())
                {
                    changed_lines
                        .entry(path)
                        .or_default()
                        .old
                        .insert(line_no as usize);
                }
            }
            _ => {}
        }
        true
    })
    .map_err(|err| format!("unable to enumerate diff lines: {err}"))?;

    for change in &mut changes {
        // A delta the walk never reported a line for keeps the zeroes it was
        // built with, which is already the right answer for it.
        if let Some(counts) = change
            .path
            .as_ref()
            .or(change.old_path.as_ref())
            .and_then(|path| counts.get(path))
        {
            change.insertions = counts.insertions;
            change.deletions = counts.deletions;
            change.is_binary = counts.is_binary;
        }
    }
    changes.sort_by(|a, b| {
        a.path
            .as_deref()
            .or(a.old_path.as_deref())
            .cmp(&b.path.as_deref().or(b.old_path.as_deref()))
    });
    Ok((changes, changed_lines))
}

fn snapshot_tree(repo: &Repository, snapshot: Snapshot) -> Result<git2::Tree<'_>, String> {
    match snapshot {
        Snapshot::Commit(oid) => repo
            .find_commit(oid)
            .and_then(|commit| commit.tree())
            .map_err(|err| format!("unable to read tree for commit {oid}: {err}")),
        Snapshot::Tree(oid) => repo
            .find_tree(oid)
            .map_err(|err| format!("unable to read tree {oid}: {err}")),
        Snapshot::Worktree => Err("working tree has no immutable Git tree".to_string()),
    }
}

/// An analyzable image of one diff endpoint.
///
/// An immutable endpoint -- a commit or a bare tree -- is materialized under a
/// private temp directory from its resolved tree; the working-tree endpoint is
/// analyzed in place from the real project root.
///
/// What a snapshot names depends on which materializer built it. The two
/// path-restricted ones (`materialize`, `materialize_symbols`) name the diff's
/// own changed paths plus what `export_snapshot_files` adds for name resolution
/// and newly-referenced packages, and write every byte of them.
/// `materialize_file_dependencies` names the whole selected ecosystem, because
/// a file graph that omits a file reads its absence as absence, but writes only
/// the analyzers' configuration inputs: every other named path is created empty
/// so module resolution's filesystem probes still find it, and its bytes are
/// served on demand from `objects`. Either way the image names every file it
/// claims to analyze, with the blob id that identifies it.
pub(crate) enum RevisionImage {
    Snapshot {
        temp: RevisionTempDir,
        files: Vec<PathBuf>,
        /// The blob ids the image's tree walk already resolved for `files`.
        /// A tree entry carries its blob id, so this inventory costs nothing to
        /// collect and saves the analyzer a read-and-hash of every exported
        /// byte: the export directory holds no Git repository, so nothing there
        /// can tell the analyzer what these files are.
        blobs: Arc<RevisionBlobIdentities>,
        /// Serves the bytes of any named file the export did not write.
        objects: Arc<RevisionObjectDatabase>,
    },
    Worktree {
        root: PathBuf,
        files: Vec<PathBuf>,
    },
}

impl RevisionImage {
    /// Assemble a snapshot image from one materialization's `(path, blob id)`
    /// inventory.
    ///
    /// The inventory names every analyzer-visible file of the revision whether
    /// or not its bytes were written to `temp`; the object database serves the
    /// rest.
    fn snapshot(
        temp: RevisionTempDir,
        written: Vec<(PathBuf, Oid)>,
        named_only: Vec<(PathBuf, Oid)>,
        repo: &Repository,
        alternate_object_dirs: &[PathBuf],
    ) -> Result<Self, String> {
        let files = written
            .iter()
            .chain(named_only.iter())
            .map(|(path, _)| path.clone())
            .collect();
        let objects = RevisionObjectDatabase::new(repo, alternate_object_dirs);
        if let Some((_, oid)) = named_only.first().or_else(|| written.first()) {
            objects.probe(*oid)?;
        }
        Ok(Self::Snapshot {
            temp,
            files,
            blobs: Arc::new(RevisionBlobIdentities::new(written, named_only)),
            objects: Arc::new(objects),
        })
    }

    /// `paths: None` exports every file in the snapshot, for `export_revision`'s
    /// whole-tree policy gating. `paths: Some(_)` restricts the export to
    /// those paths plus what's described above.
    ///
    /// `cache` reaches only the path-restricted branch, whose import expansion
    /// analyzes the changed files to find the packages they now reference. The
    /// complete-tree branch has no expansion step to route: it already holds
    /// every file of the revision.
    fn materialize(
        repo: &Repository,
        snapshot: Snapshot,
        paths: Option<&[String]>,
        alternate_object_dirs: &[PathBuf],
        cache: Option<&SharedAnalyzerCache>,
    ) -> Result<Self, String> {
        match snapshot {
            Snapshot::Commit(oid) | Snapshot::Tree(oid) => {
                let temp = RevisionTempDir::new(&oid.to_string())?;
                let exported = match paths {
                    Some(paths) => {
                        export_snapshot_files(repo, snapshot, temp.path(), paths, cache)?
                    }
                    None => {
                        export_complete_tree(repo, &snapshot_tree(repo, snapshot)?, temp.path())?
                    }
                };
                Self::snapshot(temp, exported, Vec::new(), repo, alternate_object_dirs)
            }
            Snapshot::Worktree => {
                let root = repo
                    .workdir()
                    .ok_or_else(|| {
                        "repository has no working tree; pass an explicit `target` commit"
                            .to_string()
                    })?
                    .to_path_buf();
                let files = match paths {
                    Some(paths) => worktree_files(&root, paths)?,
                    None => {
                        let project = FilesystemProject::new(&root).map_err(|err| {
                            format!("unable to list working tree {}: {err}", root.display())
                        })?;
                        project
                            .all_files()
                            .map_err(|err| {
                                format!("unable to list working tree {}: {err}", root.display())
                            })?
                            .into_iter()
                            .map(|file| file.rel_path().to_path_buf())
                            .collect()
                    }
                };
                Ok(Self::Worktree { root, files })
            }
        }
    }

    /// Materialize only what callable discovery needs: the changed files plus
    /// ambient ancestor manifests that establish package/crate identity.
    ///
    /// Exact diff analysis uses [`Self::materialize`] because call resolution
    /// also needs imported target packages. Callable pairing never resolves
    /// calls, so recursively exporting those packages is wasted work and can
    /// be slower than exporting a complete large revision.
    fn materialize_symbols(
        repo: &Repository,
        snapshot: Snapshot,
        paths: &[String],
        alternate_object_dirs: &[PathBuf],
    ) -> Result<Self, String> {
        match snapshot {
            Snapshot::Commit(oid) | Snapshot::Tree(oid) => {
                let temp = RevisionTempDir::new(&oid.to_string())?;
                let exported = export_snapshot_symbol_files(repo, snapshot, temp.path(), paths)?;
                Self::snapshot(temp, exported, Vec::new(), repo, alternate_object_dirs)
            }
            Snapshot::Worktree => {
                let root = repo
                    .workdir()
                    .ok_or_else(|| {
                        "repository has no working tree; pass an explicit `target` commit"
                            .to_string()
                    })?
                    .to_path_buf();
                let files = worktree_symbol_files(&root, paths)?;
                Ok(Self::Worktree { root, files })
            }
        }
    }

    /// Materialize the bounded immutable image consumed by blast-radius's
    /// coarse file-dependency graph. Every analyzer-visible source file in a
    /// selected usage ecosystem is retained, along with the package/build
    /// inputs that existing workspace analyzers read for that ecosystem.
    ///
    /// `materialize` remains the complete-tree operation for `paths: None`;
    /// keeping this operation separate prevents a caller from accidentally
    /// changing that long-standing whole-revision contract.
    fn materialize_file_dependencies(
        repo: &Repository,
        snapshot: Snapshot,
        languages: &BTreeSet<Language>,
        alternate_object_dirs: &[PathBuf],
    ) -> Result<Self, String> {
        match snapshot {
            Snapshot::Commit(oid) | Snapshot::Tree(oid) => {
                let temp = RevisionTempDir::new(&oid.to_string())?;
                let tree = snapshot_tree(repo, snapshot)?;
                let exported = export_file_dependency_tree(
                    repo,
                    &tree,
                    temp.path(),
                    languages,
                    alternate_object_dirs,
                )?;
                Self::snapshot(
                    temp,
                    exported.configuration_inputs,
                    exported.sources,
                    repo,
                    alternate_object_dirs,
                )
            }
            Snapshot::Worktree => {
                let root = repo
                    .workdir()
                    .ok_or_else(|| {
                        "repository has no working tree; pass an explicit `target` commit"
                            .to_string()
                    })?
                    .to_path_buf();
                let project = FilesystemProject::new(&root).map_err(|err| {
                    format!("unable to list working tree {}: {err}", root.display())
                })?;
                let files = project
                    .all_files()
                    .map_err(|err| {
                        format!("unable to list working tree {}: {err}", root.display())
                    })?
                    .into_iter()
                    .map(|file| file.rel_path().to_path_buf())
                    .filter(|path| file_dependency_tree_path(path, languages))
                    .collect();
                Ok(Self::Worktree { root, files })
            }
        }
    }

    pub(crate) fn root(&self) -> &Path {
        match self {
            Self::Snapshot { temp, .. } => temp.path(),
            Self::Worktree { root, .. } => root,
        }
    }

    pub(crate) fn files(&self) -> &[PathBuf] {
        match self {
            Self::Snapshot { files, .. } | Self::Worktree { files, .. } => files,
        }
    }

    /// The project an analyzer of this image reads through, paired with the
    /// revision's own blob ids when it has them.
    ///
    /// A worktree image has neither: its root is the live project root, which
    /// is a real Git repository, so the analyzer's ordinary identity source
    /// both answers for it and sees the uncommitted edits this image must
    /// respect, and its bytes are the files on disk.
    fn project(&self) -> (Arc<dyn Project>, Option<Arc<RevisionBlobIdentities>>) {
        let files = FileSetProject::new(self.root().to_path_buf(), self.files().iter().cloned());
        match self {
            Self::Snapshot { blobs, objects, .. } => (
                Arc::new(RevisionImageProject {
                    files,
                    objects: Arc::clone(objects),
                    blobs: Arc::clone(blobs),
                }),
                Some(Arc::clone(blobs)),
            ),
            Self::Worktree { .. } => (Arc::new(files), None),
        }
    }
}

/// A complete private on-disk export of one committed revision's workspace
/// subtree, plus the resolved commit id.
///
/// Diff-aware policy gating evaluates policies against this image instead of
/// the checkout. The export directory lives under the process temp directory
/// with owner-only permissions and is deleted when this value drops.
pub struct RevisionExport {
    image: RevisionImage,
    commit_id: String,
}

impl RevisionExport {
    /// Root directory containing the exported files.
    pub fn root(&self) -> &Path {
        self.image.root()
    }

    /// Workspace-relative paths of every exported regular file.
    pub fn files(&self) -> &[PathBuf] {
        self.image.files()
    }

    /// Full hex id of the commit the requested revision resolved to.
    pub fn commit_id(&self) -> &str {
        &self.commit_id
    }

    /// The exported image, for a caller that analyzes it through
    /// [`build_revision_analyzer`] rather than reading its files directly.
    pub(crate) fn image(&self) -> &RevisionImage {
        &self.image
    }

    /// Build an analyzer over this whole exported revision, reading and writing
    /// the primary repository's shared content-addressed cache.
    ///
    /// `repository_root` is the *live* workspace root this export came from,
    /// never [`Self::root`]. The cache location resolves through the standard
    /// funnel, which walks up to the primary repository, and a temp export
    /// directory has no repository to walk up to. Because the revision's
    /// content is immutable, every fact this build publishes is keyed by blob
    /// id and is reusable by the worktree build, by a linked worktree, and by
    /// every later revision request -- and this build in turn parses only the
    /// blobs no earlier request already published.
    ///
    /// The returned value borrows nothing, but the files it analyzes live under
    /// this export, so the caller must keep the export alive for the whole
    /// lifetime of the returned workspace: dropping the export deletes the tree
    /// out from under it.
    pub fn build_workspace(&self, repository_root: &Path) -> Result<RevisionWorkspace, String> {
        let cache =
            SharedAnalyzerCache::open(repository_root).map_err(|error| error.to_string())?;
        // Claimed before the build, so a build that fails partway still leaves
        // no rows naming this export's directory behind.
        let projection = cache.claim_revision_workspace(self.image.root());
        let (project, blobs) = self.image.project();
        let blobs = blobs.expect(
            "an export always materializes a snapshot image, which carries the revision's blob ids",
        );
        let workspace = WorkspaceAnalyzer::build_revision_image(
            project,
            AnalyzerConfig::default(),
            None,
            Some(&cache),
            blobs,
        )
        .map_err(|error| format!("Failed to build the revision export analyzer: {error}"))?;
        Ok(RevisionWorkspace {
            workspace,
            _projection: projection,
        })
    }
}

/// An analyzer over one whole exported revision, together with the workspace
/// projection rows that export published into the shared analyzer cache.
///
/// The projection is declared after the analyzer so it drops after it: every
/// query the request makes still sees the export's files mounted, and the rows
/// naming a temp-directory root are gone before the request returns.
pub struct RevisionWorkspace {
    workspace: WorkspaceAnalyzer,
    _projection: RevisionWorkspaceProjection,
}

impl RevisionWorkspace {
    /// The built analyzer. Concrete rather than `&dyn IAnalyzer` because pack
    /// activation and policy evaluation both read the workspace itself.
    pub fn workspace(&self) -> &WorkspaceAnalyzer {
        &self.workspace
    }
}

/// Resolve `revision` in the repository that contains `workspace_root`, peel it
/// to a commit, and export that commit's workspace subtree into a private
/// temporary directory.
///
/// `workspace_root` may be the repository work-tree root or a subdirectory of
/// it. The export always contains paths relative to `workspace_root`, so a
/// finding identity computed over the export joins with one computed over the
/// live workspace.
pub fn export_revision(workspace_root: &Path, revision: &str) -> Result<RevisionExport, String> {
    let repo = Repository::discover(workspace_root).map_err(|err| {
        format!(
            "workspace root {} is not inside a git repository: {err}",
            workspace_root.display()
        )
    })?;
    let commit_id = match resolve_snapshot(&repo, revision)? {
        Snapshot::Commit(oid) => oid,
        Snapshot::Tree(_) => {
            return Err(format!("revision `{revision}` is a tree, not a commit"));
        }
        Snapshot::Worktree => unreachable!("explicit revisions never resolve to worktree"),
    };
    let workdir = repo.workdir().ok_or_else(|| {
        format!(
            "repository for {} has no working tree",
            workspace_root.display()
        )
    })?;
    let workdir = workdir.canonicalize().map_err(|err| {
        format!(
            "unable to resolve repository work tree {}: {err}",
            workdir.display()
        )
    })?;
    let workspace_root = workspace_root.canonicalize().map_err(|err| {
        format!(
            "unable to resolve workspace root {}: {err}",
            workspace_root.display()
        )
    })?;
    let prefix = workspace_root.strip_prefix(&workdir).map_err(|_| {
        format!(
            "workspace root {} is outside the repository work tree {}",
            workspace_root.display(),
            workdir.display()
        )
    })?;
    let commit_tree = repo
        .find_commit(commit_id)
        .and_then(|commit| commit.tree())
        .map_err(|err| format!("unable to read tree for commit {commit_id}: {err}"))?;
    let tree = if prefix.as_os_str().is_empty() {
        commit_tree
    } else {
        commit_tree
            .get_path(prefix)
            .map_err(|err| {
                format!(
                    "revision `{revision}` has no entry for workspace directory `{}`: {err}",
                    prefix.display()
                )
            })?
            .to_object(&repo)
            .and_then(|object| object.peel_to_tree())
            .map_err(|err| {
                format!(
                    "workspace directory `{}` at revision `{revision}` is not a directory: {err}",
                    prefix.display()
                )
            })?
    };
    let subtree = Snapshot::Tree(tree.id());
    // The complete-tree branch runs no import expansion, so there is nothing
    // here for a shared cache to serve. `correspond_revisions` opens the cache
    // itself and hands it to the analyzer it builds over this image.
    let image = RevisionImage::materialize(&repo, subtree, None, &[], None)?;
    Ok(RevisionExport {
        image,
        commit_id: commit_id.to_string(),
    })
}

/// Every regular file anywhere under `dir`, recursively, as paths relative to
/// `root`. Filesystem analog of [`tree_dir_file_paths`]; see its doc comment
/// for why an import-expansion target needs a recursive walk rather than a
/// direct-children listing.
fn fs_dir_file_paths(root: &Path, dir: &Path) -> Vec<PathBuf> {
    if !fs::symlink_metadata(dir)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
    {
        return Vec::new();
    }
    walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| entry.path().strip_prefix(root).ok().map(Path::to_path_buf))
        .collect()
}

/// Collect the changed paths that actually exist as regular files on disk,
/// plus everything [`symbol_identity_ancestor_paths_fs`] and
/// [`worktree_import_expansion_targets`] add for the same reasons
/// `export_snapshot_files` does for a committed endpoint.
///
/// A path deleted in the working tree still appears in the diff but has no
/// file to analyze, so it is skipped the same way a missing tree entry is.
fn worktree_files(root: &Path, paths: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut present = worktree_symbol_files(root, paths)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut changed = Vec::with_capacity(paths.len());
    for raw_path in paths {
        let rel = safe_tree_entry_path(raw_path)?;
        let absolute = root.join(&rel);
        let is_regular_file = fs::symlink_metadata(&absolute)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
        if is_regular_file {
            changed.push(rel);
        }
    }
    for target in worktree_import_expansion_targets(root, &changed)? {
        match target {
            ImportExpansionTarget::Directory(dir) => {
                present.extend(fs_dir_file_paths(root, &root.join(&dir)));
            }
            ImportExpansionTarget::File(file) => {
                if fs::symlink_metadata(root.join(&file))
                    .map(|metadata| metadata.file_type().is_file())
                    .unwrap_or(false)
                {
                    present.insert(file);
                }
            }
        }
    }
    Ok(present.into_iter().collect())
}

fn worktree_symbol_files(root: &Path, paths: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut present = BTreeSet::new();
    for raw_path in paths {
        let rel = safe_tree_entry_path(raw_path)?;
        let is_regular_file = fs::symlink_metadata(root.join(&rel))
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
        if is_regular_file {
            present.insert(rel);
        }
    }
    present.extend(symbol_identity_ancestor_paths_fs(root, paths));
    Ok(present.into_iter().collect())
}

/// Analyzer configuration and package-identity files sitting directly inside
/// an ancestor directory of a changed path, up to `root`, deduplicated across
/// `paths`. Filesystem analog of [`symbol_identity_ancestor_paths`].
fn symbol_identity_ancestor_paths_fs(root: &Path, paths: &[String]) -> Vec<PathBuf> {
    let mut visited_dirs = BTreeSet::new();
    let mut ambient = Vec::new();
    for raw_path in paths {
        let Ok(rel) = safe_tree_entry_path(raw_path) else {
            continue;
        };
        let mut dir = rel.parent();
        while let Some(current) = dir {
            // See `symbol_identity_ancestor_paths`: once a directory is
            // revisited, the rest of this path's ancestors were already swept.
            if !visited_dirs.insert(current.to_path_buf()) {
                break;
            }
            for entry in fs::read_dir(root.join(current))
                .into_iter()
                .flatten()
                .flatten()
            {
                let path = entry.path();
                if symbol_identity_file(&path)
                    && fs::symlink_metadata(&path)
                        .map(|metadata| metadata.file_type().is_file())
                        .unwrap_or(false)
                    && let Ok(rel_file) = path.strip_prefix(root)
                {
                    ambient.push(rel_file.to_path_buf());
                }
            }
            dir = current.parent();
        }
    }
    ambient
}

/// Something an import's own repo-relative directory/file might resolve to,
/// generic across languages: `paths`' own imports, discovered through each
/// file's `ImportAnalysisProvider` -- the same interface every language's
/// real analyzer already implements -- not per-language parsing.
///
/// This answers "what does the diff's own code now reference" -- not "what
/// else references the diff", which needs a reverse index of the whole
/// repository to answer cheaply, a different and harder problem than this
/// one.
///
/// The two endpoint kinds ask the question differently, and each has its own
/// entry point: [`snapshot_import_expansion_targets`] checks a candidate's
/// existence against the revision's Git tree and reads the shared cache, while
/// [`worktree_import_expansion_targets`] checks it on disk under the live
/// project root and cannot.
pub(crate) enum ImportExpansionTarget {
    Directory(PathBuf),
    File(PathBuf),
}

/// What `rel` imports, resolved to workspace-relative paths against the image
/// on disk at `root`.
///
/// The two `*_import_expansion_targets` entry points answer the same question
/// for a whole path set at once and throw away which file asked, because their
/// consumer only needs the union to export. A caller building adjacency between
/// two files needs the attribution, so it asks per file here instead of
/// re-deriving import syntax.
pub(crate) fn resolved_imports_of(
    analyzer: &dyn IAnalyzer,
    root: &Path,
    rel: &Path,
) -> Vec<ImportExpansionTarget> {
    let Some(provider) = analyzer.import_analysis_provider() else {
        return Vec::new();
    };
    let Some(file) = analyzer.project().file_by_rel_path(rel) else {
        return Vec::new();
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let importing_dir = rel.parent().unwrap_or_else(|| Path::new(""));
    let mut targets = Vec::new();
    for info in provider.import_info_of(token, &file) {
        for import_target in import_targets(&info) {
            if let Some((path, is_directory)) =
                resolve_import_target(importing_dir, &import_target, |candidate| {
                    worktree_entry_kind(root, candidate)
                })
            {
                targets.push(if is_directory {
                    ImportExpansionTarget::Directory(path)
                } else {
                    ImportExpansionTarget::File(path)
                });
            }
        }
    }
    targets
}

/// Import expansion for a committed endpoint, whose `root` is the private
/// export directory the surrounding materialization is filling in and whose
/// `changed_paths` are genuine blobs of `tree`.
///
/// This build shares the repository's content-addressed cache. The blobs it
/// parses are the diff's own changed files, which the endpoint analyzer of the
/// same request parses again moments later and every later request against this
/// revision reads instead of parsing. `cache` of `None` means the host has no
/// usable persisted cache; the same build then runs against an ephemeral store
/// and returns the same targets.
///
/// A candidate's existence is checked against `tree` rather than the export
/// directory, because the export holds only the files selected so far -- the
/// whole point of the expansion is to name the ones it does not yet hold.
fn snapshot_import_expansion_targets(
    root: &Path,
    tree: &git2::Tree,
    changed_paths: &[PathBuf],
    cache: Option<&SharedAnalyzerCache>,
) -> Result<Vec<ImportExpansionTarget>, String> {
    // The tree entry that put each changed path on disk carries its blob id, so
    // the facts this build publishes are keyed by the revision's own content
    // identity without re-hashing a byte. A changed path with no tree entry was
    // added on the other endpoint and has nothing on disk here either; both the
    // inventory and the project listing simply pass over it.
    let blobs = changed_paths
        .iter()
        .filter_map(|rel| {
            let entry = tree.get_path(rel).ok()?;
            (entry.kind() == Some(ObjectType::Blob) && is_regular_file_mode(entry.filemode()))
                .then(|| (rel.clone(), entry.id()))
        })
        .collect::<Vec<_>>();
    let analyzer = RevisionAnalyzer::over_partial_export(
        root,
        changed_paths,
        Arc::new(RevisionBlobIdentities::new(blobs, Vec::new())),
        cache,
    )
    .map_err(|error| format!("Failed to build import-expansion analyzer: {error}"))?;
    Ok(collect_import_expansion_targets(
        analyzer.analyzer(),
        changed_paths,
        |candidate| {
            tree.get_path(candidate)
                .ok()
                .map(|entry| entry.kind() == Some(ObjectType::Tree))
        },
    ))
}

/// Import expansion for the working-tree endpoint, where `root` already IS the
/// live project root and a candidate's existence is checked on disk.
///
/// This build stays ephemeral, for the reason [`build_analyzer`] states: a
/// partial view of a live root must not become that workspace's cached picture
/// of itself. It is the same discrimination [`RevisionAnalyzer::build`] makes
/// when it withholds the shared cache from a worktree image.
fn worktree_import_expansion_targets(
    root: &Path,
    changed_paths: &[PathBuf],
) -> Result<Vec<ImportExpansionTarget>, String> {
    let analyzer = build_analyzer(root, changed_paths)?;
    Ok(collect_import_expansion_targets(
        analyzer.analyzer(),
        changed_paths,
        |candidate| worktree_entry_kind(root, candidate),
    ))
}

/// Resolve every import of `changed_paths` through `analyzer`, keeping the
/// candidates `entry_kind` says the endpoint actually holds.
///
/// `entry_kind` reports `Some(true)` for a directory, `Some(false)` for a file,
/// and `None` for a path the endpoint does not hold.
fn collect_import_expansion_targets(
    analyzer: &dyn IAnalyzer,
    changed_paths: &[PathBuf],
    entry_kind: impl Fn(&Path) -> Option<bool>,
) -> Vec<ImportExpansionTarget> {
    let Some(provider) = analyzer.import_analysis_provider() else {
        return Vec::new();
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();

    let mut targets = Vec::new();
    for rel in changed_paths {
        let Some(file) = analyzer.project().file_by_rel_path(rel) else {
            continue;
        };
        let importing_dir = rel.parent().unwrap_or_else(|| Path::new(""));
        for info in provider.import_info_of(token, &file) {
            for import_target in import_targets(&info) {
                if let Some((path, is_directory)) =
                    resolve_import_target(importing_dir, &import_target, &entry_kind)
                {
                    targets.push(if is_directory {
                        ImportExpansionTarget::Directory(path)
                    } else {
                        ImportExpansionTarget::File(path)
                    });
                }
            }
        }
    }
    targets
}

/// Return the kind of a worktree entry only when every path component below
/// the trusted project root is a real directory or file. A final-file check
/// alone is insufficient: `root/linked/other.ts` follows `linked` when the
/// directory is a symlink, even though `symlink_metadata` sees a regular file
/// at the final path.
fn worktree_entry_kind(root: &Path, candidate: &Path) -> Option<bool> {
    let mut current = root.to_path_buf();
    let mut components = candidate.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return None;
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current).ok()?;
        if metadata.file_type().is_symlink() {
            return None;
        }
        if components.peek().is_none() {
            let file_type = metadata.file_type();
            return (file_type.is_file() || file_type.is_dir()).then(|| file_type.is_dir());
        }
        if !metadata.file_type().is_dir() {
            return None;
        }
    }
    None
}

/// A best-effort guess at where an import points, used only to decide what
/// extra tree paths to export before the diff's own real analyzer resolves
/// calls normally -- not a replacement for each language's own resolver,
/// which needs the target file to already exist to run at all (confirmed
/// true for every language's `ImportAnalysisProvider` impl), so nothing can
/// resolve an import "for real" before its target is exported anyway. A
/// wrong guess here costs a harmless extra export; a missed one just falls
/// back to today's baseline.
#[derive(Debug)]
enum ImportTarget {
    /// Resolve relative to the importing file's own directory, climbing `up`
    /// parent directories first (0 = same directory).
    Relative { up: usize, rest: Vec<String> },
    /// A logical/absolute path, tried as a suffix (longest first) against the
    /// snapshot's real directory structure.
    Absolute(Vec<String>),
}

/// `ImportTarget`s for one `ImportInfo`. Uses only parser-derived structure,
/// normalizing two well-known shapes (Rust's leading `crate`/`self`/`super`
/// segment, Python's leading-dot relative segment) rather than recovering
/// import structure from `raw_snippet`.
fn import_targets(info: &ImportInfo) -> Vec<ImportTarget> {
    let Some(path) = &info.path else {
        return Vec::new();
    };

    // JS/TS module specifiers are AST string-literal values, kept as one
    // structured segment because their slash-separated path is not a
    // language identifier path. Interpret that path with `Path` components,
    // never by scanning the raw import declaration.
    if path.kind.is_none()
        && let [module_specifier] = path.segments.as_slice()
    {
        return js_ts_import_target(module_specifier).into_iter().collect();
    }

    if let Some((first, rest)) = path.segments.split_first() {
        let dots = first.chars().take_while(|ch| *ch == '.').count();
        if dots > 0 {
            let mut rest = rest.to_vec();
            let remainder = &first[dots..];
            if !remainder.is_empty() {
                rest.insert(0, remainder.to_string());
            }
            return vec![ImportTarget::Relative { up: dots - 1, rest }];
        }
        if matches!(first.as_str(), "crate" | "self" | "super") {
            return if rest.is_empty() {
                Vec::new()
            } else {
                vec![ImportTarget::Absolute(rest.to_vec())]
            };
        }
        return vec![ImportTarget::Absolute(path.segments.clone())];
    }
    Vec::new()
}

fn js_ts_import_target(module_specifier: &str) -> Option<ImportTarget> {
    let mut relative = false;
    let mut up = 0usize;
    let mut rest = Vec::new();
    for component in Path::new(module_specifier).components() {
        match component {
            Component::CurDir => relative = true,
            Component::ParentDir if rest.is_empty() => {
                relative = true;
                up += 1;
            }
            Component::ParentDir => return None,
            Component::Normal(segment) => rest.push(segment.to_string_lossy().into_owned()),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if rest.is_empty() {
        return None;
    }
    if relative {
        Some(ImportTarget::Relative { up, rest })
    } else {
        Some(ImportTarget::Absolute(rest))
    }
}

fn resolve_import_target(
    importing_dir: &Path,
    target: &ImportTarget,
    mut exists: impl FnMut(&Path) -> Option<bool>,
) -> Option<(PathBuf, bool)> {
    match target {
        ImportTarget::Relative { up, rest } => {
            let mut dir = importing_dir.to_path_buf();
            for _ in 0..*up {
                dir = dir.parent()?.to_path_buf();
            }
            let candidate = rest.iter().fold(dir, |acc, segment| acc.join(segment));
            resolve_candidate(&candidate, &mut exists)
        }
        // An absolute path's directory-meaningful part can sit at either end:
        // Go names a package at the tail, behind a module prefix to strip
        // (`k8s.io/kubernetes/pkg/controller` -> `pkg/controller`), while a
        // `use`/`from`-style import often names a leaf item at the tail, with
        // the directory as a prefix (`crate_b::make_thing` -> `crate_b`).
        // Prefixes (longest first) catch the second shape; a full prefix scan
        // costs nothing extra when the first shape is what actually matches,
        // since every prefix attempt but one is a cheap tree/disk miss.
        ImportTarget::Absolute(segments) => (1..=segments.len())
            .rev()
            .find_map(|end| {
                let candidate = PathBuf::from(segments[..end].join("/"));
                resolve_candidate(&candidate, &mut exists)
            })
            .or_else(|| {
                (1..segments.len()).find_map(|start| {
                    let candidate = PathBuf::from(segments[start..].join("/"));
                    resolve_candidate(&candidate, &mut exists)
                })
            }),
    }
}

/// `candidate` itself if it names a real entry, else `candidate` with a
/// common source extension appended, for an import that omits the file
/// suffix (JS/TS, and Python's dotted-module style).
///
/// `candidate` comes from parsing an import statement's own text -- content
/// an attacker controls in any file under review, not a value this code
/// constructed itself. An absolute literal (`import x from "/etc/passwd"`) or
/// one carrying an embedded `..` (`"a/../../../../tmp"`, surviving because
/// only a *leading* `./`/`../` run is stripped upstream) must never reach the
/// `exists` closure: on the working-tree endpoint that closure joins
/// `candidate` onto the real project root with `Path::join`, which discards
/// the root entirely for an absolute argument and lets the OS resolve an
/// embedded `..` past it, checking or walking a directory outside the
/// project entirely. Rejecting anything but an all-`Normal`-component path
/// here, before the first `exists` call, closes that off for every caller
/// (git-tree and filesystem alike) in one place, matching the same
/// containment `safe_tree_entry_path` already enforces for every other path
/// this file writes to disk.
fn resolve_candidate(
    candidate: &Path,
    exists: &mut impl FnMut(&Path) -> Option<bool>,
) -> Option<(PathBuf, bool)> {
    if candidate.as_os_str().is_empty()
        || !candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return None;
    }
    if let Some(is_directory) = exists(candidate) {
        return Some((candidate.to_path_buf(), is_directory));
    }
    const EXTENSIONS: &[&str] = &[
        "go", "rs", "py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "java", "kt", "scala", "cs",
        "cpp", "cc", "h", "hpp", "php", "rb",
    ];
    EXTENSIONS.iter().find_map(|extension| {
        let with_extension = candidate.with_extension(extension);
        exists(&with_extension).map(|is_directory| (with_extension, is_directory))
    })
}

/// Reads an immutable revision image's file bytes out of the repository's Git
/// object database.
///
/// The ecosystem-scoped export writes only the analyzers' configuration inputs
/// to disk (see `export_file_dependency_tree`), because a revision's source
/// blobs are already stored, deduplicated, in the repository the request names.
/// Inflating all of them per request is the cost this exists to remove: on a
/// warm shared cache almost none of them is ever read, since the parsed facts
/// they would produce are already published.
///
/// `git2::Repository` is `Send` but not `Sync`, so handles are pooled rather
/// than shared behind one lock: a reader borrows a handle, reads, and returns
/// it. The pool grows to the number of concurrent readers -- one per parse
/// worker at the peak -- and the lock is held only for the borrow and the
/// return, never for the object read.
pub(crate) struct RevisionObjectDatabase {
    git_dir: PathBuf,
    alternate_object_dirs: Vec<PathBuf>,
    idle: Mutex<Vec<Repository>>,
}

impl RevisionObjectDatabase {
    /// `alternate_object_dirs` must be the same trusted set the request's own
    /// repository handle carries (`DiffRepository::alternate_object_dirs`).
    ///
    /// An immutable comparison runs against a private bare repository whose
    /// only objects are the real repository's, attached as an in-memory
    /// alternate (`open_repository`). Reopening that bare repository without
    /// the alternate produces a handle that finds no object at all, and the
    /// symptom is not an error but silence: every read fails, every file goes
    /// unparsed, and the answer is simply smaller. `probe` turns that into a
    /// failure at construction.
    fn new(repo: &Repository, alternate_object_dirs: &[PathBuf]) -> Self {
        Self {
            git_dir: repo.path().to_path_buf(),
            alternate_object_dirs: alternate_object_dirs.to_vec(),
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Read one of the image's own blobs, so a handle that cannot see the
    /// revision's objects is reported here rather than as missing analysis.
    fn probe(&self, oid: Oid) -> Result<(), String> {
        self.read_blob(oid).map(|_| ())
    }

    fn read_blob(&self, oid: Oid) -> Result<Vec<u8>, String> {
        let repo = match self
            .idle
            .lock()
            .expect("revision object database mutex poisoned")
            .pop()
        {
            Some(repo) => repo,
            None => self.open()?,
        };
        let read = (|| {
            let odb = repo
                .odb()
                .map_err(|error| format!("unable to open revision object database: {error}"))?;
            odb.read(oid)
                .map(|object| object.data().to_vec())
                .map_err(|error| format!("unable to read revision blob {oid}: {error}"))
        })();
        self.idle
            .lock()
            .expect("revision object database mutex poisoned")
            .push(repo);
        read
    }

    fn open(&self) -> Result<Repository, String> {
        let repo = Repository::open(&self.git_dir).map_err(|error| {
            format!(
                "unable to reopen repository {}: {error}",
                self.git_dir.display()
            )
        })?;
        if !self.alternate_object_dirs.is_empty() {
            let odb = repo
                .odb()
                .map_err(|error| format!("unable to open revision object database: {error}"))?;
            for directory in &self.alternate_object_dirs {
                let path = directory.to_str().ok_or_else(|| {
                    format!(
                        "trusted Git object directory {} is not valid UTF-8",
                        directory.display()
                    )
                })?;
                odb.add_disk_alternate(path).map_err(|error| {
                    format!("unable to trust Git object directory {path}: {error}")
                })?;
            }
        }
        Ok(repo)
    }
}

/// The [`Project`] an immutable revision image is analyzed through.
///
/// It names every analyzer-visible file of the revision, exactly as the plain
/// file set does, so absence still means absence and `analyzed_files` is
/// complete. It differs in where the bytes come from: every file the image's
/// inventory names is read from the repository's object database by the blob id
/// the revision's tree walk recorded, and only a file the inventory does not
/// name falls through to the filesystem, where the read fails as it should.
struct RevisionImageProject {
    files: FileSetProject,
    objects: Arc<RevisionObjectDatabase>,
    blobs: Arc<RevisionBlobIdentities>,
}

impl Project for RevisionImageProject {
    fn root(&self) -> &Path {
        self.files.root()
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.files.analyzer_languages()
    }

    fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
        self.files.all_files()
    }

    fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
        self.files.analyzable_files(language)
    }

    fn analyzable_files_from(
        &self,
        files: &BTreeSet<ProjectFile>,
        language: Language,
    ) -> std::io::Result<BTreeSet<ProjectFile>> {
        self.files.analyzable_files_from(files, language)
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        self.files.file_by_rel_path(rel_path)
    }

    fn persistence_root(&self) -> Option<&Path> {
        self.files.persistence_root()
    }

    fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
        match self.revision_bytes(file) {
            Some(bytes) => {
                bytes.and_then(brokk_bifrost_core::analyzer::project::decode_source_bytes)
            }
            None => self.files.read_source(file),
        }
    }

    fn read_source_limited(
        &self,
        file: &ProjectFile,
        max_bytes: usize,
    ) -> std::io::Result<Option<String>> {
        match self.revision_bytes(file) {
            Some(bytes) => {
                let bytes = bytes?;
                if bytes.len() > max_bytes {
                    return Ok(None);
                }
                brokk_bifrost_core::analyzer::project::decode_source_bytes(bytes).map(Some)
            }
            None => self.files.read_source_limited(file, max_bytes),
        }
    }
}

impl RevisionImageProject {
    /// `file`'s bytes as the revision holds them, or `None` for a file this
    /// image does not name -- whose disk read then fails, as it should.
    ///
    /// The inventory is consulted before the filesystem, never after. A source
    /// file's on-disk copy is an empty placeholder that exists only so module
    /// resolution can see the path (see `create_empty_source_files`), so
    /// reading disk first would hand every caller an empty file.
    fn revision_bytes(&self, file: &ProjectFile) -> Option<std::io::Result<Vec<u8>>> {
        let oid = self.blobs.oid_for(file)?;
        Some(self.objects.read_blob(oid).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{}: {error}", file.rel_path().display()),
            )
        }))
    }
}

pub(crate) struct RevisionTempDir {
    path: PathBuf,
}

impl RevisionTempDir {
    fn new(label: &str) -> Result<Self, String> {
        let base = std::env::temp_dir();
        for attempt in 0..100 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default();
            let path = base.join(format!(
                "bifrost-analyze-{}-{nanos}-{attempt}-{label}",
                std::process::id()
            ));
            match create_private_dir(&path) {
                Ok(()) => {
                    set_private_dir_permissions(&path)?;
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "unable to create temp revision directory {}: {err}",
                        path.display()
                    ));
                }
            }
        }
        Err("unable to create unique temp revision directory".to_string())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RevisionTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Export the changed files plus ambient ancestor manifests used to establish
/// their package/crate identity. Callable discovery needs this bounded image,
/// but does not resolve imported callees.
fn export_snapshot_symbol_files(
    repo: &Repository,
    snapshot: Snapshot,
    root: &Path,
    paths: &[String],
) -> Result<Vec<(PathBuf, Oid)>, String> {
    let tree = snapshot_tree(repo, snapshot)?;
    export_snapshot_symbol_files_from_tree(repo, &tree, root, paths)
}

fn export_snapshot_symbol_files_from_tree(
    repo: &Repository,
    tree: &git2::Tree,
    root: &Path,
    paths: &[String],
) -> Result<Vec<(PathBuf, Oid)>, String> {
    let mut exported = export_tree_paths(repo, tree, root, paths)?;
    let already_exported = paths.iter().cloned().collect::<BTreeSet<_>>();
    let ambient = symbol_identity_ancestor_paths(repo, tree, paths)
        .into_iter()
        .filter(|path| !already_exported.contains(path))
        .collect::<Vec<_>>();
    exported.extend(export_tree_paths(repo, tree, root, &ambient)?);
    Ok(exported)
}

/// Extend the symbol image with every package the changed files' imports
/// concretely reference. Exact call analysis needs those files to be real
/// analyzer inputs; callable discovery deliberately stops before this step.
///
/// `cache` is the repository's shared analyzer cache, which the import-expansion
/// analyzer built below reads and writes; see
/// [`snapshot_import_expansion_targets`].
fn export_snapshot_files(
    repo: &Repository,
    snapshot: Snapshot,
    root: &Path,
    paths: &[String],
    cache: Option<&SharedAnalyzerCache>,
) -> Result<Vec<(PathBuf, Oid)>, String> {
    let tree = snapshot_tree(repo, snapshot)?;
    let mut exported = export_snapshot_symbol_files_from_tree(repo, &tree, root, paths)?;
    let already_exported = exported
        .iter()
        .map(|(path, _)| path.to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();

    // Import expansion resolves against a manifest that just landed on disk
    // above (a `go.mod`, a `Cargo.toml`, ...), so it only runs now.
    let changed: Vec<PathBuf> = paths
        .iter()
        .filter_map(|path| safe_tree_entry_path(path).ok())
        .collect();
    let mut expansion = BTreeSet::new();
    for target in snapshot_import_expansion_targets(root, &tree, &changed, cache)? {
        match target {
            ImportExpansionTarget::Directory(dir) => {
                expansion.extend(tree_dir_file_paths(repo, &tree, &dir));
            }
            ImportExpansionTarget::File(file) => {
                expansion.insert(file.to_string_lossy().into_owned());
            }
        }
    }
    let expansion: Vec<String> = expansion
        .into_iter()
        .filter(|path| !already_exported.contains(path))
        .collect();
    exported.extend(export_tree_paths(repo, &tree, root, &expansion)?);

    Ok(exported)
}

fn export_tree_paths(
    repo: &Repository,
    tree: &git2::Tree,
    root: &Path,
    paths: &[String],
) -> Result<Vec<(PathBuf, Oid)>, String> {
    let mut written = Vec::with_capacity(paths.len());
    let mut created_dirs = HashSet::new();
    for raw_path in paths {
        let rel = safe_tree_entry_path(raw_path)?;
        let Ok(entry) = tree.get_path(&rel) else {
            continue;
        };
        if entry.kind() != Some(ObjectType::Blob) || !is_regular_file_mode(entry.filemode()) {
            continue;
        }
        let blob = repo
            .find_blob(entry.id())
            .map_err(|err| format!("unable to read blob `{}`: {err}", rel.display()))?;
        let path = root.join(&rel);
        if let Some(parent) = path.parent() {
            create_private_dirs_cached(root, parent, &mut created_dirs)?;
        }
        write_private_file(&path, blob.content())?;
        set_private_file_permissions(&path)?;
        written.push((rel, entry.id()));
    }
    Ok(written)
}

/// Export a complete immutable tree in one traversal.
///
/// The restricted exporter above starts from a small path set, where a
/// `tree.get_path` per file is appropriate. A complete revision already has
/// the tree walk in hand. Turning every walked path back into a fresh tree
/// lookup, and re-running `mkdir` plus permission changes for each ancestor of
/// every file, made deep 10k-file repositories spend minutes before analysis
/// began. This walk reads each tree entry once and creates each directory once.
fn export_complete_tree(
    repo: &Repository,
    tree: &git2::Tree,
    root: &Path,
) -> Result<Vec<(PathBuf, Oid)>, String> {
    let _scope = crate::profiling::scope("RevisionImage::export_complete_tree");
    let mut entries = Vec::new();
    let mut failure = None;
    let walk = tree.walk(TreeWalkMode::PreOrder, |parent, entry| {
        let Some(name) = entry.name() else {
            return TreeWalkResult::Ok;
        };
        let raw_path = format!("{parent}{name}");
        let rel = match safe_tree_entry_path(&raw_path) {
            Ok(rel) => rel,
            Err(error) => {
                failure = Some(error);
                return TreeWalkResult::Abort;
            }
        };
        if entry.kind() != Some(ObjectType::Blob) || !is_regular_file_mode(entry.filemode()) {
            return TreeWalkResult::Ok;
        }
        entries.push((rel, entry.id()));
        TreeWalkResult::Ok
    });
    if let Some(error) = failure {
        return Err(error);
    }
    walk.map_err(|error| format!("unable to walk immutable revision tree: {error}"))?;

    export_tree_entries(repo, root, entries, &[])
}

/// Export a tree-walk result while preserving lexical error reporting.
///
/// Keeping the one-pass walk separate from the selection predicate lets the
/// complete exporter and the ecosystem-scoped exporter share the same safe
/// path, directory, and blob handling without making the complete exporter
/// depend on a filter.
///
/// The entries are returned with their blob ids: the caller hands them to the
/// analyzer as the image's content identities, which is what keeps the
/// analyzer from re-hashing bytes this function just wrote.
fn export_tree_entries(
    repo: &Repository,
    root: &Path,
    entries: Vec<(PathBuf, Oid)>,
    alternate_object_dirs: &[PathBuf],
) -> Result<Vec<(PathBuf, Oid)>, String> {
    let mut created_dirs = HashSet::new();
    for (rel, _) in &entries {
        if let Some(parent) = root.join(rel).parent() {
            create_private_dirs_cached(root, parent, &mut created_dirs)?;
        }
    }

    // Git's batch protocol performs one pack traversal for the complete
    // object stream. Calling libgit2's `Odb::read` independently for tens of
    // thousands of blobs repeatedly re-enters pack lookup and delta setup;
    // on dotnet/runtime that object-read shape alone took about 71 seconds.
    // Keep the existing libgit2 implementation as a portable fallback. The
    // destination is a new private temp image, so removing a partial batch
    // before retrying cannot affect caller-owned files.
    if let Err(error) = export_tree_entries_with_git(repo, root, &entries, alternate_object_dirs) {
        profiling::note(format!(
            "bulk Git revision export unavailable; falling back to libgit2: {error}"
        ));
        for (rel, _) in &entries {
            let _ = fs::remove_file(root.join(rel));
        }
        export_tree_entries_with_libgit2(repo, root, &entries)?;
    }

    Ok(entries)
}

fn export_tree_entries_with_git(
    repo: &Repository,
    root: &Path,
    entries: &[(PathBuf, Oid)],
    alternate_object_dirs: &[PathBuf],
) -> Result<(), String> {
    let mut command = Command::new("git");
    command
        .arg("--git-dir")
        .arg(repo.path())
        .arg("cat-file")
        .arg("--batch")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !alternate_object_dirs.is_empty() {
        let joined = std::env::join_paths(alternate_object_dirs)
            .map_err(|error| format!("unable to encode trusted Git object directories: {error}"))?;
        command.env("GIT_ALTERNATE_OBJECT_DIRECTORIES", joined);
    }

    let mut child = command
        .spawn()
        .map_err(|error| format!("unable to start `git cat-file --batch`: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "bulk Git exporter has no stdin".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "bulk Git exporter has no stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "bulk Git exporter has no stderr".to_string())?;

    let mut requests = Vec::with_capacity(entries.len().saturating_mul(41));
    for (_, oid) in entries {
        writeln!(&mut requests, "{oid}")
            .map_err(|error| format!("unable to prepare bulk Git request: {error}"))?;
    }
    let request_writer = std::thread::spawn(move || {
        stdin
            .write_all(&requests)
            .map_err(|error| format!("unable to send bulk Git request: {error}"))
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut reader = stderr;
        reader
            .read_to_end(&mut bytes)
            .map(|_| String::from_utf8_lossy(&bytes).trim().to_string())
            .map_err(|error| format!("unable to read bulk Git diagnostics: {error}"))
    });

    let writer_threads = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(16);
    let mut writers = Vec::with_capacity(writer_threads);
    for _ in 0..writer_threads {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<(PathBuf, Vec<u8>)>(2);
        let writer_root = root.to_path_buf();
        let handle = std::thread::spawn(move || -> Result<(), String> {
            while let Ok((rel, contents)) = receiver.recv() {
                write_private_file(&writer_root.join(rel), &contents)?;
            }
            Ok(())
        });
        writers.push((sender, handle));
    }

    let mut reader = BufReader::new(stdout);
    let export_result = (|| {
        for (index, (rel, expected_oid)) in entries.iter().enumerate() {
            let mut header = String::new();
            let bytes = reader.read_line(&mut header).map_err(|error| {
                format!(
                    "unable to read bulk Git header for `{}`: {error}",
                    rel.display()
                )
            })?;
            if bytes == 0 {
                return Err(format!(
                    "bulk Git output ended before blob `{}`",
                    rel.display()
                ));
            }
            let mut fields = header.split_ascii_whitespace();
            let actual_oid = fields.next().ok_or_else(|| {
                format!("bulk Git returned an empty header for `{}`", rel.display())
            })?;
            let kind = fields.next().ok_or_else(|| {
                format!("bulk Git omitted the object kind for `{}`", rel.display())
            })?;
            let size = fields
                .next()
                .ok_or_else(|| format!("bulk Git omitted the object size for `{}`", rel.display()))?
                .parse::<usize>()
                .map_err(|error| {
                    format!(
                        "bulk Git returned an invalid size for `{}`: {error}",
                        rel.display()
                    )
                })?;
            if fields.next().is_some() || actual_oid != expected_oid.to_string() || kind != "blob" {
                return Err(format!(
                    "bulk Git returned unexpected header {:?} for blob `{}` ({expected_oid})",
                    header.trim_end(),
                    rel.display()
                ));
            }

            let mut contents = vec![0; size];
            reader.read_exact(&mut contents).map_err(|error| {
                format!("unable to read bulk Git blob `{}`: {error}", rel.display())
            })?;
            let mut separator = [0_u8; 1];
            reader.read_exact(&mut separator).map_err(|error| {
                format!(
                    "unable to read bulk Git separator for `{}`: {error}",
                    rel.display()
                )
            })?;
            if separator != *b"\n" {
                return Err(format!(
                    "bulk Git returned an invalid blob separator for `{}`",
                    rel.display()
                ));
            }
            writers[index % writers.len()]
                .0
                .send((rel.clone(), contents))
                .map_err(|_| format!("bulk Git file writer stopped before `{}`", rel.display()))?;
        }
        Ok(())
    })();

    if export_result.is_err() {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|error| format!("unable to wait for bulk Git exporter: {error}"))?;
    request_writer
        .join()
        .map_err(|_| "bulk Git request writer panicked".to_string())??;
    let diagnostics = stderr_reader
        .join()
        .map_err(|_| "bulk Git diagnostics reader panicked".to_string())??;
    let writer_handles = writers
        .into_iter()
        .map(|(sender, handle)| {
            drop(sender);
            handle
        })
        .collect::<Vec<_>>();
    let mut writer_result = Ok(());
    for handle in writer_handles {
        let result = handle
            .join()
            .map_err(|_| "bulk Git file writer panicked".to_string())?;
        if writer_result.is_ok() {
            writer_result = result;
        }
    }
    export_result?;
    writer_result?;
    if !status.success() {
        return Err(format!(
            "bulk Git exporter exited with {status}: {diagnostics}"
        ));
    }
    Ok(())
}

fn export_tree_entries_with_libgit2(
    repo: &Repository,
    root: &Path,
    entries: &[(PathBuf, Oid)],
) -> Result<(), String> {
    let odb = repo
        .odb()
        .map_err(|error| format!("unable to open repository object database: {error}"))?;
    for (rel, oid) in entries {
        let object = odb
            .read(*oid)
            .map_err(|error| format!("unable to read blob `{}`: {error}", rel.display()))?;
        write_private_file(&root.join(rel), object.data())?;
    }
    Ok(())
}

/// Inventory every regular file that can participate in the selected usage
/// ecosystems, and write to disk only the ones that must be real files.
///
/// The dependency graph only creates nodes for analyzer source extensions, but
/// its analyzers also read package/build inputs to establish module, package,
/// and project identity, and several of those readers open the manifest by path
/// rather than through the project -- `read_manifest` in
/// `brokk_bifrost_rust::cargo_routes` opens `Cargo.toml` with `std::fs`, and
/// `brokk_bifrost_go::packages` opens `go.mod` the same way. Those inputs are
/// therefore written.
///
/// Source files are not. Their bytes already exist, deduplicated, in the
/// repository's object database, and `RevisionImageProject` reads them from
/// there for whatever actually needs them. On a warm shared cache that is
/// almost nothing: the parsed facts for a blob the cache has already seen are
/// read out of the store, and the blob itself is never touched. The returned
/// inventory names every file either way, so the analyzer's file listing, its
/// graph nodes and its blob identities describe the whole revision.
struct ExportedFileDependencyTree {
    /// Written to disk with their real content.
    configuration_inputs: Vec<(PathBuf, Oid)>,
    /// Named, and created as empty paths, but served from the object database.
    sources: Vec<(PathBuf, Oid)>,
}

fn export_file_dependency_tree(
    repo: &Repository,
    tree: &git2::Tree,
    root: &Path,
    languages: &BTreeSet<Language>,
    alternate_object_dirs: &[PathBuf],
) -> Result<ExportedFileDependencyTree, String> {
    let _scope = crate::profiling::scope("RevisionImage::export_file_dependency_tree");
    let mut entries = Vec::new();
    let mut failure = None;
    let walk = tree.walk(TreeWalkMode::PreOrder, |parent, entry| {
        let Some(name) = entry.name() else {
            return TreeWalkResult::Ok;
        };
        let raw_path = format!("{parent}{name}");
        let rel = match safe_tree_entry_path(&raw_path) {
            Ok(rel) => rel,
            Err(error) => {
                failure = Some(error);
                return TreeWalkResult::Abort;
            }
        };
        if entry.kind() == Some(ObjectType::Blob)
            && is_regular_file_mode(entry.filemode())
            && file_dependency_tree_path(&rel, languages)
        {
            entries.push((rel, entry.id()));
        }
        TreeWalkResult::Ok
    });
    if let Some(error) = failure {
        return Err(error);
    }
    walk.map_err(|error| format!("unable to walk immutable revision tree: {error}"))?;

    let (configuration_inputs, sources): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .partition(|(rel, _)| ecosystem_identity_file(rel, languages));
    let configuration_inputs =
        export_tree_entries(repo, root, configuration_inputs, alternate_object_dirs)?;
    create_empty_source_files(root, &sources)?;
    Ok(ExportedFileDependencyTree {
        configuration_inputs,
        sources,
    })
}

/// Create every source file the image names, with no content.
///
/// The bytes come from the object database on demand, but the PATH has to be
/// on disk: module resolution in several languages answers "does this module
/// exist" by probing the filesystem for candidate files -- Rust's `mod foo;`
/// tries `foo.rs` and `foo/mod.rs` (`rust_external_module_children` in
/// `brokk_bifrost_rust::cargo_routes`), and a JavaScript or TypeScript
/// specifier tries each extension and `index.<ext>`
/// (`brokk_bifrost_js_ts::imports`). Both take absence as proof that the module
/// is not there, so an unwritten path silently deletes real graph edges.
///
/// This is much cheaper than the export it replaces: no blob is inflated and no
/// content is written, only an empty inode per file. `RevisionImageProject`
/// reads through the inventory rather than the filesystem, so nothing ever sees
/// the empty content.
fn create_empty_source_files(root: &Path, sources: &[(PathBuf, Oid)]) -> Result<(), String> {
    let mut created_dirs = HashSet::new();
    for (rel, _) in sources {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            create_private_dirs_cached(root, parent, &mut created_dirs)?;
        }
        write_private_file(&path, &[])?;
    }
    Ok(())
}

fn file_dependency_tree_path(path: &Path, languages: &BTreeSet<Language>) -> bool {
    let source_language = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None);
    if languages.contains(&source_language) {
        return true;
    }

    ecosystem_identity_file(path, languages)
}

/// Return whether `path` is a package/build identity input for one selected
/// usage ecosystem. The dependency-input registry is the source of truth for
/// resolver-owned inputs; the small additions cover analyzer identity facts
/// that are not dependency-pack inputs (Python package markers and compiler
/// configuration files).
fn ecosystem_identity_file(path: &Path, languages: &BTreeSet<Language>) -> bool {
    DependencyPackEcosystem::ALL
        .into_iter()
        .filter(|ecosystem| {
            ecosystem
                .languages()
                .iter()
                .any(|language| languages.contains(language))
        })
        .any(|ecosystem| ecosystem.is_file_dependency_input(path))
}

/// Whether a file is structured package/workspace identity used while naming
/// declarations in a bounded callable-discovery image.
///
/// Exact call analysis deliberately uses the broader materialization path.
/// Callable discovery does not need neighboring source or fixture files, and
/// sweeping every direct child of an ancestor directory is not bounded in
/// practice: TypeScript's compiler baseline directory has more than 20,000
/// siblings. Keep only the checked-in configuration facts the analyzers
/// already consume, plus Python package markers.
fn symbol_identity_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        "__init__.py"
            | "Cargo.toml"
            | "go.mod"
            | "go.work"
            | "package.json"
            | "tsconfig.json"
            | "jsconfig.json"
            | "pom.xml"
            | "settings.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "settings.gradle"
            | "settings.gradle.kts"
            | "gradle.properties"
            | "gradle.lockfile"
            | "libs.versions.toml"
            | "compile_commands.json"
            | "compile_flags.txt"
            | "CMakeLists.txt"
            | "Gemfile"
            | "composer.json"
            | "Directory.Build.props"
            | "Directory.Build.targets"
            | "Directory.Packages.props"
            | "NuGet.config"
    ) || matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("csproj" | "fsproj" | "vbproj")
    )
}

/// Structured identity inputs sitting directly inside ancestor directories of
/// changed paths, up to the snapshot root, deduplicated across `paths`.
fn symbol_identity_ancestor_paths(
    repo: &Repository,
    tree: &git2::Tree,
    paths: &[String],
) -> Vec<String> {
    fn push_blobs(dir: &git2::Tree, prefix: &str, out: &mut Vec<String>) {
        for entry in dir.iter() {
            if entry.kind() == Some(ObjectType::Blob)
                && is_regular_file_mode(entry.filemode())
                && let Some(name) = entry.name()
                && symbol_identity_file(Path::new(name))
            {
                out.push(format!("{prefix}{name}"));
            }
        }
    }

    let mut visited_dirs = BTreeSet::new();
    let mut ambient = Vec::new();
    for raw_path in paths {
        let Ok(rel) = safe_tree_entry_path(raw_path) else {
            continue;
        };
        let mut dir = rel.parent();
        while let Some(current) = dir {
            // Every ancestor of an already-visited directory was visited
            // in the same pass that visited it, so once we hit one, the
            // rest of this path's ancestors were already swept too.
            if !visited_dirs.insert(current.to_path_buf()) {
                break;
            }
            if current.as_os_str().is_empty() {
                push_blobs(tree, "", &mut ambient);
            } else if let Ok(dir_tree) = tree
                .get_path(current)
                .and_then(|entry| entry.to_object(repo))
                .and_then(|object| object.peel_to_tree())
            {
                push_blobs(&dir_tree, &format!("{}/", current.display()), &mut ambient);
            }
            dir = current.parent();
        }
    }
    ambient
}

/// Every regular file anywhere under `dir` (workspace-relative), recursively.
///
/// An import-expansion target names a package, not a fixed layout: a Go
/// package's files sit directly in one directory, but a Rust crate's own
/// source lives a level down in `src/`, and a Java package is nested one
/// directory per name segment. Walking the whole subtree once, instead of
/// just its direct children, is correct for all of those without needing to
/// know which shape a given language uses.
fn tree_dir_file_paths(repo: &Repository, tree: &git2::Tree, dir: &Path) -> Vec<String> {
    let dir_tree_id = if dir.as_os_str().is_empty() {
        tree.id()
    } else {
        let Ok(entry) = tree.get_path(dir) else {
            return Vec::new();
        };
        entry.id()
    };
    let Ok(dir_tree) = repo.find_tree(dir_tree_id) else {
        return Vec::new();
    };
    let prefix = if dir.as_os_str().is_empty() {
        String::new()
    } else {
        format!("{}/", dir.display())
    };
    let mut paths = Vec::new();
    let _ = dir_tree.walk(TreeWalkMode::PreOrder, |parent, entry| {
        if entry.kind() == Some(ObjectType::Blob)
            && is_regular_file_mode(entry.filemode())
            && let Some(name) = entry.name()
        {
            paths.push(format!("{prefix}{parent}{name}"));
        }
        TreeWalkResult::Ok
    });
    paths
}

#[cfg(test)]
fn create_private_dirs(root: &Path, parent: &Path) -> Result<(), String> {
    create_private_dirs_cached(root, parent, &mut HashSet::new())
}

fn create_private_dirs_cached(
    root: &Path,
    parent: &Path,
    created_dirs: &mut HashSet<PathBuf>,
) -> Result<(), String> {
    let rel = parent.strip_prefix(root).map_err(|err| {
        format!(
            "unable to create directory outside revision root {}: {err}",
            parent.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in rel.components() {
        current.push(component.as_os_str());
        if !created_dirs.insert(current.clone()) {
            continue;
        }
        match create_private_dir(&current) {
            Ok(()) => set_private_dir_permissions(&current)?,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                set_private_dir_permissions(&current)?
            }
            Err(err) => return Err(format!("unable to create {}: {err}", current.display())),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("unable to write {}: {err}", path.display()))?;
    file.write_all(contents)
        .map_err(|err| format!("unable to write {}: {err}", path.display()))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    fs::write(path, contents).map_err(|err| format!("unable to write {}: {err}", path.display()))
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
        format!(
            "unable to set private permissions on {}: {err}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "unable to set private permissions on {}: {err}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn safe_tree_entry_path(name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    if path.as_os_str().is_empty() {
        return Err("empty tree entry path".to_string());
    }
    if path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        Ok(path.to_path_buf())
    } else {
        Err(format!("unsafe tree entry path `{name}`"))
    }
}

fn is_regular_file_mode(mode: i32) -> bool {
    mode == i32::from(FileMode::Blob)
        || mode == i32::from(FileMode::BlobGroupWritable)
        || mode == i32::from(FileMode::BlobExecutable)
}

/// Build a throwaway analyzer over exactly `files` under a live project root.
///
/// One production caller remains: [`worktree_import_expansion_targets`], whose
/// root is the *live* project root for a working-tree endpoint. It may not
/// write an on-disk cache under that root's workspace identity, because a
/// partial file set must not become the workspace's cached picture of itself.
/// `build_ephemeral_footgun` states that requirement at the call site instead of
/// relying on `FileSetProject::persistence_root()` happening to be `None`.
///
/// The rule is about the *live root*, not about partiality or about immutable
/// revisions. Every immutable path shares the repository's content-addressed
/// cache: a `blast_radius` or `analyze_diff` endpoint image through
/// [`build_revision_analyzer`] or [`build_file_dependency_analyzer`], a
/// committed endpoint's import expansion through
/// [`RevisionAnalyzer::over_partial_export`], and `correspond_revisions`
/// through the first of those. A revision's facts are keyed by blob content and
/// are reusable however few of its files one request happened to select; a
/// live root's workspace projection is not.
pub(crate) fn build_analyzer(root: &Path, files: &[PathBuf]) -> Result<WorkspaceAnalyzer, String> {
    let project = Arc::new(FileSetProject::new(
        root.to_path_buf(),
        files.iter().cloned(),
    ));
    WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
        .map_err(|error| format!("Failed to build diff endpoint analyzer: {error}"))
}

/// An analyzer over one diff-endpoint image, together with the workspace
/// projection rows the image published into a shared analyzer cache.
///
/// The projection is declared after the analyzer so it drops after it: every
/// query the request makes still sees the image's files mounted, and the rows
/// naming a temp-directory root are gone before the request returns.
pub(crate) struct RevisionAnalyzer {
    workspace: WorkspaceAnalyzer,
    _projection: Option<RevisionWorkspaceProjection>,
}

impl RevisionAnalyzer {
    fn build(
        image: &RevisionImage,
        cache: Option<&SharedAnalyzerCache>,
        languages: Option<&BTreeSet<Language>>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let (project, blobs) = image.project();
        // Only a temp-directory export may share the repository's cache. A
        // worktree image's root is the *live* project root, and publishing a
        // partial file listing under that workspace identity would replace the
        // workspace's own picture of itself.
        let cache = match image {
            RevisionImage::Snapshot { .. } => cache,
            RevisionImage::Worktree { .. } => None,
        };
        // Claimed before the build, so a build that fails partway still leaves
        // no workspace rows behind.
        let projection = cache.map(|cache| cache.claim_revision_workspace(image.root()));
        let workspace = match blobs {
            Some(blobs) => WorkspaceAnalyzer::build_revision_image(
                project,
                AnalyzerConfig::default(),
                languages,
                cache,
                blobs,
            ),
            None => match languages {
                Some(languages) => WorkspaceAnalyzer::build_ephemeral_for_languages_footgun(
                    project,
                    AnalyzerConfig::default(),
                    languages,
                ),
                None => {
                    WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                }
            },
        }?;
        Ok(Self {
            workspace,
            _projection: projection,
        })
    }

    /// Build over part of a revision export: `root` is the private export
    /// directory a materialization is still filling in, `files` the subset
    /// already written there, and `blobs` their ids from the same tree walk.
    ///
    /// A partial listing is safe to publish here for the reason a complete one
    /// is: the root is a self-deleting temp directory whose workspace rows the
    /// returned lease removes, and the parsed facts that stay behind are keyed
    /// by blob content, which a partial selection cannot make partial.
    fn over_partial_export(
        root: &Path,
        files: &[PathBuf],
        blobs: Arc<RevisionBlobIdentities>,
        cache: Option<&SharedAnalyzerCache>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let project = Arc::new(FileSetProject::new(
            root.to_path_buf(),
            files.iter().cloned(),
        ));
        // Claimed before the build, as in `build` above.
        let projection = cache.map(|cache| cache.claim_revision_workspace(root));
        let workspace = WorkspaceAnalyzer::build_revision_image(
            project,
            AnalyzerConfig::default(),
            None,
            cache,
            blobs,
        )?;
        Ok(Self {
            workspace,
            _projection: projection,
        })
    }

    pub(crate) fn analyzer(&self) -> &dyn IAnalyzer {
        self.workspace.analyzer()
    }
}

/// Build the complete analyzer of one diff-endpoint image.
///
/// An immutable image reads and writes the repository's shared
/// content-addressed cache, so a blob it shares with the worktree, a linked
/// worktree, or an earlier revision request is read instead of re-parsed.
/// Without a usable cache the same build runs against an ephemeral store: the
/// answers are identical, only the parse bill differs.
pub(crate) fn build_revision_analyzer(
    image: &RevisionImage,
    cache: Option<&SharedAnalyzerCache>,
) -> Result<RevisionAnalyzer, String> {
    RevisionAnalyzer::build(image, cache, None)
        .map_err(|error| format!("Failed to build diff endpoint analyzer: {error}"))
}

/// Build the file-dependency view of one revision image, restricted to the
/// usage ecosystems the coarse graph will walk.
///
/// The project still names every analyzer-visible file, so an omitted graph
/// node is never mistaken for negative dependency evidence.
pub(crate) fn build_file_dependency_analyzer(
    image: &RevisionImage,
    cache: Option<&SharedAnalyzerCache>,
    languages: &BTreeSet<Language>,
) -> Result<RevisionAnalyzer, String> {
    RevisionAnalyzer::build(image, cache, Some(languages))
        .map_err(|error| format!("Failed to build file-dependency analyzer: {error}"))
}

fn symbol_snapshot_map(
    analyzer: &dyn IAnalyzer,
    include_tests: bool,
) -> BTreeMap<SymbolKey, SymbolSnapshot> {
    let _query_scope = AnalyzerQueryScope::new(analyzer);
    let mut out = BTreeMap::new();
    // Read each file at most once: many declarations share a source, and the
    // body hash only needs the file's text sliced by line range.
    let mut file_text: HashMap<PathBuf, Option<String>> = HashMap::new();
    for unit in analyzer.all_declarations() {
        if unit.is_synthetic() {
            continue;
        }
        let path = rel_path(unit.source());
        // Symbol-level test filtering (#1102): filter a declaration only when it
        // is itself in a structurally-evidenced test region or under a test-tree
        // path, so production symbols in a file with inline tests still surface.
        let is_test = analyzer.in_test_region(&unit)
            || test_paths::is_test_like_path(&path, path_language(unit.source().rel_path()));
        if is_test && !include_tests {
            continue;
        }
        let Some(range) = primary_range(analyzer, &unit) else {
            continue;
        };
        let language = language_for_path(unit.source().rel_path());
        let kind = kind_name(unit.kind()).to_string();
        let key = SymbolKey {
            fqn: unit.fq_name(),
            kind: kind.clone(),
            language: language.clone(),
        };
        let signature = analyzer
            .signatures(&unit)
            .first()
            .map(|s| s.to_string())
            .or_else(|| unit.signature().map(str::to_string))
            .unwrap_or_default();
        let name = unit.identifier().to_string();
        let token_sig = file_text
            .entry(unit.source().abs_path())
            .or_insert_with(|| unit.source().read_to_string().ok())
            .as_deref()
            .and_then(|text| {
                body_token_signature_for_bytes(text, &name, range.start_byte, range.end_byte)
            });
        out.insert(
            key.clone(),
            SymbolSnapshot {
                key,
                token_sig,
                symbol: CommitSymbol {
                    fqn: unit.fq_name(),
                    name,
                    kind,
                    signature,
                    path,
                    start_line: range.start_line,
                    end_line: range.end_line,
                    language,
                    is_test,
                },
            },
        );
    }
    out
}

/// How the two endpoints' symbols line up.
struct EndpointPairing<'a> {
    /// `(preimage, postimage)` for every symbol both endpoints hold.
    pairs: Vec<(&'a SymbolSnapshot, &'a SymbolSnapshot)>,
    postimage_only: Vec<&'a SymbolSnapshot>,
    preimage_only: Vec<&'a SymbolSnapshot>,
    /// Symbols paired by the body-similarity rule rather than by identity or a
    /// Git rename, keyed on BOTH endpoints' keys, each mapped to the pair's
    /// similarity score. These relocated (and possibly were renamed or lightly
    /// edited), but the hunks that deleted them from one place and inserted
    /// them at another are not edits to report -- see the classifier, which
    /// also surfaces the score on the resulting [`MovedSymbol`].
    fallback_paired: HashMap<&'a SymbolKey, f64>,
}

/// Match preimage symbols to postimage symbols.
///
/// Two symbols pair when their key -- fqn, kind and language -- is identical,
/// which covers everything a patch leaves in place (an unqualified fqn -- a
/// bare name, as flat-namespace languages produce -- must additionally keep
/// its path; see the guard below). The second rule exists
/// because a fully-qualified name derived from a path does not survive a file
/// move: when Git reports a rename, a preimage symbol under the old path pairs
/// with a postimage symbol under the new one, provided the name, kind and
/// language single one candidate out on each side.
///
/// Without that rule a moved module reports every symbol it declares as both
/// deleted and introduced, and every call between two of them as churn.
///
/// Overloads are exactly the case the uniqueness requirement rejects: two
/// same-named declarations in a renamed file offer no evidence about which
/// preimage one became which postimage one, so both stay unpaired.
///
/// The third rule catches what the first two miss: a symbol moved to a file Git
/// did not report as a rename, or renamed in place -- possibly with light
/// internal edits -- keeps neither its key nor a rename bucket. Leftovers are
/// paired by token-similarity of their bodies, greedily and one-to-one above a
/// threshold, so a relocated-and-renamed symbol still lines up. Trivial bodies
/// never participate.
fn pair_endpoints<'a>(
    before: &'a BTreeMap<SymbolKey, SymbolSnapshot>,
    after: &'a BTreeMap<SymbolKey, SymbolSnapshot>,
    file_changes: &[FileChange],
) -> EndpointPairing<'a> {
    // First rule: identity of the key (fqn, kind, language) -- with one guard.
    // In flat-namespace languages (JavaScript most prominently) a symbol's fqn
    // can be its bare unqualified name, so two UNRELATED same-name functions in
    // different files share an identity key: a deleted `updateConfig` in a.js
    // would identity-pair with a brand-new `updateConfig` in b.js, fabricating
    // a "moved" symbol and suppressing the real delete+introduce. When the fqn
    // carries no qualifier (fqn == bare name), identity across DIFFERENT paths
    // is no evidence at all, so such a pair must also agree on the path.
    // Refused pairs fall through to the leftover sets, where the rename bucket
    // (rule 2) or body similarity (rule 3, which also tags a similarity score)
    // can legitimately claim a genuine cross-file move; this guard only
    // refuses suspect identity pairs, it never creates new ones.
    let flat_identity_conflict = |pre: &SymbolSnapshot, post: &SymbolSnapshot| {
        (pre.symbol.fqn == pre.symbol.name || post.symbol.fqn == post.symbol.name)
            && pre.symbol.path != post.symbol.path
    };
    let mut pairs = Vec::new();
    let mut preimage_only = Vec::new();
    let mut postimage_only = Vec::new();
    for (key, post) in after {
        match before.get(key) {
            Some(pre) if !flat_identity_conflict(pre, post) => pairs.push((pre, post)),
            _ => postimage_only.push(post),
        }
    }
    for (key, pre) in before {
        match after.get(key) {
            Some(post) if !flat_identity_conflict(pre, post) => {}
            _ => preimage_only.push(pre),
        }
    }

    let renamed_paths: HashMap<&str, &str> = file_changes
        .iter()
        .filter_map(|change| Some((change.old_path.as_deref()?, change.path.as_deref()?)))
        .collect();

    // Bucket both leftovers under the postimage path so a rename lines them up,
    // then keep only the buckets where one preimage symbol faces exactly one
    // postimage symbol.
    type SymbolIdentity<'i> = (&'i str, &'i str, &'i str, &'i str);
    let mut candidates: HashMap<
        SymbolIdentity<'_>,
        (Vec<&'a SymbolSnapshot>, Vec<&'a SymbolSnapshot>),
    > = HashMap::new();
    for pre in preimage_only.iter().copied() {
        let Some(new_path) = renamed_paths.get(pre.symbol.path.as_str()).copied() else {
            continue;
        };
        candidates
            .entry((
                new_path,
                pre.symbol.name.as_str(),
                pre.key.kind.as_str(),
                pre.key.language.as_str(),
            ))
            .or_default()
            .0
            .push(pre);
    }
    for post in postimage_only.iter().copied() {
        candidates
            .entry((
                post.symbol.path.as_str(),
                post.symbol.name.as_str(),
                post.key.kind.as_str(),
                post.key.language.as_str(),
            ))
            .or_default()
            .1
            .push(post);
    }
    let mut moved_keys: HashSet<&SymbolKey> = HashSet::new();
    for (pre, post) in candidates
        .into_values()
        .filter(|(pre, post)| pre.len() == 1 && post.len() == 1)
        .map(|(pre, post)| (pre[0], post[0]))
    {
        moved_keys.insert(&pre.key);
        moved_keys.insert(&post.key);
        pairs.push((pre, post));
    }
    preimage_only.retain(|snapshot| !moved_keys.contains(&snapshot.key));
    postimage_only.retain(|snapshot| !moved_keys.contains(&snapshot.key));

    // Third rule: pair the remaining leftovers by body SIMILARITY. A symbol cut
    // from one place and pasted at another -- under a new name, in a file Git
    // did not report as a rename, and perhaps with a few internal edits --
    // shares no identity key and lands in no rename bucket, so it would
    // otherwise surface as delete+introduce plus the very call-edge churn
    // `fqn_renames` exists to cancel. Score every leftover preimage against
    // every leftover postimage by IDF-weighted token similarity and greedily
    // accept the best mutual matches above the threshold, one-to-one.
    // Greedy-by-descending score means the most confident relocation claims its
    // counterpart first; ties break on fqn so the result is deterministic.
    // Trivial bodies carry `token_sig == None` and never participate.
    //
    // The df pool spans EVERY tokenizable body on both endpoints -- leftovers
    // and identity-paired symbols alike -- so a token's weight reflects how
    // ordinary it is across the whole change, not just among the leftovers.
    let pre_candidates: Vec<(&'a SymbolSnapshot, &'a [String])> = preimage_only
        .iter()
        .filter_map(|pre| Some((*pre, pre.token_sig.as_deref()?)))
        .collect();
    let post_candidates: Vec<(&'a SymbolSnapshot, &'a [String])> = postimage_only
        .iter()
        .filter_map(|post| Some((*post, post.token_sig.as_deref()?)))
        .collect();
    let mut fallback_paired: HashMap<&SymbolKey, f64> = HashMap::new();
    // Hard cap: scoring is O(P x Q) over the leftover candidates, and a
    // mass-churn commit (a vendored tree drop, a generated-code rewrite) could
    // otherwise blow up analyze_diff latency. Past the cap, skip the rule
    // entirely for this diff: bounded latency beats unbounded matching on
    // pathological commits, and the fallback is the pre-feature baseline --
    // every leftover reports as plain delete+introduce -- never worse.
    let candidate_products = pre_candidates.len().saturating_mul(post_candidates.len());
    if candidate_products > 0 && candidate_products <= FUZZY_PAIRING_CANDIDATE_CAP {
        let idf = diff_local_idf(
            before
                .values()
                .chain(after.values())
                .filter_map(|snapshot| snapshot.token_sig.as_deref()),
        );
        let bag_weight = |sig: &[String]| -> f64 {
            sig.iter()
                .map(|t| {
                    idf.get(t.as_str())
                        .copied()
                        .unwrap_or(std::f64::consts::LN_2)
                })
                .sum()
        };
        let pre_weights: Vec<f64> = pre_candidates
            .iter()
            .map(|(_, sig)| bag_weight(sig))
            .collect();
        let post_weights: Vec<f64> = post_candidates
            .iter()
            .map(|(_, sig)| bag_weight(sig))
            .collect();
        let mut scored: Vec<(f64, &'a SymbolSnapshot, &'a SymbolSnapshot)> = Vec::new();
        for (pre_idx, (pre, pre_sig)) in pre_candidates.iter().enumerate() {
            for (post_idx, (post, post_sig)) in post_candidates.iter().enumerate() {
                // Size-ratio prefilter -- a pure fast-path, not a behavior
                // change: see `within_fuzzy_weight_ratio`.
                if !within_fuzzy_weight_ratio(pre_weights[pre_idx], post_weights[post_idx]) {
                    continue;
                }
                let score = body_similarity(pre_sig, post_sig, &idf);
                if score >= BODY_MOVE_SIMILARITY_THRESHOLD {
                    scored.push((score, pre, post));
                }
            }
        }
        scored.sort_by(|(sa, pa, qa), (sb, pb, qb)| {
            sb.partial_cmp(sa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| pa.symbol.fqn.cmp(&pb.symbol.fqn))
                .then_with(|| qa.symbol.fqn.cmp(&qb.symbol.fqn))
        });
        for (score, pre, post) in scored {
            if fallback_paired.contains_key(&pre.key) || fallback_paired.contains_key(&post.key) {
                continue;
            }
            fallback_paired.insert(&pre.key, score);
            fallback_paired.insert(&post.key, score);
            pairs.push((pre, post));
        }
    }
    preimage_only.retain(|snapshot| !fallback_paired.contains_key(&snapshot.key));
    postimage_only.retain(|snapshot| !fallback_paired.contains_key(&snapshot.key));

    EndpointPairing {
        pairs,
        postimage_only,
        preimage_only,
        fallback_paired,
    }
}

/// Replace every whole-identifier occurrence of `name` in `line` with a fixed
/// placeholder, leaving substrings (a `sum` inside `summary`) untouched.
///
/// This is what makes the body fingerprint name-independent: the symbol's own
/// name appears in its declaration line and in any recursive call, so a rename
/// would otherwise change the hash and defeat move detection. Neutralizing the
/// name -- and only the name -- lets a renamed body still match its original.
fn blank_identifier<'a>(line: &'a str, name: &str) -> Cow<'a, str> {
    if name.is_empty() {
        return Cow::Borrowed(line);
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut out: Option<String> = None;
    let mut last = 0;
    for (idx, _) in line.match_indices(name) {
        let boundary_before = line[..idx].chars().next_back().is_none_or(|c| !is_word(c));
        let boundary_after = line[idx + name.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_word(c));
        if boundary_before && boundary_after {
            let buf = out.get_or_insert_with(|| String::with_capacity(line.len()));
            buf.push_str(&line[last..idx]);
            buf.push('\u{0}');
            last = idx + name.len();
        }
    }
    match out {
        Some(mut buf) => {
            buf.push_str(&line[last..]);
            Cow::Owned(buf)
        }
        None => Cow::Borrowed(line),
    }
}

/// The minimum IDF-weighted body token similarity for two leftover symbols to
/// be paired as the same symbol relocated. Chosen to accept a renamed method
/// whose body also saw a few internal renames or a small edit, while rejecting
/// merely structurally-similar but unrelated code.
///
/// Tuned on the RefactoringMiner oracle via `tools/rename-eval` (641 real
/// move/rename pairs, ~330k negatives): at 0.40 the diff-local-IDF-weighted
/// metric reaches whole-commit precision 0.896 / recall 0.815, vs 0.865 /
/// 0.712 for the previous unweighted bag Jaccard at its 0.70 threshold --
/// higher precision AND recall simultaneously. Unrelated pairs score ~0.03-0.05
/// on this scale. See `tools/rename-eval/RESULTS.md`.
const BODY_MOVE_SIMILARITY_THRESHOLD: f64 = 0.40;

/// The most leftover preimage x postimage candidate pairs the fuzzy third rule
/// of [`pair_endpoints`] will score. Scoring is O(P x Q); past this cap the
/// rule is skipped for the whole diff and leftovers report as plain
/// delete+introduce -- the pre-feature baseline, never worse than it.
const FUZZY_PAIRING_CANDIDATE_CAP: usize = 250_000;

/// The largest total-bag-weight mismatch [`pair_endpoints`] will bother
/// scoring: the larger side may outweigh the smaller by at most this factor.
const FUZZY_WEIGHT_RATIO_LIMIT: f64 = 3.0;

// The prefilter is sound only while a maximally-mismatched pair still cannot
// reach the acceptance threshold: 1 / limit must stay below it.
const _: () = assert!(1.0 / FUZZY_WEIGHT_RATIO_LIMIT < BODY_MOVE_SIMILARITY_THRESHOLD);

/// Whether two token bags' total IDF weights are close enough in size that
/// [`body_similarity`] could reach [`BODY_MOVE_SIMILARITY_THRESHOLD`].
///
/// A pure fast-path, not a behavior change: weighted bag Jaccard is bounded by
/// the ratio of the two bags' total weights -- the intersection sums
/// `w * min(ca, cb)`, at most the smaller bag's total, while the union sums
/// `w * max(ca, cb)`, at least the larger bag's total -- so a pair whose
/// totals differ by more than [`FUZZY_WEIGHT_RATIO_LIMIT`] scores below
/// `1 / limit = 0.33..`, under the 0.40 threshold, and skipping it cannot
/// change the outcome.
fn within_fuzzy_weight_ratio(weight_a: f64, weight_b: f64) -> bool {
    weight_a.max(weight_b) <= FUZZY_WEIGHT_RATIO_LIMIT * weight_a.min(weight_b)
}

/// Tokenize a declaration directly from its analyzer byte range.
///
/// `symbol_snapshot_map` may visit hundreds of declarations in one generated
/// or compiler source file. Restarting `source.lines()` at byte zero for every
/// declaration makes that pass quadratic in file length. Analyzer ranges
/// already carry exact UTF-8 byte offsets, so this slices once. The symbol's
/// own name is blanked and the slice is tokenized into word/number runs and
/// punctuation; bodies with fewer than two non-blank lines are too weak to
/// identify a move and return `None`.
fn body_token_signature_for_bytes(
    source: &str,
    name: &str,
    start_byte: usize,
    end_byte: usize,
) -> Option<Vec<String>> {
    let body = source.get(start_byte..end_byte)?;
    let mut tokens = Vec::new();
    let mut non_blank_lines = 0;
    for line in body.lines() {
        tokenize_body_line(line, name, &mut tokens, &mut non_blank_lines);
    }
    finish_body_token_signature(tokens, non_blank_lines)
}

fn tokenize_body_line(
    line: &str,
    name: &str,
    tokens: &mut Vec<String>,
    non_blank_lines: &mut usize,
) {
    let blanked = blank_identifier(line, name);
    let before = tokens.len();
    tokenize_into(&blanked, tokens);
    if tokens.len() > before {
        *non_blank_lines += 1;
    }
}

fn finish_body_token_signature(tokens: Vec<String>, non_blank_lines: usize) -> Option<Vec<String>> {
    if non_blank_lines < 2 || tokens.is_empty() {
        return None;
    }
    Some(tokens)
}

/// Append `line`'s tokens to `out`: maximal `[A-Za-z0-9_]`/NUL runs (words,
/// numbers, and the blanked-name placeholder) and every other non-whitespace
/// character as its own token. Whitespace is dropped, so indentation and
/// spacing never affect the signature.
fn tokenize_into(line: &str, out: &mut Vec<String>) {
    let mut word = String::new();
    for ch in line.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '\u{0}' {
            word.push(ch);
        } else {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            if !ch.is_whitespace() {
                out.push(ch.to_string());
            }
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
}

/// Per-token IDF weights over a diff-local document-frequency pool.
///
/// Each item of `pool` is one symbol body's token sequence; the pool should
/// hold EVERY tokenizable body on both endpoints of the diff (including
/// identity-paired ones), so the weights reflect what is common *in this
/// change*. With `N` bodies and `df(t)` = the number of bodies whose token
/// multiset contains `t` (each body counted once per distinct token), the
/// weight is `ln((N + 1) / (df(t) + 0.5))`: boilerplate every body shares
/// (braces, keywords, common type names) weighs near zero, while tokens unique
/// to one body dominate. Computed per diff -- no shipped background table.
fn diff_local_idf<'a>(pool: impl Iterator<Item = &'a [String]>) -> HashMap<&'a str, f64> {
    let mut df: HashMap<&str, usize> = HashMap::new();
    let mut n = 0usize;
    for sig in pool {
        n += 1;
        let distinct: HashSet<&str> = sig.iter().map(String::as_str).collect();
        for token in distinct {
            *df.entry(token).or_default() += 1;
        }
    }
    let n = n as f64;
    df.into_iter()
        .map(|(token, count)| (token, ((n + 1.0) / (count as f64 + 0.5)).ln()))
        .collect()
}

/// IDF-weighted multiset (bag) Jaccard similarity of two token sequences, in
/// `[0.0, 1.0]`.
///
/// Per token `t` with counts `ca`/`cb` in the two bags, the shared size sums
/// `w(t) * min(ca, cb)` and the total sums `w(t) * max(ca, cb)`, with `w`
/// taken from `idf` (see [`diff_local_idf`]). Weighting by rarity is what
/// separates a genuine relocation from structural coincidence: two bodies that
/// agree only on braces, keywords and common calls share almost no weight,
/// while agreement on rare identifiers -- the tokens that actually identify
/// the logic -- counts heavily. Both bags are drawn from the df pool, so every
/// token has an entry; the `ln 2` fallback (a body absent from the pool, e.g.
/// in a unit test) mirrors an unseen token's `df = 0` weight at `N = 1`.
///
/// The tolerated costs are unchanged from the unweighted version: bag
/// semantics forgive the scattered token changes a rename introduces, and
/// order-blindness means two arrangements of one token bag score alike --
/// acceptable for a move-pairing heuristic guarded by a threshold and
/// one-to-one assignment.
fn body_similarity(a: &[String], b: &[String], idf: &HashMap<&str, f64>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<&str, (u32, u32)> = HashMap::new();
    for token in a {
        counts.entry(token).or_default().0 += 1;
    }
    for token in b {
        counts.entry(token).or_default().1 += 1;
    }
    let mut intersection = 0.0;
    let mut union = 0.0;
    for (token, (ca, cb)) in counts {
        let weight = idf.get(token).copied().unwrap_or(std::f64::consts::LN_2);
        intersection += weight * f64::from(ca.min(cb));
        union += weight * f64::from(ca.max(cb));
    }
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

/// Whether a paired symbol's line change is fully explained by edits ELSEWHERE
/// in the same file (a pure shift), as opposed to a genuine relocation.
///
/// An unchanged symbol occupies the same position *among unchanged lines* on
/// both endpoints. Subtracting the deletions before its old start and the
/// insertions before its new start collapses both sides to that shared
/// unchanged-line index; equal indices mean the symbol only slid, it did not
/// move. Same-file only -- a path change is always a relocation.
fn is_pure_line_shift(
    pre: &CommitSymbol,
    post: &CommitSymbol,
    changed_lines: &BTreeMap<String, ChangedLines>,
) -> bool {
    if pre.path != post.path {
        return false;
    }
    let deletions_before = changed_lines
        .get(&pre.path)
        .map_or(0, |cl| cl.old.range(..pre.start_line).count());
    let insertions_before = changed_lines
        .get(&post.path)
        .map_or(0, |cl| cl.new.range(..post.start_line).count());
    pre.start_line.saturating_sub(deletions_before)
        == post.start_line.saturating_sub(insertions_before)
}

/// Deleted lines of the patch that fall inside a preimage symbol's range.
///
/// `symbol.path` is the preimage path, which is also how `-` lines are keyed,
/// so a rename resolves against the correct side of the diff.
fn old_overlap(
    symbol: &CommitSymbol,
    changed_lines: &BTreeMap<String, ChangedLines>,
) -> Vec<usize> {
    touched_lines(
        changed_lines.get(&symbol.path).map(|lines| &lines.old),
        symbol.start_line,
        symbol.end_line,
    )
}

/// Added lines of the patch that fall inside a postimage symbol's range.
fn new_overlap(
    symbol: &CommitSymbol,
    changed_lines: &BTreeMap<String, ChangedLines>,
) -> Vec<usize> {
    touched_lines(
        changed_lines.get(&symbol.path).map(|lines| &lines.new),
        symbol.start_line,
        symbol.end_line,
    )
}

fn touched_lines(lines: Option<&BTreeSet<usize>>, start: usize, end: usize) -> Vec<usize> {
    lines
        .into_iter()
        .flat_map(|lines| lines.range(start..=end).copied())
        .collect()
}

fn import_changes(
    before: &dyn IAnalyzer,
    after: &dyn IAnalyzer,
    paths: &[String],
) -> Vec<ImportChange> {
    let mut out = Vec::new();
    for path in paths {
        let file = Path::new(path);
        let old = imports_for_path(before, file);
        let new = imports_for_path(after, file);
        let added: Vec<_> = new.difference(&old).cloned().collect();
        let removed: Vec<_> = old.difference(&new).cloned().collect();
        if !added.is_empty() || !removed.is_empty() {
            out.push(ImportChange {
                path: path.clone(),
                added,
                removed,
            });
        }
    }
    out
}

fn imports_for_path(analyzer: &dyn IAnalyzer, path: &Path) -> BTreeSet<String> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let Some(file) = analyzer.project().file_by_rel_path(path) else {
        return BTreeSet::new();
    };
    let structured = analyzer
        .import_analysis_provider()
        .map(|provider| {
            provider
                .import_info_of(token, &file)
                .iter()
                .map(|info| info.raw_snippet.clone())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if !structured.is_empty() {
        return structured;
    }
    analyzer.import_statements(&file).into_iter().collect()
}

/// A usage-graph endpoint as the graph itself names one: fqn plus language.
///
/// Kind is deliberately absent. [`UsageGraphEdge`] carries only these two
/// fields, so this is the finest key an edge can be attributed by.
type CallerKey = (String, String);

/// Added and removed callees of one symbol.
#[derive(Debug, Clone, Default)]
struct CalleeDelta {
    added: Vec<CalleeChange>,
    removed: Vec<CalleeChange>,
}

/// What comparing the two scoped usage graphs produced.
struct CallEdgeDiff {
    /// Callee deltas keyed by caller. Every caller is named the way the
    /// postimage names it, including symbols the patch moved to a new fqn.
    deltas: HashMap<CallerKey, CalleeDelta>,
    dependency_symbols: Vec<CommitSymbol>,
}

/// Key a symbol by the shared ecosystem namespace used by usage-graph edges.
/// `CommitSymbol::language` is per-dialect (`typescript`), while an edge can
/// cross JavaScript and TypeScript and therefore uses their shared ecosystem
/// label (`js_ts`).
fn symbol_edge_key(symbol: &CommitSymbol) -> CallerKey {
    let ecosystem = UsageEcosystem::of(path_language(Path::new(&symbol.path))).as_str();
    (symbol.fqn.clone(), ecosystem.to_string())
}

/// `(preimage fqn, language) -> postimage fqn` for every symbol the patch moved
/// to a new fully-qualified name.
///
/// This is what keeps a move from masquerading as call-edge churn. Moving a
/// module renames every symbol it declares, so an untouched call between two of
/// them becomes a removed edge under the old names and an added edge under the
/// new ones, and every outside caller of a moved callee reports the same
/// spurious pair. Rewriting the preimage graph through this mapping before the
/// comparison cancels both.
///
/// Ambiguity is dropped rather than guessed: overloads and same-name
/// declarations of different kinds can map one preimage name onto two postimage
/// names, and an edge endpoint carries no kind to tell them apart.
fn fqn_renames(moved: &[MovedSymbol]) -> HashMap<CallerKey, String> {
    let mut candidates: HashMap<CallerKey, BTreeSet<String>> = HashMap::new();
    for entry in moved {
        if entry.before.fqn == entry.after.fqn {
            continue;
        }
        candidates
            .entry(symbol_edge_key(&entry.before))
            .or_default()
            .insert(entry.after.fqn.clone());
    }
    candidates
        .into_iter()
        .filter(|(_, targets)| targets.len() == 1)
        .map(|(key, targets)| {
            let target = targets
                .into_iter()
                .next()
                .expect("a one-element set has a first element");
            (key, target)
        })
        .collect()
}

/// Rewrite both endpoints of every preimage edge under the postimage names.
///
/// A patch that moved nothing borrows the graph it was given: the rewrite would
/// copy every edge and its callsites to change none of them.
fn rename_edges<'e>(
    edges: &'e [UsageGraphEdge],
    renames: &HashMap<CallerKey, String>,
) -> Cow<'e, [UsageGraphEdge]> {
    if renames.is_empty() {
        return Cow::Borrowed(edges);
    }
    let renamed = |fqn: &String, language: &String| -> String {
        renames
            .get(&(fqn.clone(), language.clone()))
            .cloned()
            .unwrap_or_else(|| fqn.clone())
    };
    Cow::Owned(
        edges
            .iter()
            .map(|edge| UsageGraphEdge {
                // Diffing still keys moved symbols by their before/after names.
                // Preserve the snapshot-local exact identities while rewriting
                // only the display names used by that comparison.
                from_id: edge.from_id.clone(),
                to_id: edge.to_id.clone(),
                from: renamed(&edge.from, &edge.language),
                to: renamed(&edge.to, &edge.language),
                language: edge.language.clone(),
                weight: edge.weight,
                sites: edge.sites.clone(),
            })
            .collect(),
    )
}

/// Compare the two scoped usage graphs and group the differences by caller.
///
/// Edge identity is `(from, to, language)`, so a weight-only change is not a
/// difference: the same call written twice instead of once keeps one edge.
fn diff_call_edges(
    before: &[UsageGraphEdge],
    after: &[UsageGraphEdge],
    renames: &HashMap<CallerKey, String>,
    postimage: &BTreeMap<SymbolKey, SymbolSnapshot>,
) -> CallEdgeDiff {
    let before = rename_edges(before, renames);
    let old = edge_map(&before);
    let new = edge_map(after);
    let definitions = symbols_by_edge_key(postimage);
    let mut deltas: HashMap<CallerKey, CalleeDelta> = HashMap::new();
    let mut deps: BTreeMap<String, CommitSymbol> = BTreeMap::new();
    for (key, edge) in &new {
        if old.contains_key(key) {
            continue;
        }
        deltas
            .entry((edge.from.clone(), edge.language.clone()))
            .or_default()
            .added
            .push(callee_change(edge));
        if let Some(symbol) = definitions.get(&(edge.to.clone(), edge.language.clone())) {
            deps.insert(symbol.fqn.clone(), (*symbol).clone());
        }
    }
    for (key, edge) in &old {
        if new.contains_key(key) {
            continue;
        }
        deltas
            .entry((edge.from.clone(), edge.language.clone()))
            .or_default()
            .removed
            .push(callee_change(edge));
    }
    for delta in deltas.values_mut() {
        sort_callee_changes(&mut delta.added);
        sort_callee_changes(&mut delta.removed);
    }
    let mut dependency_symbols: Vec<_> = deps.into_values().collect();
    sort_symbols(&mut dependency_symbols);
    CallEdgeDiff {
        deltas,
        dependency_symbols,
    }
}

/// Restore the `from` and `change` fields that per-symbol attribution implied,
/// for the edges no patch symbol claimed.
fn flatten_unattributed(
    deltas: HashMap<CallerKey, CalleeDelta>,
    claimed_added: &HashSet<CallerKey>,
    claimed_removed: &HashSet<CallerKey>,
) -> Vec<CallEdgeChange> {
    let mut changes: Vec<CallEdgeChange> = deltas
        .into_iter()
        .flat_map(|(key, delta)| {
            let added = if claimed_added.contains(&key) {
                Vec::new()
            } else {
                delta.added
            };
            let removed = if claimed_removed.contains(&key) {
                Vec::new()
            } else {
                delta.removed
            };
            let (from, _) = key;
            added
                .into_iter()
                .map(|callee| ("added", callee))
                .chain(removed.into_iter().map(|callee| ("removed", callee)))
                .map(move |(change, callee)| CallEdgeChange {
                    change: change.to_string(),
                    from: from.clone(),
                    to: callee.to,
                    language: callee.language,
                    weight: callee.weight,
                    sites: callee.sites,
                })
        })
        .collect();
    changes.sort_by(|a, b| {
        a.language
            .cmp(&b.language)
            .then_with(|| a.from.cmp(&b.from))
            .then_with(|| a.to.cmp(&b.to))
            .then_with(|| a.change.cmp(&b.change))
    });
    changes
}

fn sort_callee_changes(changes: &mut [CalleeChange]) {
    changes.sort_by(|a, b| a.language.cmp(&b.language).then_with(|| a.to.cmp(&b.to)));
}

fn edge_map(edges: &[UsageGraphEdge]) -> BTreeMap<EdgeKey, &UsageGraphEdge> {
    edges
        .iter()
        .map(|edge| {
            (
                EdgeKey {
                    from: edge.from.clone(),
                    to: edge.to.clone(),
                    language: edge.language.clone(),
                },
                edge,
            )
        })
        .collect()
}

fn callee_change(edge: &UsageGraphEdge) -> CalleeChange {
    CalleeChange {
        to: edge.to.clone(),
        language: edge.language.clone(),
        weight: edge.weight,
        sites: edge.sites.clone(),
    }
}

/// Index the postimage symbols the way an edge endpoint names them.
///
/// The snapshot map is keyed by fqn, kind and language, but an edge carries no
/// kind, so the two fqns a class and a function share collapse onto one entry.
/// The first in snapshot-key order wins, which is the symbol a scan of the map
/// would have found.
fn symbols_by_edge_key(
    symbols: &BTreeMap<SymbolKey, SymbolSnapshot>,
) -> HashMap<CallerKey, &CommitSymbol> {
    let mut out: HashMap<CallerKey, &CommitSymbol> = HashMap::new();
    for snapshot in symbols.values() {
        out.entry(symbol_edge_key(&snapshot.symbol))
            .or_insert(&snapshot.symbol);
    }
    out
}

fn large_callsite_symbols(
    before: Vec<UsageGraphTruncatedSymbol>,
    after: Vec<UsageGraphTruncatedSymbol>,
) -> Vec<LargeCallsiteSymbol> {
    let mut out: BTreeMap<(String, String), LargeCallsiteSymbol> = BTreeMap::new();
    for item in before.into_iter().chain(after) {
        out.insert(
            (item.language.clone(), item.fqn.clone()),
            LargeCallsiteSymbol {
                fqn: item.fqn,
                language: item.language,
                total_callsites: item.total_callsites,
                limit: item.limit,
            },
        );
    }
    out.into_values().collect()
}

pub(crate) fn primary_range(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<crate::analyzer::Range> {
    analyzer
        .ranges(unit)
        .iter()
        .copied()
        .min_by_key(|range| (range.start_line, range.start_byte))
}

fn sort_symbols(symbols: &mut [CommitSymbol]) {
    symbols.sort();
}

pub(crate) fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn rel_path(file: &ProjectFile) -> String {
    path_string(file.rel_path())
}

fn delta_status(status: Delta) -> &'static str {
    match status {
        // A working-tree diff reports never-committed files as `Untracked`;
        // relative to the base endpoint they are simply new.
        Delta::Added | Delta::Untracked => "added",
        Delta::Deleted => "deleted",
        Delta::Conflicted => "conflicted",
        Delta::Modified => "modified",
        Delta::Renamed => "renamed",
        Delta::Copied => "copied",
        Delta::Typechange => "typechange",
        _ => "unknown",
    }
}

fn is_parseable_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| Language::from_extension(ext) != Language::None)
        .unwrap_or(false)
}

fn language_for_path(path: &Path) -> String {
    let language = path_language(path);
    if language == Language::None {
        "unknown".to_string()
    } else {
        format!("{language:?}").to_lowercase()
    }
}

pub(crate) fn path_language(path: &Path) -> Language {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

fn kind_name(kind: CodeUnitType) -> &'static str {
    kind.display_lowercase()
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        AnalyzeDiffParams, BODY_MOVE_SIMILARITY_THRESHOLD, ChangedLines, CommitSymbol,
        DiffAnalysisOptions, DiffEndpointParams, FileChange, ImportTarget, Language, PreparedDiff,
        RevisionImage, RevisionTempDir, SharedAnalyzerCache, Snapshot, SymbolKey, SymbolSnapshot,
        WORKTREE_ENDPOINT, analyze_diff_at_root, analyze_prepared_diff,
        analyze_prepared_symbol_changes, body_similarity, body_token_signature_for_bytes,
        create_private_dirs, diff_local_idf, is_pure_line_shift, pair_endpoints,
        resolve_import_target, within_fuzzy_weight_ratio, worktree_files, write_private_file,
    };
    use crate::gitblob::test_repo;
    use git2::{Oid, Repository};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    #[test]
    fn complete_revision_export_preserves_every_regular_tree_file() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::create_dir_all(dir.path().join("deep/one/two")).unwrap();
        fs::write(dir.path().join("root.ts"), "export const root = 1;\n").unwrap();
        fs::write(
            dir.path().join("deep/one/first.ts"),
            "export const first = 1;\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("deep/one/two/second.ts"),
            "export const second = 2;\n",
        )
        .unwrap();
        let commit = test_repo::commit_all(&repo, "complete tree");

        let image =
            RevisionImage::materialize(&repo, Snapshot::Commit(commit), None, &[], None).unwrap();
        let files = image.files().iter().cloned().collect::<BTreeSet<_>>();

        assert_eq!(
            BTreeSet::from([
                PathBuf::from("deep/one/first.ts"),
                PathBuf::from("deep/one/two/second.ts"),
                PathBuf::from("root.ts"),
            ]),
            files
        );
        assert_eq!(
            "export const second = 2;\n",
            fs::read_to_string(image.root().join("deep/one/two/second.ts")).unwrap()
        );
    }

    #[test]
    fn file_dependency_export_keeps_selected_sources_and_identity_inputs_only() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.ts"), "export const main = 1;\n").unwrap();
        fs::write(
            dir.path().join("src/shared.js"),
            "export const shared = 1;\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("src/unrelated.java"),
            "class Unrelated {}\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("src/app.cs"),
            "namespace Fixture; class App {}\n",
        )
        .unwrap();
        fs::write(dir.path().join("package.json"), "{\"name\":\"fixture\"}\n").unwrap();
        fs::write(dir.path().join("package-lock.json"), "{}\n").unwrap();
        fs::write(dir.path().join("tsconfig.json"), "{}\n").unwrap();
        fs::write(dir.path().join("pom.xml"), "<project/>\n").unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::write(dir.path().join("Directory.Build.props"), "<Project/>\n").unwrap();
        fs::write(dir.path().join("generated.targets"), "<Project/>\n").unwrap();
        fs::write(dir.path().join("fixture.dll"), b"managed fixture").unwrap();
        let commit = test_repo::commit_all(&repo, "scoped graph image");

        let selected = BTreeSet::from([Language::JavaScript, Language::TypeScript]);
        let image = RevisionImage::materialize_file_dependencies(
            &repo,
            Snapshot::Commit(commit),
            &selected,
            &[],
        )
        .unwrap();
        let files = image.files().iter().cloned().collect::<BTreeSet<_>>();

        assert!(files.contains(Path::new("src/main.ts")));
        assert!(files.contains(Path::new("src/shared.js")));
        assert!(files.contains(Path::new("package.json")));
        assert!(files.contains(Path::new("package-lock.json")));
        assert!(files.contains(Path::new("tsconfig.json")));
        assert!(!files.contains(Path::new("src/unrelated.java")));
        assert!(!files.contains(Path::new("pom.xml")));
        assert!(!files.contains(Path::new("Cargo.toml")));
        assert!(!files.contains(Path::new("Directory.Build.props")));
        assert!(!files.contains(Path::new("generated.targets")));
        assert!(!files.contains(Path::new("fixture.dll")));

        let csharp_image = RevisionImage::materialize_file_dependencies(
            &repo,
            Snapshot::Commit(commit),
            &BTreeSet::from([Language::CSharp]),
            &[],
        )
        .unwrap();
        let csharp_files = csharp_image
            .files()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(csharp_files.contains(Path::new("src/app.cs")));
        assert!(csharp_files.contains(Path::new("Directory.Build.props")));
        assert!(csharp_files.contains(Path::new("generated.targets")));
        assert!(csharp_files.contains(Path::new("fixture.dll")));
        assert!(!csharp_files.contains(Path::new("src/main.ts")));

        // The complete exporter remains an independent contract for callers
        // that need every regular tree file.
        let complete =
            RevisionImage::materialize(&repo, Snapshot::Commit(commit), None, &[], None).unwrap();
        let complete_files = complete.files().iter().cloned().collect::<BTreeSet<_>>();
        assert!(complete_files.contains(Path::new("src/unrelated.java")));
        assert!(complete_files.contains(Path::new("pom.xml")));
        assert!(complete_files.contains(Path::new("Cargo.toml")));
    }

    #[test]
    fn file_dependency_export_writes_only_configuration_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.ts"), "export const main = 1;\n").unwrap();
        fs::write(
            dir.path().join("src/shared.js"),
            "export const shared = 1;\n",
        )
        .unwrap();
        fs::write(dir.path().join("package.json"), "{\"name\":\"fixture\"}\n").unwrap();
        let commit = test_repo::commit_all(&repo, "scoped graph image");

        let image = RevisionImage::materialize_file_dependencies(
            &repo,
            Snapshot::Commit(commit),
            &BTreeSet::from([Language::JavaScript, Language::TypeScript]),
            &[],
        )
        .unwrap();

        // The manifest is a real file: several dependency resolvers open it
        // with `std::fs` rather than through the project.
        assert_eq!(
            fs::read_to_string(image.root().join("package.json")).unwrap(),
            "{\"name\":\"fixture\"}\n"
        );
        // Source blobs are not inflated. The paths exist so module resolution
        // can find them; the bytes stay in the repository.
        for source in ["src/main.ts", "src/shared.js"] {
            let path = image.root().join(source);
            assert!(path.is_file(), "{source} must exist for module resolution");
            assert_eq!(
                fs::metadata(&path).unwrap().len(),
                0,
                "{source} must not be inflated into the export"
            );
        }

        // The project still serves the revision's real source for every named
        // file, so nothing downstream sees the empty placeholder.
        let (project, _) = image.project();
        let main = project.file_by_rel_path(Path::new("src/main.ts")).unwrap();
        assert_eq!(
            project.read_source(&main).unwrap(),
            "export const main = 1;\n"
        );
        let manifest = project.file_by_rel_path(Path::new("package.json")).unwrap();
        assert_eq!(
            project.read_source(&manifest).unwrap(),
            "{\"name\":\"fixture\"}\n"
        );
    }

    #[test]
    fn symbol_materialization_keeps_ambient_identity_without_import_expansion() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(dir.path().join("go.mod"), "module repro\n\ngo 1.21\n").unwrap();
        fs::create_dir_all(dir.path().join("pkga")).unwrap();
        fs::create_dir_all(dir.path().join("pkgb")).unwrap();
        fs::write(
            dir.path().join("pkga/a.go"),
            "package pkga\n\nimport \"repro/pkgb\"\n\nfunc Caller() int { return pkgb.Value() }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("pkga/unrelated.go"),
            "package pkga\n\nfunc Unrelated() int { return 2 }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("pkgb/b.go"),
            "package pkgb\n\nfunc Value() int { return 1 }\n",
        )
        .unwrap();
        let commit = test_repo::commit_all(&repo, "base");
        let paths = vec!["pkga/a.go".to_string()];

        let symbols =
            RevisionImage::materialize_symbols(&repo, Snapshot::Commit(commit), &paths, &[])
                .unwrap();
        let symbol_files = symbols.files().iter().cloned().collect::<BTreeSet<_>>();
        assert!(symbol_files.contains(Path::new("go.mod")));
        assert!(symbol_files.contains(Path::new("pkga/a.go")));
        assert!(!symbol_files.contains(Path::new("pkga/unrelated.go")));
        assert!(!symbol_files.contains(Path::new("pkgb/b.go")));

        let exact =
            RevisionImage::materialize(&repo, Snapshot::Commit(commit), Some(&paths), &[], None)
                .unwrap();
        assert!(exact.files().contains(&PathBuf::from("pkgb/b.go")));
    }

    #[test]
    fn full_diff_composes_exact_calls_after_standalone_symbol_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(dir.path().join("go.mod"), "module repro\n\ngo 1.21\n").unwrap();
        fs::create_dir_all(dir.path().join("sample")).unwrap();
        fs::write(
            dir.path().join("sample/calls.go"),
            "package sample\n\nfunc Left() int { return 1 }\nfunc Right() int { return 2 }\nfunc Caller() int { return Left() }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "base");
        fs::write(
            dir.path().join("sample/calls.go"),
            "package sample\n\nfunc Left() int { return 1 }\nfunc Right() int { return 2 }\nfunc Caller() int { return Right() }\n",
        )
        .unwrap();

        let prepared = PreparedDiff::at_root(
            dir.path(),
            DiffEndpointParams {
                base: Some("HEAD".to_string()),
                target: None,
            },
            &DiffAnalysisOptions::default(),
        )
        .unwrap();
        let paired_only = analyze_prepared_symbol_changes(&prepared, true).unwrap();
        let full = analyze_prepared_diff(&prepared, true).unwrap();

        assert_eq!(1, paired_only.symbol_changes.edited.len());
        assert_eq!("Caller", paired_only.symbol_changes.edited[0].after.name);
        let caller = full
            .patch_symbols
            .edited
            .iter()
            .find(|pair| pair.after.name == "Caller")
            .expect("full diff must retain the paired callable");
        assert_eq!(
            vec!["repro/sample.Right"],
            caller
                .added_calls
                .iter()
                .map(|call| call.to.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec!["repro/sample.Left"],
            caller
                .removed_calls
                .iter()
                .map(|call| call.to.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn zero_argument_worktree_diff_starts_at_the_default_branch_merge_base() {
        let temp = RevisionTempDir::new("default-branch-merge-base").unwrap();
        let root = temp.path();
        let repo = Repository::init(root).unwrap();
        let signature = git2::Signature::now("Tester", "tester@example.com").unwrap();
        let commit = |update_ref: &str, parent: Option<Oid>, body: &str, message: &str| {
            fs::write(
                root.join("lib.go"),
                format!("package sample\n\nfunc Existing() int {{\n\treturn {body}\n}}\n"),
            )
            .unwrap();
            let mut index = repo.index().unwrap();
            index.clear().unwrap();
            index.add_path(Path::new("lib.go")).unwrap();
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            let parents = parent
                .into_iter()
                .map(|oid| repo.find_commit(oid).unwrap())
                .collect::<Vec<_>>();
            repo.commit(
                Some(update_ref),
                &signature,
                &signature,
                message,
                &tree,
                &parents.iter().collect::<Vec<_>>(),
            )
            .unwrap()
        };

        let common = commit("HEAD", None, "1", "common");
        let default_head = commit("refs/heads/master", Some(common), "10", "default");
        let feature_head = commit("refs/heads/feature", Some(common), "2", "feature");
        repo.set_head("refs/heads/feature").unwrap();
        repo.reference(
            "refs/remotes/origin/master",
            default_head,
            true,
            "test default branch",
        )
        .unwrap();
        repo.reference_symbolic(
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/master",
            true,
            "test remote HEAD",
        )
        .unwrap();
        fs::write(
            root.join("lib.go"),
            "package sample\n\nfunc Existing() int {\n\treturn 3\n}\n",
        )
        .unwrap();

        let result = analyze_diff_at_root(
            root,
            AnalyzeDiffParams::default(),
            &DiffAnalysisOptions::default(),
        )
        .unwrap();

        assert_eq!(common.to_string(), result.endpoints.base);
        assert_eq!(WORKTREE_ENDPOINT, result.endpoints.target);
        assert_eq!(feature_head, repo.head().unwrap().target().unwrap());
        assert!(
            result
                .patch_symbols
                .edited
                .iter()
                .any(|pair| pair.after.name == "Existing"),
            "the implicit diff must include committed feature-branch changes"
        );
    }

    /// The working-tree sentinel (`target: None`) must report the same
    /// `patch_symbols`/`dependency_symbols` as an equivalent explicit target,
    /// for a working tree with no uncommitted changes. A Go file's fqn needs
    /// its module's `go.mod` to resolve correctly; without it, `Caller`
    /// resolves to two different names on the two sides of the pair
    /// (`pkga.Caller` vs. the correctly module-qualified `repro/pkga.Caller`)
    /// and looks like one symbol deleted and an unrelated one introduced.
    #[test]
    fn working_tree_sentinel_matches_explicit_target_for_a_go_module() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(dir.path().join("go.mod"), "module repro\n\ngo 1.21\n").unwrap();
        fs::create_dir_all(dir.path().join("pkga")).unwrap();
        fs::write(
            dir.path().join("pkga/a.go"),
            "package pkga\n\nfunc helper() int { return 1 }\nfunc Caller() int { return helper() }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");

        fs::write(
            dir.path().join("pkga/a.go"),
            "package pkga\n\nfunc helper() int { return 1 }\nfunc Caller() int { return helper() + 1 }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2");
        drop(repo);

        let sentinel = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: None,
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("sentinel analyze_diff failed");
        let explicit = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: Some("HEAD".to_string()),
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("explicit-target analyze_diff failed");

        assert_eq!(
            explicit.patch_symbols.edited.len(),
            1,
            "control: explicit target must report Caller as edited"
        );
        assert_eq!(
            sentinel.patch_symbols.edited.len(),
            1,
            "the working-tree sentinel must also report Caller as edited, not \
             delete-and-reintroduce it under a different fqn"
        );
        assert_eq!(
            sentinel.patch_symbols.edited[0].after.fqn, "repro/pkga.Caller",
            "the reported fqn must be module-qualified"
        );
        assert_eq!(
            sentinel.patch_symbols.edited[0].after.fqn, explicit.patch_symbols.edited[0].after.fqn,
            "the sentinel and an equivalent explicit target must agree on the fqn"
        );
    }

    /// Same defect as the Go test above, for Rust: a crate's fqn needs its
    /// `Cargo.toml` (via `nearest_crate`'s ancestor walk) to resolve as
    /// crate-qualified rather than falling back to an unqualified name.
    #[test]
    fn working_tree_sentinel_matches_explicit_target_for_a_rust_crate() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"repro\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(
            dir.path().join("src/lib.rs"),
            "fn helper() -> i32 { 1 }\npub fn caller() -> i32 { helper() }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");

        fs::write(
            dir.path().join("src/lib.rs"),
            "fn helper() -> i32 { 1 }\npub fn caller() -> i32 { helper() + 1 }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2");
        drop(repo);

        let sentinel = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: None,
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("sentinel analyze_diff failed");
        let explicit = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: Some("HEAD".to_string()),
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("explicit-target analyze_diff failed");

        assert_eq!(
            explicit.patch_symbols.edited.len(),
            1,
            "control: explicit target must report caller as edited"
        );
        assert_eq!(
            sentinel.patch_symbols.edited.len(),
            1,
            "the working-tree sentinel must also report caller as edited, not \
             delete-and-reintroduce it under a different fqn"
        );
        assert!(
            sentinel.patch_symbols.edited[0].after.fqn.contains("repro"),
            "the reported fqn must be crate-qualified, got {:?}",
            sentinel.patch_symbols.edited[0].after.fqn
        );
        assert_eq!(
            sentinel.patch_symbols.edited[0].after.fqn, explicit.patch_symbols.edited[0].after.fqn,
            "the sentinel and an equivalent explicit target must agree on the fqn"
        );
    }

    /// A two-commit Go module whose second commit makes `pkga` start importing
    /// `pkgb`, so a committed endpoint's import expansion must follow the new
    /// `import "repro/pkgb"`. Returns the second commit.
    fn go_import_expansion_repo(root: &Path) -> Oid {
        let repo = test_repo::init_repo(root);
        fs::write(root.join("go.mod"), "module repro\n\ngo 1.21\n").unwrap();
        fs::create_dir_all(root.join("pkga")).unwrap();
        fs::create_dir_all(root.join("pkgb")).unwrap();
        fs::write(
            root.join("pkga/a.go"),
            "package pkga\n\nfunc helper() int { return 1 }\nfunc Caller() int { return helper() }\n",
        )
        .unwrap();
        fs::write(
            root.join("pkgb/b.go"),
            "package pkgb\n\nfunc MakeThing(x int) int { return x }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");
        fs::write(
            root.join("pkga/a.go"),
            "package pkga\n\nimport \"repro/pkgb\"\n\nfunc helper() int { return 1 }\nfunc Caller() int { return helper() + pkgb.MakeThing(2) }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2")
    }

    /// Materialize the changed-file-scoped image of `commit`, whose export runs
    /// the import expansion, and report the files the expansion settled on.
    fn expanded_image_files(
        repo: &Repository,
        commit: Oid,
        cache: Option<&SharedAnalyzerCache>,
    ) -> BTreeSet<PathBuf> {
        let paths = ["pkga/a.go".to_string()];
        let image =
            RevisionImage::materialize(repo, Snapshot::Commit(commit), Some(&paths), &[], cache)
                .unwrap();
        image.files().iter().cloned().collect()
    }

    fn cache_row_count(root: &Path, table: &str) -> i64 {
        rusqlite::Connection::open(crate::analyzer::store::analyzer_db_path(root))
            .expect("open the shared analyzer cache")
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count cache rows")
    }

    /// A committed endpoint's import expansion parses the diff's own changed
    /// files, and those parses describe blobs of the revision, so they belong in
    /// the repository's shared cache: a second identical materialization must
    /// publish nothing.
    #[test]
    fn snapshot_import_expansion_reuses_the_shared_cache() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let head = go_import_expansion_repo(root);
        let repo = Repository::open(root).unwrap();
        let cache = SharedAnalyzerCache::open(root).expect("the fixture is a git repository");

        let cold = expanded_image_files(&repo, head, Some(&cache));
        let after_cold = cache_row_count(root, "blobs");
        let warm = expanded_image_files(&repo, head, Some(&cache));
        let after_warm = cache_row_count(root, "blobs");
        drop(cache);

        assert!(
            cold.contains(Path::new("pkgb/b.go")),
            "the expansion must follow the new import into pkgb: {cold:?}"
        );
        assert_eq!(cold, warm, "warm and cold must select the same image");
        assert!(
            after_cold > 0,
            "a cold expansion publishes the changed file's parsed blob"
        );
        assert_eq!(
            after_cold, after_warm,
            "a warm expansion must publish no new blobs"
        );
        // Both export directories are gone, so any surviving workspace row
        // names a path that no longer exists.
        assert_eq!(0, cache_row_count(root, "workspace_heads"));
        assert_eq!(0, cache_row_count(root, "workspace_revisions"));
        assert_eq!(0, cache_row_count(root, "workspace_file_versions"));
    }

    /// The fallback a host without a usable persisted cache takes: the same
    /// expansion runs against an ephemeral store and must select the same image.
    #[test]
    fn snapshot_import_expansion_without_a_cache_selects_the_same_image() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let head = go_import_expansion_repo(root);
        let repo = Repository::open(root).unwrap();

        let fallback = expanded_image_files(&repo, head, None);
        let cache = SharedAnalyzerCache::open(root).expect("the fixture is a git repository");
        let shared = expanded_image_files(&repo, head, Some(&cache));
        drop(cache);

        assert_eq!(fallback, shared);
        assert!(
            cache_row_count(root, "blobs") > 0,
            "the shared run must have used the cache"
        );
    }

    /// A changed file that starts calling a function in an untouched sibling
    /// package: `MakeThing`'s own file was never part of the diff, so
    /// resolving the call and attaching its full definition both depend on
    /// `snapshot_import_expansion_targets` following the new `import
    /// "repro/pkgb"` to `pkgb`'s directory and exporting it alongside the
    /// diff's own files.
    #[test]
    fn dependency_symbols_includes_a_newly_called_function_in_an_untouched_package() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(dir.path().join("go.mod"), "module repro\n\ngo 1.21\n").unwrap();
        fs::create_dir_all(dir.path().join("pkga")).unwrap();
        fs::create_dir_all(dir.path().join("pkgb")).unwrap();
        fs::write(
            dir.path().join("pkga/a.go"),
            "package pkga\n\nfunc helper() int { return 1 }\nfunc Caller() int { return helper() }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("pkgb/b.go"),
            "package pkgb\n\nfunc MakeThing(x int) int { return x }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");

        fs::write(
            dir.path().join("pkga/a.go"),
            "package pkga\n\nimport \"repro/pkgb\"\n\nfunc helper() int { return 1 }\nfunc Caller() int { return helper() + pkgb.MakeThing(2) }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2");
        drop(repo);

        let result = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: Some("HEAD".to_string()),
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("analyze_diff failed");

        assert_eq!(
            result.patch_symbols.edited.len(),
            1,
            "sanity check: Caller itself must still be reported as edited"
        );
        assert!(
            result.patch_symbols.edited[0]
                .added_calls
                .iter()
                .any(|call| call.to.contains("MakeThing")),
            "the new call to MakeThing must be detected as an added call, got {:?}",
            result.patch_symbols.edited[0].added_calls
        );
        assert!(
            result
                .dependency_symbols
                .iter()
                .any(|symbol| symbol.fqn.contains("MakeThing")),
            "a newly-called function in an untouched sibling package must appear \
             in dependency_symbols, got {:?}",
            result.dependency_symbols
        );
    }

    /// Same fixture as above, but through the working-tree sentinel: import
    /// expansion must resolve identically on both endpoint kinds, not just
    /// the explicit-target/explicit-target case above.
    #[test]
    fn working_tree_sentinel_also_sees_a_newly_called_function_in_an_untouched_package() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(dir.path().join("go.mod"), "module repro\n\ngo 1.21\n").unwrap();
        fs::create_dir_all(dir.path().join("pkga")).unwrap();
        fs::create_dir_all(dir.path().join("pkgb")).unwrap();
        fs::write(
            dir.path().join("pkga/a.go"),
            "package pkga\n\nfunc helper() int { return 1 }\nfunc Caller() int { return helper() }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("pkgb/b.go"),
            "package pkgb\n\nfunc MakeThing(x int) int { return x }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");

        fs::write(
            dir.path().join("pkga/a.go"),
            "package pkga\n\nimport \"repro/pkgb\"\n\nfunc helper() int { return 1 }\nfunc Caller() int { return helper() + pkgb.MakeThing(2) }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2");
        drop(repo);

        let sentinel = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: None,
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("sentinel analyze_diff failed");

        assert!(
            sentinel
                .dependency_symbols
                .iter()
                .any(|symbol| symbol.fqn.contains("MakeThing")),
            "the working-tree sentinel must also see a newly-called function in \
             an untouched sibling package, got {:?}",
            sentinel.dependency_symbols
        );
    }

    /// A changed file's own import statement is attacker-controlled content
    /// (any file in a diff under review), not something this code
    /// constructed. An absolute-looking literal must never resolve to a real
    /// absolute path: on the working-tree endpoint, `Path::join` on an
    /// absolute argument discards `root` entirely, so an unvalidated
    /// candidate here would let `worktree_files` return a path outside the
    /// project -- which then panics deep inside `ProjectFile::new`'s
    /// `assert!(!rel_path.is_absolute())` once fed to the analyzer.
    #[test]
    fn worktree_import_expansion_rejects_an_absolute_import_target() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{\"name\": \"repro\"}\n").unwrap();
        fs::write(
            dir.path().join("a.ts"),
            "import thing from \"/etc/passwd\";\nexport function caller() { return thing; }\n",
        )
        .unwrap();

        let files =
            worktree_files(dir.path(), &["a.ts".to_string()]).expect("worktree_files failed");

        assert!(
            files.iter().all(|file| file.is_relative()),
            "worktree_files must never return an absolute path, got {files:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn worktree_import_expansion_does_not_follow_a_symlinked_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("other.ts"),
            "export function makeThing() { return 1; }\n",
        )
        .unwrap();
        symlink(outside.path(), dir.path().join("linked")).unwrap();
        fs::write(
            dir.path().join("a.ts"),
            "import { makeThing } from './linked/other';\nexport function caller() { return makeThing(); }\n",
        )
        .unwrap();

        let files =
            worktree_files(dir.path(), &["a.ts".to_string()]).expect("worktree_files failed");

        assert!(
            files
                .iter()
                .all(|file| file != Path::new("linked/other.ts")),
            "worktree import expansion must not walk through symlinked directories: {files:?}"
        );
    }

    /// Same attack, via an import whose literal carries an embedded `..`
    /// rather than being outright absolute. Unit-tests `resolve_import_target`
    /// directly with
    /// a spy `exists` closure: this is the choke point that must reject the
    /// candidate *before* checking whether it exists, not after -- an
    /// end-to-end assertion on `worktree_files`'s returned file list can't
    /// tell the two apart, since a path that escapes to an unrelated real
    /// directory (like `/tmp`) is *also* filtered out by an unrelated,
    /// incidental `strip_prefix(root)` check further downstream, regardless
    /// of whether this containment check exists at all.
    #[test]
    fn resolve_import_target_rejects_a_candidate_with_an_embedded_parent_dir_segment() {
        // A permissive spy: everything "exists", so the only reason a
        // `..`-carrying candidate would ever be absent from `calls` is
        // `resolve_candidate` rejecting it up front, not a lucky `exists`
        // miss. A short, safe suffix (`"tmp"` alone) is expected to resolve
        // once the loop reaches it -- that is correct behavior, not the bug.
        let target = ImportTarget::Absolute(
            ["a", "..", "..", "..", "..", "..", "..", "tmp"]
                .into_iter()
                .map(String::from)
                .collect(),
        );
        let mut calls = Vec::new();
        resolve_import_target(Path::new(""), &target, |candidate| {
            calls.push(candidate.to_path_buf());
            Some(true)
        });

        for candidate in &calls {
            assert!(
                candidate
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_))),
                "resolve_candidate must never call `exists` with a path carrying a `..` \
                 segment, but it was called with {candidate:?}"
            );
        }
    }

    /// Same shape as the Go fixture, for Rust: `use crate_b::make_thing` names
    /// an item at the end of its path, with the crate directory as a *prefix*
    /// -- the opposite shape from Go's module-prefixed package path -- so this
    /// specifically exercises `resolve_import_target`'s prefix search, not
    /// just its suffix search.
    #[test]
    fn dependency_symbols_includes_a_newly_called_function_in_an_untouched_crate() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crate_a\", \"crate_b\"]\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("crate_a/src")).unwrap();
        fs::write(
            dir.path().join("crate_a/Cargo.toml"),
            "[package]\nname = \"crate_a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\ncrate_b = { path = \"../crate_b\" }\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("crate_b/src")).unwrap();
        fs::write(
            dir.path().join("crate_b/Cargo.toml"),
            "[package]\nname = \"crate_b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("crate_b/src/lib.rs"),
            "pub fn make_thing(x: i32) -> i32 { x }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("crate_a/src/lib.rs"),
            "fn helper() -> i32 { 1 }\npub fn caller() -> i32 { helper() }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");

        fs::write(
            dir.path().join("crate_a/src/lib.rs"),
            "use crate_b::make_thing;\n\nfn helper() -> i32 { 1 }\n\
             pub fn caller() -> i32 { helper() + make_thing(2) }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2");
        drop(repo);

        let result = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: Some("HEAD".to_string()),
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("analyze_diff failed");

        assert!(
            result
                .dependency_symbols
                .iter()
                .any(|symbol| symbol.fqn.contains("make_thing")),
            "a newly-called function in an untouched crate must appear in \
             dependency_symbols, got {:?}",
            result.dependency_symbols
        );
    }

    /// Same shape again, for Python: `from pkgb.b import make_thing` has no
    /// leading dots (an absolute import), so this exercises the plain
    /// structured-segments path rather than the relative-import handling.
    #[test]
    fn dependency_symbols_includes_a_newly_called_function_in_an_untouched_python_package() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"repro\"\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("pkga")).unwrap();
        fs::create_dir_all(dir.path().join("pkgb")).unwrap();
        fs::write(dir.path().join("pkga/__init__.py"), "").unwrap();
        fs::write(dir.path().join("pkgb/__init__.py"), "").unwrap();
        fs::write(
            dir.path().join("pkgb/b.py"),
            "def make_thing(x):\n    return x\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("pkga/a.py"),
            "def helper():\n    return 1\n\n\ndef caller():\n    return helper()\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");

        fs::write(
            dir.path().join("pkga/a.py"),
            "from pkgb.b import make_thing\n\n\ndef helper():\n    return 1\n\n\n\
             def caller():\n    return helper() + make_thing(2)\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2");
        drop(repo);

        let result = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: Some("HEAD".to_string()),
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("analyze_diff failed");

        assert!(
            result
                .dependency_symbols
                .iter()
                .any(|symbol| symbol.fqn.contains("make_thing")),
            "a newly-called function in an untouched Python package must appear \
             in dependency_symbols, got {:?}",
            result.dependency_symbols
        );
    }

    /// Same shape again, for TypeScript: the parser records the AST-derived
    /// module specifier as a structured import path, which expansion resolves
    /// without reparsing the raw import declaration.
    #[test]
    fn dependency_symbols_includes_a_newly_called_function_in_an_untouched_ts_module() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(dir.path().join("package.json"), "{\"name\": \"repro\"}\n").unwrap();
        fs::create_dir_all(dir.path().join("pkgb")).unwrap();
        fs::write(
            dir.path().join("pkgb/other.ts"),
            "export function makeThing(x: number): number { return x; }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("a.ts"),
            "function helper(): number { return 1; }\n\
             export function caller(): number { return helper(); }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");

        fs::write(
            dir.path().join("a.ts"),
            "import { makeThing } from './pkgb/other';\n\n\
             function helper(): number { return 1; }\n\
             export function caller(): number { return helper() + makeThing(2); }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2");
        drop(repo);

        let result = analyze_diff_at_root(
            dir.path(),
            AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: Some("HEAD".to_string()),
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("analyze_diff failed");

        assert!(
            result
                .dependency_symbols
                .iter()
                .any(|symbol| symbol.fqn.contains("makeThing")),
            "a newly-called function in an untouched TS module must appear in \
             dependency_symbols, got {:?}",
            result.dependency_symbols
        );
    }

    /// Tokenize with the production normalizer, then score -- the path a real
    /// symbol body takes. The df pool is just the two bodies, the smallest
    /// diff-local pool a scored pair can occur in.
    fn similarity(a_name: &str, a_src: &str, b_name: &str, b_src: &str) -> f64 {
        let a = body_token_signature_for_bytes(a_src, a_name, 0, a_src.len()).unwrap();
        let b = body_token_signature_for_bytes(b_src, b_name, 0, b_src.len()).unwrap();
        let idf = diff_local_idf([a.as_slice(), b.as_slice()].into_iter());
        body_similarity(&a, &b, &idf)
    }

    /// The weighted-Jaccard arithmetic against a value computed by hand.
    ///
    /// Pool of N = 3 bodies: A = [a, a, b, x], B = [a, b, y], C = [b].
    /// df: a -> 2, b -> 3, x -> 1, y -> 1. Weights w(t) = ln((N+1)/(df+0.5)):
    ///   w(a) = ln(4/2.5) = ln 1.6,  w(b) = ln(4/3.5) = ln(8/7),
    ///   w(x) = w(y) = ln(4/1.5) = ln(8/3).
    /// Score(A, B) = [w(a)*min(2,1) + w(b)*min(1,1)]
    ///             / [w(a)*max(2,1) + w(b)*max(1,1) + w(x)*1 + w(y)*1]
    ///   = (0.4700036 + 0.1335314)
    ///   / (0.9400073 + 0.1335314 + 0.9808293 + 0.9808293)
    ///   = 0.6035350 / 3.0351972 = 0.1988454...
    #[test]
    fn body_similarity_matches_hand_computed_idf_weighted_score() {
        let bag =
            |tokens: &[&str]| -> Vec<String> { tokens.iter().map(|t| t.to_string()).collect() };
        let a = bag(&["a", "a", "b", "x"]);
        let b = bag(&["a", "b", "y"]);
        let c = bag(&["b"]);
        let idf = diff_local_idf([a.as_slice(), b.as_slice(), c.as_slice()].into_iter());

        let w_a = (4.0f64 / 2.5).ln();
        let w_b = (4.0f64 / 3.5).ln();
        let w_xy = (4.0f64 / 1.5).ln();
        assert_eq!(idf.get("a").copied(), Some(w_a));
        assert_eq!(idf.get("b").copied(), Some(w_b));
        assert_eq!(idf.get("x").copied(), Some(w_xy));
        assert_eq!(idf.get("y").copied(), Some(w_xy));

        let score = body_similarity(&a, &b, &idf);
        assert!(
            (score - 0.198_845_409_580_926_95).abs() < 1e-12,
            "hand-computed weighted Jaccard mismatch: got {score}"
        );
    }

    fn symbol_at(path: &str, start_line: usize) -> CommitSymbol {
        CommitSymbol {
            fqn: format!("{path}::sym"),
            name: "sym".to_string(),
            kind: "function".to_string(),
            signature: "fn sym()".to_string(),
            path: path.to_string(),
            start_line,
            end_line: start_line + 3,
            language: "rust".to_string(),
            is_test: false,
        }
    }

    fn snapshot(
        fqn: &str,
        name: &str,
        path: &str,
        token_sig: Option<Vec<String>>,
    ) -> SymbolSnapshot {
        SymbolSnapshot {
            key: SymbolKey {
                fqn: fqn.to_string(),
                kind: "function".to_string(),
                language: "rust".to_string(),
            },
            token_sig,
            symbol: CommitSymbol {
                fqn: fqn.to_string(),
                name: name.to_string(),
                kind: "function".to_string(),
                signature: format!("fn {name}()"),
                path: path.to_string(),
                start_line: 1,
                end_line: 4,
                language: "rust".to_string(),
                is_test: false,
            },
        }
    }

    /// Guards the regression behind #1897: a symbol whose start line only slid
    /// because lines were inserted/deleted *before* it must not be reported as
    /// moved. A single early insert once produced hundreds of spurious "moved"
    /// rows -- one per symbol below it -- because any `start_line` delta was
    /// treated as a relocation.
    #[test]
    fn pure_line_shift_is_not_a_move() {
        // Three lines inserted before the symbol: it slid 10 -> 13 with no
        // deletions on the old side. Same position among unchanged lines.
        let mut changed = BTreeMap::new();
        changed.insert(
            "src/a.rs".to_string(),
            ChangedLines {
                old: Default::default(),
                new: [1usize, 2, 3].into_iter().collect(),
            },
        );
        let pre = symbol_at("src/a.rs", 10);
        let post = symbol_at("src/a.rs", 13);
        assert!(is_pure_line_shift(&pre, &post, &changed));

        // A larger jump than the 3 insertions explain is a genuine relocation.
        let moved_post = symbol_at("src/a.rs", 20);
        assert!(!is_pure_line_shift(&pre, &moved_post, &changed));

        // A path change is always a relocation, regardless of line arithmetic.
        let renamed_post = symbol_at("src/b.rs", 13);
        assert!(!is_pure_line_shift(&pre, &renamed_post, &changed));
    }

    // A realistic reduce-over-a-slice body, parameterized by function and
    // accumulator name so tests can rename either.
    fn accumulate_body(fn_name: &str, acc: &str) -> String {
        format!(
            "pub fn {fn_name}(items: &[i32]) -> i32 {{\n    \
             let mut {acc} = 0;\n    \
             for it in items {{\n        \
             {acc} += *it;\n    \
             }}\n    \
             {acc}\n}}\n"
        )
    }

    #[test]
    fn body_similarity_tolerates_rename_and_indentation_but_not_unrelated_code() {
        let foo = accumulate_body("compute_total", "sum");

        // Pure rename: only the function name changed. Blanking the symbol's own
        // name must make the two bodies score identically.
        let renamed = accumulate_body("sum_all", "sum");
        assert_eq!(similarity("compute_total", &foo, "sum_all", &renamed), 1.0);

        // Reindented into a deeper scope with a blank line: whitespace is
        // dropped, so the score is unaffected.
        let reindented = format!(
            "\n        {}",
            accumulate_body("sum_all", "sum").replace('\n', "\n        ")
        );
        assert_eq!(
            similarity("compute_total", &foo, "sum_all", &reindented),
            1.0
        );

        // Move + rename + an internal variable rename (sum -> total): still
        // above the pairing threshold on the IDF-weighted scale (~0.58 with
        // this two-body pool: the differing accumulator names are the rarest
        // tokens, so they weigh heaviest).
        let edited = accumulate_body("sum_all", "total");
        let score = similarity("compute_total", &foo, "sum_all", &edited);
        assert!(
            score >= BODY_MOVE_SIMILARITY_THRESHOLD,
            "renamed move with an internal rename scored {score}, below threshold"
        );

        // Unrelated function: must fall well below the threshold (~0.10 here;
        // the bodies agree mostly on low-weight punctuation and keywords).
        let unrelated = "pub fn greet(name: &str) -> String {\n    let mut out = String::new();\n    out.push_str(name);\n    out.push('!');\n    out\n}\n";
        let score = similarity("compute_total", &foo, "greet", unrelated);
        assert!(
            score < BODY_MOVE_SIMILARITY_THRESHOLD,
            "unrelated bodies scored {score}, at/above threshold"
        );
    }

    #[test]
    fn body_token_signature_rejects_trivial_and_degenerate_byte_ranges() {
        let src = accumulate_body("f", "sum");
        assert!(body_token_signature_for_bytes(&src, "f", 0, src.len()).is_some());
        // One non-blank line is too weak a fingerprint.
        assert_eq!(
            body_token_signature_for_bytes(
                "pub fn f() { done() }\n",
                "f",
                0,
                "pub fn f() { done() }\n".len(),
            ),
            None
        );
        // Degenerate ranges are rejected, not panicked on.
        assert_eq!(body_token_signature_for_bytes(&src, "f", 5, 1), None);
        assert_eq!(
            body_token_signature_for_bytes(&src, "f", src.len(), src.len() + 1),
            None
        );
    }

    fn snap_src(fqn: &str, name: &str, path: &str, src: &str) -> SymbolSnapshot {
        snapshot(
            fqn,
            name,
            path,
            body_token_signature_for_bytes(src, name, 0, src.len()),
        )
    }

    /// The third pairing rule (RM-style move detection): a symbol relocated to a
    /// file Git did not flag as a rename -- renamed and lightly edited in the
    /// process -- keeps no identity key and no rename bucket, yet body
    /// similarity pairs it. An unrelated leftover must NOT be dragged in.
    #[test]
    fn fuzzy_pairing_matches_a_renamed_move_and_resists_false_positives() {
        // compute_total moved a.rs -> b.rs, renamed sum_all, accumulator renamed.
        let before = BTreeMap::from([
            {
                let s = snap_src(
                    "a::compute_total",
                    "compute_total",
                    "src/a.rs",
                    &accumulate_body("compute_total", "sum"),
                );
                (s.key.clone(), s)
            },
            {
                // An unrelated deleted function that must stay unpaired.
                let src = "pub fn greet(name: &str) -> String {\n    let mut out = String::new();\n    out.push_str(name);\n    out\n}\n";
                let s = snap_src("a::greet", "greet", "src/a.rs", src);
                (s.key.clone(), s)
            },
        ]);
        let after = BTreeMap::from([{
            let s = snap_src(
                "b::sum_all",
                "sum_all",
                "src/b.rs",
                &accumulate_body("sum_all", "total"),
            );
            (s.key.clone(), s)
        }]);

        let pairing = pair_endpoints(&before, &after, &[] as &[FileChange]);
        assert_eq!(pairing.pairs.len(), 1, "the renamed move should pair");
        assert_eq!(pairing.pairs[0].0.symbol.fqn, "a::compute_total");
        assert_eq!(pairing.pairs[0].1.symbol.fqn, "b::sum_all");
        let score = pairing
            .fallback_paired
            .get(&pairing.pairs[0].0.key)
            .copied()
            .expect("fuzzy pair records its similarity score");
        assert!(
            score >= BODY_MOVE_SIMILARITY_THRESHOLD,
            "recorded score {score} must clear the threshold"
        );
        assert_eq!(
            pairing
                .fallback_paired
                .get(&pairing.pairs[0].1.key)
                .copied(),
            Some(score),
            "both endpoints map to the pair's score"
        );
        // greet stayed unpaired -- not a false-positive move.
        assert_eq!(pairing.preimage_only.len(), 1);
        assert_eq!(pairing.preimage_only[0].symbol.fqn, "a::greet");
        assert!(pairing.postimage_only.is_empty());

        // Greedy one-to-one: two candidate moves, each must claim its true twin
        // rather than cross-pair. Give b a clearly-better match than a.
        let before = BTreeMap::from([
            {
                let s = snap_src(
                    "a::compute_total",
                    "compute_total",
                    "src/a.rs",
                    &accumulate_body("compute_total", "sum"),
                );
                (s.key.clone(), s)
            },
            {
                let src = "pub fn render(node: &Node) -> String {\n    let mut buf = String::new();\n    buf.push_str(node.label());\n    buf.push('\\n');\n    buf\n}\n";
                let s = snap_src("a::render", "render", "src/a.rs", src);
                (s.key.clone(), s)
            },
        ]);
        let after = BTreeMap::from([
            {
                let s = snap_src(
                    "b::sum_all",
                    "sum_all",
                    "src/b.rs",
                    &accumulate_body("sum_all", "total"),
                );
                (s.key.clone(), s)
            },
            {
                let src = "pub fn draw(node: &Node) -> String {\n    let mut buf = String::new();\n    buf.push_str(node.label());\n    buf.push('\\n');\n    buf\n}\n";
                let s = snap_src("b::draw", "draw", "src/b.rs", src);
                (s.key.clone(), s)
            },
        ]);
        let pairing = pair_endpoints(&before, &after, &[] as &[FileChange]);
        let mut got: Vec<(&str, &str)> = pairing
            .pairs
            .iter()
            .map(|(p, q)| (p.symbol.fqn.as_str(), q.symbol.fqn.as_str()))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![("a::compute_total", "b::sum_all"), ("a::render", "b::draw")],
            "each move claimed its own twin"
        );
    }

    /// The flat-fqn identity guard: an unqualified fqn (fqn == bare name, as
    /// flat-namespace languages produce) may identity-pair only within one
    /// path. Unrelated same-name functions in different files must not pair;
    /// a genuine cross-file move is recovered by the body-similarity rule.
    #[test]
    fn unqualified_identity_requires_a_matching_path() {
        // Two unrelated same-name `updateConfig` functions, a.js deleted,
        // b.js added, dissimilar bodies: refuse the identity pair AND the
        // fuzzy pair -- report delete+introduce.
        let before = BTreeMap::from([{
            let src = "pub fn updateConfig(c: &mut Config) {\n    c.retries = 3;\n    c.verbose = true;\n    c.apply();\n}\n";
            let s = snap_src("updateConfig", "updateConfig", "src/a.js", src);
            (s.key.clone(), s)
        }]);
        let after = BTreeMap::from([{
            let src = "pub fn updateConfig(db: &Db) -> Row {\n    let row = db.fetch(\"config\");\n    db.write(&row);\n    row\n}\n";
            let s = snap_src("updateConfig", "updateConfig", "src/b.js", src);
            (s.key.clone(), s)
        }]);
        let pairing = pair_endpoints(&before, &after, &[] as &[FileChange]);
        assert!(
            pairing.pairs.is_empty(),
            "unrelated same-name flat symbols must not pair"
        );
        assert_eq!(pairing.preimage_only.len(), 1);
        assert_eq!(pairing.postimage_only.len(), 1);
        assert!(pairing.fallback_paired.is_empty());

        // A true cross-file move of an unqualified symbol with an identical
        // body: rule 1 refuses it, but body similarity pairs it and records
        // the score a MovedSymbol will surface.
        let src = "pub fn updateConfig(c: &mut Config) {\n    c.retries = 3;\n    c.verbose = true;\n    c.apply();\n}\n";
        let before = BTreeMap::from([{
            let s = snap_src("updateConfig", "updateConfig", "src/a.js", src);
            (s.key.clone(), s)
        }]);
        let after = BTreeMap::from([{
            let s = snap_src("updateConfig", "updateConfig", "src/b.js", src);
            (s.key.clone(), s)
        }]);
        let pairing = pair_endpoints(&before, &after, &[] as &[FileChange]);
        assert_eq!(
            pairing.pairs.len(),
            1,
            "an identical body pairs the true move"
        );
        let score = pairing
            .fallback_paired
            .get(&pairing.pairs[0].0.key)
            .copied()
            .expect("the recovered move is a fuzzy pair and carries a score");
        assert!(score >= BODY_MOVE_SIMILARITY_THRESHOLD);

        // A qualified fqn (fqn != bare name) still identity-pairs across a
        // path change exactly as before the guard.
        let before = BTreeMap::from([{
            let s = snap_src("a.Foo.bar", "bar", "src/Foo.java", src);
            (s.key.clone(), s)
        }]);
        let after = BTreeMap::from([{
            let s = snap_src("a.Foo.bar", "bar", "src/other/Foo.java", src);
            (s.key.clone(), s)
        }]);
        let pairing = pair_endpoints(&before, &after, &[] as &[FileChange]);
        assert_eq!(
            pairing.pairs.len(),
            1,
            "qualified fqns keep identity pairing"
        );
        assert!(
            pairing.fallback_paired.is_empty(),
            "an identity pair is not a fuzzy pair"
        );
    }

    /// The size-ratio prefilter: candidate enumeration must skip pairs whose
    /// total bag weights differ by more than the limit -- they provably cannot
    /// reach the threshold -- and keep everything at or under it.
    #[test]
    fn fuzzy_prefilter_skips_pairs_beyond_the_weight_ratio_limit() {
        assert!(within_fuzzy_weight_ratio(1.0, 1.0));
        assert!(within_fuzzy_weight_ratio(1.0, 2.0));
        assert!(
            within_fuzzy_weight_ratio(1.0, 3.0),
            "the boundary is inclusive"
        );
        assert!(!within_fuzzy_weight_ratio(1.0, 3.01));
        assert!(
            !within_fuzzy_weight_ratio(4.0, 1.0),
            "symmetric in its arguments"
        );

        // Behavior level: a body that is an identical prefix of a ~4x-larger
        // one never pairs -- the weight mismatch alone rules the pair out.
        let small = "pub fn part(a: u32) -> u32 {\n    let alpha = a + 1;\n    alpha * 2\n}\n";
        let large = "pub fn whole(a: u32) -> u32 {\n    let alpha = a + 1;\n    let beta = alpha * 2;\n    let gamma = beta ^ 0x5f;\n    let delta = gamma.rotate_left(7);\n    let epsilon = delta.wrapping_mul(31);\n    let zeta = epsilon | 0b1010;\n    let eta = zeta >> 3;\n    let theta = eta + 0o17;\n    let iota = theta.count_ones();\n    let kappa = iota.pow(2);\n    kappa\n}\n";
        let before = BTreeMap::from([{
            let s = snap_src("a::part", "part", "src/a.rs", small);
            (s.key.clone(), s)
        }]);
        let after = BTreeMap::from([{
            let s = snap_src("b::whole", "whole", "src/b.rs", large);
            (s.key.clone(), s)
        }]);
        let pairing = pair_endpoints(&before, &after, &[] as &[FileChange]);
        assert!(pairing.pairs.is_empty());
        assert!(pairing.fallback_paired.is_empty());
        assert_eq!(pairing.preimage_only.len(), 1);
        assert_eq!(pairing.postimage_only.len(), 1);
    }

    /// The hard candidate cap: past `FUZZY_PAIRING_CANDIDATE_CAP` leftover
    /// pre x post combinations, the fuzzy rule is skipped wholesale and every
    /// leftover reports as plain delete+introduce -- even identical bodies
    /// that would otherwise pair at score 1.0.
    #[test]
    fn fuzzy_pairing_is_skipped_past_the_candidate_cap() {
        // 501 x 500 = 250_500 > 250_000. All bodies identical and substantial;
        // the symbol names do not occur in the body, so every token signature
        // is identical and every pair would score 1.0 if scored.
        let body = accumulate_body("worker", "sum");
        let mut before = BTreeMap::new();
        for i in 0..501 {
            let s = snap_src(&format!("a::sym{i}"), &format!("sym{i}"), "src/a.rs", &body);
            before.insert(s.key.clone(), s);
        }
        let mut after = BTreeMap::new();
        for i in 0..500 {
            let s = snap_src(&format!("b::sym{i}"), &format!("sym{i}"), "src/b.rs", &body);
            after.insert(s.key.clone(), s);
        }
        let pairing = pair_endpoints(&before, &after, &[] as &[FileChange]);
        assert!(pairing.pairs.is_empty(), "past the cap nothing may pair");
        assert!(pairing.fallback_paired.is_empty());
        assert_eq!(pairing.preimage_only.len(), 501);
        assert_eq!(pairing.postimage_only.len(), 500);
    }

    #[test]
    fn dependency_symbols_and_added_calls_include_a_newly_called_ts_function() {
        let dir = tempfile::tempdir().unwrap();
        let repo = test_repo::init_repo(dir.path());
        fs::write(dir.path().join("package.json"), "{\"name\": \"repro\"}\n").unwrap();
        fs::write(
            dir.path().join("a.ts"),
            "function makeThing(x: number): number { return x; }\n\
             function helper(): number { return 1; }\n\
             export function caller(): number { return helper(); }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 1");

        fs::write(
            dir.path().join("a.ts"),
            "function makeThing(x: number): number { return x; }\n\
             function helper(): number { return 1; }\n\
             export function caller(): number { return helper() + makeThing(2); }\n",
        )
        .unwrap();
        test_repo::commit_all(&repo, "commit 2");
        drop(repo);

        let result = super::analyze_diff_at_root(
            dir.path(),
            super::AnalyzeDiffParams {
                base: Some("HEAD~1".to_string()),
                target: Some("HEAD".to_string()),
                include_tests: true,
            },
            &super::DiffAnalysisOptions::default(),
        )
        .expect("analyze_diff failed");

        let caller = result
            .patch_symbols
            .edited
            .iter()
            .find(|pair| pair.after.name == "caller")
            .expect("caller must be reported as edited");
        assert!(
            caller
                .added_calls
                .iter()
                .any(|call| call.to.contains("makeThing")),
            "the new call to makeThing must be detected, got {:?}",
            caller.added_calls
        );
        assert!(
            result
                .dependency_symbols
                .iter()
                .any(|symbol| symbol.fqn.contains("makeThing")),
            "the newly called function must appear in dependency_symbols, got {:?}",
            result.dependency_symbols
        );
    }

    #[test]
    fn snapshot_materialization_uses_private_permissions() {
        let temp = RevisionTempDir::new("permissions").unwrap();
        let nested = temp.path().join("nested").join("source");
        create_private_dirs(temp.path(), &nested).unwrap();
        let file = nested.join("lib.go");
        write_private_file(&file, b"package sample\n").unwrap();

        assert_eq!(
            fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(nested).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(test)]
mod entry_point_tests {
    use super::*;

    /// A two-commit repository whose second commit edits `lib.go`, built with
    /// `git2` so the lib tests do not need a `git` binary on PATH.
    fn two_commit_repo(root: &Path) -> Oid {
        let repo = Repository::init(root).unwrap();
        let signature = git2::Signature::now("Tester", "tester@example.com").unwrap();
        let mut head: Option<Oid> = None;
        for body in ["\treturn 1\n", "\treturn 2\n"] {
            fs::write(
                root.join("lib.go"),
                format!("package sample\n\nfunc Existing() int {{\n{body}}}\n"),
            )
            .unwrap();
            let mut index = repo.index().unwrap();
            index.add_path(Path::new("lib.go")).unwrap();
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            let parents: Vec<git2::Commit> = head
                .into_iter()
                .map(|oid| repo.find_commit(oid).unwrap())
                .collect();
            head = Some(
                repo.commit(
                    Some("HEAD"),
                    &signature,
                    &signature,
                    "commit",
                    &tree,
                    &parents.iter().collect::<Vec<_>>(),
                )
                .unwrap(),
            );
        }
        head.unwrap()
    }

    #[test]
    fn analyze_diff_diffs_the_analyzers_own_project_root() {
        let temp = RevisionTempDir::new("analyzer-entry").unwrap();
        let root = temp.path();
        let head = two_commit_repo(root);
        let analyzer = build_analyzer(root, &[PathBuf::from("lib.go")]).unwrap();

        let result = analyze_diff(
            analyzer.analyzer(),
            AnalyzeDiffParams {
                base: None,
                target: Some(head.to_string()),
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .unwrap();

        assert_eq!(result.endpoints.target, head.to_string());
        assert_eq!(
            result
                .patch_symbols
                .edited
                .iter()
                .map(|pair| pair.after.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Existing"],
            "the analyzer's project root is the repository that gets diffed"
        );
    }

    /// End-to-end over a real repository: a fuzzy-paired move (relocated AND
    /// renamed, so only body similarity lines it up) carries `similarity:
    /// Some(score >= threshold)`, while a move paired by identity or a Git
    /// rename reports `similarity: None`.
    #[test]
    fn analyze_diff_reports_similarity_only_for_fuzzy_moved_pairs() {
        let temp = RevisionTempDir::new("fuzzy-move-entry").unwrap();
        let root = temp.path();
        let repo = Repository::init(root).unwrap();
        let signature = git2::Signature::now("Tester", "tester@example.com").unwrap();
        let accumulate = |name: &str, acc: &str| {
            format!(
                "func {name}(xs []int) int {{\n\t{acc} := 0\n\tfor _, x := range xs {{\n\t\t{acc} += x\n\t\tif x > 10 {{\n\t\t\t{acc} += 2\n\t\t}}\n\t}}\n\treturn {acc}\n}}\n"
            )
        };
        let keep = "func Keep() int {\n\tv := 3\n\tv *= 7\n\treturn v\n}\n";
        let commit = |parent: Option<Oid>, message: &str, files: &[&str]| {
            let mut index = repo.index().unwrap();
            index.clear().unwrap();
            for file in files {
                index.add_path(Path::new(file)).unwrap();
            }
            index.write().unwrap();
            let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
            let parents: Vec<git2::Commit> = parent
                .into_iter()
                .map(|oid| repo.find_commit(oid).unwrap())
                .collect();
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                message,
                &tree,
                &parents.iter().collect::<Vec<_>>(),
            )
            .unwrap()
        };

        // Base: ComputeTotal lives in lib.go, Keep in keep.go.
        fs::write(
            root.join("lib.go"),
            format!("package sample\n\n{}", accumulate("ComputeTotal", "sum")),
        )
        .unwrap();
        fs::write(root.join("keep.go"), format!("package sample\n\n{keep}")).unwrap();
        let base = commit(None, "base", &["lib.go", "keep.go"]);

        // Target: ComputeTotal moves to other.go as SumAll with a renamed
        // accumulator -- only the fuzzy third rule can pair it -- while keep.go
        // is renamed wholesale with Keep untouched, which pairs by identity or
        // the Git-rename bucket.
        fs::write(root.join("lib.go"), "package sample\n").unwrap();
        fs::write(
            root.join("other.go"),
            format!("package sample\n\n{}", accumulate("SumAll", "total")),
        )
        .unwrap();
        fs::remove_file(root.join("keep.go")).unwrap();
        fs::write(root.join("kept.go"), format!("package sample\n\n{keep}")).unwrap();
        let head = commit(Some(base), "move", &["lib.go", "other.go", "kept.go"]);

        let analyzer = build_analyzer(
            root,
            &[
                PathBuf::from("lib.go"),
                PathBuf::from("other.go"),
                PathBuf::from("kept.go"),
            ],
        )
        .unwrap();
        let result = analyze_diff(
            analyzer.analyzer(),
            AnalyzeDiffParams {
                base: Some(base.to_string()),
                target: Some(head.to_string()),
                include_tests: true,
            },
            &DiffAnalysisOptions::default(),
        )
        .unwrap();

        let moved = &result.patch_symbols.moved;
        let fuzzy = moved
            .iter()
            .find(|entry| entry.after.name == "SumAll")
            .expect("the renamed move should be reported as moved");
        assert_eq!(fuzzy.before.name, "ComputeTotal");
        let score = fuzzy
            .similarity
            .expect("a fuzzy-paired move carries its similarity score");
        assert!(
            score >= BODY_MOVE_SIMILARITY_THRESHOLD,
            "reported similarity {score} must clear the threshold"
        );
        let exact = moved
            .iter()
            .find(|entry| entry.after.name == "Keep")
            .expect("the renamed-file move should be reported as moved");
        assert_eq!(
            exact.similarity, None,
            "a move paired by identity or Git rename must not report a score"
        );
    }

    /// Snapshot trees can come from a host-supplied object directory, so the
    /// export refuses any entry name that would escape the revision root.
    #[test]
    fn safe_tree_entry_path_rejects_names_that_escape_the_root() {
        assert_eq!(
            safe_tree_entry_path("pkg/inner/lib.go").unwrap(),
            PathBuf::from("pkg/inner/lib.go")
        );
        for name in ["", "../escape.go", "/absolute.go", "pkg/../../escape.go"] {
            assert!(
                safe_tree_entry_path(name).is_err(),
                "`{name}` must be rejected"
            );
        }
    }

    /// A whole-revision export analyzes through the primary repository's shared
    /// content-addressed cache, and the rows naming its self-deleting export
    /// directory are gone once the workspace drops. The parsed blob facts the
    /// same build published are keyed by content and stay: those are the asset
    /// the next request reuses.
    #[test]
    fn a_revision_export_workspace_answers_and_then_drops_its_projection() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        two_commit_repo(root);

        let export = export_revision(root, "HEAD").expect("export HEAD");
        // Resolved while the export directory still exists: the identity
        // canonicalizes its root, exactly as the claim did.
        let export_identity = brokk_bifrost_core::gitblob::workspace_cache_identity(export.root());
        let workspace = export.build_workspace(root).expect("revision workspace");

        let names = {
            let analyzer = workspace.workspace().analyzer();
            let _scope = AnalyzerQueryScope::new(analyzer);
            analyzer
                .all_declarations()
                .map(|unit| unit.fq_name())
                .collect::<BTreeSet<_>>()
        };
        assert!(
            names.iter().any(|name| name.ends_with("Existing")),
            "the export's analyzer must answer over the exported files: {names:?}"
        );

        drop(workspace);
        drop(export);

        let connection = rusqlite::Connection::open(crate::analyzer::store::analyzer_db_path(root))
            .expect("open the shared analyzer cache");
        let workspaces: BTreeSet<String> = {
            let mut statement = connection
                .prepare("SELECT DISTINCT workspace_id FROM workspace_heads")
                .expect("prepare workspace listing");
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .expect("query workspace listing");
            rows.map(|row| row.expect("read workspace id")).collect()
        };
        assert!(
            !workspaces.contains(&export_identity),
            "the export's workspace rows must not outlive it: {workspaces:?}"
        );
        let blobs: i64 = connection
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .expect("count cached blobs");
        assert!(
            blobs > 0,
            "the export must have published its parsed blob facts to the shared cache"
        );
    }
}
