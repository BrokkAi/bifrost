use crate::analyzer::test_paths;
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
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
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Endpoint label reported for the uncommitted working tree.
pub const WORKTREE_ENDPOINT: &str = "worktree";

/// Parameters for `analyze_diff`.
///
/// Both endpoints are optional; see [`resolve_endpoints`] for the resolution
/// table. `{}` means "HEAD vs the working tree".
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AnalyzeDiffParams {
    /// Revspec of the "before" endpoint. Defaults to the first parent of
    /// `target` when `target` is a commit, and to `HEAD` when `target` is the
    /// working tree.
    #[serde(default)]
    pub base: Option<String>,
    /// Revspec of the "after" endpoint. Omitted means the working tree.
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default = "default_include_tests")]
    pub include_tests: bool,
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
enum Snapshot {
    Commit(Oid),
    Tree(Oid),
    Worktree,
}

impl Snapshot {
    fn label(&self) -> String {
        match self {
            Self::Commit(oid) => oid.to_string(),
            Self::Tree(oid) => format!("tree:{oid}"),
            Self::Worktree => WORKTREE_ENDPOINT.to_string(),
        }
    }

    fn is_immutable(self) -> bool {
        !matches!(self, Self::Worktree)
    }
}

/// Resolve `params` into `(base, target)` snapshots.
///
/// | params                     | base                | target      |
/// |----------------------------|---------------------|-------------|
/// | `{}`                       | `HEAD`              | working tree|
/// | `{target: X}`              | first parent of `X` | `X`         |
/// | `{base: A, target: B}`     | `A`                 | `B`         |
/// | `{base: A}`                | `A`                 | working tree|
///
fn resolve_endpoints(
    repo: &Repository,
    params: &AnalyzeDiffParams,
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
        Snapshot::Worktree => resolve_commit(repo, "HEAD")
            .map(Snapshot::Commit)
            .map_err(|err| {
                format!("unable to default `base` to HEAD for a working-tree diff: {err}")
            }),
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
    let resolution_repo = open_repository(root, options, false)?;
    let (base, target) = resolve_endpoints(&resolution_repo.repo, &params)?;
    let repository = if base.is_immutable() && target.is_immutable() {
        open_repository(root, options, true)?
    } else {
        resolution_repo
    };
    let repo = &repository.repo;

    let (file_changes, changed_lines) = diff_metadata(repo, base, target)?;
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

    let base_image = RevisionImage::materialize(repo, base, Some(&base_paths))?;
    let target_image = RevisionImage::materialize(repo, target, Some(&target_paths))?;
    let base_analyzer = build_analyzer(base_image.root(), base_image.files())?;
    let target_analyzer = build_analyzer(target_image.root(), target_image.files())?;

    let before = symbol_snapshot_map(base_analyzer.analyzer(), params.include_tests);
    let after = symbol_snapshot_map(target_analyzer.analyzer(), params.include_tests);

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
    let endpoint_pairing = pair_endpoints(&before, &after, &file_changes);
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
                && !is_pure_line_shift(&pre.symbol, &post.symbol, &changed_lines));
        let fallback_score = endpoint_pairing.fallback_paired.get(&pre.key).copied();
        if relocated {
            moved.push(MovedSymbol {
                before: pre.symbol.clone(),
                after: post.symbol.clone(),
                added_calls: Vec::new(),
                removed_calls: Vec::new(),
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
        let touched_old_lines = old_overlap(&pre.symbol, &changed_lines);
        let touched_new_lines = new_overlap(&post.symbol, &changed_lines);
        if relocated_by_body || (touched_old_lines.is_empty() && touched_new_lines.is_empty()) {
            continue;
        }
        edited.push(EditedSymbolPair {
            before: pre.symbol.clone(),
            after: post.symbol.clone(),
            touched_old_lines,
            touched_new_lines,
            added_calls: Vec::new(),
            removed_calls: Vec::new(),
        });
    }
    for post in &endpoint_pairing.postimage_only {
        let touched_new_lines = new_overlap(&post.symbol, &changed_lines);
        if !touched_new_lines.is_empty() {
            introduced.push(IntroducedSymbol {
                after: post.symbol.clone(),
                touched_new_lines,
                calls: Vec::new(),
            });
        }
    }
    for pre in &endpoint_pairing.preimage_only {
        let touched_old_lines = old_overlap(&pre.symbol, &changed_lines);
        if !touched_old_lines.is_empty() {
            deleted.push(DeletedSymbol {
                before: pre.symbol.clone(),
                touched_old_lines,
                called: Vec::new(),
            });
        }
    }

    edited.sort_by(|a, b| a.after.cmp(&b.after));
    introduced.sort_by(|a, b| a.after.cmp(&b.after));
    deleted.sort_by(|a, b| a.before.cmp(&b.before));
    moved.sort_by(|a, b| a.after.cmp(&b.after));
    signature_changes.sort_by(|a, b| a.after.cmp(&b.after));

    let import_changes = import_changes(
        base_analyzer.analyzer(),
        target_analyzer.analyzer(),
        &changed_paths,
    );
    let graph_before = usage_graph(
        base_analyzer.analyzer(),
        UsageGraphParams {
            include_tests: params.include_tests,
            paths: Some(changed_paths.clone()),
            depth: 1,
        },
    );
    let graph_after = usage_graph(
        target_analyzer.analyzer(),
        UsageGraphParams {
            include_tests: params.include_tests,
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

    Ok(DiffAnalysisResult {
        endpoints: DiffEndpoints {
            base: base.label(),
            target: target.label(),
        },
        file_changes,
        patch_symbols,
        dependency_symbols,
        import_changes,
        unattributed_call_edge_changes,
        large_callsite_symbols,
    })
}

struct DiffRepository {
    repo: Repository,
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
        return attach_snapshot_alternate(repo, options).map(|repo| DiffRepository {
            repo,
            _temp: Some(temp),
        });
    } else {
        Repository::open(root)
    }
    .map_err(|err| format!("not a git repository at project root: {err}"))?;
    attach_snapshot_alternate(repo, options).map(|repo| DiffRepository { repo, _temp: None })
}

fn attach_snapshot_alternate(
    repo: Repository,
    options: &DiffAnalysisOptions,
) -> Result<Repository, String> {
    if let Some(path) = options.snapshot_object_dir.as_deref() {
        add_odb_alternate(&repo, path, "configured diff snapshot object directory")?;
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
/// Immutable endpoints — a commit or a bare tree — are exported into a private
/// temp directory from their resolved tree; the working-tree endpoint is
/// analyzed in place from the real project root. Both sides carry the diff's
/// own changed paths plus what `export_snapshot_files`/`worktree_files` add
/// for name resolution and newly-referenced packages -- not the revision's
/// entire file set, which stays correct only at whole-tree scale (see
/// `export_revision`'s much larger cost budget).
enum RevisionImage {
    Snapshot {
        temp: RevisionTempDir,
        files: Vec<PathBuf>,
    },
    Worktree {
        root: PathBuf,
        files: Vec<PathBuf>,
    },
}

impl RevisionImage {
    /// `paths: None` exports every file in the snapshot, for `export_revision`'s
    /// whole-tree policy gating. `paths: Some(_)` restricts the export to
    /// those paths plus what's described above.
    fn materialize(
        repo: &Repository,
        snapshot: Snapshot,
        paths: Option<&[String]>,
    ) -> Result<Self, String> {
        match snapshot {
            Snapshot::Commit(oid) | Snapshot::Tree(oid) => {
                let temp = RevisionTempDir::new(&oid.to_string())?;
                let files = match paths {
                    Some(paths) => export_snapshot_files(repo, snapshot, temp.path(), paths)?,
                    None => {
                        let all = all_tree_paths(repo, snapshot)?;
                        export_tree_paths(repo, &snapshot_tree(repo, snapshot)?, temp.path(), &all)?
                    }
                };
                Ok(Self::Snapshot { temp, files })
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

    fn root(&self) -> &Path {
        match self {
            Self::Snapshot { temp, .. } => temp.path(),
            Self::Worktree { root, .. } => root,
        }
    }

    fn files(&self) -> &[PathBuf] {
        match self {
            Self::Snapshot { files, .. } | Self::Worktree { files, .. } => files,
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
    let image = RevisionImage::materialize(&repo, subtree, None)?;
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
/// plus everything [`ambient_ancestor_paths_fs`] and
/// [`import_expansion_targets`] add for the same reasons `export_snapshot_files`
/// does for a committed endpoint.
///
/// A path deleted in the working tree still appears in the diff but has no
/// file to analyze, so it is skipped the same way a missing tree entry is.
fn worktree_files(root: &Path, paths: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut present = BTreeSet::new();
    let mut changed = Vec::with_capacity(paths.len());
    for raw_path in paths {
        let rel = safe_tree_entry_path(raw_path)?;
        let absolute = root.join(&rel);
        let is_regular_file = fs::symlink_metadata(&absolute)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
        if is_regular_file {
            present.insert(rel.clone());
            changed.push(rel);
        }
    }
    present.extend(ambient_ancestor_paths_fs(root, paths));
    for target in import_expansion_targets(root, None, &changed)? {
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

/// Every regular file sitting directly inside an ancestor directory of a
/// changed path, up to `root`, deduplicated across `paths`. Filesystem analog
/// of [`ambient_ancestor_paths`], for the working-tree endpoint.
fn ambient_ancestor_paths_fs(root: &Path, paths: &[String]) -> Vec<PathBuf> {
    let mut visited_dirs = BTreeSet::new();
    let mut ambient = Vec::new();
    for raw_path in paths {
        let Ok(rel) = safe_tree_entry_path(raw_path) else {
            continue;
        };
        let mut dir = rel.parent();
        while let Some(current) = dir {
            // See `ambient_ancestor_paths`: once a directory is revisited,
            // the rest of this path's ancestors were already swept too.
            if !visited_dirs.insert(current.to_path_buf()) {
                break;
            }
            for entry in fs::read_dir(root.join(current))
                .into_iter()
                .flatten()
                .flatten()
            {
                let path = entry.path();
                if fs::symlink_metadata(&path)
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
/// `tree` distinguishes how a candidate's existence gets checked: against a
/// snapshot's git tree for a committed endpoint (`Some`), or directly on disk
/// for the working tree (`None`, where `root` already IS the project root).
enum ImportExpansionTarget {
    Directory(PathBuf),
    File(PathBuf),
}

fn import_expansion_targets(
    root: &Path,
    tree: Option<&git2::Tree>,
    changed_paths: &[PathBuf],
) -> Result<Vec<ImportExpansionTarget>, String> {
    let analyzer = build_analyzer(root, changed_paths)?;
    let analyzer = analyzer.analyzer();
    let Some(provider) = analyzer.import_analysis_provider() else {
        return Ok(Vec::new());
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
                let resolved =
                    resolve_import_target(importing_dir, &import_target, |candidate| match tree {
                        Some(tree) => tree
                            .get_path(candidate)
                            .ok()
                            .map(|entry| entry.kind() == Some(ObjectType::Tree)),
                        None => worktree_entry_kind(root, candidate),
                    });
                if let Some((path, is_directory)) = resolved {
                    targets.push(if is_directory {
                        ImportExpansionTarget::Directory(path)
                    } else {
                        ImportExpansionTarget::File(path)
                    });
                }
            }
        }
    }
    Ok(targets)
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

struct RevisionTempDir {
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

/// Every regular file path in `snapshot`'s tree, workspace-relative.
fn all_tree_paths(repo: &Repository, snapshot: Snapshot) -> Result<Vec<String>, String> {
    let tree = snapshot_tree(repo, snapshot)?;
    Ok(tree_dir_file_paths(repo, &tree, Path::new("")))
}

/// Export `paths` from `snapshot`'s tree into `root`, plus every ambient
/// manifest an ancestor directory up (see [`ambient_ancestor_paths`]) and
/// every package `paths`' own imports concretely reference (see
/// [`import_expansion_targets`]), which -- unlike the ambient export -- must
/// join the returned list: an import's target needs to be a real, analyzed
/// declaration for its callee to resolve, not just a file sitting on disk for
/// a manifest reader to open.
///
/// A restricted export (just the diff's own changed paths) cannot resolve a
/// symbol whose name or call graph depends on a file the diff never touches:
/// a module/package manifest an ancestor directory up, or a callee that
/// lives in some other, untouched file entirely.
fn export_snapshot_files(
    repo: &Repository,
    snapshot: Snapshot,
    root: &Path,
    paths: &[String],
) -> Result<Vec<PathBuf>, String> {
    let tree = snapshot_tree(repo, snapshot)?;
    let mut exported = export_tree_paths(repo, &tree, root, paths)?;

    // Ambient files join `exported` too: Go's own module-root discovery
    // (`go_module_roots`) finds `go.mod` by filtering the project's file
    // list, not by reading the filesystem directly, so a `go.mod` written to
    // disk but left out of this list is invisible to it.
    let mut already_exported: BTreeSet<String> = paths.iter().cloned().collect();
    let ambient: Vec<String> = ambient_ancestor_paths(repo, &tree, paths)
        .into_iter()
        .filter(|path| !already_exported.contains(path))
        .collect();
    exported.extend(export_tree_paths(repo, &tree, root, &ambient)?);
    already_exported.extend(ambient);

    // Import expansion resolves against a manifest that just landed on disk
    // above (a `go.mod`, a `Cargo.toml`, ...), so it only runs now.
    let changed: Vec<PathBuf> = paths
        .iter()
        .filter_map(|path| safe_tree_entry_path(path).ok())
        .collect();
    let mut expansion = BTreeSet::new();
    for target in import_expansion_targets(root, Some(&tree), &changed)? {
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
) -> Result<Vec<PathBuf>, String> {
    let mut written = Vec::with_capacity(paths.len());
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
            create_private_dirs(root, parent)?;
        }
        write_private_file(&path, blob.content())?;
        set_private_file_permissions(&path)?;
        written.push(rel);
    }
    Ok(written)
}

/// Every regular file sitting directly inside an ancestor directory of a
/// changed path, up to the snapshot root, deduplicated across `paths`.
///
/// This has no notion of what a "manifest" is named. A per-language file
/// list would have to track every module/package/build file each analyzer
/// might walk up to find (and every path-based variant, like a JVM Gradle
/// lockfile under `gradle/dependency-locks/`) and would silently miss
/// whichever one it forgot. Copying whatever an ancestor directory actually
/// contains cannot miss a name it wasn't told about, and stays cheap because
/// it is bounded by each changed path's own depth, not the size of the tree.
fn ambient_ancestor_paths(repo: &Repository, tree: &git2::Tree, paths: &[String]) -> Vec<String> {
    fn push_blobs(dir: &git2::Tree, prefix: &str, out: &mut Vec<String>) {
        for entry in dir.iter() {
            if entry.kind() == Some(ObjectType::Blob)
                && is_regular_file_mode(entry.filemode())
                && let Some(name) = entry.name()
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

fn create_private_dirs(root: &Path, parent: &Path) -> Result<(), String> {
    let rel = parent.strip_prefix(root).map_err(|err| {
        format!(
            "unable to create directory outside revision root {}: {err}",
            parent.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in rel.components() {
        current.push(component.as_os_str());
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

/// Build a throwaway analyzer over exactly `files`.
///
/// This must never touch an on-disk analyzer cache: for commit endpoints the
/// root is a temp directory that is deleted immediately afterwards, and for the
/// working-tree endpoint the root is the *live* project root, whose real cache
/// must not be replaced by one that only ever saw a handful of changed files.
/// `build_ephemeral` states that requirement at the call site instead of
/// relying on `FileSetProject::persistence_root()` happening to be `None`.
pub(crate) fn build_analyzer(root: &Path, files: &[PathBuf]) -> Result<WorkspaceAnalyzer, String> {
    let project = Arc::new(FileSetProject::new(
        root.to_path_buf(),
        files.iter().cloned(),
    ));
    WorkspaceAnalyzer::build_ephemeral(project, AnalyzerConfig::default())
        .map_err(|error| format!("Failed to build diff endpoint analyzer: {error}"))
}

fn symbol_snapshot_map(
    analyzer: &dyn IAnalyzer,
    include_tests: bool,
) -> BTreeMap<SymbolKey, SymbolSnapshot> {
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
            .and_then(|text| body_token_signature(text, &name, range.start_line, range.end_line));
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

/// A normalized token sequence for a symbol's body, or `None` when the body is
/// too trivial to identify a move by content alone.
///
/// The symbol's own `name` is blanked (see [`blank_identifier`]) so a rename
/// does not change the signature, then the `[start_line, end_line]` span
/// (1-based, inclusive) is tokenized into identifier/number runs and individual
/// punctuation characters. Internal identifiers are deliberately KEPT: they let
/// [`body_similarity`] tell genuinely different logic apart, and the threshold
/// absorbs the few that a rename touches. A body of fewer than two non-blank
/// lines is rejected (`None`): too weak a fingerprint to pair on without
/// inventing moves.
fn body_token_signature(
    source: &str,
    name: &str,
    start_line: usize,
    end_line: usize,
) -> Option<Vec<String>> {
    if start_line == 0 || end_line < start_line {
        return None;
    }
    let mut tokens = Vec::new();
    let mut non_blank_lines = 0;
    for line in source
        .lines()
        .skip(start_line - 1)
        .take(end_line - start_line + 1)
    {
        let blanked = blank_identifier(line, name);
        let before = tokens.len();
        tokenize_into(&blanked, &mut tokens);
        if tokens.len() > before {
            non_blank_lines += 1;
        }
    }
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

fn primary_range(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<crate::analyzer::Range> {
    analyzer
        .ranges(unit)
        .iter()
        .copied()
        .min_by_key(|range| (range.start_line, range.start_byte))
}

fn sort_symbols(symbols: &mut [CommitSymbol]) {
    symbols.sort();
}

fn path_string(path: &Path) -> String {
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

fn path_language(path: &Path) -> Language {
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
        DiffAnalysisOptions, FileChange, ImportTarget, RevisionTempDir, SymbolKey, SymbolSnapshot,
        analyze_diff_at_root, body_similarity, body_token_signature, create_private_dirs,
        diff_local_idf, is_pure_line_shift, pair_endpoints, resolve_import_target,
        within_fuzzy_weight_ratio, worktree_files, write_private_file,
    };
    use crate::gitblob::test_repo;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

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

    /// A changed file that starts calling a function in an untouched sibling
    /// package: `MakeThing`'s own file was never part of the diff, so
    /// resolving the call and attaching its full definition both depend on
    /// `import_expansion_targets` following the new `import "repro/pkgb"` to
    /// `pkgb`'s directory and exporting it alongside the diff's own files.
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
        let lines_a = a_src.lines().count();
        let lines_b = b_src.lines().count();
        let a = body_token_signature(a_src, a_name, 1, lines_a).unwrap();
        let b = body_token_signature(b_src, b_name, 1, lines_b).unwrap();
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
    fn body_token_signature_rejects_trivial_and_degenerate_ranges() {
        let src = accumulate_body("f", "sum");
        let n = src.lines().count();
        assert!(body_token_signature(&src, "f", 1, n).is_some());
        // One non-blank line is too weak a fingerprint.
        assert_eq!(
            body_token_signature("pub fn f() { done() }\n", "f", 1, 1),
            None
        );
        // Degenerate ranges are rejected, not panicked on.
        assert_eq!(body_token_signature(&src, "f", 0, n), None);
        assert_eq!(body_token_signature(&src, "f", 5, 1), None);
    }

    fn snap_src(fqn: &str, name: &str, path: &str, src: &str) -> SymbolSnapshot {
        let n = src.lines().count();
        snapshot(fqn, name, path, body_token_signature(src, name, 1, n))
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
}
