use crate::analyzer::test_paths;
use crate::analyzer::{AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile};
use crate::searchtools::{
    UsageGraphCallSite, UsageGraphEdge, UsageGraphParams, UsageGraphTruncatedSymbol, usage_graph,
};
use crate::{FileSetProject, WorkspaceAnalyzer};
use git2::{Delta, DiffFormat, DiffOptions, FileMode, ObjectType, Oid, Repository};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
    pub call_edge_changes: Vec<CallEdgeChange>,
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
}

/// A symbol the postimage has and the preimage does not.
#[derive(Debug, Clone, Serialize)]
pub struct IntroducedSymbol {
    pub after: CommitSymbol,
    pub touched_new_lines: Vec<usize>,
}

/// A symbol the preimage has and the postimage does not.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedSymbol {
    pub before: CommitSymbol,
    pub touched_old_lines: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MovedSymbol {
    pub before: CommitSymbol,
    pub after: CommitSymbol,
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

#[derive(Debug, Clone, Serialize)]
pub struct CallEdgeChange {
    /// Closed set, produced by [`call_edge_changes_and_dependencies`]: `added`
    /// for an edge only the postimage graph has, `removed` for one only the
    /// preimage graph has. An edge present in both is not reported.
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

    let base_image = RevisionImage::materialize(repo, base, &base_paths)?;
    let target_image = RevisionImage::materialize(repo, target, &target_paths)?;
    let base_analyzer = build_analyzer(base_image.root(), base_image.files())?;
    let target_analyzer = build_analyzer(target_image.root(), target_image.files())?;

    let before = symbol_snapshot_map(base_analyzer.analyzer(), params.include_tests);
    let after = symbol_snapshot_map(target_analyzer.analyzer(), params.include_tests);

    let mut introduced = Vec::new();
    let mut edited = Vec::new();
    let mut deleted = Vec::new();
    let mut moved = Vec::new();
    let mut signature_changes = Vec::new();

    // A key present at both endpoints yields at most one `edited` record, which
    // carries both endpoint descriptors and both line lists. A hunk touching
    // either side edits the symbol, so the record exists whenever either
    // overlap is non-empty; a lopsided hunk simply leaves the untouched side's
    // list empty. `introduced` and `deleted` stay one-sided because only one
    // endpoint has the symbol at all.
    //
    // Boundary, deliberately left as is: a matched symbol whose own lines see no
    // hunk is not reported even when the patch changed its meaning from above
    // (an enclosing scope or an import shifting parse context), and an unmatched
    // symbol with no overlap is likewise dropped rather than reported.
    for (key, post) in &after {
        let Some(pre) = before.get(key) else {
            let touched_new_lines = new_overlap(&post.symbol, &changed_lines);
            if !touched_new_lines.is_empty() {
                introduced.push(IntroducedSymbol {
                    after: post.symbol.clone(),
                    touched_new_lines,
                });
            }
            continue;
        };
        if pre.symbol.path != post.symbol.path || pre.symbol.start_line != post.symbol.start_line {
            moved.push(MovedSymbol {
                before: pre.symbol.clone(),
                after: post.symbol.clone(),
            });
        }
        if pre.symbol.signature != post.symbol.signature {
            signature_changes.push(SignatureChange {
                before: pre.symbol.clone(),
                after: post.symbol.clone(),
            });
        }
        let touched_old_lines = old_overlap(&pre.symbol, &changed_lines);
        let touched_new_lines = new_overlap(&post.symbol, &changed_lines);
        if touched_old_lines.is_empty() && touched_new_lines.is_empty() {
            continue;
        }
        edited.push(EditedSymbolPair {
            before: pre.symbol.clone(),
            after: post.symbol.clone(),
            touched_old_lines,
            touched_new_lines,
        });
    }
    for (key, pre) in &before {
        if after.contains_key(key) {
            continue;
        }
        let touched_old_lines = old_overlap(&pre.symbol, &changed_lines);
        if !touched_old_lines.is_empty() {
            deleted.push(DeletedSymbol {
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

    let patch_symbols = PatchSymbols {
        edited,
        introduced,
        deleted,
        moved,
        signature_changes,
    };

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
        },
    );
    let graph_after = usage_graph(
        target_analyzer.analyzer(),
        UsageGraphParams {
            include_tests: params.include_tests,
            paths: Some(changed_paths),
        },
    );
    let (call_edge_changes, dependency_symbols) =
        call_edge_changes_and_dependencies(&graph_before.edges, &graph_after.edges, &after);
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
        call_edge_changes,
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

/// An analyzable image of one diff endpoint, restricted to the changed files.
///
/// Immutable endpoints — a commit or a bare tree — are exported into a private
/// temp directory from their resolved tree; the working-tree endpoint is
/// analyzed in place from the real project root. Both sides stay restricted to
/// the changed paths so the symbol and call-edge diffs compare like for like.
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
    fn materialize(
        repo: &Repository,
        snapshot: Snapshot,
        paths: &[String],
    ) -> Result<Self, String> {
        match snapshot {
            Snapshot::Commit(oid) | Snapshot::Tree(oid) => {
                let temp = RevisionTempDir::new(&oid.to_string())?;
                let files = export_snapshot_files(repo, snapshot, temp.path(), paths)?;
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
                let files = worktree_files(&root, paths)?;
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

/// Collect the changed paths that actually exist as regular files on disk.
///
/// A path deleted in the working tree still appears in the diff but has no file
/// to analyze, so it is skipped the same way [`export_commit_files`] skips
/// missing tree entries.
fn worktree_files(root: &Path, paths: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut present = Vec::new();
    for raw_path in paths {
        let rel = safe_tree_entry_path(raw_path)?;
        let absolute = root.join(&rel);
        let is_regular_file = fs::symlink_metadata(&absolute)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
        if is_regular_file {
            present.push(rel);
        }
    }
    Ok(present)
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

fn export_snapshot_files(
    repo: &Repository,
    snapshot: Snapshot,
    root: &Path,
    paths: &[String],
) -> Result<Vec<PathBuf>, String> {
    let tree = snapshot_tree(repo, snapshot)?;
    let mut exported = Vec::new();
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
        exported.push(rel);
    }
    Ok(exported)
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
fn build_analyzer(root: &Path, files: &[PathBuf]) -> Result<WorkspaceAnalyzer, String> {
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
        out.insert(
            key.clone(),
            SymbolSnapshot {
                key,
                symbol: CommitSymbol {
                    fqn: unit.fq_name(),
                    name: unit.identifier().to_string(),
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
    let Some(file) = analyzer.project().file_by_rel_path(path) else {
        return BTreeSet::new();
    };
    let structured = analyzer
        .import_analysis_provider()
        .map(|provider| {
            provider
                .import_info_of(&file)
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

fn call_edge_changes_and_dependencies(
    before: &[UsageGraphEdge],
    after: &[UsageGraphEdge],
    symbols: &BTreeMap<SymbolKey, SymbolSnapshot>,
) -> (Vec<CallEdgeChange>, Vec<CommitSymbol>) {
    let old = edge_map(before);
    let new = edge_map(after);
    let mut changes = Vec::new();
    let mut deps = BTreeMap::new();
    for (key, edge) in &new {
        if !old.contains_key(key) {
            changes.push(edge_change("added", edge));
            if let Some(symbol) = find_symbol(symbols, &edge.to, &edge.language) {
                deps.insert(symbol.fqn.clone(), symbol.clone());
            }
        }
    }
    for (key, edge) in &old {
        if !new.contains_key(key) {
            changes.push(edge_change("removed", edge));
        }
    }
    changes.sort_by(|a, b| {
        a.language
            .cmp(&b.language)
            .then_with(|| a.from.cmp(&b.from))
            .then_with(|| a.to.cmp(&b.to))
            .then_with(|| a.change.cmp(&b.change))
    });
    let mut dependency_symbols: Vec<_> = deps.into_values().collect();
    sort_symbols(&mut dependency_symbols);
    (changes, dependency_symbols)
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

fn edge_change(change: &str, edge: &UsageGraphEdge) -> CallEdgeChange {
    CallEdgeChange {
        change: change.to_string(),
        from: edge.from.clone(),
        to: edge.to.clone(),
        language: edge.language.clone(),
        weight: edge.weight,
        sites: edge.sites.clone(),
    }
}

fn find_symbol(
    symbols: &BTreeMap<SymbolKey, SymbolSnapshot>,
    fqn: &str,
    language: &str,
) -> Option<CommitSymbol> {
    symbols
        .values()
        .find(|snapshot| snapshot.key.fqn == fqn && snapshot.key.language == language)
        .map(|snapshot| snapshot.symbol.clone())
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
    use super::{RevisionTempDir, create_private_dirs, write_private_file};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

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
