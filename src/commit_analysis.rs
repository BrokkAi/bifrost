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

#[derive(Debug, Clone, Deserialize)]
pub struct AnalyzeCommitParams {
    pub revision: String,
    #[serde(default = "default_include_tests")]
    pub include_tests: bool,
}

fn default_include_tests() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct CommitAnalysisResult {
    pub commit: CommitPair,
    pub file_changes: Vec<FileChange>,
    pub patch_symbols: PatchSymbols,
    pub moved_symbols: Vec<MovedSymbol>,
    pub dependency_symbols: Vec<CommitSymbol>,
    pub signature_changes: Vec<SignatureChange>,
    pub import_changes: Vec<ImportChange>,
    pub call_edge_changes: Vec<CallEdgeChange>,
    pub changed_test_symbols: ChangedTestSymbols,
    pub large_callsite_symbols: Vec<LargeCallsiteSymbol>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommitPair {
    pub hash: String,
    pub parent_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileChange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub status: String,
    pub loc_changed: usize,
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

#[derive(Debug, Clone, Serialize, Default)]
pub struct PatchSymbols {
    pub preimage: PreimagePatchSymbols,
    pub postimage: PostimagePatchSymbols,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PreimagePatchSymbols {
    pub edited: Vec<PatchTouchedSymbol>,
    pub deleted: Vec<PatchTouchedSymbol>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PostimagePatchSymbols {
    pub edited: Vec<PatchTouchedSymbol>,
    pub introduced: Vec<PatchTouchedSymbol>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatchTouchedSymbol {
    pub fqn: String,
    pub name: String,
    pub kind: String,
    pub signature: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub language: String,
    pub is_test: bool,
    pub touched_old_lines: Vec<usize>,
    pub touched_new_lines: Vec<usize>,
    pub change_reason: String,
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
    pub change: String,
    pub from: String,
    pub to: String,
    pub language: String,
    pub weight: usize,
    pub sites: Vec<UsageGraphCallSite>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ChangedTestSymbols {
    pub introduced: Vec<PatchTouchedSymbol>,
    pub edited: Vec<PatchTouchedSymbol>,
    pub deleted: Vec<PatchTouchedSymbol>,
    pub moved: Vec<MovedSymbol>,
    pub signature_changes: Vec<SignatureChange>,
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

pub fn analyze_commit(
    analyzer: &dyn IAnalyzer,
    params: AnalyzeCommitParams,
) -> Result<CommitAnalysisResult, String> {
    analyze_commit_at_root(analyzer.project().root(), params)
}

pub fn analyze_commit_at_root(
    root: &Path,
    params: AnalyzeCommitParams,
) -> Result<CommitAnalysisResult, String> {
    let repo = Repository::open(root)
        .map_err(|err| format!("not a git repository at project root: {err}"))?;
    let object = repo
        .revparse_single(params.revision.trim())
        .map_err(|err| format!("unable to resolve revision `{}`: {err}", params.revision))?;
    let commit = object
        .peel_to_commit()
        .map_err(|err| format!("revision `{}` is not a commit: {err}", params.revision))?;

    match commit.parent_count() {
        0 => return Err("analyze_commit does not support root commits".to_string()),
        1 => {}
        n => {
            return Err(format!(
                "analyze_commit does not support merge commits ({n} parents)"
            ));
        }
    }

    let parent = commit
        .parent(0)
        .map_err(|err| format!("unable to read parent commit: {err}"))?;
    let commit_oid = commit.id();
    let parent_oid = parent.id();

    let (file_changes, changed_lines) = diff_metadata(&repo, parent_oid, commit_oid)?;
    let changed_paths: Vec<String> = file_changes
        .iter()
        .flat_map(|change| [change.old_path.clone(), change.path.clone()])
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let parent_paths: Vec<String> = file_changes
        .iter()
        .filter_map(|change| change.old_path.as_ref().or(change.path.as_ref()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let commit_paths: Vec<String> = file_changes
        .iter()
        .filter_map(|change| change.path.as_ref())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let parent_tree = MaterializedRevision::new(&repo, parent_oid, &parent_paths)?;
    let commit_tree = MaterializedRevision::new(&repo, commit_oid, &commit_paths)?;
    let parent_analyzer = build_analyzer(parent_tree.path(), parent_tree.files())?;
    let commit_analyzer = build_analyzer(commit_tree.path(), commit_tree.files())?;

    let before = symbol_index(parent_analyzer.analyzer(), params.include_tests);
    let after = symbol_index(commit_analyzer.analyzer(), params.include_tests);

    let mut postimage_introduced = Vec::new();
    let mut postimage_edited = Vec::new();
    let mut preimage_edited = Vec::new();
    let mut preimage_deleted = Vec::new();
    let mut moved = Vec::new();
    let mut signature_changes = Vec::new();

    for (key, post) in &after {
        match before.get(key) {
            None => {
                if let Some(symbol) = postimage_touched_symbol(&post.symbol, &changed_lines) {
                    postimage_introduced.push(symbol);
                }
            }
            Some(pre) => {
                if pre.symbol.path != post.symbol.path
                    || pre.symbol.start_line != post.symbol.start_line
                {
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
                if let Some(symbol) = postimage_touched_symbol(&post.symbol, &changed_lines) {
                    postimage_edited.push(symbol);
                }
            }
        }
    }
    for (key, pre) in &before {
        if after.contains_key(key) {
            if let Some(symbol) = preimage_touched_symbol(&pre.symbol, &changed_lines) {
                preimage_edited.push(symbol);
            }
        } else if let Some(symbol) = preimage_touched_symbol(&pre.symbol, &changed_lines) {
            preimage_deleted.push(symbol);
        }
    }

    sort_patch_symbols(&mut postimage_introduced);
    sort_patch_symbols(&mut postimage_edited);
    sort_patch_symbols(&mut preimage_edited);
    sort_patch_symbols(&mut preimage_deleted);
    moved.sort_by(|a, b| a.after.cmp(&b.after));
    signature_changes.sort_by(|a, b| a.after.cmp(&b.after));

    let patch_symbols = PatchSymbols {
        preimage: PreimagePatchSymbols {
            edited: preimage_edited,
            deleted: preimage_deleted,
        },
        postimage: PostimagePatchSymbols {
            edited: postimage_edited,
            introduced: postimage_introduced,
        },
    };

    let import_changes = import_changes(
        parent_analyzer.analyzer(),
        commit_analyzer.analyzer(),
        &changed_paths,
    );
    let graph_before = usage_graph(
        parent_analyzer.analyzer(),
        UsageGraphParams {
            include_tests: params.include_tests,
            paths: Some(changed_paths.clone()),
        },
    );
    let graph_after = usage_graph(
        commit_analyzer.analyzer(),
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

    let changed_test_symbols = ChangedTestSymbols {
        introduced: patch_symbols
            .postimage
            .introduced
            .iter()
            .filter(|s| s.is_test)
            .cloned()
            .collect(),
        edited: patch_symbols
            .preimage
            .edited
            .iter()
            .chain(patch_symbols.postimage.edited.iter())
            .filter(|s| s.is_test)
            .cloned()
            .collect(),
        deleted: patch_symbols
            .preimage
            .deleted
            .iter()
            .filter(|s| s.is_test)
            .cloned()
            .collect(),
        moved: moved
            .iter()
            .filter(|m| m.before.is_test || m.after.is_test)
            .cloned()
            .collect(),
        signature_changes: signature_changes
            .iter()
            .filter(|s| s.before.is_test || s.after.is_test)
            .cloned()
            .collect(),
    };

    Ok(CommitAnalysisResult {
        commit: CommitPair {
            hash: commit_oid.to_string(),
            parent_hash: parent_oid.to_string(),
        },
        file_changes,
        patch_symbols,
        moved_symbols: moved,
        dependency_symbols,
        signature_changes,
        import_changes,
        call_edge_changes,
        changed_test_symbols,
        large_callsite_symbols,
    })
}

fn diff_metadata(
    repo: &Repository,
    parent_oid: Oid,
    commit_oid: Oid,
) -> Result<(Vec<FileChange>, BTreeMap<String, ChangedLines>), String> {
    let parent_tree = repo
        .find_commit(parent_oid)
        .and_then(|commit| commit.tree())
        .map_err(|err| format!("unable to read parent tree: {err}"))?;
    let commit_tree = repo
        .find_commit(commit_oid)
        .and_then(|commit| commit.tree())
        .map_err(|err| format!("unable to read commit tree: {err}"))?;
    let mut opts = DiffOptions::new();
    let mut diff = repo
        .diff_tree_to_tree(Some(&parent_tree), Some(&commit_tree), Some(&mut opts))
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
            loc_changed: 0,
            is_test: is_test_like_path(&display_path),
            is_parseable: is_parseable_path(&display_path),
        });
    }

    let mut changed_lines: BTreeMap<String, ChangedLines> = BTreeMap::new();
    let mut loc_by_path: BTreeMap<String, usize> = BTreeMap::new();
    diff.print(DiffFormat::Patch, |delta, _hunk, line| {
        let display_path = delta
            .new_file()
            .path()
            .or_else(|| delta.old_file().path())
            .map(path_string);
        match line.origin() {
            '+' => {
                if let (Some(path), Some(line_no)) =
                    (delta.new_file().path().map(path_string), line.new_lineno())
                {
                    changed_lines
                        .entry(path)
                        .or_default()
                        .new
                        .insert(line_no as usize);
                }
                if let Some(path) = display_path {
                    *loc_by_path.entry(path).or_default() += 1;
                }
            }
            '-' => {
                if let (Some(path), Some(line_no)) =
                    (delta.old_file().path().map(path_string), line.old_lineno())
                {
                    changed_lines
                        .entry(path)
                        .or_default()
                        .old
                        .insert(line_no as usize);
                }
                if let Some(path) = display_path {
                    *loc_by_path.entry(path).or_default() += 1;
                }
            }
            _ => {}
        }
        true
    })
    .map_err(|err| format!("unable to enumerate diff lines: {err}"))?;

    for change in &mut changes {
        if let Some(path) = change.path.as_ref().or(change.old_path.as_ref()) {
            change.loc_changed = loc_by_path.get(path).copied().unwrap_or(0);
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

struct MaterializedRevision {
    temp: RevisionTempDir,
    files: Vec<PathBuf>,
}

impl MaterializedRevision {
    fn new(repo: &Repository, oid: Oid, paths: &[String]) -> Result<Self, String> {
        let temp = RevisionTempDir::new(oid)?;
        let files = export_commit_files(repo, oid, temp.path(), paths)?;
        Ok(Self { temp, files })
    }

    fn path(&self) -> &Path {
        self.temp.path()
    }

    fn files(&self) -> &[PathBuf] {
        &self.files
    }
}

struct RevisionTempDir {
    path: PathBuf,
}

impl RevisionTempDir {
    fn new(oid: Oid) -> Result<Self, String> {
        let base = std::env::temp_dir();
        for attempt in 0..100 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default();
            let path = base.join(format!(
                "bifrost-analyze-{}-{nanos}-{attempt}-{oid}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
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

fn export_commit_files(
    repo: &Repository,
    oid: Oid,
    root: &Path,
    paths: &[String],
) -> Result<Vec<PathBuf>, String> {
    let tree = repo
        .find_commit(oid)
        .and_then(|commit| commit.tree())
        .map_err(|err| format!("unable to read tree for {oid}: {err}"))?;
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
            fs::create_dir_all(parent)
                .map_err(|err| format!("unable to create {}: {err}", parent.display()))?;
        }
        fs::write(&path, blob.content())
            .map_err(|err| format!("unable to write {}: {err}", path.display()))?;
        exported.push(rel);
    }
    Ok(exported)
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

fn build_analyzer(root: &Path, files: &[PathBuf]) -> Result<WorkspaceAnalyzer, String> {
    let project = Arc::new(FileSetProject::new(
        root.to_path_buf(),
        files.iter().cloned(),
    ));
    Ok(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()))
}

fn symbol_index(
    analyzer: &dyn IAnalyzer,
    include_tests: bool,
) -> BTreeMap<SymbolKey, SymbolSnapshot> {
    let mut out = BTreeMap::new();
    for unit in analyzer.all_declarations() {
        if unit.is_synthetic() {
            continue;
        }
        let path = rel_path(unit.source());
        let is_test = analyzer.contains_tests(unit.source()) || is_test_like_path(&path);
        if is_test && !include_tests {
            continue;
        }
        let Some(range) = primary_range(analyzer, unit) else {
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
            .signatures(unit)
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

fn preimage_touched_symbol(
    symbol: &CommitSymbol,
    changed_lines: &BTreeMap<String, ChangedLines>,
) -> Option<PatchTouchedSymbol> {
    let touched = touched_lines(
        changed_lines.get(&symbol.path).map(|lines| &lines.old),
        symbol.start_line,
        symbol.end_line,
    );
    (!touched.is_empty()).then(|| PatchTouchedSymbol {
        fqn: symbol.fqn.clone(),
        name: symbol.name.clone(),
        kind: symbol.kind.clone(),
        signature: symbol.signature.clone(),
        path: symbol.path.clone(),
        start_line: symbol.start_line,
        end_line: symbol.end_line,
        language: symbol.language.clone(),
        is_test: symbol.is_test,
        touched_old_lines: touched,
        touched_new_lines: Vec::new(),
        change_reason: "old_hunk_overlap".to_string(),
    })
}

fn postimage_touched_symbol(
    symbol: &CommitSymbol,
    changed_lines: &BTreeMap<String, ChangedLines>,
) -> Option<PatchTouchedSymbol> {
    let touched = touched_lines(
        changed_lines.get(&symbol.path).map(|lines| &lines.new),
        symbol.start_line,
        symbol.end_line,
    );
    (!touched.is_empty()).then(|| PatchTouchedSymbol {
        fqn: symbol.fqn.clone(),
        name: symbol.name.clone(),
        kind: symbol.kind.clone(),
        signature: symbol.signature.clone(),
        path: symbol.path.clone(),
        start_line: symbol.start_line,
        end_line: symbol.end_line,
        language: symbol.language.clone(),
        is_test: symbol.is_test,
        touched_old_lines: Vec::new(),
        touched_new_lines: touched,
        change_reason: "new_hunk_overlap".to_string(),
    })
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
    analyzer.import_statements_of(&file).into_iter().collect()
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

fn sort_patch_symbols(symbols: &mut [PatchTouchedSymbol]) {
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
        Delta::Added => "added",
        Delta::Deleted => "deleted",
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
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .filter(|language| *language != Language::None)
        .map(|language| format!("{language:?}").to_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

fn kind_name(kind: CodeUnitType) -> &'static str {
    kind.display_lowercase()
}

fn is_test_like_path(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path.split('/')
        .any(|segment| matches!(segment, "test" | "tests" | "__tests__" | "spec" | "specs"))
        || PathBuf::from(&path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(|stem| {
                stem.ends_with("_test")
                    || stem.ends_with("test")
                    || stem.ends_with("_spec")
                    || stem.ends_with("spec")
            })
            .unwrap_or(false)
}
