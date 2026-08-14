//! Git plumbing for the semantic content cache.
//!
//! The analyzer cache identifies the exact bytes that tree-sitter parsed. The
//! semantic cache has a different contract: clean tracked files use the Git
//! index OID without a content read. Dirty and untracked files use the OID of
//! their working bytes. Paths with a content-changing Git attribute also use
//! their working bytes, even when Git reports them as clean.

use std::collections::{HashMap, HashSet};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use git2::{
    AttrCheckFlags, AttrValue, Config, DiffOptions, ErrorCode, Index, ObjectType, Oid, Repository,
};
use growable_bloom_filter::GrowableBloom;

type Result<T> = std::result::Result<T, String>;

pub fn discover(root: &Path) -> Option<Repository> {
    brokk_bifrost_analysis::gitblob::discover(root)
}

pub fn is_git_repo(root: &Path) -> bool {
    brokk_bifrost_analysis::gitblob::is_git_repo(root)
}

pub fn working_tree_oids(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    let started = Instant::now();
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?;
    let mut index = repo.index().map_err(|err| err.to_string())?;
    // Bifrost keeps this repository open while another process can run Git.
    // Reload the index so newly staged content gets its current index OID.
    index.read(true).map_err(|err| err.to_string())?;
    let dirty = dirty_worktree_paths(repo, &index, None)?;
    let index_oids: HashMap<String, Oid> = index
        .iter()
        .map(|entry| {
            let path = String::from_utf8(entry.path).map_err(|err| {
                format!("non-UTF-8 git index path while building semantic cache: {err}")
            })?;
            Ok((path, entry.id))
        })
        .collect::<Result<_>>()?;
    let mut transforms = ContentTransformProbe::new(repo, &index, workdir);
    // Only a clean tracked path can serve an index OID, so only such a path
    // needs an attribute verdict. Ask about all of them at once.
    let clean_tracked: Vec<&str> = rel_paths
        .iter()
        .filter(|rel| !dirty.contains(*rel) && index_oids.contains_key(*rel))
        .map(String::as_str)
        .collect();
    let transformed = transforms.resolve(&clean_tracked)?;
    let mut out = HashMap::with_capacity(rel_paths.len());
    let mut hashed = 0usize;
    for rel in rel_paths {
        let use_worktree =
            dirty.contains(rel) || !index_oids.contains_key(rel) || transformed.contains(rel);
        let oid = if use_worktree {
            hashed += 1;
            hash_working_file(workdir, rel)?
        } else {
            *index_oids
                .get(rel)
                .expect("tracked clean semantic path has an index OID")
        };
        out.insert(rel.clone(), oid.to_string());
    }
    eprintln!(
        "bifrost semantic identities: files={}; index={}; hashed={hashed}; attr_paths={}; attr_lookups={}; time={:?}",
        rel_paths.len(),
        rel_paths.len() - hashed,
        transforms.asked,
        transforms.lookups,
        started.elapsed()
    );
    Ok(out)
}

pub fn working_tree_oids_targeted(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    let started = Instant::now();
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?;
    let mut index = repo.index().map_err(|err| err.to_string())?;
    // Watcher updates also run after external Git commands on a long-lived repo.
    index.read(true).map_err(|err| err.to_string())?;
    let dirty = dirty_worktree_paths(repo, &index, Some(rel_paths))?;
    let mut transforms = ContentTransformProbe::new(repo, &index, workdir);
    let clean_tracked: Vec<&str> = rel_paths
        .iter()
        .filter(|rel| !dirty.contains(*rel) && index.get_path(Path::new(rel.as_str()), 0).is_some())
        .map(String::as_str)
        .collect();
    let transformed = transforms.resolve(&clean_tracked)?;
    let mut out = HashMap::with_capacity(rel_paths.len());
    let mut hashed = 0usize;
    for rel in rel_paths {
        let path = Path::new(rel);
        let entry = index.get_path(path, 0);
        let use_worktree = dirty.contains(rel) || entry.is_none() || transformed.contains(rel);
        let oid = if use_worktree {
            hashed += 1;
            hash_working_file(workdir, rel)?
        } else {
            entry
                .expect("tracked clean semantic path has an index OID")
                .id
        };
        out.insert(rel.clone(), oid.to_string());
    }
    eprintln!(
        "bifrost semantic watcher identities: files={}; index={}; hashed={hashed}; attr_paths={}; attr_lookups={}; time={:?}",
        rel_paths.len(),
        rel_paths.len() - hashed,
        transforms.asked,
        transforms.lookups,
        started.elapsed()
    );
    Ok(out)
}

fn dirty_worktree_paths(
    repo: &Repository,
    index: &Index,
    rel_paths: Option<&[String]>,
) -> Result<HashSet<String>> {
    // A targeted request with no paths asks about nothing, so nothing can be
    // dirty. libgit2 treats a diff with no pathspec as match-all, so building
    // the diff anyway walks the whole worktree to answer that empty question.
    if rel_paths.is_some_and(|paths| paths.is_empty()) {
        return Ok(HashSet::new());
    }

    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_typechange(true)
        .ignore_submodules(true)
        .skip_binary_check(true);
    if let Some(paths) = rel_paths {
        options.disable_pathspec_match(true);
        for path in paths {
            options.pathspec(path);
        }
    }

    let diff = repo
        .diff_index_to_workdir(Some(index), Some(&mut options))
        .map_err(|err| err.to_string())?;
    let mut dirty = HashSet::new();
    for delta in diff.deltas() {
        if let Some(path) = delta.old_file().path() {
            dirty.insert(path.to_string_lossy().into_owned());
        }
        if let Some(path) = delta.new_file().path() {
            dirty.insert(path.to_string_lossy().into_owned());
        }
    }
    Ok(dirty)
}

/// The attributes that let Git show worktree bytes which differ from the index
/// blob. A path carries a content transform when any of them is set to anything
/// other than unspecified or unset.
const CONTENT_TRANSFORM_ATTRIBUTES: [&str; 3] = ["filter", "ident", "working-tree-encoding"];

/// Answers whether Git can show worktree bytes that differ from the index blob
/// for a path, which is true when `filter`, `ident` or `working-tree-encoding`
/// is set on it.
///
/// The probe answers a whole walk at once, in two stages.
///
/// First it drops the paths that no rule can reach. Git reads these attributes
/// from a fixed set of sources: the system attributes file, `core.attributesFile`
/// or its XDG default, `$GIT_DIR/info/attributes`, and a `.gitattributes` file in
/// each directory from the worktree root down to the path, taken from the
/// worktree or, when it is absent there, from the index. No source above a path
/// means no rule and no macro can match it, so nothing is asked about it and no
/// subprocess runs for a repository that has no attribute file at all.
///
/// The paths that survive go to one `git check-attr --stdin -z` process. libgit2
/// has no attribute session here, so it re-reads every attribute source on each
/// of the up-to-three lookups it does per path: it answers Firefox's 1,205,412
/// questions in 55.3 s of CPU where this batch answers the same 401,804 paths in
/// 4.4 s (issue #1904). The CLI is the same escape `gitblob` already takes for
/// `git rev-list` and `git worktree list`. It reads the same sources in the same
/// order -- its default check-in direction is file-then-index, which is what
/// `AttrCheckFlags::FILE_THEN_INDEX` asks libgit2 for -- and it expands macros,
/// so the verdicts agree.
///
/// When the CLI is absent or fails for any reason, libgit2 answers the same
/// paths per path. Correctness never depends on the subprocess.
///
/// The cached verdicts describe files on disk and in the index, so an instance
/// is valid for one identity walk.
struct ContentTransformProbe<'a> {
    repo: &'a Repository,
    index: &'a Index,
    workdir: &'a Path,
    /// Program asked for the batched verdicts. Production always uses `git` from
    /// `PATH`; the fallback test points this at a name that cannot spawn.
    git_program: &'a str,
    /// A source outside the directory chain exists, so every path needs a verdict.
    repository_wide_rules: bool,
    /// `.gitattributes` presence for each directory already inspected, keyed by
    /// its worktree-relative path.
    directories: HashMap<PathBuf, bool>,
    /// Paths that reached an attribute answerer, whichever one answered.
    asked: usize,
    /// Attribute lookups handed to libgit2, which is three per answered path.
    /// Zero whenever the batch answered. Reported in the walk's timing line and
    /// asserted by the tests that pin the skipped and batched cases.
    lookups: usize,
}

impl<'a> ContentTransformProbe<'a> {
    fn new(repo: &'a Repository, index: &'a Index, workdir: &'a Path) -> Self {
        Self {
            repo,
            index,
            workdir,
            git_program: "git",
            repository_wide_rules: has_repository_wide_attribute_rules(repo),
            directories: HashMap::new(),
            asked: 0,
            lookups: 0,
        }
    }

    /// The subset of `paths` whose worktree bytes Git can transform.
    fn resolve(&mut self, paths: &[&str]) -> Result<HashSet<String>> {
        let candidates: Vec<&str> = paths
            .iter()
            .copied()
            .filter(|path| self.has_rules_above(Path::new(path)))
            .collect();
        self.asked += candidates.len();
        if candidates.is_empty() {
            return Ok(HashSet::new());
        }
        match batched_transform_verdicts(self.git_program, self.workdir, &candidates) {
            Ok(transformed) => Ok(transformed),
            Err(error) => {
                eprintln!(
                    "bifrost semantic identities: batched git check-attr unavailable ({error}); \
                     asking libgit2 about {} paths",
                    candidates.len()
                );
                let mut transformed = HashSet::new();
                for path in candidates {
                    if self.libgit2_verdict(Path::new(path))? {
                        transformed.insert(path.to_string());
                    }
                }
                Ok(transformed)
            }
        }
    }

    fn libgit2_verdict(&mut self, path: &Path) -> Result<bool> {
        for name in CONTENT_TRANSFORM_ATTRIBUTES {
            self.lookups += 1;
            let value = self
                .repo
                .get_attr(path, name, AttrCheckFlags::FILE_THEN_INDEX)
                .map_err(|err| {
                    format!("reading Git attribute {name} for {}: {err}", path.display())
                })?;
            if !matches!(
                AttrValue::from_string(value),
                AttrValue::False | AttrValue::Unspecified
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn has_rules_above(&mut self, path: &Path) -> bool {
        if self.repository_wide_rules {
            return true;
        }
        let mut directory = path.parent();
        while let Some(current) = directory {
            if self.directory_has_attributes(current) {
                return true;
            }
            directory = current.parent();
        }
        false
    }

    fn directory_has_attributes(&mut self, directory: &Path) -> bool {
        if let Some(present) = self.directories.get(directory) {
            return *present;
        }
        // FILE_THEN_INDEX reads the worktree copy first and the index copy when
        // the worktree has none, so either presence makes the rules reachable.
        let candidate = directory.join(".gitattributes");
        let present =
            self.workdir.join(&candidate).is_file() || self.index.get_path(&candidate, 0).is_some();
        self.directories.insert(directory.to_path_buf(), present);
        present
    }
}

/// Ask one `git check-attr` process about every candidate path and return the
/// paths that carry a content transform.
///
/// `-z` makes both directions NUL-delimited, so a path that holds a quote, a
/// space or a newline needs no escaping and comes back byte for byte. Git
/// answers three `<path> NUL <attribute> NUL <value> NUL` records per path, in
/// the order it was asked, where the value is `unspecified`, `unset`, `set` or
/// the attribute's string value.
///
/// Any failure is returned to the caller, which falls back to libgit2.
fn batched_transform_verdicts(
    git_program: &str,
    workdir: &Path,
    paths: &[&str],
) -> Result<HashSet<String>> {
    let mut child = Command::new(git_program)
        .current_dir(workdir)
        .args(["check-attr", "--stdin", "-z"])
        .args(CONTENT_TRANSFORM_ATTRIBUTES)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("git check-attr failed to spawn: {err}"))?;
    let stdin = child.stdin.take().expect("git check-attr stdin is piped");
    let mut stdout = child.stdout.take().expect("git check-attr stdout is piped");

    // Git answers while it reads, so writing every path before reading fills the
    // output pipe and deadlocks. Write from a scoped thread and read here. The
    // identity walk owns its thread, so nothing in a worker pool waits on this.
    let (read, written) = std::thread::scope(|scope| {
        let writer = scope.spawn(|| -> std::io::Result<()> {
            let mut stdin = BufWriter::new(stdin);
            for path in paths {
                stdin.write_all(path.as_bytes())?;
                stdin.write_all(b"\0")?;
            }
            stdin.flush()
        });
        let mut output = Vec::new();
        let read = stdout.read_to_end(&mut output).map(|_| output);
        let written = writer
            .join()
            .expect("git check-attr writer thread panicked");
        (read, written)
    });
    let output = read.map_err(|err| format!("reading git check-attr output: {err}"))?;
    written.map_err(|err| format!("writing paths to git check-attr: {err}"))?;
    let status = child
        .wait()
        .map_err(|err| format!("git check-attr wait failed: {err}"))?;
    if !status.success() {
        return Err(format!("git check-attr exited with {status}"));
    }

    let mut fields: Vec<&[u8]> = output.split(|byte| *byte == 0).collect();
    // The final record ends with the delimiter, so the split leaves a tail.
    if fields.last().is_some_and(|last| last.is_empty()) {
        fields.pop();
    }
    // One record per attribute per path, three fields in each record.
    let expected = paths.len() * CONTENT_TRANSFORM_ATTRIBUTES.len() * 3;
    if fields.len() != expected {
        return Err(format!(
            "git check-attr answered {} fields for {} paths, expected {expected}",
            fields.len(),
            paths.len()
        ));
    }

    let mut unanswered: HashSet<&str> = paths.iter().copied().collect();
    let mut transformed = HashSet::new();
    for record in fields.chunks_exact(3) {
        let path = std::str::from_utf8(record[0])
            .map_err(|err| format!("non-UTF-8 path in git check-attr output: {err}"))?;
        unanswered.remove(path);
        if !matches!(record[2], b"unspecified" | b"unset") {
            transformed.insert(path.to_string());
        }
    }
    if !unanswered.is_empty() {
        return Err(format!("git check-attr did not answer for {unanswered:?}"));
    }
    Ok(transformed)
}

/// Whether an attribute file that can carry a rule or a macro for any path in
/// `repo` exists.
///
/// These are the sources outside the worktree's directory chain, in libgit2's
/// own order: the system file, `core.attributesFile` or its XDG default, and
/// `$GIT_DIR/info/attributes`. A source that cannot be resolved counts as
/// present, so the probe keeps its per-path behavior instead of skipping a rule
/// it could not rule out.
fn has_repository_wide_attribute_rules(repo: &Repository) -> bool {
    let mut files = vec![
        // A linked worktree keeps `info` in the common directory.
        repo.path().join("info").join("attributes"),
        repo.commondir().join("info").join("attributes"),
    ];
    // libgit2 finds the system attributes file beside the system config file.
    if let Ok(system_config) = Config::find_system()
        && let Some(directory) = system_config.parent()
    {
        files.push(directory.join("gitattributes"));
    }
    if cfg!(unix) {
        files.push(PathBuf::from("/etc/gitattributes"));
    }
    let Ok(config) = repo.config() else {
        return true;
    };
    match config.get_path("core.attributesFile") {
        Ok(configured) => files.push(configured),
        // libgit2 falls back to the XDG location when the key is unset.
        Err(error) if error.code() == ErrorCode::NotFound => files.extend(xdg_attributes_file()),
        Err(_) => return true,
    }
    files.iter().any(|file| file.exists())
}

fn xdg_attributes_file() -> Option<PathBuf> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })?;
    Some(config_home.join("git").join("attributes"))
}

fn hash_working_file(workdir: &Path, rel: &str) -> Result<Oid> {
    Oid::hash_file(ObjectType::Blob, workdir.join(rel)).map_err(|err| err.to_string())
}

pub fn read_blob(repo: &Repository, oid_hex: &str) -> Result<Vec<u8>> {
    brokk_bifrost_analysis::gitblob::read_blob(repo, oid_hex)
}

pub fn reachable_bloom(repo: &Repository) -> Result<GrowableBloom> {
    brokk_bifrost_analysis::gitblob::reachable_bloom(repo)
}

pub fn worktree_roots(repo: &Repository) -> Result<Vec<PathBuf>> {
    brokk_bifrost_analysis::gitblob::worktree_roots(repo)
}

pub fn uncommitted_oids(root: &Path) -> Result<HashSet<String>> {
    brokk_bifrost_analysis::gitblob::uncommitted_oids(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn run_git<const N: usize>(root: &Path, args: [&str; N]) {
        let status = Command::new("git")
            .current_dir(root)
            .args(["-c", "commit.gpgSign=false"])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_repo() -> (tempfile::TempDir, Repository) {
        let temp = tempfile::tempdir().unwrap();
        run_git(temp.path(), ["init"]);
        run_git(temp.path(), ["config", "user.email", "test@example.com"]);
        run_git(temp.path(), ["config", "user.name", "Test"]);
        // Repository scope wins over the host's global and system config, so
        // the attribute-source checks see the same absent file everywhere.
        run_git(
            temp.path(),
            ["config", "core.attributesFile", "missing-attributes"],
        );
        std::fs::write(temp.path().join("tracked.rs"), "fn first() {}\n").unwrap();
        run_git(temp.path(), ["add", "tracked.rs"]);
        run_git(temp.path(), ["commit", "-m", "initial"]);
        let repo = Repository::open(temp.path()).unwrap();
        (temp, repo)
    }

    #[test]
    fn clean_and_staged_files_use_the_current_index_oid() {
        let (temp, repo) = init_repo();
        let path = "tracked.rs".to_string();
        let index_oid = repo
            .index()
            .unwrap()
            .get_path(Path::new(&path), 0)
            .unwrap()
            .id;
        assert_eq!(
            working_tree_oids(&repo, std::slice::from_ref(&path)).unwrap()[&path],
            index_oid.to_string()
        );

        std::fs::write(temp.path().join(&path), "fn staged() {}\n").unwrap();
        run_git(temp.path(), ["add", "tracked.rs"]);
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        let staged_oid = index.get_path(Path::new(&path), 0).unwrap().id;
        assert_eq!(
            working_tree_oids_targeted(&repo, std::slice::from_ref(&path)).unwrap()[&path],
            staged_oid.to_string()
        );
    }

    #[test]
    fn dirty_and_untracked_files_use_working_byte_oids() {
        let (temp, repo) = init_repo();
        std::fs::write(temp.path().join("tracked.rs"), "fn dirty() {}\n").unwrap();
        std::fs::write(temp.path().join("new.rs"), "fn new_file() {}\n").unwrap();
        let paths = ["tracked.rs".to_string(), "new.rs".to_string()];
        let resolved = working_tree_oids(&repo, &paths).unwrap();

        for path in paths {
            assert_eq!(
                resolved[&path],
                Oid::hash_file(ObjectType::Blob, temp.path().join(path))
                    .unwrap()
                    .to_string()
            );
        }
    }

    #[test]
    fn an_empty_targeted_request_does_not_diff_the_worktree() {
        let (temp, repo) = init_repo();
        std::fs::write(temp.path().join("tracked.rs"), "fn dirty() {}\n").unwrap();
        let index = repo.index().unwrap();

        // The whole-worktree form finds the edit. The targeted form asked about
        // no path, so it must report no dirty path and must not walk the tree.
        assert!(
            dirty_worktree_paths(&repo, &index, None)
                .unwrap()
                .contains("tracked.rs")
        );
        assert!(
            dirty_worktree_paths(&repo, &index, Some(&[]))
                .unwrap()
                .is_empty()
        );
        assert!(working_tree_oids_targeted(&repo, &[]).unwrap().is_empty());
    }

    #[test]
    fn a_repository_without_attribute_files_asks_nothing() {
        let (_temp, repo) = init_repo();
        let index = repo.index().unwrap();
        let mut transforms = ContentTransformProbe::new(&repo, &index, repo.workdir().unwrap());

        assert!(transforms.resolve(&["tracked.rs"]).unwrap().is_empty());
        assert_eq!(transforms.asked, 0);
        assert_eq!(transforms.lookups, 0);
    }

    #[test]
    fn only_paths_under_a_gitattributes_file_are_asked_about() {
        let (temp, repo) = init_repo();
        std::fs::create_dir(temp.path().join("sub")).unwrap();
        std::fs::write(temp.path().join("sub/.gitattributes"), "*.rs filter=fake\n").unwrap();
        std::fs::write(temp.path().join("sub/nested.rs"), "fn nested() {}\n").unwrap();
        let index = repo.index().unwrap();
        let mut transforms = ContentTransformProbe::new(&repo, &index, repo.workdir().unwrap());

        let transformed = transforms
            .resolve(&["sub/nested.rs", "tracked.rs"])
            .unwrap();
        assert_eq!(
            transformed,
            HashSet::from(["sub/nested.rs".to_string()]),
            "only the path under the rule is transformed"
        );
        assert_eq!(
            transforms.asked, 1,
            "the path with no rule above it is dropped"
        );
    }

    #[test]
    fn a_gitattributes_file_only_in_the_index_is_still_a_source() {
        let (temp, repo) = init_repo();
        std::fs::write(temp.path().join(".gitattributes"), "*.rs ident\n").unwrap();
        run_git(temp.path(), ["add", ".gitattributes"]);
        std::fs::remove_file(temp.path().join(".gitattributes")).unwrap();
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        let mut transforms = ContentTransformProbe::new(&repo, &index, repo.workdir().unwrap());

        assert_eq!(
            transforms.resolve(&["tracked.rs"]).unwrap(),
            HashSet::from(["tracked.rs".to_string()])
        );
        assert_eq!(transforms.asked, 1);
    }

    /// A repository whose root `.gitattributes` sets attributes that no content
    /// transform uses -- the shape of llvm, gcc and firefox. Every path has a
    /// source above it, so the directory-chain short-circuit cannot help and the
    /// batch has to answer all of them without a single libgit2 lookup.
    #[test]
    fn a_root_gitattributes_file_is_answered_in_one_batch() {
        let (temp, repo) = init_repo();
        std::fs::write(
            temp.path().join(".gitattributes"),
            "* -text\n*.ident ident\n",
        )
        .unwrap();
        std::fs::write(temp.path().join("keeps.ident"), "$Id$\n").unwrap();
        run_git(temp.path(), ["add", ".gitattributes", "keeps.ident"]);
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        let mut transforms = ContentTransformProbe::new(&repo, &index, repo.workdir().unwrap());

        let transformed = transforms
            .resolve(&["tracked.rs", "keeps.ident", ".gitattributes"])
            .unwrap();
        assert_eq!(
            transformed,
            HashSet::from(["keeps.ident".to_string()]),
            "-text is not a content transform; ident is"
        );
        assert_eq!(
            transforms.asked, 3,
            "the root file puts a rule above every path"
        );
        assert_eq!(
            transforms.lookups, 0,
            "the batch answered, so libgit2 was never asked"
        );
    }

    #[test]
    fn libgit2_answers_the_same_paths_when_the_git_cli_cannot_run() {
        let (temp, repo) = init_repo();
        std::fs::write(
            temp.path().join(".gitattributes"),
            "* -text\n*.ident ident\n",
        )
        .unwrap();
        std::fs::write(temp.path().join("keeps.ident"), "$Id$\n").unwrap();
        run_git(temp.path(), ["add", ".gitattributes", "keeps.ident"]);
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        let paths = ["tracked.rs", "keeps.ident", ".gitattributes"];

        let mut batched = ContentTransformProbe::new(&repo, &index, repo.workdir().unwrap());
        let mut fallback = ContentTransformProbe::new(&repo, &index, repo.workdir().unwrap());
        fallback.git_program = "bifrost-no-such-git-binary";

        assert_eq!(
            fallback.resolve(&paths).unwrap(),
            batched.resolve(&paths).unwrap()
        );
        assert_eq!(
            batched.lookups, 0,
            "the batch answers without a libgit2 lookup"
        );
        // Three lookups each for `tracked.rs` and `.gitattributes`, and two for
        // `keeps.ident`, where the second attribute is the set one.
        assert_eq!(fallback.lookups, 8);
    }

    /// `-z` delimits with NUL, so a path that needs quoting in Git's default
    /// output comes back byte for byte.
    #[test]
    fn a_path_that_needs_escaping_survives_the_batch() {
        let (temp, repo) = init_repo();
        // Windows rejects a quote in a filename; a space exercises the same
        // quoting in Git's non-`-z` output.
        let awkward = if cfg!(windows) {
            "od d.ident"
        } else {
            "od\" d.ident"
        };
        std::fs::write(temp.path().join(".gitattributes"), "*.ident ident\n").unwrap();
        std::fs::write(temp.path().join(awkward), "$Id$\n").unwrap();
        run_git(temp.path(), ["add", "-A"]);
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        let mut transforms = ContentTransformProbe::new(&repo, &index, repo.workdir().unwrap());

        assert_eq!(
            transforms.resolve(&[awkward, "tracked.rs"]).unwrap(),
            HashSet::from([awkward.to_string()])
        );
        assert_eq!(transforms.lookups, 0);
    }

    #[test]
    fn ident_attributes_use_the_transformed_working_bytes() {
        let (temp, repo) = init_repo();
        std::fs::write(temp.path().join(".gitattributes"), "ident.txt ident\n").unwrap();
        std::fs::write(temp.path().join("ident.txt"), "$Id$\n").unwrap();
        run_git(temp.path(), ["add", ".gitattributes", "ident.txt"]);
        run_git(temp.path(), ["commit", "-m", "ident"]);
        std::fs::remove_file(temp.path().join("ident.txt")).unwrap();
        run_git(temp.path(), ["checkout", "--", "ident.txt"]);

        let path = "ident.txt".to_string();
        let index_oid = repo
            .index()
            .unwrap()
            .get_path(Path::new(&path), 0)
            .unwrap()
            .id;
        let working_oid = Oid::hash_file(ObjectType::Blob, temp.path().join(&path)).unwrap();
        assert_ne!(working_oid, index_oid);
        assert_eq!(
            working_tree_oids(&repo, std::slice::from_ref(&path)).unwrap()[&path],
            working_oid.to_string()
        );
    }
}
