use git2::{ObjectType, Repository};
use std::path::{Component, Path, PathBuf};

pub fn parse_rev_path(input: &str) -> Option<(&str, &str)> {
    let (rev, path) = input.split_once(':')?;
    if rev.is_empty() || path.is_empty() {
        return None;
    }
    if crate::path_utils::is_windows_absolute_path(input) {
        return None;
    }
    Some((rev, path))
}

pub fn resolve_git_file_path(path: &str, workspace_root: &Path) -> PathBuf {
    let path = path.trim();
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return normalize_path_lexically(PathBuf::from(home).join(rest));
    }

    let raw = Path::new(path);
    if raw.is_absolute() {
        normalize_path_lexically(raw.to_path_buf())
    } else {
        normalize_path_lexically(workspace_root.join(raw))
    }
}

/// Discovers the git repository containing `abs_path` and computes the
/// repository-relative path used to look it up inside a revision tree. Shared
/// by [`read_git_file`] and [`git_history_path_is_file`] so both consult the
/// same repo-discovery/canonicalization rules.
fn discover_history_repo_relative_path(abs_path: &Path) -> Result<(Repository, PathBuf), String> {
    if !abs_path.is_absolute() {
        return Err(format!(
            "git history path must be absolute after resolution: {}",
            abs_path.display()
        ));
    }

    let discover_from = nearest_existing_ancestor(abs_path).ok_or_else(|| {
        format!(
            "path is not in any git repository because no existing ancestor could be found: {}",
            abs_path.display()
        )
    })?;
    let repo = Repository::discover(&discover_from).map_err(|err| {
        format!(
            "path is not in any git repository: {} ({err})",
            abs_path.display()
        )
    })?;
    let workdir = repo.workdir().ok_or_else(|| {
        format!(
            "git repository has no working tree: {}",
            repo.path().display()
        )
    })?;

    let canonical_workdir = workdir.canonicalize().map_err(|err| {
        format!(
            "unable to canonicalize git workdir {}: {err}",
            workdir.display()
        )
    })?;
    let canonical_abs = canonicalize_allow_missing(abs_path)?;
    let repo_rel = canonical_abs
        .strip_prefix(&canonical_workdir)
        .map_err(|_| {
            format!(
                "path is outside discovered git workdir: {} (workdir: {})",
                abs_path.display(),
                canonical_workdir.display()
            )
        })?
        .to_path_buf();
    Ok((repo, repo_rel))
}

/// Structured existence probe for the `#`-split boundary search in
/// `split_git_history_source_selector` (bifrost#1216): a committed filename
/// may itself contain `#` (e.g. `Foo.VerifyGeneratedCode#01.verified.cs`), so
/// the CLI selector parser walks candidate anchors and needs to know which
/// ones actually name a blob at `rev`. Unlike [`read_git_file`] this never
/// reads blob content and never errors — any failure to discover the repo,
/// resolve the revision, or find the path simply means "not a file", which is
/// exactly what the caller needs to move on to the next candidate.
pub fn git_history_path_is_file(rev: &str, abs_path: &Path) -> bool {
    let Ok((repo, repo_rel)) = discover_history_repo_relative_path(abs_path) else {
        return false;
    };
    let Ok(object) = repo.revparse_single(rev) else {
        return false;
    };
    let Ok(commit) = object.peel_to_commit() else {
        return false;
    };
    let Ok(tree) = commit.tree() else {
        return false;
    };
    matches!(
        tree.get_path(&repo_rel).ok().and_then(|entry| entry.kind()),
        Some(ObjectType::Blob)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitFileBytes {
    content: Vec<u8>,
    binary: bool,
    repo_relative_path: PathBuf,
}

impl GitFileBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.content
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.content
    }

    pub const fn is_binary(&self) -> bool {
        self.binary
    }

    pub fn repo_relative_path(&self) -> &Path {
        &self.repo_relative_path
    }
}

/// Read the exact bytes of a file at a Git revision.
///
/// Analyzer ingestion uses this byte-preserving API before deciding whether a
/// source projection is safe. Text-oriented history tools should continue to
/// call [`read_git_file`], which deliberately rejects binary blobs.
pub fn read_git_file_bytes(rev: &str, abs_path: &Path) -> Result<GitFileBytes, String> {
    let (repo, repo_rel) = discover_history_repo_relative_path(abs_path)?;

    let object = repo
        .revparse_single(rev)
        .map_err(|err| format!("bad git revision `{rev}`: {err}"))?;
    let commit = object
        .peel_to_commit()
        .map_err(|err| format!("git revision `{rev}` is not a commit: {err}"))?;
    let tree = commit
        .tree()
        .map_err(|err| format!("unable to read tree for git revision `{rev}`: {err}"))?;
    let entry = tree.get_path(&repo_rel).map_err(|err| {
        format!(
            "path `{}` is absent at git revision `{rev}`: {err}",
            repo_rel.display()
        )
    })?;
    if entry.kind() != Some(ObjectType::Blob) {
        return Err(format!(
            "path `{}` at git revision `{rev}` is not a file blob",
            repo_rel.display()
        ));
    }
    let blob = repo.find_blob(entry.id()).map_err(|err| {
        format!(
            "unable to read blob `{}` at git revision `{rev}`: {err}",
            repo_rel.display()
        )
    })?;
    Ok(GitFileBytes {
        content: blob.content().to_vec(),
        binary: blob.is_binary(),
        repo_relative_path: repo_rel,
    })
}

pub fn read_git_file(rev: &str, abs_path: &Path) -> Result<String, String> {
    let blob = read_git_file_bytes(rev, abs_path)?;
    if blob.is_binary() {
        return Err(format!(
            "path `{}` at git revision `{rev}` is binary and cannot be returned as text",
            blob.repo_relative_path().display()
        ));
    }
    // Non-UTF8 text (legacy encodings like Windows-1252/GBK) passes the binary
    // check above; convert lossily so pinned-revision reads tolerate the same
    // files a live session does instead of failing session startup.
    Ok(String::from_utf8_lossy(blob.as_bytes()).into_owned())
}

pub fn list_git_files_at_revision(
    workspace_root: &Path,
    rev: &str,
) -> Result<Vec<PathBuf>, String> {
    let canonical_root = workspace_root.canonicalize().map_err(|err| {
        format!(
            "unable to canonicalize workspace root {}: {err}",
            workspace_root.display()
        )
    })?;
    let repo = Repository::discover(&canonical_root).map_err(|err| {
        format!(
            "workspace root is not in any git repository: {} ({err})",
            workspace_root.display()
        )
    })?;
    let workdir = repo.workdir().ok_or_else(|| {
        format!(
            "git repository has no working tree: {}",
            repo.path().display()
        )
    })?;
    let canonical_workdir = workdir.canonicalize().map_err(|err| {
        format!(
            "unable to canonicalize git workdir {}: {err}",
            workdir.display()
        )
    })?;
    let workspace_repo_rel = canonical_root
        .strip_prefix(&canonical_workdir)
        .map_err(|_| {
            format!(
                "workspace root is outside discovered git workdir: {} (workdir: {})",
                workspace_root.display(),
                canonical_workdir.display()
            )
        })?;

    let object = repo
        .revparse_single(rev)
        .map_err(|err| format!("bad git revision `{rev}`: {err}"))?;
    let commit = object
        .peel_to_commit()
        .map_err(|err| format!("git revision `{rev}` is not a commit: {err}"))?;
    let tree = commit
        .tree()
        .map_err(|err| format!("unable to read tree for git revision `{rev}`: {err}"))?;

    let root_tree = if workspace_repo_rel.as_os_str().is_empty() {
        tree
    } else {
        let entry = tree.get_path(workspace_repo_rel).map_err(|err| {
            format!(
                "workspace root `{}` is absent at git revision `{rev}`: {err}",
                workspace_repo_rel.display()
            )
        })?;
        if entry.kind() != Some(ObjectType::Tree) {
            return Err(format!(
                "workspace root `{}` at git revision `{rev}` is not a tree",
                workspace_repo_rel.display()
            ));
        }
        repo.find_tree(entry.id()).map_err(|err| {
            format!(
                "unable to read workspace tree `{}` at git revision `{rev}`: {err}",
                workspace_repo_rel.display()
            )
        })?
    };

    let mut files = Vec::new();
    let mut stack = vec![(PathBuf::new(), root_tree)];
    while let Some((prefix, tree)) = stack.pop() {
        for entry in &tree {
            let Some(name) = entry.name() else {
                continue;
            };
            let rel = prefix.join(name);
            match entry.kind() {
                Some(ObjectType::Blob) => files.push(rel),
                Some(ObjectType::Tree) => {
                    let child = repo.find_tree(entry.id()).map_err(|err| {
                        format!(
                            "unable to read tree `{}` at git revision `{rev}`: {err}",
                            rel.display()
                        )
                    })?;
                    stack.push((rel, child));
                }
                _ => {}
            }
        }
    }
    files.sort();
    Ok(files)
}

fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    start
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .map(Path::to_path_buf)
}

fn canonicalize_allow_missing(path: &Path) -> Result<PathBuf, String> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }

    let existing = nearest_existing_ancestor(path).ok_or_else(|| {
        format!(
            "unable to canonicalize {} because no existing ancestor could be found",
            path.display()
        )
    })?;
    let canonical_existing = existing
        .canonicalize()
        .map_err(|err| format!("unable to canonicalize {}: {err}", existing.display()))?;
    let suffix = path.strip_prefix(&existing).map_err(|_| {
        format!(
            "unable to compute missing suffix for {} from {}",
            path.display(),
            existing.display()
        )
    })?;
    Ok(normalize_path_lexically(canonical_existing.join(suffix)))
}

fn normalize_path_lexically(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use git2::Signature;

    use super::{
        git_history_path_is_file, list_git_files_at_revision, parse_rev_path, read_git_file,
        read_git_file_bytes, resolve_git_file_path,
    };
    use crate::gitblob::test_repo::init_repo;

    fn commit(repo: &git2::Repository) -> String {
        let signature = Signature::now("T", "t@example.com").unwrap();
        crate::test_git_support::commit_all_with_deletions(repo, "fixture", &signature).to_string()
    }

    fn write(root: &Path, rel: &str, bytes: &[u8]) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn paths(rels: &[&str]) -> Vec<PathBuf> {
        rels.iter().map(PathBuf::from).collect()
    }

    /// The `rev:path` selector split must leave Windows drive paths alone and
    /// cut at the first colon only, so a committed name containing `:` survives.
    #[test]
    fn parse_rev_path_splits_at_the_first_colon_and_spares_drive_paths() {
        assert_eq!(
            parse_rev_path("HEAD~2:src/lib.rs"),
            Some(("HEAD~2", "src/lib.rs"))
        );
        assert_eq!(
            parse_rev_path("main:dir/a:b.txt"),
            Some(("main", "dir/a:b.txt"))
        );
        // A one-letter revision with a drive-absolute path is a path.
        assert_eq!(parse_rev_path("C:\\src\\lib.rs"), None);
        assert_eq!(parse_rev_path("C:/src/lib.rs"), None);
        // A drive-relative spelling is not drive-absolute, so it is a selector.
        assert_eq!(parse_rev_path("C:lib.rs"), Some(("C", "lib.rs")));
        for malformed in ["", "HEAD", ":path", "HEAD:", ":"] {
            assert_eq!(parse_rev_path(malformed), None, "accepted {malformed:?}");
        }
    }

    #[test]
    fn resolve_git_file_path_anchors_trims_and_normalizes() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();

        assert_eq!(
            resolve_git_file_path("  a/./b/../c.rs\n", root),
            root.join("a").join("c.rs"),
        );
        // `..` past the workspace root leaves the root: this is a resolver for
        // caller-chosen files, not a sandbox.
        let outside = root.parent().unwrap().join("sibling.rs");
        assert_eq!(resolve_git_file_path("../sibling.rs", root), outside);

        let absolute = root.join("x").join("..").join("y.rs");
        assert_eq!(
            resolve_git_file_path(absolute.to_str().unwrap(), Path::new("/unused-root")),
            root.join("y.rs"),
        );

        if let Some(home) = std::env::var_os("HOME") {
            let resolved = resolve_git_file_path("~/q/../r.rs", root);
            assert!(resolved.is_absolute(), "{resolved:?}");
            assert!(resolved.ends_with("r.rs"), "{resolved:?}");
            assert!(
                !resolved.starts_with(root),
                "{resolved:?} was workspace-relative"
            );
            assert!(
                resolved.starts_with(super::normalize_path_lexically(PathBuf::from(home))),
                "{resolved:?} is not under HOME",
            );
        }
    }

    /// Two commits in a real repository, read back through the same chain a
    /// `rev:path` selector takes: parse, resolve against the workspace, read.
    /// The fixture has a non-ASCII path, a path deleted between the commits
    /// (and from the working tree, so its absolute path is missing on disk), a
    /// binary blob, and a non-UTF-8 text blob.
    #[test]
    fn git_readers_agree_with_a_two_commit_repository() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let repo = init_repo(root);

        write(root, "src/lib.rs", b"v1\n");
        write(root, "caf\u{e9}/\u{4e2d}.txt", "unicode v1\n".as_bytes());
        write(root, "gone.txt", b"bye\n");
        write(root, "bin.dat", &[0, 1, 2, 0xff, 0]);
        write(root, "latin.txt", b"caf\xe9\n");
        let first = commit(&repo);

        write(root, "src/lib.rs", b"v2\n");
        fs::remove_file(root.join("gone.txt")).unwrap();
        write(root, "later/new.txt", b"new\n");
        let second = commit(&repo);

        let read = |rev: &str, rel: &str| read_git_file(rev, &root.join(rel));

        // Revision-selected content, through the selector pipeline.
        for (rev, expected) in [(&first, "v1\n"), (&second, "v2\n")] {
            let selector = format!("{rev}:src/lib.rs");
            let (parsed_rev, parsed_path) = parse_rev_path(&selector).unwrap();
            let abs = resolve_git_file_path(parsed_path, root);
            assert_eq!(read_git_file(parsed_rev, &abs).unwrap(), expected);
            assert!(git_history_path_is_file(parsed_rev, &abs));
        }
        assert_eq!(read("HEAD", "src/lib.rs").unwrap(), "v2\n");
        assert_eq!(read("HEAD~1", "src/lib.rs").unwrap(), "v1\n");
        assert!(read(&first, "caf\u{e9}/missing.txt").is_err());
        assert_eq!(
            read(&first, "caf\u{e9}/\u{4e2d}.txt").unwrap(),
            "unicode v1\n"
        );

        // A deleted file is readable where it existed and absent afterwards,
        // even though its working-tree path no longer exists.
        let gone = root.join("gone.txt");
        assert!(!gone.exists());
        assert_eq!(read(&first, "gone.txt").unwrap(), "bye\n");
        assert!(git_history_path_is_file(&first, &gone));
        let err = read(&second, "gone.txt").unwrap_err();
        assert!(err.contains("absent at git revision"), "{err}");
        assert!(!git_history_path_is_file(&second, &gone));

        // A file added by the second commit is absent from the first.
        assert!(read(&first, "later/new.txt").is_err());
        assert_eq!(read(&second, "later/new.txt").unwrap(), "new\n");

        // Bytes are preserved exactly; text reads convert lossily; binary
        // blobs are refused as text.
        let bytes = read_git_file_bytes(&first, &root.join("bin.dat")).unwrap();
        assert_eq!(bytes.as_bytes(), &[0, 1, 2, 0xff, 0]);
        assert!(bytes.is_binary());
        assert_eq!(bytes.repo_relative_path(), Path::new("bin.dat"));
        assert_eq!(bytes.into_bytes(), vec![0, 1, 2, 0xff, 0]);
        let err = read(&first, "bin.dat").unwrap_err();
        assert!(err.contains("is binary"), "{err}");
        let latin = read_git_file_bytes(&first, &root.join("latin.txt")).unwrap();
        assert!(!latin.is_binary());
        assert_eq!(latin.as_bytes(), b"caf\xe9\n");
        assert_eq!(read(&first, "latin.txt").unwrap(), "caf\u{fffd}\n");

        // Failure modes keep their distinct causes.
        let err = read("no-such-revision", "src/lib.rs").unwrap_err();
        assert!(err.contains("bad git revision"), "{err}");
        let err = read(&first, "src").unwrap_err();
        assert!(err.contains("is not a file blob"), "{err}");
        assert!(!git_history_path_is_file(&first, &root.join("src")));
        assert!(!git_history_path_is_file(
            "no-such-revision",
            &root.join("src/lib.rs")
        ));
        assert!(!git_history_path_is_file(
            &first,
            &root.join("never/existed.txt")
        ));
        let err = read_git_file("HEAD", Path::new("relative/lib.rs")).unwrap_err();
        assert!(err.contains("must be absolute"), "{err}");

        // Listing: whole-tree and subdirectory workspaces, per revision.
        assert_eq!(
            list_git_files_at_revision(root, &first).unwrap(),
            paths(&[
                "bin.dat",
                "caf\u{e9}/\u{4e2d}.txt",
                "gone.txt",
                "latin.txt",
                "src/lib.rs",
            ]),
        );
        assert_eq!(
            list_git_files_at_revision(root, &second).unwrap(),
            paths(&[
                "bin.dat",
                "caf\u{e9}/\u{4e2d}.txt",
                "later/new.txt",
                "latin.txt",
                "src/lib.rs",
            ]),
        );
        assert_eq!(
            list_git_files_at_revision(&root.join("src"), &second).unwrap(),
            paths(&["lib.rs"]),
        );
        let err = list_git_files_at_revision(&root.join("later"), &first).unwrap_err();
        assert!(err.contains("absent at git revision"), "{err}");
        let err = list_git_files_at_revision(&root.join("bin.dat"), &first).unwrap_err();
        assert!(err.contains("is not a tree"), "{err}");
        let err = list_git_files_at_revision(root, "no-such-revision").unwrap_err();
        assert!(err.contains("bad git revision"), "{err}");
        let err = list_git_files_at_revision(&root.join("missing-dir"), &first).unwrap_err();
        assert!(
            err.contains("unable to canonicalize workspace root"),
            "{err}"
        );
    }
}

/// Generative tests with independent oracles: a stack machine for lexical
/// normalization, the directory structure the test itself built for the
/// filesystem helpers, and the bytes the test itself committed for the readers.
#[cfg(test)]
mod git_file_properties {
    use std::path::{Component, PathBuf};

    use proptest::prelude::*;

    use super::{
        canonicalize_allow_missing, nearest_existing_ancestor, normalize_path_lexically,
        read_git_file_bytes,
    };

    fn join_tokens(root: &str, stack: &[String]) -> PathBuf {
        let mut path = PathBuf::from(root);
        path.extend(stack);
        path
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Lexical normalization against a stack machine: names push, `.` is
        /// skipped, and `..` pops, doing nothing at the root or on an empty
        /// relative path. The output is a fixed point holding no `.` or `..`.
        #[test]
        fn normalize_path_lexically_matches_a_stack_reference(
            anchored in any::<bool>(),
            tokens in prop::collection::vec(
                prop_oneof![
                    3 => "[a-z]{1,3}",
                    1 => Just(".".to_string()),
                    2 => Just("..".to_string()),
                ],
                0..10,
            ),
        ) {
            let mut stack: Vec<String> = Vec::new();
            for token in &tokens {
                match token.as_str() {
                    "." => {}
                    ".." => {
                        stack.pop();
                    }
                    name => stack.push(name.to_string()),
                }
            }
            let root = if anchored { "/" } else { "" };
            let input = join_tokens(root, &tokens);
            let normalized = normalize_path_lexically(input.clone());

            prop_assert_eq!(&normalized, &join_tokens(root, &stack), "input {:?}", input);
            prop_assert_eq!(normalize_path_lexically(normalized.clone()), normalized.clone());
            prop_assert!(
                normalized
                    .components()
                    .all(|c| !matches!(c, Component::CurDir | Component::ParentDir)),
                "dot component left in {normalized:?}",
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// On a directory tree the test built: the nearest existing ancestor
        /// of a missing path is the deepest directory that exists, and
        /// `canonicalize_allow_missing` is `canonicalize` of that directory
        /// joined with the missing tail. A fully existing path canonicalizes
        /// as `std` does.
        #[test]
        fn missing_tails_resolve_against_the_deepest_existing_directory(
            existing in prop::collection::vec("[a-z]{1,3}", 0..3),
            missing in prop::collection::vec("[a-z]{1,3}", 1..4),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let deepest = existing.iter().fold(root.clone(), |acc, name| acc.join(name));
            std::fs::create_dir_all(&deepest).unwrap();
            // A missing tail whose first name matches an existing sibling would
            // not be missing; make it distinct from every created name.
            let missing: Vec<String> = missing.iter().map(|name| format!("m-{name}")).collect();
            let target = missing.iter().fold(deepest.clone(), |acc, name| acc.join(name));

            prop_assert_eq!(nearest_existing_ancestor(&target), Some(deepest.clone()));
            prop_assert_eq!(canonicalize_allow_missing(&target), Ok(target.clone()));
            prop_assert_eq!(nearest_existing_ancestor(&deepest), Some(deepest.clone()));
            prop_assert_eq!(canonicalize_allow_missing(&deepest), Ok(deepest.clone()));

            // An unnormalized spelling of the same missing path resolves the same.
            let dotted = deepest.join(".").join(missing.join("/"));
            prop_assert_eq!(canonicalize_allow_missing(&dotted), Ok(target));
        }

        /// Bytes committed to a real repository come back unchanged. Content is
        /// printable ASCII, newlines and NULs, so git's binary heuristic reduces
        /// to "contains a NUL" (other control bytes can also trip it).
        #[test]
        fn read_git_file_bytes_round_trips_committed_content(
            content in prop::collection::vec(
                prop_oneof![8 => 0x20u8..0x7f, 1 => Just(b'\n'), 1 => Just(0u8)],
                0..48,
            ),
            name in "[a-z]{1,6}\\.[a-z]{1,3}",
        ) {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let repo = crate::gitblob::test_repo::init_repo(root);
            std::fs::write(root.join(&name), &content).unwrap();
            crate::gitblob::test_repo::commit_all(&repo, "fixture");

            let blob = read_git_file_bytes("HEAD", &root.join(&name)).unwrap();
            prop_assert_eq!(blob.as_bytes(), content.as_slice());
            prop_assert_eq!(blob.is_binary(), content.contains(&0));
            prop_assert_eq!(blob.repo_relative_path(), std::path::Path::new(&name));
        }
    }
}
