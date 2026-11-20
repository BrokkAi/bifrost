//! Answers "what did a bounded revision image leave out" from the endpoint's
//! Git tree, lazily, without walking the whole tree.
//!
//! A path is omitted if and only if the endpoint holds an entry there and the
//! image did not materialize it. The endpoint is the Git tree, adjusted for a
//! working-tree endpoint by an overlay: paths the worktree holds that the tree
//! lacks or changed (`overlay_present`) and tree paths it deleted
//! (`overlay_absent`). Links are resolved lazily in the Git tree only when
//! the overlay is empty; otherwise all links stay opaque because their targets
//! may have changed in the worktree. A file link resolved from the exact tree
//! is an unmaterialized leaf: it is omitted, but no entry exists below it.
//! Directory links, unresolved links and gitlinks stay opaque, so probes below
//! them are omitted. A path the endpoint does not hold
//! is not omitted: Rust probes both `foo.rs` and `foo/mod.rs`, and only one of
//! them exists.
//!
//! Names match by the case-folded, NFD-normalized key the Rust listing
//! certificate uses, because the analyzed volume may fold case and normalize
//! Unicode. A tree can hold two entries with one key (`Foo.rs` and `foo.rs`),
//! so a query considers every entry that matches and is omitted when any of
//! them is not materialized; the materialized set itself stays exact.
//!
//! Every Git failure, a missing or shallow object or a name that is not UTF-8,
//! is `Err(ListingUnknown)`: the caller treats the listing as unknown, never as
//! complete.

use super::RevisionObjectDatabase;
use brokk_bifrost_core::analyzer::project::{BoundedListingResolver, ListingUnknown};
use brokk_bifrost_rust::cargo_routes::rust_omission_path_key;
use git2::{ObjectType, Oid, Repository, Tree, TreeEntry};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};

/// What a resolver holds; see `BoundedTreeOmission`.
pub(super) struct BoundedSets {
    pub(super) tree: Oid,
    pub(super) materialized: Arc<[String]>,
    pub(super) overlay_present: Arc<[String]>,
    pub(super) overlay_absent: Arc<[String]>,
    pub(super) digest: [u8; 32],
}

pub(super) struct GitTreeResolver {
    objects: Arc<RevisionObjectDatabase>,
    sets: BoundedSets,
    /// Derived on first use.
    materialized_exact: OnceLock<HashSet<String>>,
    absent_exact: OnceLock<HashSet<String>>,
    present_by_key: OnceLock<HashMap<String, Vec<String>>>,
}

/// What a tree holds at one path.
#[derive(Clone)]
enum Node<'r> {
    Tree(Tree<'r>),
    Blob,
    /// A gitlink, directory link or unresolved link; probes below it are omitted.
    Opaque,
}

/// A tree entry reached by a probe, with its actual path in the tree.
#[derive(Clone)]
struct Entry<'r> {
    node: Node<'r>,
    path: String,
}

/// The entries one probe prefix reaches.
#[derive(Clone, Default)]
struct Reached<'r> {
    entries: Vec<Entry<'r>>,
    /// An earlier component was opaque, so the rest of the path is omitted.
    crosses_opaque: bool,
}

fn unknown(reason: impl Into<String>) -> ListingUnknown {
    ListingUnknown {
        reason: reason.into(),
    }
}

fn git_unknown(error: git2::Error) -> ListingUnknown {
    unknown(format!("Git object database error: {error}"))
}

impl GitTreeResolver {
    /// A resolver for the endpoint `sets` describe. Fails when the object
    /// database cannot read the tree: a record that cannot be queried must not
    /// replace the root Unknown omission.
    pub(super) fn open(
        objects: Arc<RevisionObjectDatabase>,
        sets: BoundedSets,
    ) -> Result<Self, ListingUnknown> {
        objects
            .with_repository(|repo| repo.find_tree(sets.tree).map(|_| ()).map_err(git_unknown))
            .map_err(unknown)??;
        Ok(Self {
            objects,
            sets,
            materialized_exact: OnceLock::new(),
            absent_exact: OnceLock::new(),
            present_by_key: OnceLock::new(),
        })
    }

    fn is_materialized(&self, path: &str) -> bool {
        self.materialized_exact
            .get_or_init(|| self.sets.materialized.iter().cloned().collect())
            .contains(path)
    }

    fn is_deleted(&self, path: &str) -> bool {
        self.absent_exact
            .get_or_init(|| self.sets.overlay_absent.iter().cloned().collect())
            .contains(path)
    }

    /// The overlay-present paths whose key is `key`.
    fn present_with_key(&self, key: &str) -> &[String] {
        self.present_by_key
            .get_or_init(|| {
                let mut by_key: HashMap<String, Vec<String>> = HashMap::new();
                for path in self.sets.overlay_present.iter() {
                    by_key
                        .entry(rust_omission_path_key(path))
                        .or_default()
                        .push(path.clone());
                }
                by_key
            })
            .get(key)
            .map_or(&[], Vec::as_slice)
    }

    /// The tree that certifies a symlink's target kind, if any. With an
    /// overlay the base tree cannot: an unchanged link can now reach a
    /// directory where its target was a file.
    fn symlink_root<'a, 'r>(&self, root: &'a Tree<'r>) -> Option<&'a Tree<'r>> {
        (self.sets.overlay_present.is_empty() && self.sets.overlay_absent.is_empty())
            .then_some(root)
    }

    /// Every symlink of the endpoint's tree, with whether probes treat it as a
    /// file (`true`) or as opaque. It classifies through `node_of`, as probes
    /// do, so the two cannot disagree.
    ///
    /// A subtree object that cannot be read is skipped when `other` holds the
    /// same oid at the same path and cannot read it either. Both endpoints
    /// read one repository, so every probe into that subtree is Unknown on
    /// both sides, and a link elsewhere whose target passes through it is
    /// Unresolved on both sides: no omission there can differ. An unreadable
    /// subtree that differs between the endpoints, or is unreadable on one
    /// side only, fails closed.
    fn symlink_is_file(
        &self,
        other: &GitTreeResolver,
        repo: &Repository,
    ) -> Result<HashMap<String, bool>, ListingUnknown> {
        let root = repo.find_tree(self.sets.tree).map_err(git_unknown)?;
        let symlink_root = self.symlink_root(&root);
        let mut links = HashMap::new();
        let mut stack = vec![(root.id(), String::new())];
        while let Some((id, prefix)) = stack.pop() {
            let tree = match repo.find_tree(id) {
                Ok(tree) => tree,
                Err(error) => {
                    if other.same_unreadable_tree(repo, &prefix, id)? {
                        continue;
                    }
                    return Err(git_unknown(error));
                }
            };
            for entry in tree.iter() {
                // Probes are UTF-8 strings, so none names an entry whose name
                // is not UTF-8 or anything below it, and a link target (which
                // `resolve_git_tree_symlink` accepts only as UTF-8) cannot
                // traverse such a component. The entry has no omission status
                // that can differ between the endpoints, so it is skipped.
                let Some(name) = entry.name() else {
                    continue;
                };
                let path = format!("{prefix}{name}");
                if entry.kind() == Some(ObjectType::Tree) {
                    stack.push((entry.id(), format!("{path}/")));
                } else if entry.filemode() == 0o120000 {
                    let node = node_of(repo, symlink_root, &path, &entry)?;
                    links.insert(path, matches!(node, Node::Blob));
                }
            }
        }
        Ok(links)
    }

    /// Whether this endpoint holds the unreadable tree `id` at `prefix` (the
    /// directory path with a trailing slash, or empty for the root).
    fn same_unreadable_tree(
        &self,
        repo: &Repository,
        prefix: &str,
        id: Oid,
    ) -> Result<bool, ListingUnknown> {
        if repo.find_tree(id).is_ok() {
            return Ok(false);
        }
        let root = repo.find_tree(self.sets.tree).map_err(git_unknown)?;
        Ok(brokk_bifrost_core::gitblob::tree_entry_by_components(
            repo,
            &root,
            prefix.trim_end_matches('/').split('/'),
        )
        .is_some_and(|entry| entry.id() == id))
    }

    fn with_repo<T>(
        &self,
        f: impl FnOnce(&Repository) -> Result<T, ListingUnknown>,
    ) -> Result<T, ListingUnknown> {
        self.objects.with_repository(f).map_err(unknown)?
    }

    /// Whether an entry of the endpoint at `path` is left out: a tree entry
    /// the worktree did not delete, and not materialized.
    fn entry_is_omitted(&self, path: &str) -> bool {
        !self.is_deleted(path) && !self.is_materialized(path)
    }

    /// Whether any overlay-present path (an entry the worktree added) at or
    /// below `dir_key` is not materialized.
    fn present_below_is_omitted(&self, dir_key: &str) -> bool {
        let below = format!("{dir_key}/");
        self.sets.overlay_present.iter().any(|path| {
            (dir_key.is_empty() || rust_omission_path_key(path).starts_with(&below))
                && !self.is_materialized(path)
        })
    }

    /// Whether any entry below the tree `id` at `prefix` is omitted. Stops at
    /// the first one; never leaves the subtree.
    fn subtree_has_omission(
        &self,
        repo: &Repository,
        id: Oid,
        prefix: String,
    ) -> Result<bool, ListingUnknown> {
        let mut stack = vec![(id, prefix)];
        while let Some((id, prefix)) = stack.pop() {
            let tree = repo.find_tree(id).map_err(git_unknown)?;
            for entry in tree.iter() {
                let name = entry
                    .name()
                    .ok_or_else(|| unknown("a Git tree entry name is not UTF-8"))?;
                let path = format!("{prefix}{name}");
                match entry.kind() {
                    Some(ObjectType::Tree) => stack.push((entry.id(), format!("{path}/"))),
                    Some(ObjectType::Commit | ObjectType::Blob) => {
                        if self.entry_is_omitted(&path) {
                            return Ok(true);
                        }
                    }
                    other => return Err(unknown(format!("unexpected tree entry kind {other:?}"))),
                }
            }
        }
        Ok(false)
    }
}

/// Whether `tree` holds an entry other than `name` whose folded key is
/// `name`'s: probes match by that key, so the two cannot be told apart.
fn folded_sibling_exists(tree: &Tree<'_>, name: &str) -> bool {
    let key = rust_omission_path_key(name);
    tree.iter().any(|sibling| {
        sibling
            .name()
            .is_some_and(|other| other != name && rust_omission_path_key(other) == key)
    })
}

fn node_of<'r>(
    repo: &'r Repository,
    root: Option<&Tree<'_>>,
    path: &str,
    entry: &TreeEntry<'_>,
) -> Result<Node<'r>, ListingUnknown> {
    match entry.kind() {
        Some(ObjectType::Tree) => repo
            .find_tree(entry.id())
            .map(Node::Tree)
            .map_err(git_unknown),
        Some(ObjectType::Blob) if entry.filemode() == 0o120000 => {
            use brokk_bifrost_core::gitblob::{
                GitTreeSymlinkTarget, resolve_git_tree_symlink_unless,
            };
            // Probes match by the folded key, so a link whose component shares
            // its key with a different sibling cannot be told apart from it
            // here: it fails closed as opaque.
            Ok(
                match root.map(|root| {
                    resolve_git_tree_symlink_unless(repo, root, path, folded_sibling_exists)
                }) {
                    Some(GitTreeSymlinkTarget::File) => Node::Blob,
                    Some(GitTreeSymlinkTarget::Directory | GitTreeSymlinkTarget::Unresolved)
                    | None => Node::Opaque,
                },
            )
        }
        Some(ObjectType::Blob) => Ok(Node::Blob),
        Some(ObjectType::Commit) => Ok(Node::Opaque),
        other => Err(unknown(format!("unexpected tree entry kind {other:?}"))),
    }
}

/// A probe path as its components. A path that is empty, absolute or names a
/// parent directory cannot be a workspace-relative path. A directory probe
/// names the workspace root as "" or ".".
fn components(path: &str, allow_root: bool) -> Result<Vec<&str>, ListingUnknown> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || (allow_root && trimmed == ".") {
        return if allow_root {
            Ok(Vec::new())
        } else {
            Err(unknown(format!("probe {path:?} names no file")))
        };
    }
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(unknown(format!("probe {path:?} is not a normalized path")));
    }
    Ok(parts)
}

/// Follow `parts` from `root`, keeping every entry whose name has the same
/// key as the probe's component. Prefixes already followed in this batch are
/// reused through `memo`, keyed by the probe prefix's key, so a batch costs one
/// read of each tree object it touches.
fn reach<'r>(
    resolver: &GitTreeResolver,
    repo: &'r Repository,
    root: &Tree<'r>,
    parts: &[&str],
    memo: &mut HashMap<String, Reached<'r>>,
) -> Result<Reached<'r>, ListingUnknown> {
    let symlink_root = resolver.symlink_root(root);
    let mut reached = Reached {
        entries: vec![Entry {
            node: Node::Tree(root.clone()),
            path: String::new(),
        }],
        crosses_opaque: false,
    };
    let mut prefix_key = String::new();
    for part in parts {
        if reached.crosses_opaque {
            break;
        }
        let part_key = rust_omission_path_key(part);
        if !prefix_key.is_empty() {
            prefix_key.push('/');
        }
        prefix_key.push_str(&part_key);
        if let Some(known) = memo.get(&prefix_key) {
            reached = known.clone();
            continue;
        }
        let mut next = Reached::default();
        for entry in &reached.entries {
            match &entry.node {
                Node::Tree(tree) => {
                    for child in tree.iter() {
                        let name = child
                            .name()
                            .ok_or_else(|| unknown("a Git tree entry name is not UTF-8"))?;
                        if rust_omission_path_key(name) == part_key {
                            next.entries.push(Entry {
                                node: node_of(
                                    repo,
                                    symlink_root,
                                    &format!("{}{name}", entry.path),
                                    &child,
                                )?,
                                path: format!("{}{name}", entry.path),
                            });
                        }
                    }
                }
                Node::Opaque => next.crosses_opaque = true,
                Node::Blob => {}
            }
        }
        // Directory entries continue with a trailing slash.
        for entry in &mut next.entries {
            if matches!(entry.node, Node::Tree(_)) {
                entry.path.push('/');
            }
        }
        memo.insert(prefix_key.clone(), next.clone());
        reached = next;
    }
    Ok(reached)
}

/// One entry of a tree level: kind, mode and object id.
type LevelEntry = (Option<ObjectType>, i32, Oid);

/// The entries of one tree level by name.
fn level(tree: &Tree<'_>) -> Result<HashMap<String, LevelEntry>, ListingUnknown> {
    tree.iter()
        .map(|entry| {
            let name = entry
                .name()
                .ok_or_else(|| unknown("a Git tree entry name is not UTF-8"))?;
            Ok((
                name.to_string(),
                (entry.kind(), entry.filemode(), entry.id()),
            ))
        })
        .collect()
}

/// Every blob and gitlink path below the tree `id` at `prefix`.
fn files_below(
    repo: &Repository,
    id: Oid,
    prefix: &str,
    into: &mut BTreeSet<String>,
) -> Result<(), ListingUnknown> {
    let mut stack = vec![(id, prefix.to_string())];
    while let Some((id, prefix)) = stack.pop() {
        let tree = repo.find_tree(id).map_err(git_unknown)?;
        for (name, (kind, _, entry_id)) in level(&tree)? {
            let path = format!("{prefix}{name}");
            match kind {
                Some(ObjectType::Tree) => stack.push((entry_id, format!("{path}/"))),
                _ => {
                    into.insert(path);
                }
            }
        }
    }
    Ok(())
}

/// The paths whose entry differs between the trees `old` and `new`. A subtree
/// that has the same object id on both sides is skipped without being read,
/// so the cost follows the change, not the tree. (libgit2's own tree diff
/// reads such subtrees.) A directory that exists on one side only, or that is a
/// file on the other, contributes every path below it.
fn changed_tree_paths(
    repo: &Repository,
    old: Oid,
    new: Oid,
) -> Result<BTreeSet<String>, ListingUnknown> {
    let mut changed = BTreeSet::new();
    let mut stack = vec![(old, new, String::new())];
    while let Some((old, new, prefix)) = stack.pop() {
        let old_level = level(&repo.find_tree(old).map_err(git_unknown)?)?;
        let new_level = level(&repo.find_tree(new).map_err(git_unknown)?)?;
        let names: BTreeSet<&String> = old_level.keys().chain(new_level.keys()).collect();
        for name in names {
            let path = format!("{prefix}{name}");
            let sides = (old_level.get(name), new_level.get(name));
            if let (Some(old_entry), Some(new_entry)) = sides {
                if old_entry.1 == new_entry.1 && old_entry.2 == new_entry.2 {
                    continue;
                }
                if old_entry.0 == Some(ObjectType::Tree) && new_entry.0 == Some(ObjectType::Tree) {
                    stack.push((old_entry.2, new_entry.2, format!("{path}/")));
                    continue;
                }
            }
            for entry in [sides.0, sides.1].into_iter().flatten() {
                if entry.0 == Some(ObjectType::Tree) {
                    files_below(repo, entry.2, &format!("{path}/"), &mut changed)?;
                } else {
                    changed.insert(path.clone());
                }
            }
        }
    }
    Ok(changed)
}

impl BoundedListingResolver for GitTreeResolver {
    fn omitted_files(&self, files: &[&str]) -> Result<Vec<String>, ListingUnknown> {
        let parsed = files
            .iter()
            .map(|file| components(file, false))
            .collect::<Result<Vec<_>, _>>()?;
        self.with_repo(|repo| {
            let root = repo.find_tree(self.sets.tree).map_err(git_unknown)?;
            let mut memo = HashMap::new();
            let mut omitted = Vec::new();
            for (file, parts) in files.iter().zip(&parsed) {
                let reached = reach(self, repo, &root, parts, &mut memo)?;
                // A tree entry is a file or a symlink or gitlink, never a
                // directory, for the last component to name an omitted file.
                let tree_omits = reached.crosses_opaque
                    || reached.entries.iter().any(|entry| match entry.node {
                        Node::Blob | Node::Opaque => self.entry_is_omitted(&entry.path),
                        Node::Tree(_) => false,
                    });
                let key = rust_omission_path_key(&parts.join("/"));
                let overlay_omits = self
                    .present_with_key(&key)
                    .iter()
                    .any(|path| !self.is_materialized(path));
                if tree_omits || overlay_omits {
                    omitted.push((*file).to_string());
                }
            }
            Ok(omitted)
        })
    }

    fn dirs_with_omissions(&self, dirs: &[&str]) -> Result<Vec<String>, ListingUnknown> {
        let parsed = dirs
            .iter()
            .map(|dir| components(dir, true))
            .collect::<Result<Vec<_>, _>>()?;
        self.with_repo(|repo| {
            let root = repo.find_tree(self.sets.tree).map_err(git_unknown)?;
            let mut memo = HashMap::new();
            let mut with_omissions = Vec::new();
            for (dir, parts) in dirs.iter().zip(&parsed) {
                let reached = reach(self, repo, &root, parts, &mut memo)?;
                let mut has_omission = reached.crosses_opaque;
                for entry in &reached.entries {
                    has_omission = has_omission
                        || match &entry.node {
                            // The probe names a gitlink or symlink: everything
                            // below it is omitted.
                            Node::Opaque => true,
                            Node::Blob => false,
                            Node::Tree(tree) => {
                                self.subtree_has_omission(repo, tree.id(), entry.path.clone())?
                            }
                        };
                }
                let dir_key = rust_omission_path_key(&parts.join("/"));
                if has_omission || self.present_below_is_omitted(&dir_key) {
                    with_omissions.push((*dir).to_string());
                }
            }
            Ok(with_omissions)
        })
    }

    fn changed_paths(
        &self,
        other: &dyn BoundedListingResolver,
    ) -> Result<Vec<String>, ListingUnknown> {
        let other_any: &dyn std::any::Any = other;
        let other = other_any
            .downcast_ref::<GitTreeResolver>()
            .ok_or_else(|| unknown("the other resolver does not read a Git tree"))?;
        if self.sets.tree == other.sets.tree && self.sets.digest == other.sets.digest {
            return Ok(Vec::new());
        }
        let mut changed: BTreeSet<String> = BTreeSet::new();
        if self.sets.tree != other.sets.tree {
            self.with_repo(|repo| {
                changed = changed_tree_paths(repo, self.sets.tree, other.sets.tree)?;
                Ok(())
            })?;
        }
        for (mine, theirs) in [
            (&self.sets.materialized, &other.sets.materialized),
            (&self.sets.overlay_present, &other.sets.overlay_present),
            (&self.sets.overlay_absent, &other.sets.overlay_absent),
        ] {
            let mine: BTreeSet<&String> = mine.iter().collect();
            let theirs: BTreeSet<&String> = theirs.iter().collect();
            changed.extend(
                mine.symmetric_difference(&theirs)
                    .map(|path| (*path).clone()),
            );
        }
        // A link's omission depends on its target, which lies outside its own
        // path, so a link can change without its entry or the overlay naming it.
        self.with_repo(|repo| {
            let mine = self.symlink_is_file(other, repo)?;
            let theirs = other.symlink_is_file(self, repo)?;
            changed.extend(
                mine.iter()
                    .filter(|(path, is_file)| theirs.get(*path) != Some(is_file))
                    .map(|(path, _)| path.clone()),
            );
            changed.extend(
                theirs
                    .keys()
                    .filter(|path| !mine.contains_key(*path))
                    .cloned(),
            );
            Ok(())
        })?;
        Ok(changed.into_iter().collect())
    }
}
