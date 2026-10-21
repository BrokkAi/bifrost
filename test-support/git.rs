use git2::{Commit, Index, IndexAddOption, Oid, Repository, Signature};
use std::path::Path;

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_index(
    repo: &Repository,
    index: Index,
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    let parent = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repo.find_commit(oid).ok());
    let parents = parent.iter().collect::<Vec<_>>();
    commit_index_with_parents(repo, index, message, signature, &parents)
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_index_without_parent(
    repo: &Repository,
    index: Index,
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    commit_index_with_parents(repo, index, message, signature, &[])
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_index_after_head(
    repo: &Repository,
    index: Index,
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    let parent = repo
        .head()
        .expect("repository HEAD")
        .peel_to_commit()
        .expect("parent commit");
    commit_index_with_parents(repo, index, message, signature, &[&parent])
}

fn commit_index_with_parents(
    repo: &Repository,
    mut index: Index,
    message: &str,
    signature: &Signature<'_>,
    parents: &[&Commit<'_>],
) -> Oid {
    index.write().expect("write fixture index");
    let tree_id = index.write_tree().expect("write fixture tree");
    let tree = repo.find_tree(tree_id).expect("find fixture tree");
    repo.commit(Some("HEAD"), signature, signature, message, &tree, parents)
        .expect("commit fixture")
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_all(repo: &Repository, message: &str, signature: &Signature<'_>) -> Oid {
    let mut index = repo.index().expect("repository index");
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .expect("stage fixture");
    commit_index(repo, index, message, signature)
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_all_without_parent(
    repo: &Repository,
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    let mut index = repo.index().expect("repository index");
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .expect("stage fixture");
    commit_index_without_parent(repo, index, message, signature)
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_all_after_head(repo: &Repository, message: &str, signature: &Signature<'_>) -> Oid {
    let mut index = repo.index().expect("repository index");
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .expect("stage fixture");
    commit_index_after_head(repo, index, message, signature)
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_all_with_deletions(
    repo: &Repository,
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    let mut index = repo.index().expect("repository index");
    index
        .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
        .expect("stage fixture");
    index
        .update_all(["*"].iter(), None)
        .expect("stage fixture deletions");
    commit_index(repo, index, message, signature)
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_all_skipping_bifrost_cache(
    repo: &Repository,
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    let mut index = repo.index().expect("repository index");
    let mut skip_analyzer_cache = |path: &Path, _matched_pathspec: &[u8]| {
        i32::from(path.starts_with(Path::new(".bifrost/cache")))
    };
    index
        .add_all(
            ["*"].iter(),
            IndexAddOption::DEFAULT,
            Some(&mut skip_analyzer_cache),
        )
        .expect("stage fixture");
    commit_index(repo, index, message, signature)
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_paths(
    repo: &Repository,
    paths: &[&str],
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    let mut index = repo.index().expect("repository index");
    for path in paths {
        index.add_path(Path::new(path)).expect("stage fixture path");
    }
    commit_index(repo, index, message, signature)
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_paths_without_parent(
    repo: &Repository,
    paths: &[&str],
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    let mut index = repo.index().expect("repository index");
    for path in paths {
        index.add_path(Path::new(path)).expect("stage fixture path");
    }
    commit_index_without_parent(repo, index, message, signature)
}

#[allow(dead_code)]
#[doc(hidden)]
pub fn commit_paths_with_removals(
    repo: &Repository,
    add: &[&str],
    remove: &[&str],
    message: &str,
    signature: &Signature<'_>,
) -> Oid {
    let mut index = repo.index().expect("repository index");
    for path in remove {
        index
            .remove_path(Path::new(path))
            .expect("remove fixture path");
    }
    for path in add {
        index.add_path(Path::new(path)).expect("stage fixture path");
    }
    commit_index(repo, index, message, signature)
}
