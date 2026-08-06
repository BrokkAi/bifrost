use crate::benchmark::BenchmarkRepoTarget;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn prepare_repo(
    target: &BenchmarkRepoTarget,
    repo_cache_dir: &Path,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(repo_cache_dir).map_err(|err| {
        format!(
            "failed to create repo cache dir `{}`: {err}",
            repo_cache_dir.display()
        )
    })?;

    // The fixtures must be full clones. `most_relevant_files` refuses the git
    // co-change history walk on a partial clone with a network promisor remote
    // (issue #1373), so a blobless fixture would silently benchmark the
    // import-only fallback instead of the history ranking the baseline pinned.
    let checkout_path = repo_cache_dir.join(&target.name);
    let mut reuse_cached_clone = false;
    if checkout_path.exists() {
        reuse_cached_clone = matches!(unpartial_cached_clone(&checkout_path)?, CachedClone::Full);
        if !reuse_cached_clone {
            // The in-place upgrade needs git 2.36 (see `unpartial_cached_clone`).
            // On older git the cached partial clone cannot become full, so it is
            // discarded and cloned again below. A fresh clone carries no filter,
            // which is the state the caller needs.
            std::fs::remove_dir_all(&checkout_path).map_err(|err| {
                format!(
                    "failed to discard partial cached clone `{}`: {err}",
                    checkout_path.display()
                )
            })?;
        }
    }

    if reuse_cached_clone {
        if !repo_has_commit(&checkout_path, &target.commit)? {
            run_git_command(
                Command::new("git")
                    .arg("-C")
                    .arg(&checkout_path)
                    .arg("fetch")
                    .arg("--all")
                    .arg("--tags"),
                None,
                format!("fetch `{}`", checkout_path.display()),
            )?;
        }
    } else {
        run_git_command(
            Command::new("git")
                .arg("clone")
                .args(["-c", "core.autocrlf=false"])
                .arg("--no-checkout")
                .arg(&target.url)
                .arg(&checkout_path),
            None,
            format!("clone `{}` into `{}`", target.url, checkout_path.display()),
        )?;
    }

    // Benchmark input must be byte-stable across hosts: the persisted analyzer
    // deliberately keys data by working-tree bytes, including CRLF differences.
    run_git_command(
        Command::new("git").arg("-C").arg(&checkout_path).args([
            "config",
            "core.autocrlf",
            "false",
        ]),
        None,
        format!(
            "disable line-ending conversion in `{}`",
            checkout_path.display()
        ),
    )?;

    run_git_command(
        Command::new("git")
            .arg("-C")
            .arg(&checkout_path)
            .arg("checkout")
            .arg("--detach")
            .arg("--force")
            .arg(&target.commit),
        None,
        format!(
            "checkout commit `{}` in `{}`",
            target.commit,
            checkout_path.display()
        ),
    )?;

    checkout_path.canonicalize().map_err(|err| {
        format!(
            "failed to canonicalize checkout path `{}`: {err}",
            checkout_path.display()
        )
    })
}

/// Result of upgrading a cached checkout in place.
enum CachedClone {
    /// The checkout is a full clone, either already or after the refetch.
    Full,
    /// The checkout is partial and this git cannot upgrade it in place.
    UnusablePartial,
}

/// Upgrade a cached blobless clone left behind by the pre-#1373 harness into a
/// full clone. Earlier harness versions cloned with `--filter=blob:none`;
/// restored CI caches and local caches keep that shape until targets change.
/// `git fetch --refetch` transfers every object for the advertised refs as a
/// fresh clone would, after which the promisor and filter markers are removed
/// so the repository is an ordinary full clone.
///
/// `--refetch` needs git 2.36 or later (issue #1727). Older git cannot perform
/// this upgrade at all, so it reports `UnusablePartial` and the caller re-clones.
fn unpartial_cached_clone(checkout_path: &Path) -> Result<CachedClone, String> {
    let repo = git2::Repository::open(checkout_path).map_err(|err| {
        format!(
            "failed to open cached checkout `{}`: {err}",
            checkout_path.display()
        )
    })?;
    let config = repo.config().map_err(|err| {
        format!(
            "failed to read config of `{}`: {err}",
            checkout_path.display()
        )
    })?;
    let remotes = repo.remotes().map_err(|err| {
        format!(
            "failed to list remotes of `{}`: {err}",
            checkout_path.display()
        )
    })?;
    let partial_remotes: Vec<String> = remotes
        .iter()
        .flatten()
        .filter(|remote| {
            config
                .get_bool(&format!("remote.{remote}.promisor"))
                .unwrap_or(false)
                || config
                    .get_string(&format!("remote.{remote}.partialclonefilter"))
                    .is_ok()
        })
        .map(str::to_string)
        .collect();
    drop(config);
    drop(repo);

    for remote in partial_remotes {
        // Drop the filter first so the refetch negotiates unfiltered.
        run_git_command(
            Command::new("git").arg("-C").arg(checkout_path).args([
                "config",
                "--unset-all",
                &format!("remote.{remote}.partialclonefilter"),
            ]),
            None,
            format!(
                "remove partial-clone filter of remote `{remote}` in `{}`",
                checkout_path.display()
            ),
        )
        .or_else(ignore_unset_of_missing_key)?;
        if let Err(error) = run_git_command(
            Command::new("git")
                .arg("-C")
                .arg(checkout_path)
                .arg("fetch")
                .arg("--refetch")
                .arg("--tags")
                .arg(&remote),
            None,
            format!(
                "refetch full objects from remote `{remote}` in `{}`",
                checkout_path.display()
            ),
        ) {
            // Context-specific recovery: git before 2.36 has no `--refetch`, and
            // a full re-clone reaches the same end state. Every other refetch
            // failure still propagates with its original context.
            if !refetch_option_unsupported(&error) {
                return Err(error);
            }
            return Ok(CachedClone::UnusablePartial);
        }
        run_git_command(
            Command::new("git").arg("-C").arg(checkout_path).args([
                "config",
                "--unset-all",
                &format!("remote.{remote}.promisor"),
            ]),
            None,
            format!(
                "remove promisor marker of remote `{remote}` in `{}`",
                checkout_path.display()
            ),
        )
        .or_else(ignore_unset_of_missing_key)?;
    }
    Ok(CachedClone::Full)
}

/// `git fetch --refetch` arrived in git 2.36. Older git rejects it in
/// parse-options, which exits with status 129 and reports `unknown option`.
/// The quoting around the option name differs between git versions, so only
/// the stable part of the message is matched. A refetch that fails for any
/// other reason, on any git version, exits with a different status.
fn refetch_option_unsupported(error: &str) -> bool {
    error.contains("status=129") && error.contains("unknown option")
}

/// `git config --unset-all` exits with status 5 when the key does not exist.
/// A partial clone can carry only one of the two markers; removing the absent
/// one is not an error.
fn ignore_unset_of_missing_key(error: String) -> Result<(), String> {
    if error.contains("status=5") {
        return Ok(());
    }
    Err(error)
}

fn repo_has_commit(checkout_path: &Path, commit: &str) -> Result<bool, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout_path)
        .arg("rev-parse")
        .arg("--verify")
        .arg("--quiet")
        .arg(format!("{commit}^{{commit}}"))
        .output()
        .map_err(|err| {
            format!(
                "failed to inspect cached commit `{commit}` in `{}`: {err}",
                checkout_path.display()
            )
        })?;
    Ok(output.status.success())
}

fn run_git_command(
    command: &mut Command,
    current_dir: Option<&Path>,
    description: String,
) -> Result<(), String> {
    if let Some(dir) = current_dir {
        command.current_dir(dir);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to {description}: {err}"))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(format!(
        "failed to {description}: status={} stdout=`{}` stderr=`{}`",
        output
            .status
            .code()
            .map_or_else(|| "signal".to_string(), |code| code.to_string()),
        stdout.trim(),
        stderr.trim()
    ))
}
