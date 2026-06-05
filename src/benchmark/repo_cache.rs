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

    let checkout_path = repo_cache_dir.join(&target.name);
    if !checkout_path.exists() {
        run_git_command(
            Command::new("git")
                .arg("clone")
                .arg("--filter=blob:none")
                .arg(&target.url)
                .arg(&checkout_path),
            None,
            format!("clone `{}` into `{}`", target.url, checkout_path.display()),
        )?;
    } else if !repo_has_commit(&checkout_path, &target.commit)? {
        run_git_command(
            Command::new("git")
                .arg("-C")
                .arg(&checkout_path)
                .arg("fetch")
                .arg("--filter=blob:none")
                .arg("--all")
                .arg("--tags"),
            None,
            format!("fetch `{}`", checkout_path.display()),
        )?;
    }

    run_git_command(
        Command::new("git")
            .arg("-C")
            .arg(&checkout_path)
            .arg("checkout")
            .arg("--detach")
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
