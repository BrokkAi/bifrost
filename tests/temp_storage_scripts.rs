#![cfg(unix)]

use filetime::{FileTime, set_file_mtime};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join(name)
}

fn entries(root: &Path) -> Vec<PathBuf> {
    let mut entries = fs::read_dir(root)
        .expect("read temporary root")
        .map(|entry| entry.expect("read directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn make_old(path: &Path) {
    let old = SystemTime::now() - Duration::from_secs(48 * 60 * 60);
    set_file_mtime(path, FileTime::from_system_time(old)).expect("set old mtime");
}

fn mark_managed(path: &Path) {
    let name = path.file_name().expect("candidate name").to_string_lossy();
    fs::write(
        path.join(".bifrost-managed-target"),
        format!(
            "version=1\nuid={}\nname={name}\n",
            fs::metadata(path).expect("candidate metadata").uid()
        ),
    )
    .expect("write managed marker");
}

fn prepend_path(directory: &Path) -> std::ffi::OsString {
    let mut paths = vec![directory.to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::join_paths(paths).expect("join PATH")
}

fn failing_rm(directory: &Path) -> PathBuf {
    let bin = directory.join("bin");
    fs::create_dir(&bin).expect("fake bin");
    let rm = bin.join("rm");
    fs::write(&rm, "#!/usr/bin/env bash\nexit 1\n").expect("fake rm");
    fs::set_permissions(&rm, fs::Permissions::from_mode(0o755)).expect("executable fake rm");
    bin
}

#[test]
fn isolated_target_is_removed_after_success_and_failure() {
    let temp = tempfile::tempdir().expect("temporary root");
    for exit_code in [0, 7] {
        let command = format!(
            "test -d \"$CARGO_TARGET_DIR\"; touch \"$CARGO_TARGET_DIR/proof\"; exit {exit_code}"
        );
        let output = Command::new(script("with-isolated-cargo-target.sh"))
            .env("BIFROST_TMP_ROOT", temp.path())
            .args(["bash", "-c", &command])
            .output()
            .expect("run isolated target helper");
        assert_eq!(output.status.code(), Some(exit_code), "{output:?}");
        assert!(entries(temp.path()).is_empty(), "{output:?}");
    }
}

#[test]
fn isolated_target_can_be_intentionally_retained() {
    let temp = tempfile::tempdir().expect("temporary root");
    let output = Command::new(script("with-isolated-cargo-target.sh"))
        .env("BIFROST_TMP_ROOT", temp.path())
        .env("BIFROST_KEEP_TARGET", "1")
        .args(["bash", "-c", "touch \"$CARGO_TARGET_DIR/proof\""])
        .output()
        .expect("run retained target helper");
    assert!(output.status.success(), "{output:?}");

    let retained = entries(temp.path());
    assert_eq!(retained.len(), 1, "{retained:?}");
    assert!(retained[0].join("proof").is_file());
    assert!(retained[0].join(".bifrost-keep").is_file());
    assert!(!retained[0].join(".bifrost-active-pid").exists());
}

#[test]
fn isolated_target_is_removed_after_interruption() {
    let temp = tempfile::tempdir().expect("temporary root");
    let mut helper = Command::new(script("with-isolated-cargo-target.sh"))
        .env("BIFROST_TMP_ROOT", temp.path())
        .args(["sleep", "30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start isolated target helper");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while entries(temp.path())
        .into_iter()
        .next()
        .is_none_or(|target| {
            fs::read_to_string(target.join(".bifrost-active-pid"))
                .map_or(true, |pids| pids.lines().count() < 2)
        })
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        entries(temp.path()).len(),
        1,
        "helper did not create target"
    );

    let signal = Command::new("kill")
        .args(["-TERM", &helper.id().to_string()])
        .status()
        .expect("interrupt helper");
    assert!(signal.success());
    let status = helper.wait().expect("wait for interrupted helper");
    assert_eq!(status.code(), Some(143));
    assert!(entries(temp.path()).is_empty());
}

#[test]
fn isolated_target_interrupts_descendants_and_stubborn_children() {
    for signal in ["-INT", "-TERM"] {
        let temp = tempfile::tempdir().expect("temporary root");
        let mut helper = Command::new(script("with-isolated-cargo-target.sh"))
            .env("BIFROST_TMP_ROOT", temp.path())
            .args([
                "bash",
                "-c",
                "trap '' TERM INT; sleep 30 & echo $! > \"$CARGO_TARGET_DIR/descendant-pid\"; wait",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start stubborn process tree");

        let deadline = Instant::now() + Duration::from_secs(5);
        let pid_file = loop {
            let target = entries(temp.path()).into_iter().next();
            if let Some(pid_file) = target.map(|path| path.join("descendant-pid"))
                && pid_file.is_file()
            {
                break pid_file;
            }
            assert!(Instant::now() < deadline, "descendant PID was not written");
            std::thread::sleep(Duration::from_millis(10));
        };
        let descendant_pid = fs::read_to_string(pid_file).expect("descendant PID");

        let started = Instant::now();
        assert!(
            Command::new("kill")
                .args([signal, &helper.id().to_string()])
                .status()
                .expect("signal helper")
                .success()
        );
        let status = helper.wait().expect("wait for helper");
        assert_eq!(
            status.code(),
            Some(if signal == "-INT" { 130 } else { 143 })
        );
        assert!(started.elapsed() < Duration::from_secs(8));
        assert!(entries(temp.path()).is_empty());
        assert!(
            !Command::new("kill")
                .args(["-0", descendant_pid.trim()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("probe descendant")
                .success(),
            "descendant {descendant_pid} survived"
        );
    }
}

#[test]
fn isolated_target_reports_cleanup_failure() {
    let temp = tempfile::tempdir().expect("temporary root");
    let fake_bin = failing_rm(temp.path());
    let output = Command::new(script("with-isolated-cargo-target.sh"))
        .env("BIFROST_TMP_ROOT", temp.path())
        .env("PATH", prepend_path(&fake_bin))
        .arg("true")
        .output()
        .expect("run helper with failing rm");
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Failed to remove isolated Cargo target")
    );
    assert_eq!(entries(temp.path()).len(), 2, "fake bin plus leaked target");
}

#[test]
fn cleanup_is_dry_run_by_default_and_apply_is_prefix_scoped() {
    let temp = tempfile::tempdir().expect("temporary root");
    let stale = temp.path().join("bifrost-cargo-target.stale");
    let unrelated = temp.path().join("other-stale");
    fs::create_dir(&stale).expect("stale candidate");
    fs::create_dir(&unrelated).expect("unrelated directory");
    mark_managed(&stale);
    make_old(&stale);
    make_old(&unrelated);

    let dry_run = Command::new(script("cleanup-bifrost-tmp.sh"))
        .args(["--tmp-root", temp.path().to_str().expect("utf8 root")])
        .output()
        .expect("run cleanup dry-run");
    assert!(dry_run.status.success(), "{dry_run:?}");
    assert!(stale.exists());
    assert!(String::from_utf8_lossy(&dry_run.stdout).contains("Would remove:"));

    let apply = Command::new(script("cleanup-bifrost-tmp.sh"))
        .args([
            "--apply",
            "--tmp-root",
            temp.path().to_str().expect("utf8 root"),
        ])
        .output()
        .expect("apply cleanup");
    assert!(apply.status.success(), "{apply:?}");
    assert!(!stale.exists(), "{apply:?}");
    assert!(unrelated.exists(), "{apply:?}");
}

#[test]
fn cleanup_requires_explicit_opt_in_for_unmanaged_directories() {
    let temp = tempfile::tempdir().expect("temporary root");
    let unmanaged = temp.path().join("bifrost-unmanaged-worktree");
    fs::create_dir(&unmanaged).expect("unmanaged candidate");
    make_old(&unmanaged);

    let default_apply = Command::new(script("cleanup-bifrost-tmp.sh"))
        .args([
            "--apply",
            "--tmp-root",
            temp.path().to_str().expect("utf8 root"),
        ])
        .output()
        .expect("apply managed-only cleanup");
    assert!(default_apply.status.success(), "{default_apply:?}");
    assert!(unmanaged.exists());
    assert!(String::from_utf8_lossy(&default_apply.stdout).contains("Skip unmanaged"));

    let explicit_apply = Command::new(script("cleanup-bifrost-tmp.sh"))
        .args([
            "--apply",
            "--include-unmanaged",
            "--tmp-root",
            temp.path().to_str().expect("utf8 root"),
        ])
        .output()
        .expect("apply unmanaged cleanup");
    assert!(explicit_apply.status.success(), "{explicit_apply:?}");
    assert!(!unmanaged.exists(), "{explicit_apply:?}");
}

#[test]
fn cleanup_rejects_overflowing_age() {
    let temp = tempfile::tempdir().expect("temporary root");
    let output = Command::new(script("cleanup-bifrost-tmp.sh"))
        .args([
            "--apply",
            "--older-than-hours",
            "18446744073709551615",
            "--tmp-root",
            temp.path().to_str().expect("utf8 root"),
        ])
        .output()
        .expect("run cleanup with overflowing age");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not exceed"));
}

#[test]
fn cleanup_reports_deletion_failure() {
    let temp = tempfile::tempdir().expect("temporary root");
    let candidate = temp.path().join("bifrost-cargo-target.rm-failure");
    fs::create_dir(&candidate).expect("candidate");
    mark_managed(&candidate);
    make_old(&candidate);
    let fake_bin = failing_rm(temp.path());

    let output = Command::new(script("cleanup-bifrost-tmp.sh"))
        .env("PATH", prepend_path(&fake_bin))
        .args([
            "--apply",
            "--tmp-root",
            temp.path().to_str().expect("utf8 root"),
        ])
        .output()
        .expect("run cleanup with failing rm");
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Failed to remove directory; remaining data is at")
    );
    assert!(candidate.exists());
}

#[test]
fn cleanup_preserves_young_active_retained_open_and_symlinked_directories() {
    let temp = tempfile::tempdir().expect("temporary root");
    let young = temp.path().join("bifrost-young");
    let active = temp.path().join("bifrost-cargo-target.active");
    let retained = temp.path().join("bifrost-cargo-target.retained");
    let open = temp.path().join("bifrost-cargo-target.open");
    let outside = temp.path().join("outside");
    let symlink = temp.path().join("bifrost-symlink");
    for path in [&young, &active, &retained, &open, &outside] {
        fs::create_dir(path).expect("create test directory");
    }
    fs::write(
        active.join(".bifrost-active-pid"),
        format!("2147483647\n{}\n", std::process::id()),
    )
    .expect("write active marker");
    fs::write(retained.join(".bifrost-keep"), "").expect("write keep marker");
    for path in [&active, &retained, &open] {
        mark_managed(path);
    }
    for path in [&active, &retained, &open, &outside] {
        make_old(path);
    }
    std::os::unix::fs::symlink(&outside, &symlink).expect("create symlink candidate");

    let mut holder = Command::new("sleep")
        .arg("30")
        .current_dir(&open)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("hold candidate directory open");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Command::new("lsof")
        .arg("-Fn")
        .arg("+D")
        .arg(&open)
        .output()
        .expect("probe open candidate")
        .stdout
        .is_empty()
    {
        assert!(Instant::now() < deadline, "holder did not open candidate");
        std::thread::sleep(Duration::from_millis(10));
    }

    let apply = Command::new(script("cleanup-bifrost-tmp.sh"))
        .args([
            "--apply",
            "--tmp-root",
            temp.path().to_str().expect("utf8 root"),
        ])
        .output()
        .expect("apply safe cleanup");
    holder.kill().expect("stop holder");
    holder.wait().expect("wait for holder");

    assert!(apply.status.success(), "{apply:?}");
    assert!(young.exists(), "{apply:?}");
    assert!(active.exists(), "{apply:?}");
    assert!(retained.exists(), "{apply:?}");
    assert!(open.exists(), "{apply:?}");
    assert!(outside.exists(), "{apply:?}");
    assert!(symlink.is_symlink(), "{apply:?}");
    let stdout = String::from_utf8_lossy(&apply.stdout);
    assert!(stdout.contains("Skip active PID"), "{stdout}");
    assert!(stdout.contains("Skip retained"), "{stdout}");
    assert!(stdout.contains("Skip open directory"), "{stdout}");
}
