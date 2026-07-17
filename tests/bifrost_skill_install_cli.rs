use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn bifrost_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bifrost"))
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn skill_file(skills_root: &Path, name: &str) -> PathBuf {
    skills_root.join(name).join("SKILL.md")
}

#[test]
fn project_copy_installs_default_code_skills() {
    let project = TempDir::new().expect("temp project");
    let output = bifrost_command()
        .arg("--install-skills")
        .arg("--target")
        .arg("project")
        .arg("--mode")
        .arg("copy")
        .arg("--root")
        .arg(project.path())
        .output()
        .expect("run bifrost --install-skills");
    assert_success(&output);

    let skills_root = project.path().join(".agents").join("skills");
    assert!(skill_file(&skills_root, "bifrost-code-navigation").is_file());
    assert!(skill_file(&skills_root, "bifrost-code-reading").is_file());
    assert!(skill_file(&skills_root, "bifrost-codebase-search").is_file());
    assert!(!skill_file(&skills_root, "adversarial-test-sweep").exists());
    assert!(!skill_file(&skills_root, "guided-review").exists());
    assert!(
        skills_root
            .join("bifrost-code-navigation")
            .join(".bifrost-install.json")
            .is_file()
    );
}

#[test]
fn project_copy_is_idempotent() {
    let project = TempDir::new().expect("temp project");
    for _ in 0..2 {
        let output = bifrost_command()
            .arg("--install-skills")
            .arg("--target")
            .arg("project")
            .arg("--mode")
            .arg("copy")
            .arg("--root")
            .arg(project.path())
            .output()
            .expect("run bifrost --install-skills");
        assert_success(&output);
    }

    let output = bifrost_command()
        .arg("--install-skills")
        .arg("--target")
        .arg("project")
        .arg("--mode")
        .arg("copy")
        .arg("--root")
        .arg(project.path())
        .output()
        .expect("run bifrost --install-skills again");
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Up to date: bifrost-code-navigation"),
        "{stdout}"
    );
}

#[test]
fn dry_run_does_not_create_files() {
    let project = TempDir::new().expect("temp project");
    let output = bifrost_command()
        .arg("--install-skills")
        .arg("--target")
        .arg("project")
        .arg("--mode")
        .arg("copy")
        .arg("--dry-run")
        .arg("--root")
        .arg(project.path())
        .output()
        .expect("run bifrost --install-skills --dry-run");
    assert_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Would copy bifrost-code-navigation"),
        "{stdout}"
    );
    assert!(!project.path().join(".agents").exists());
}

#[test]
fn unmanaged_skill_conflict_is_not_overwritten() {
    let project = TempDir::new().expect("temp project");
    let skills_root = project.path().join(".agents").join("skills");
    let conflict = skills_root.join("bifrost-code-navigation");
    fs::create_dir_all(&conflict).expect("create conflict skill");
    fs::write(conflict.join("SKILL.md"), "user skill\n").expect("write conflict skill");

    let output = bifrost_command()
        .arg("--install-skills")
        .arg("--target")
        .arg("project")
        .arg("--mode")
        .arg("copy")
        .arg("--root")
        .arg(project.path())
        .output()
        .expect("run bifrost --install-skills with conflict");
    assert_failure(&output);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Refusing to replace existing unmanaged skill directory"),
        "{stderr}"
    );
    assert_eq!(
        fs::read_to_string(conflict.join("SKILL.md")).expect("read conflict skill"),
        "user skill\n"
    );
}

#[test]
fn managed_copy_with_drift_requires_force() {
    let project = TempDir::new().expect("temp project");
    let install = || {
        bifrost_command()
            .arg("--install-skills")
            .arg("--target")
            .arg("project")
            .arg("--mode")
            .arg("copy")
            .arg("--root")
            .arg(project.path())
            .output()
            .expect("run bifrost --install-skills")
    };
    let output = install();
    assert_success(&output);

    let skill_path = project
        .path()
        .join(".agents")
        .join("skills")
        .join("bifrost-code-navigation")
        .join("SKILL.md");
    fs::write(&skill_path, "locally changed\n").expect("drift managed skill");

    let output = install();
    assert_failure(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("local changes"), "{stderr}");

    let output = bifrost_command()
        .arg("--install-skills")
        .arg("--target")
        .arg("project")
        .arg("--mode")
        .arg("copy")
        .arg("--force")
        .arg("--root")
        .arg(project.path())
        .output()
        .expect("run bifrost --install-skills --force");
    assert_success(&output);
    let restored = fs::read_to_string(&skill_path).expect("read restored skill");
    assert!(restored.contains("name: bifrost-code-navigation"));
    assert!(!restored.contains("locally changed"));
}

#[test]
fn custom_skills_root_installs_without_project_agents_directory() {
    let project = TempDir::new().expect("temp project");
    let custom_root = project.path().join("custom-skills");
    let output = bifrost_command()
        .arg("--install-skills")
        .arg("--skills-root")
        .arg(&custom_root)
        .arg("--mode")
        .arg("copy")
        .arg("--root")
        .arg(project.path())
        .output()
        .expect("run bifrost --install-skills --skills-root");
    assert_success(&output);

    assert!(skill_file(&custom_root, "bifrost-code-navigation").is_file());
    assert!(!project.path().join(".agents").exists());
}

#[test]
fn interactive_menu_accepts_project_choice() {
    let project = TempDir::new().expect("temp project");
    let mut child = bifrost_command()
        .arg("--install-skills")
        .arg("--mode")
        .arg("copy")
        .arg("--root")
        .arg(project.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bifrost --install-skills");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(b"1\n").expect("write menu choice");
    }
    let output = wait_with_output(child, Duration::from_secs(15));
    assert_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Select install destination"), "{stdout}");
    assert!(
        skill_file(
            &project.path().join(".agents").join("skills"),
            "bifrost-code-navigation"
        )
        .is_file()
    );
}

#[test]
fn help_lists_install_skills_mode() {
    let output = bifrost_command()
        .arg("--help")
        .output()
        .expect("run bifrost --help");
    assert_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--install-skills"), "{stdout}");
    assert!(stdout.contains("--skills-root DIR"), "{stdout}");
}

#[test]
fn all_skill_set_installs_workflow_skills() {
    let temp = TempDir::new().expect("temp dir");
    let skills_root = temp.path().join("skills-root");
    let output = bifrost_command()
        .arg("--install-skills")
        .arg("--skills-root")
        .arg(&skills_root)
        .arg("--mode")
        .arg("copy")
        .arg("--skill-set")
        .arg("all")
        .output()
        .expect("run bifrost --install-skills --skill-set all");
    assert_success(&output);

    assert!(skill_file(&skills_root, "guided-review").is_file());
    assert!(skill_file(&skills_root, "adversarial-test-sweep").is_file());
}

#[cfg(unix)]
#[test]
fn project_symlink_mode_links_to_checkout_skill_dirs() {
    let project = TempDir::new().expect("temp project");
    let output = bifrost_command()
        .arg("--install-skills")
        .arg("--target")
        .arg("project")
        .arg("--mode")
        .arg("symlink")
        .arg("--root")
        .arg(project.path())
        .output()
        .expect("run bifrost --install-skills --mode symlink");
    assert_success(&output);

    let link_path = project
        .path()
        .join(".agents")
        .join("skills")
        .join("bifrost-code-navigation");
    let metadata = fs::symlink_metadata(&link_path).expect("symlink metadata");
    assert!(metadata.file_type().is_symlink());

    let target = fs::read_link(&link_path).expect("read symlink");
    let absolute_target = if target.is_absolute() {
        target
    } else {
        link_path.parent().unwrap().join(target)
    };
    let expected = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("plugins")
        .join("bifrost-agent")
        .join("skills")
        .join("bifrost-code-navigation");
    assert_eq!(
        absolute_target.canonicalize().expect("canonical target"),
        expected.canonicalize().expect("canonical expected")
    );
}

fn wait_with_output(mut child: std::process::Child, timeout: Duration) -> std::process::Output {
    let started = Instant::now();
    loop {
        match child.try_wait().expect("poll child") {
            Some(_) => return child.wait_with_output().expect("wait for child output"),
            None if started.elapsed() >= timeout => {
                let _ = child.kill();
                let output = child.wait_with_output().expect("wait after killing child");
                panic!(
                    "child timed out after {:?}\nstdout:\n{}\nstderr:\n{}",
                    timeout,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}
