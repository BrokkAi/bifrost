#![allow(dead_code)]
//! Shared inline test-project harness.
//!
//! This harness lives in the top-level `test-support/` directory rather than
//! under `tests/common/` because it is `#[path]`-included by public
//! crate-nested suites as well as by the private root suites. Keeping it
//! outside `tests/**` lets the open-core projection publish the crate-nested
//! suites without publishing the private assurance corpus.

use brokk_bifrost_analysis::{
    AnalyzerConfig, Language, Project, ProjectFile, TestProject, WorkspaceAnalyzer,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Run one git command in `dir` and panic with its transcript on failure.
///
/// Tests that need a repository fixture (for example diff-aware policy gating)
/// call this instead of hand-rolling `std::process::Command`. It lives beside
/// the inline project rather than in `tests/common/` because the inline project
/// builds repositories itself and this harness is included by public
/// crate-nested suites that must not reach into `tests/`.
pub fn run_git(dir: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .current_dir(dir)
        .args(["-c", "commit.gpgSign=false"])
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// `git init` plus the throwaway committer identity test commits need.
pub fn init_git_repo_with_identity(dir: &Path) {
    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test User"]);
    // Diff tests compare identities derived from exact source byte spans.
    // Keep their temporary repositories independent of a Windows host's
    // global core.autocrlf setting so base and working-tree bytes agree.
    run_git(dir, &["config", "core.autocrlf", "false"]);
}

#[derive(Default)]
pub struct InlineTestProject {
    language: Option<Language>,
    files: Vec<(PathBuf, String)>,
    git: bool,
}

impl InlineTestProject {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_language(language: Language) -> Self {
        Self::new().language(language)
    }

    pub fn language(mut self, language: Language) -> Self {
        self.language = Some(language);
        self
    }

    pub fn file(mut self, rel_path: impl Into<PathBuf>, contents: impl Into<String>) -> Self {
        self.files.push((rel_path.into(), contents.into()));
        self
    }

    /// Build the project inside a git repository whose initial commit is the
    /// files declared here.
    ///
    /// A diff-aware run needs a revision to compare against, and it needs the
    /// declared files to be *committed*, so that a later working-tree write is
    /// an uncommitted edit: the shape a pull request has.
    pub const fn with_git(mut self) -> Self {
        self.git = true;
        self
    }

    pub fn build(self) -> BuiltInlineTestProject {
        let temp = tempfile::tempdir().expect("failed to create temp dir");
        let root = temp
            .path()
            .canonicalize()
            .expect("failed to canonicalize temp dir");

        for (path, contents) in &self.files {
            ProjectFile::new(root.clone(), path.clone())
                .write(contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
        }

        let project = match self.language {
            Some(language) => TestProject::new(root.clone(), language),
            None => {
                TestProject::from_root_with_inferred_languages(root.clone()).unwrap_or_else(|err| {
                    panic!("inline test project must include at least one supported file: {err}")
                })
            }
        };

        let built = BuiltInlineTestProject { temp, project };
        if self.git {
            init_git_repo_with_identity(built.root());
            built.commit("initial commit");
        }
        built
    }
}

pub struct BuiltInlineTestProject {
    temp: tempfile::TempDir,
    project: TestProject,
}

impl BuiltInlineTestProject {
    pub fn project(&self) -> &TestProject {
        &self.project
    }

    pub fn project_arc(&self) -> Arc<TestProject> {
        Arc::new(self.project.clone())
    }

    pub fn project_dyn(&self) -> Arc<dyn Project> {
        self.project_arc()
    }

    pub fn root(&self) -> &Path {
        self.project.root()
    }

    pub fn file(&self, rel_path: impl AsRef<Path>) -> ProjectFile {
        ProjectFile::new(
            self.project.root().to_path_buf(),
            rel_path.as_ref().to_path_buf(),
        )
    }

    pub fn languages(&self) -> BTreeSet<Language> {
        self.project.analyzer_languages()
    }

    /// Stage every file under the root and commit them.
    ///
    /// Only meaningful for a project built with [`InlineTestProject::with_git`];
    /// git reports the missing repository and [`run_git`] panics with its
    /// transcript otherwise.
    pub fn commit(&self, message: &str) {
        run_git(self.root(), &["add", "-A"]);
        run_git(self.root(), &["commit", "-m", message]);
    }

    pub fn workspace_analyzer(&self, config: AnalyzerConfig) -> WorkspaceAnalyzer {
        WorkspaceAnalyzer::build_ephemeral_footgun(self.project_dyn(), config)
            .expect("ephemeral inline workspace should build")
    }
}
