use super::*;
use brokk_bifrost_core::analyzer::project::TestProject;
use brokk_bifrost_core::analyzer::usages::model::UsageAnalysisDiagnostic;
use std::path::{Path, PathBuf};
#[doc(hidden)]
pub fn write_project(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonicalize temp dir");
    brokk_bifrost_analysis::test_support::write_fixture_files(&root, files);
    (temp, root)
}

/// A Rails-shaped Zeitwerk layout: `UsersController#show` references `User.build`
/// with no `require`, so only the autoload graph connects the two files.
#[doc(hidden)]
pub fn zeitwerk_project() -> (tempfile::TempDir, PathBuf) {
    write_project(&[
        (
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"rails\"\n",
        ),
        (
            "app/models/user.rb",
            "class User\n  def self.build\n    new\n  end\nend\n",
        ),
        (
            "app/controllers/users_controller.rb",
            "class UsersController\n  def show\n    User.build\n  end\nend\n",
        ),
    ])
}

#[doc(hidden)]
pub fn ruby_analyzer(root: &Path) -> RubyAnalyzer {
    RubyAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Ruby))
}

#[doc(hidden)]
pub fn declaration(analyzer: &dyn IAnalyzer, file: &ProjectFile, identifier: &str) -> CodeUnit {
    analyzer
        .declarations(file)
        .into_iter()
        .find(|unit| unit.identifier() == identifier)
        .unwrap_or_else(|| panic!("fixture declares {identifier} in {file:?}"))
}

#[doc(hidden)]
pub fn fallback_diagnostic(outcome: GraphUsageOutcome) -> UsageAnalysisDiagnostic {
    match outcome {
        GraphUsageOutcome::FallbackSafe(diagnostic) => diagnostic,
        other => panic!("expected a fallback-safe outcome, got {other:?}"),
    }
}
