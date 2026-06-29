// Ruby usage discovery via `RubyUsageGraphStrategy`. Ruby's dynamic dispatch
// only permits precise graph hits when parser/analyzer facts prove the receiver
// or constant target. These tests pin structured Ruby usage discovery.

mod common;

use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{
    CandidateFileProvider, FuzzyResult, ImportGraphCandidateProvider, UsageFinder,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, ProjectFile, RubyAnalyzer, TestProject};
use common::{InlineTestProject, ruby_analyzer_with_files};

fn analyzer() -> RubyAnalyzer {
    RubyAnalyzer::from_project(TestProject::new(
        std::fs::canonicalize("tests/fixtures/usage-graph-ruby").unwrap(),
        brokk_bifrost::Language::Ruby,
    ))
}

fn definition(analyzer: &RubyAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn hit_enclosing_ids(analyzer: &RubyAnalyzer, fq_name: &str) -> Vec<String> {
    let target = definition(analyzer, fq_name);
    analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed")
        .iter()
        .map(|hit| hit.enclosing.identifier().to_string())
        .collect()
}

fn hit_source_lines(
    hits: &std::collections::BTreeSet<brokk_bifrost::usages::UsageHit>,
) -> Vec<String> {
    hits.iter()
        .map(|hit| {
            let source = std::fs::read_to_string(hit.file.abs_path()).expect("read hit file");
            source
                .lines()
                .nth(hit.line - 1)
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .collect()
}

struct FixedCandidateProvider {
    files: HashSet<ProjectFile>,
}

impl CandidateFileProvider for FixedCandidateProvider {
    fn find_candidates(
        &self,
        _target: &CodeUnit,
        _analyzer: &dyn IAnalyzer,
    ) -> HashSet<ProjectFile> {
        self.files.clone()
    }
}

#[test]
fn finds_cross_file_method_usage() {
    let analyzer = analyzer();
    let target = definition(&analyzer, "Greeter.greet");

    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    // The only call site is App#run in app.rb.
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "run"),
        "expected Greeter#greet usage inside App#run, got {:?}",
        hits.iter()
            .map(|h| h.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn finds_method_usage_through_a_mixin() {
    let analyzer = analyzer();
    // `log` is defined on module Loggable and called inside Service (which
    // includes Loggable). Name-based resolution finds both call sites.
    let target = definition(&analyzer, "Loggable.log");

    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let enclosing: Vec<String> = hits
        .iter()
        .map(|h| h.enclosing.identifier().to_string())
        .collect();
    assert!(enclosing.iter().any(|id| id == "work"), "got {enclosing:?}");
    assert!(
        enclosing.iter().any(|id| id == "retry_work"),
        "got {enclosing:?}"
    );
}

#[test]
fn does_not_report_the_declaration_as_a_usage() {
    let analyzer = analyzer();
    let target = definition(&analyzer, "Greeter.greet");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    // The `def greet` declaration itself must not be counted as a usage.
    assert!(hits.iter().all(|hit| hit.enclosing.identifier() != "greet"));
}

#[test]
fn import_graph_candidates_include_indirect_ruby_require_importers() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require "app/services/user_service"

class App
  def run
    User.build
  end
end
"#,
        ),
        (
            "app/services/user_service.rb",
            r#"
require "app/models/user"

class UserService
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
  def self.build
    new
  end
end
"#,
        ),
    ]);
    let target = definition(&analyzer, "User.build");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 100, 100);
    assert!(
        query.candidate_files.contains(&ProjectFile::new(
            project.root().to_path_buf(),
            "app/main.rb"
        )),
        "expected indirect importer to be an import-graph candidate, got {:?}",
        query.candidate_files
    );
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "run"),
        "expected User.build usage inside App#run, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn resolves_constant_usages_through_project_local_require_visibility() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "app/main.rb",
            r#"
require "app/models/user"

class App
  def run
    User
  end
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
end
"#,
        ),
        (
            "app/other.rb",
            r#"
class Other
  def run
    User
  end
end
"#,
        ),
    ]);

    let target = definition(&analyzer, "User");
    let provider = FixedCandidateProvider {
        files: [project.file("app/main.rb"), project.file("app/other.rb")]
            .into_iter()
            .collect(),
    };
    let hits = UsageFinder::new()
        .query_with_provider(&analyzer, &[target], Some(&provider), 100, 100)
        .result
        .into_either()
        .expect("usage lookup should succeed");
    let enclosing: Vec<String> = hits.iter().map(|hit| hit.enclosing.fq_name()).collect();

    assert!(
        enclosing.iter().any(|name| name == "App.run"),
        "{enclosing:?}"
    );
    assert!(
        enclosing.iter().all(|name| name != "Other.run"),
        "{enclosing:?}"
    );
}

#[test]
fn resolves_relative_qualified_constants_through_lexical_namespace() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/models.rb",
        r#"
module A
  module B
    class C
    end
  end

  class App
    def run
      B::C
    end
  end
end

module Other
  module B
    class C
    end
  end
end
"#,
    )]);

    let target = definition(&analyzer, "A$B$C");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let enclosing: Vec<String> = hits.iter().map(|hit| hit.enclosing.fq_name()).collect();

    assert!(
        enclosing.iter().any(|name| name == "A$App.run"),
        "{enclosing:?}"
    );
}

#[test]
fn resolves_explicit_receiver_from_local_construction_without_same_name_false_positives() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
class User
  def save
  end
end

class Account
  def save
  end
end

class App
  def run
    user = User.new
    user.save

    account = Account.new
    account.save
  end
end
"#,
    )]);

    let target = definition(&analyzer, "User.save");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let snippets: Vec<String> = hits.iter().map(|hit| hit.snippet.clone()).collect();

    assert!(snippets.iter().any(|snippet| snippet.contains("user.save")));
    assert!(
        !snippets
            .iter()
            .any(|snippet| snippet.contains("account.save"))
    );
}

#[test]
fn reports_class_constant_usages_when_constant_is_call_receiver() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
class User
  def self.find
  end
end

class App
  def run
    User.find
    User.new
  end
end
"#,
    )]);

    let target = definition(&analyzer, "User");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);

    assert!(lines.iter().any(|line| line == "User.find"), "{lines:?}");
    assert!(lines.iter().any(|line| line == "User.new"), "{lines:?}");
}

#[test]
fn resolves_bare_calls_through_enclosing_class_and_superclass() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/service.rb",
        r#"
class BaseService
  def audit
  end
end

class UserService < BaseService
  def run
    audit
  end
end
"#,
    )]);

    let enclosing = hit_enclosing_ids(&analyzer, "BaseService.audit");
    assert!(enclosing.iter().any(|id| id == "run"), "{enclosing:?}");
}

#[test]
fn resolves_bare_calls_inside_singleton_class_as_class_method_calls() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
class User
  class << self
    def run
      build
      self.build
    end

    def build
    end
  end
end
"#,
    )]);

    let target = definition(&analyzer, "User.build");
    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("usage lookup should succeed");
    let lines = hit_source_lines(&hits);

    assert!(lines.iter().any(|line| line == "build"), "{lines:?}");
    assert!(lines.iter().any(|line| line == "self.build"), "{lines:?}");
}

#[test]
fn distinguishes_include_and_extend_receiver_polarity() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
module Findable
  def find
  end
end

module Auditable
  def audit
  end
end

class User
  extend Findable
  include Auditable
end

class App
  def run
    User.find
    User.new.audit
    User.audit
    User.new.find
  end
end
"#,
    )]);

    let find = definition(&analyzer, "Findable.find");
    let find_hits = analyzer
        .find_usages(&[find])
        .into_either()
        .expect("find lookup should succeed");
    let find_lines = hit_source_lines(&find_hits);
    assert!(find_lines.iter().any(|line| line == "User.find"));
    assert!(
        !find_lines.iter().any(|line| line == "User.new.find"),
        "{find_lines:?}"
    );

    let audit = definition(&analyzer, "Auditable.audit");
    let audit_hits = analyzer
        .find_usages(&[audit])
        .into_either()
        .expect("audit lookup should succeed");
    let audit_lines = hit_source_lines(&audit_hits);
    assert!(audit_lines.iter().any(|line| line == "User.new.audit"));
    assert!(
        !audit_lines.iter().any(|line| line == "User.audit"),
        "{audit_lines:?}"
    );
}

#[test]
fn reports_unsafe_inference_for_only_dynamic_or_untyped_same_name_calls() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "app/user.rb",
        r#"
class User
  def save
  end
end

class App
  def run(obj)
    obj.save
    send(:save)
  end
end
"#,
    )]);

    let target = definition(&analyzer, "User.save");
    let query = UsageFinder::new().query(&analyzer, &[target], 100, 100);
    let diagnostic = query.graph_failure.expect("graph failure diagnostic");

    assert_eq!("RubyUsageGraphStrategy", diagnostic.strategy);
    assert_eq!("unsafe_inference", diagnostic.reason_kind);
    assert!(
        matches!(query.result, FuzzyResult::Failure { .. }),
        "expected failure, got {:?}",
        query.result
    );
}

#[test]
fn ruby_usage_graph_includes_rails_autoload_consumers() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[
        (
            "Gemfile",
            r#"source "https://rubygems.org"

gem "rails"
"#,
        ),
        (
            "app/controllers/users_controller.rb",
            r#"
class UsersController
  def show
    User.build
  end
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
  def self.build
    new
  end
end
"#,
        ),
    ]);
    let target = definition(&analyzer, "User.build");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 100, 100);
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "show"),
        "expected User.build usage inside UsersController#show, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn zeitwerk_candidates_are_filtered_before_usage_file_cap() {
    let mut builder = InlineTestProject::with_language(Language::Ruby)
        .file(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"rails\"\n",
        )
        .file(
            "app/controllers/users_controller.rb",
            r#"
class UsersController
  def show
    User.build
  end
end
"#,
        )
        .file(
            "app/models/user.rb",
            r#"
class User
  def self.build
    new
  end
end
"#,
        );
    for index in 0..40 {
        builder = builder.file(
            format!("app/services/noise_{index}.rb"),
            format!(
                r#"
class Noise{index}
  def call
    :ok
  end
end
"#
            ),
        );
    }
    let project = builder.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let target = definition(&analyzer, "User.build");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 2, 100);
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "show"),
        "expected User.build usage inside UsersController#show despite many irrelevant Zeitwerk files, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn zeitwerk_usage_candidates_include_non_app_ruby_consumers() {
    let (project, analyzer) = ruby_analyzer_with_files(&[
        (
            "Gemfile",
            r#"source "https://rubygems.org"

gem "rails"
"#,
        ),
        (
            "spec/models/user_spec.rb",
            r#"
class UserSpec
  def verifies_build
    User.build
  end
end
"#,
        ),
        (
            "app/models/user.rb",
            r#"
class User
  def self.build
    new
  end
end
"#,
        ),
    ]);
    let target = definition(&analyzer, "User.build");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 2, 100);
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter()
            .any(|hit| hit.enclosing.source() == &project.file("spec/models/user_spec.rb")),
        "expected User.build usage in spec/models/user_spec.rb, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn zeitwerk_structured_candidates_do_not_evict_precise_importers() {
    let mut builder = InlineTestProject::with_language(Language::Ruby)
        .file(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"rails\"\n",
        )
        .file(
            "app/controllers/users_controller.rb",
            r#"
require "app/models/user"

class UsersController
  def show
    User.call
  end
end
"#,
        )
        .file(
            "app/models/user.rb",
            r#"
class User
  def self.call
    new
  end
end
"#,
        );
    for index in 0..40 {
        builder = builder.file(
            format!("app/services/noise_{index}.rb"),
            format!(
                r#"
class Noise{index}
  def call
    :ok
  end
end
"#
            ),
        );
    }
    let project = builder.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let target = definition(&analyzer, "User.call");
    let provider = ImportGraphCandidateProvider::new();

    let query =
        UsageFinder::new().query_with_provider(&analyzer, &[target], Some(&provider), 2, 100);
    assert!(
        query
            .candidate_files
            .contains(&project.file("app/controllers/users_controller.rb")),
        "explicit require importer should remain in capped provider candidates, got {:?}",
        query.candidate_files
    );
    let hits = query
        .result
        .into_either()
        .expect("usage lookup should succeed");
    assert!(
        hits.iter().any(|hit| hit.enclosing.identifier() == "show"),
        "expected User.call usage inside UsersController#show despite noisy call methods, got {:?}",
        hits.iter()
            .map(|hit| hit.enclosing.fq_name())
            .collect::<Vec<_>>()
    );
}
