mod common;

use brokk_bifrost::{IAnalyzer, Language, Project, RubyAnalyzer};
use common::InlineTestProject;

fn diagnostic_count(files: &[(&str, &str)], target: &str) -> usize {
    let mut project = InlineTestProject::with_language(Language::Ruby);
    for (path, contents) in files {
        project = project.file(path, *contents);
    }
    let project = project.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let file = project.file(target);
    let source = project
        .project()
        .read_source(&file)
        .expect("read target source");
    analyzer.semantic_diagnostics(&file, &source).len()
}

#[test]
fn ruby_semantic_diagnostics_report_unknown_explicit_constants() {
    assert_eq!(
        diagnostic_count(
            &[("app.rb", "module Billing\nend\nBilling::Missing\n",)],
            "app.rb",
        ),
        1,
        "a known explicit owner must expose its missing terminal constant"
    );
}

#[test]
fn ruby_semantic_diagnostics_follow_project_local_require_closures() {
    assert_eq!(
        diagnostic_count(
            &[
                ("app.rb", "require_relative \"billing\"\nBilling::Present\n"),
                (
                    "billing.rb",
                    "module Billing\n  class Present\n  end\nend\n"
                ),
            ],
            "app.rb",
        ),
        0,
        "a supported require_relative must make indexed constants visible"
    );
    assert_eq!(
        diagnostic_count(
            &[
                ("app.rb", "require \"lib/billing\"\nBilling::Present\n"),
                (
                    "lib/billing.rb",
                    "module Billing\n  class Present\n  end\nend\n"
                ),
            ],
            "app.rb",
        ),
        0,
        "a supported project-root require must make indexed constants visible"
    );
    assert_eq!(
        diagnostic_count(
            &[
                ("app.rb", "require_relative \"boot\"\nBilling::Present\n"),
                ("boot.rb", "require_relative \"billing\"\n"),
                (
                    "billing.rb",
                    "module Billing\n  class Present\n  end\nend\n"
                ),
            ],
            "app.rb",
        ),
        0,
        "the resolver must follow transitive project-local requires"
    );
    assert_eq!(
        diagnostic_count(
            &[
                (
                    "app.rb",
                    "require_relative \"defs\"\nmodule A\n  module B\n    A::B::Present\n  end\nend\n",
                ),
                (
                    "defs.rb",
                    "module A\n  module B\n    class Present\n    end\n  end\nend\n",
                ),
            ],
            "app.rb",
        ),
        0,
        "nested lexical namespaces must retain their canonical owner paths"
    );
}

#[test]
fn ruby_semantic_diagnostics_suppress_dynamic_and_open_boundaries() {
    for (name, files) in [
        (
            "explicit autoload",
            vec![
                (
                    "app.rb",
                    "autoload :Billing, \"billing\"\nBilling::Missing\n",
                ),
                ("billing.rb", "module Billing\nend\n"),
            ],
        ),
        (
            "zeitwerk convention",
            vec![
                ("Gemfile", "gem \"zeitwerk\"\n"),
                ("app/models/billing.rb", "module Billing\nend\n"),
                ("app.rb", "Billing::Missing\n"),
            ],
        ),
        (
            "dynamic constant lookup",
            vec![(
                "app.rb",
                "module Billing\nend\nBilling.const_get(:Missing)\n",
            )],
        ),
        (
            "dynamic required file",
            vec![
                (
                    "app.rb",
                    "require_relative \"generated\"\nmodule Billing\nend\nBilling::Missing\n",
                ),
                (
                    "generated.rb",
                    "module Billing\n  const_set(:Missing, Class.new)\nend\n",
                ),
            ],
        ),
        (
            "dynamic evaluation",
            vec![(
                "app.rb",
                "module Billing\nend\neval(\"Billing::Missing = Class.new\")\nBilling::Missing\n",
            )],
        ),
        (
            "dynamic const_missing definition",
            vec![(
                "app.rb",
                "module Billing\nend\nBilling.define_singleton_method(:const_missing) { |name| Class.new }\nBilling::Missing\n",
            )],
        ),
        (
            "transitive dynamic const_missing definition",
            vec![
                (
                    "app.rb",
                    "require_relative \"runtime\"\nmodule Billing\nend\nBilling::Missing\n",
                ),
                (
                    "runtime.rb",
                    "Billing.define_method(\"const_missing\") { |name| Class.new }\n",
                ),
            ],
        ),
        (
            "transitive unresolved gem require",
            vec![
                (
                    "app.rb",
                    "require_relative \"boot\"\nmodule Billing\nend\nBilling::Missing\n",
                ),
                ("boot.rb", "require \"billing_runtime\"\n"),
            ],
        ),
        (
            "dynamic loader argument",
            vec![(
                "app.rb",
                "module Billing\nend\nBilling.autoload :Missing, ENV.fetch(\"AUTOLOAD_PATH\")\nBilling::Missing\n",
            )],
        ),
        (
            "bare core constant",
            vec![("app.rb", "module Billing\n  String\nend\n")],
        ),
        (
            "unresolved gem require",
            vec![
                ("app.rb", "require \"remote_gem\"\nBilling::Missing\n"),
                ("billing.rb", "module Billing\nend\n"),
            ],
        ),
        ("method call", vec![("app.rb", "missing_call\n")]),
        ("malformed source", vec![("app.rb", "module Billing\n")]),
    ] {
        assert_eq!(
            diagnostic_count(&files, "app.rb"),
            0,
            "{name} must remain outside the high-confidence diagnostic slice"
        );
    }
}

#[test]
fn ruby_semantic_diagnostics_suppress_inheritance_and_mixin_owners() {
    assert_eq!(
        diagnostic_count(
            &[("app.rb", "class Billing\nend\nBilling::Missing\n")],
            "app.rb",
        ),
        0,
        "class constant lookup can inherit from unindexed ancestors"
    );
    assert_eq!(
        diagnostic_count(
            &[(
                "app.rb",
                "module Extra\nend\nmodule Billing\n  include Extra\nend\nBilling::Missing\n",
            )],
            "app.rb",
        ),
        0,
        "module mixins can make a missing-looking constant visible at runtime"
    );
}

#[test]
fn ruby_semantic_diagnostics_bound_large_require_closures() {
    let mut project = InlineTestProject::with_language(Language::Ruby).file(
        "app.rb",
        "require_relative \"dep0\"\nmodule Billing\nend\nBilling::Missing\n",
    );
    for index in 0..64 {
        let next = (index + 1 < 64).then(|| format!("require_relative \"dep{}\"\n", index + 1));
        project = project.file(format!("dep{index}.rb"), next.unwrap_or_default());
    }
    let project = project.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let file = project.file("app.rb");
    let source = project
        .project()
        .read_source(&file)
        .expect("read target source");
    assert!(
        analyzer.semantic_diagnostics(&file, &source).is_empty(),
        "an overwide dependency closure must fail closed"
    );
}

#[test]
fn ruby_semantic_diagnostics_bound_required_source_bytes() {
    let oversized_dependency = "# generated\n".repeat(200_000);
    assert_eq!(
        diagnostic_count(
            &[
                (
                    "app.rb",
                    "require_relative \"generated\"\nmodule Billing\nend\nBilling::Missing\n",
                ),
                ("generated.rb", &oversized_dependency),
            ],
            "app.rb",
        ),
        0,
        "an oversized required source must fail closed before repeated parsing"
    );
}
