use brokk_bifrost::{CloneSmell, CloneSmellWeights, IAnalyzer, Language, RubyAnalyzer};

use crate::common::InlineTestProject;

fn analyze(
    files: &[(&str, &str)],
    requested_paths: &[&str],
    weights: CloneSmellWeights,
) -> Vec<CloneSmell> {
    let mut builder = InlineTestProject::with_language(Language::Ruby);
    for (path, source) in files {
        builder = builder.file(*path, *source);
    }
    let project = builder.build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    let requested = requested_paths
        .iter()
        .map(|path| project.file(path))
        .collect::<Vec<_>>();
    analyzer.find_structural_clone_smells_for_files(&requested, weights)
}

fn default_weights() -> CloneSmellWeights {
    CloneSmellWeights::defaults()
}

const ALPHA: &str = r#"
def alpha(value)
  total = value + 2
  if total > 20
    return total * 3
  end
  total - 4
end
"#;

const BETA: &str = r#"
def beta(seed)
  amount = seed + 2
  if amount > 20
    return amount * 3
  end
  amount - 4
end
"#;

#[test]
fn flags_renamed_variable_clone_in_ruby() {
    let findings = analyze(
        &[("lib/a.rb", ALPHA), ("lib/b.rb", BETA)],
        &["lib/a.rb"],
        default_weights(),
    );

    assert!(
        findings.iter().any(|finding| {
            finding.enclosing_fq_name.contains("alpha")
                && finding.peer_enclosing_fq_name.contains("beta")
        }),
        "{findings:#?}"
    );
}

#[test]
fn ast_refinement_suppresses_different_ruby_control_flow() {
    let loop_body = r#"
def beta(seed)
  amount = seed + 2
  while amount > 20
    amount -= 1
  end
  amount *= 3
  amount
end
"#;
    let files = [("lib/a.rb", ALPHA), ("lib/b.rb", loop_body)];
    let permissive = analyze(
        &files,
        &["lib/a.rb"],
        CloneSmellWeights {
            min_normalized_tokens: 12,
            min_similarity_percent: 30,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 1,
        },
    );
    assert!(!permissive.is_empty(), "{permissive:#?}");

    let findings = analyze(
        &files,
        &["lib/a.rb"],
        CloneSmellWeights {
            min_normalized_tokens: 12,
            min_similarity_percent: 30,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 85,
        },
    );

    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn strict_threshold_suppresses_small_ruby_methods() {
    let findings = analyze(
        &[
            ("lib/a.rb", "def alpha(x)\n  x + 1\nend"),
            ("lib/b.rb", "def beta(y)\n  y + 1\nend"),
        ],
        &["lib/a.rb"],
        CloneSmellWeights {
            min_normalized_tokens: 30,
            min_similarity_percent: 50,
            shingle_size: 2,
            min_shared_shingles: 2,
            ast_similarity_percent: 70,
        },
    );

    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn ruby_findings_have_stable_report_order() {
    let gamma = BETA.replace("beta", "gamma");
    let findings = analyze(
        &[
            ("lib/c.rb", gamma.as_str()),
            ("lib/b.rb", BETA),
            ("lib/a.rb", ALPHA),
        ],
        &["lib/c.rb", "lib/b.rb", "lib/a.rb"],
        default_weights(),
    );
    let pairs = findings
        .iter()
        .map(|finding| {
            (
                finding.file.to_string().replace('\\', "/"),
                finding.peer_file.to_string().replace('\\', "/"),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        vec![
            ("lib/a.rb".to_string(), "lib/b.rb".to_string()),
            ("lib/a.rb".to_string(), "lib/c.rb".to_string()),
            ("lib/b.rb".to_string(), "lib/c.rb".to_string()),
        ],
        pairs
    );
}

#[test]
fn includes_singleton_method_candidates() {
    let alpha = r#"
class Alpha
  def self.compute(value)
    total = value + 2
    if total > 20
      return total * 3
    end
    total - 4
  end
end
"#;
    let beta = r#"
class Beta
  def self.calculate(seed)
    amount = seed + 2
    if amount > 20
      return amount * 3
    end
    amount - 4
  end
end
"#;
    let findings = analyze(
        &[("lib/a.rb", alpha), ("lib/b.rb", beta)],
        &["lib/a.rb"],
        default_weights(),
    );

    assert!(
        findings.iter().any(|finding| {
            finding.enclosing_fq_name.contains("compute")
                && finding.peer_enclosing_fq_name.contains("calculate")
        }),
        "{findings:#?}"
    );
}
