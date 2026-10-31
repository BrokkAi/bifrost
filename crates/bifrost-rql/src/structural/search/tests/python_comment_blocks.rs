use super::*;

fn blocks(language: Language, filename: &str, source: &str) -> Vec<String> {
    let project = InlineTestProject::with_language(language)
        .file(filename, source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &CodeQuery::from_source("(python-commented-out-code (comment))").unwrap(),
    );
    result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => value.comment_block_text.clone(),
            _ => None,
        })
        .collect()
}

#[test]
fn python_comment_blocks_exclude_foreign_language_comments() {
    let source = "#if enabled:\n#    run_task()\nactive=1\n";
    assert_eq!(
        blocks(Language::Python, "sample.py", source),
        ["#if enabled:\n#    run_task()"]
    );
    assert!(blocks(Language::Ruby, "sample.rb", source).is_empty());
}

#[test]
fn python_comment_blocks_allow_a_minority_of_prose() {
    assert_eq!(
        blocks(
            Language::Python,
            "sample.py",
            "# explanation in prose\n#if enabled:\n#    run_task()\nactive=1\n"
        ),
        ["#if enabled:\n#    run_task()"]
    );
}

#[test]
fn python_comment_blocks_require_indented_suites() {
    assert!(
        blocks(
            Language::Python,
            "sample.py",
            "#if enabled:\n#run_task()\nactive=1\n"
        )
        .is_empty()
    );
    assert_eq!(
        blocks(
            Language::Python,
            "sample.py",
            "#if enabled:\n#    run_task()\nactive=1\n"
        ),
        ["#if enabled:\n#    run_task()"]
    );
}

#[test]
fn python_comment_blocks_recognize_with_suites() {
    assert_eq!(
        blocks(
            Language::Python,
            "sample.py",
            "#with resource() as r:\n#    run_task()\nactive=1\n"
        ),
        ["#with resource() as r:\n#    run_task()"]
    );
}

#[test]
fn python_comment_blocks_recognize_try_suites() {
    assert_eq!(
        blocks(
            Language::Python,
            "sample.py",
            "#try:\n#    run_task()\nactive=1\n"
        ),
        ["#try:\n#    run_task()"]
    );
}
