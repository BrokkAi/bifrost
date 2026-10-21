use super::super::lexical_environment::environment_for_file;
use super::super::provider::StructuralSyntaxLimitedOutcome;
use super::*;

use crate::analyzer::AnalyzerConfig;
use crate::inline_project::InlineTestProject;

#[doc(hidden)]
pub fn rows(language: Language, path: &str, source: &str) -> Vec<BranchRelationRow> {
    let fixture = InlineTestProject::with_language(language)
        .file(path, source)
        .build();
    let file = fixture.file(path);
    let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
    let provider = analyzer
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .expect("language has a structural provider");
    let StructuralSyntaxLimitedOutcome::Available(syntax) =
        provider.structural_syntax_limited(&file, 32 * 1024, None)
    else {
        panic!("fixture syntax unavailable");
    };
    let syntax = syntax.into_inner();
    let mut stack = vec![syntax.tree().root_node()];
    let mut found = None;
    while let Some(node) = stack.pop() {
        if node.kind() == "if_statement" && !is_chain_child(node) {
            found = Some(node);
            break;
        }
        for index in (0..node.child_count()).rev() {
            stack.push(node.child(index).expect("child index is in bounds"));
        }
    }
    let node = found.expect("fixture has an if statement");
    let env = environment_for_file(analyzer.analyzer(), &file);
    relations_for_if(
        &syntax,
        language,
        node_range(node),
        &env,
        &BranchReferenceProofs::default(),
    )
}
#[doc(hidden)]
pub fn verdicts(
    rows: &[BranchRelationRow],
    kind: BranchRelationKind,
) -> Vec<BranchRelationVerdict> {
    rows.iter()
        .filter(|row| row.kind == kind)
        .map(|row| row.verdict)
        .collect()
}
#[doc(hidden)]
pub fn identical_bodies(
    language: Language,
    path: &str,
    source: &str,
) -> Vec<BranchRelationVerdict> {
    verdicts(
        &rows(language, path, source),
        BranchRelationKind::IdenticalBodies,
    )
}
