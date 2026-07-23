use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, PhpDefinitionProvider, ResolutionSession, php_type_lookup_resolution_bounded,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{
    BoundedDefinitionLookup, IAnalyzer, PhpAnalyzer, ProjectFile, resolve_analyzer,
};
use crate::cancellation::CancellationToken;
use tree_sitter::Tree;

pub(crate) fn resolve_php_type_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return session.finish(no_type(
            "php_analyzer_unavailable",
            "PHP analyzer is unavailable",
        ));
    };
    let support = PhpDefinitionProvider::new(php, &session);
    let Some(resolution) =
        php_type_lookup_resolution_bounded(analyzer, &support, file, source, tree, site, &session)
    else {
        return session.finish(no_type(
            "php_no_supported_type",
            format!(
                "`{}` does not have a supported structured PHP type",
                site.text
            ),
        ));
    };
    let candidates = support.fqn(&resolution.fqn);
    if candidates.is_empty() {
        return session.finish(no_type(
            "php_no_indexed_type_definition",
            format!(
                "`{}` resolved as a PHP type but has no exact indexed definition",
                resolution.fqn
            ),
        ));
    }
    let outcome =
        candidates_outcome_with_target_kind(resolution.fqn, candidates, resolution.target_kind);
    session.finish(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::get_definition::BoundedResolution;
    use crate::analyzer::usages::get_type::TypeLookupStatus;
    use crate::analyzer::{Language, Range, TestProject};
    use crate::{AnalyzerConfig, WorkspaceAnalyzer};
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn bounded_php_current_receiver_resolves_to_its_exact_owner() {
        let source = r#"<?php
namespace Receiver;
class Service {
    public function current(): void { $this->run(); }
    public function run(): void {}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Receiver.php"));
        file.write(source).expect("write PHP fixture");
        let workspace = WorkspaceAnalyzer::build(
            Arc::new(TestProject::new(root, Language::Php)),
            AnalyzerConfig::default(),
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("PHP grammar");
        let tree = parser.parse(source, None).expect("PHP syntax tree");
        let start = source.find("$this").expect("current receiver");
        let range = Range {
            start_byte: start,
            end_byte: start + "$this".len(),
            start_line: 0,
            end_line: 0,
        };
        let site = ResolvedReferenceSite {
            path: "Receiver.php".to_string(),
            text: "$this".to_string(),
            range,
            focus_start_byte: range.start_byte,
            focus_end_byte: range.end_byte,
        };

        let outcome = resolve_php_type_bounded(
            workspace.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("bounded PHP current-receiver lookup did not complete: {outcome:#?}");
        };
        assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:#?}");
        assert_eq!(value.types.len(), 1, "{value:#?}");
        assert!(
            value.types[0].fqn.ends_with("Receiver.Service"),
            "{value:#?}"
        );
        assert_eq!(value.types[0].definitions.len(), 1, "{value:#?}");
    }
}
