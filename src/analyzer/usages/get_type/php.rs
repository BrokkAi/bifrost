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

    fn resolve_receiver(
        source: &str,
        receiver: &str,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> BoundedResolution<TypeLookupOutcome> {
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
        let start = source.rfind(receiver).expect("receiver source");
        let line = source[..start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let range = Range {
            start_byte: start,
            end_byte: start + receiver.len(),
            start_line: line,
            end_line: line,
        };
        let site = ResolvedReferenceSite {
            path: "Receiver.php".to_string(),
            text: receiver.to_string(),
            range,
            focus_start_byte: range.start_byte,
            focus_end_byte: range.end_byte,
        };
        resolve_php_type_bounded(
            workspace.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            budget,
            cancellation,
        )
    }

    fn assert_resolved_fqn(outcome: BoundedResolution<TypeLookupOutcome>, expected: &str) {
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("bounded PHP lookup did not complete: {outcome:#?}");
        };
        assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:#?}");
        assert_eq!(value.types.len(), 1, "{value:#?}");
        assert_eq!(value.types[0].fqn, expected, "{value:#?}");
        assert_eq!(value.types[0].definitions.len(), 1, "{value:#?}");
    }

    fn assert_no_precise_type(outcome: BoundedResolution<TypeLookupOutcome>) {
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("bounded PHP lookup did not complete: {outcome:#?}");
        };
        assert_ne!(value.status, TypeLookupStatus::Resolved, "{value:#?}");
        assert!(value.types.is_empty(), "{value:#?}");
    }

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

    #[test]
    fn bounded_php_nominal_paths_resolve_alias_absolute_relative_and_allocation_forms() {
        let source = r#"<?php
namespace App;
use App\Service as Alias;

class Service { public function run(): void {} }

function call(Alias $alias, \App\Service $absolute, namespace\Service $relative): void {
    $alias->run();
    $absolute->run();
    $relative->run();
    (new Alias())->run();
}
"#;

        for receiver in ["$alias", "$absolute", "$relative", "(new Alias())"] {
            assert_resolved_fqn(
                resolve_receiver(source, receiver, ReceiverAnalysisBudget::default(), None),
                "App.Service",
            );
        }
    }

    #[test]
    fn bounded_php_reopens_exact_field_return_and_ancestor_declarations() {
        let source = r#"<?php
namespace App;
use App\Product as ProductAlias;

class Product { public function run(): void {} }
class Holder {
    public Product $item;
    public function make(): Product { return new Product(); }
}
function makeProduct(): Product { return new Product(); }
function makeAliased(): ProductAlias { return new Product(); }
function makeAbsolute(): \App\Product { return new Product(); }
function makeRelative(): namespace\Product { return new Product(); }
class Factory {
    public static function make(): Product { return new Product(); }
}
class Base {
    public function inherited(): Product { return new Product(); }
}
class Child extends Base {
    public function call(Holder $holder): void {
        $holder->item->run();
        $holder->make()->run();
        makeProduct()->run();
        makeAliased()->run();
        makeAbsolute()->run();
        makeRelative()->run();
        Factory::make()->run();
        $this->inherited()->run();
    }
}
"#;

        for receiver in [
            "$holder->item",
            "$holder->make()",
            "makeProduct()",
            "makeAliased()",
            "makeAbsolute()",
            "makeRelative()",
            "Factory::make()",
            "$this->inherited()",
        ] {
            assert_resolved_fqn(
                resolve_receiver(
                    source,
                    receiver,
                    ReceiverAnalysisBudget {
                        max_scope_nodes: 100_000,
                        ..ReceiverAnalysisBudget::default()
                    },
                    None,
                ),
                "App.Product",
            );
        }
    }

    #[test]
    fn bounded_php_nullable_and_union_types_never_publish_one_arm_as_precise() {
        let source = r#"<?php
namespace App;

class Service { public function run(): void {} }
class Other { public function run(): void {} }
interface Left { public function run(): void; }
interface Right { public function run(): void; }
function maybeUnion(): Service|Other { return new Service(); }
function maybeNullable(): ?Service { return new Service(); }
class Holder {
    public Service|Other $choice;
    public ?Service $maybe;
}
function call(Service|Other $union, ?Service $nullable, Holder $holder): void {
    $union->run();
    $nullable->run();
    maybeUnion()->run();
    maybeNullable()->run();
    $holder->choice->run();
    $holder->maybe->run();
}
function callIntersection(Left&Right $intersection): void {
    $intersection->run();
}
"#;

        for receiver in [
            "$union",
            "$nullable",
            "$intersection",
            "maybeUnion()",
            "maybeNullable()",
            "$holder->choice",
            "$holder->maybe",
        ] {
            assert_no_precise_type(resolve_receiver(
                source,
                receiver,
                ReceiverAnalysisBudget {
                    max_scope_nodes: 100_000,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            ));
        }
    }

    #[test]
    fn bounded_php_deep_alternating_receiver_chain_is_stack_safe() {
        let mut receiver = "new Link()".to_string();
        for index in 0..512 {
            receiver = if index % 2 == 0 {
                format!("({receiver})")
            } else {
                format!("{receiver}->next()")
            };
        }
        let source = format!(
            "<?php\nnamespace Deep;\nclass Link {{\n\
             public function next(): Link {{ return new Link(); }}\n\
             public function run(): void {{}}\n\
             }}\nfunction call(): void {{ {receiver}->run(); }}\n"
        );
        let receiver_for_thread = receiver.clone();
        let outcome = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                resolve_receiver(
                    &source,
                    &receiver_for_thread,
                    ReceiverAnalysisBudget {
                        max_scope_nodes: 500_000,
                        max_summary_expansions: 2_000,
                        ..ReceiverAnalysisBudget::default()
                    },
                    None,
                )
            })
            .expect("spawn small-stack PHP lookup")
            .join()
            .expect("bounded PHP lookup must not overflow its thread stack");
        assert_resolved_fqn(outcome, "Deep.Link");
    }

    #[test]
    fn bounded_php_budget_and_cancellation_never_publish_partial_types() {
        let source = r#"<?php
namespace App;
class Service { public function run(): void {} }
function call(Service $service): void { $service->run(); }
"#;

        assert!(matches!(
            resolve_receiver(source, "$service", ReceiverAnalysisBudget::tiny(), None),
            BoundedResolution::Exceeded { .. }
        ));

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            resolve_receiver(
                source,
                "$service",
                ReceiverAnalysisBudget::default(),
                Some(&cancelled)
            ),
            BoundedResolution::Cancelled { .. }
        ));

        let mid_flight = CancellationToken::cancel_after_checks_for_test(12);
        assert!(matches!(
            resolve_receiver(
                source,
                "$service",
                ReceiverAnalysisBudget::default(),
                Some(&mid_flight)
            ),
            BoundedResolution::Cancelled { .. }
        ));
    }
}
