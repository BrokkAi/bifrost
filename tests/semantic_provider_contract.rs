mod common;

use brokk_bifrost::analyzer::semantic::{
    CancellationToken, SemanticBudget, SemanticBudgetDimension, SemanticCapability,
    SemanticOutcome, SemanticRequest, SemanticWork,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::InlineTestProject;

#[test]
fn workspace_routes_semantics_by_exact_file_language() {
    let project = InlineTestProject::new()
        .file(
            "src/main.ts",
            r#"
                export function main(): number {
                    return 1;
                }
            "#,
        )
        .file(
            "src/Main.java",
            r#"
                final class Main {
                    int value() { return 1; }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let ts = project.file("src/main.ts");
    let java = project.file("src/Main.java");
    let unknown = project.file("README.txt");

    assert!(analyzer.program_semantics_provider_for_file(&ts).is_some());
    assert!(
        analyzer
            .program_semantics_provider_for_file(&java)
            .is_some()
    );
    assert!(
        analyzer
            .program_semantics_provider_for_file(&unknown)
            .is_none()
    );

    let cancellation = CancellationToken::default();
    let mut ts_budget = SemanticBudget::default();
    let ts_outcome = analyzer
        .materialize_program_semantics(
            &ts,
            &mut SemanticRequest::new(&mut ts_budget, &cancellation),
        )
        .expect("TypeScript provider should lower its exact source snapshot");
    let SemanticOutcome::Complete {
        value: artifact,
        work,
    } = ts_outcome
    else {
        panic!("TypeScript semantics should be complete");
    };
    assert_eq!(artifact.procedures().len(), 1);
    assert_eq!(ts_budget.used(), work);
    assert_eq!(artifact.work().source_bytes, 0);
    assert!(work.source_bytes > 0);

    let mut java_budget = SemanticBudget::default();
    let java_outcome = analyzer
        .materialize_program_semantics(
            &java,
            &mut SemanticRequest::new(&mut java_budget, &cancellation),
        )
        .expect("Java provider should read its exact source snapshot");
    let SemanticOutcome::Complete {
        value: artifact,
        work,
    } = java_outcome
    else {
        panic!("Java semantics should be complete");
    };
    assert_eq!(artifact.procedures().len(), 1);
    assert!(work.source_bytes > 0);
    assert_eq!(java_budget.used(), work);
}

#[test]
fn single_language_workspace_does_not_route_a_different_extension() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", "export const value = 1;\n")
        .file("src/Main.java", "final class Main {}\n")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let java = project.file("src/Main.java");

    assert!(
        analyzer
            .program_semantics_provider_for_file(&java)
            .is_none()
    );
    let mut budget = SemanticBudget::default();
    let cancellation = CancellationToken::default();
    assert!(matches!(
        analyzer
            .materialize_program_semantics(
                &java,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("unsupported routing is semantic, not operational"),
        SemanticOutcome::Unsupported {
            capability: SemanticCapability::Procedures,
            partial: None,
            work,
        } if work == SemanticWork::default()
    ));
}

#[test]
fn pre_cancelled_request_never_publishes_or_charges() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/component.tsx",
            r#"
                export const Component = () => <div />;
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/component.tsx");
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let mut budget = SemanticBudget::default();

    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("cancellation is an explicit semantic outcome");
    assert!(matches!(
        outcome,
        SemanticOutcome::Cancelled {
            partial: None,
            work,
        } if work == SemanticWork::default()
    ));
    assert_eq!(budget.used(), SemanticWork::default());
}

#[test]
fn ts_and_tsx_materializations_keep_distinct_dialect_identity() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/value.ts", "export const value = () => 1;\n")
        .file(
            "src/component.tsx",
            "export const Component = () => <div />;\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();

    let materialize = |path: &str| {
        let mut budget = SemanticBudget::default();
        let outcome = analyzer
            .materialize_program_semantics(
                &project.file(path),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript dialect should materialize");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("TypeScript dialect should publish a complete artifact");
        };
        value
    };

    let ts = materialize("src/value.ts");
    let tsx = materialize("src/component.tsx");
    assert_eq!(
        ts.key().language(),
        brokk_bifrost::analyzer::LanguageDialect::Standard(Language::TypeScript)
    );
    assert_eq!(
        tsx.key().language(),
        brokk_bifrost::analyzer::LanguageDialect::TypeScriptTsx
    );
    assert_ne!(ts.key().language(), tsx.key().language());
}

#[test]
fn typescript_materializes_structured_control_calls_cleanup_async_and_gaps() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/flow.ts",
            r#"
                function target(value: number): number {
                    if (value > 0) {
                        return value;
                    }
                    return 0;
                }

                export async function exercise(flag: boolean): Promise<number> {
                    let total = 0;
                    while (flag) {
                        if (total > 2) break;
                        total++;
                        continue;
                    }
                    try {
                        const value = target(await Promise.resolve(total));
                        if (value) return value;
                        throw new Error("missing");
                    } catch (error) {
                        return target(0);
                    } finally {
                        total++;
                    }
                    target(-1);
                }

                const choose = (flag: boolean) => flag ? target(1) : 0;

                function* values() {
                    yield 1;
                    return 2;
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/flow.ts");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();

    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("structured TypeScript fixture should lower and validate");
    let SemanticOutcome::Complete { value, .. } = outcome else {
        panic!("TypeScript fixture should publish a complete artifact");
    };

    assert_eq!(value.procedures().len(), 4);
    assert!(value.procedures().iter().any(|procedure| {
        procedure
            .gaps()
            .iter()
            .any(|gap| gap.capability == SemanticCapability::GeneratorSuspension)
    }));
    assert!(
        value
            .procedures()
            .iter()
            .any(|procedure| !procedure.call_sites().is_empty())
    );
}

#[test]
fn empty_typescript_source_is_a_complete_zero_procedure_artifact() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/empty.ts", "")
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/empty.ts");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();

    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("an empty but valid TypeScript syntax snapshot should materialize");
    let SemanticOutcome::Complete { value, work } = outcome else {
        panic!("empty TypeScript source should be complete");
    };
    assert!(value.procedures().is_empty());
    assert_eq!(budget.used(), work);
    assert_eq!(work.source_bytes, 0);
}

#[test]
fn source_budget_failure_is_explicit_and_atomic() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/limited.ts",
            "export function limited(): number { return 1; }\n",
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/limited.ts");
    let cancellation = CancellationToken::default();
    let mut limits = SemanticBudget::default().limits();
    limits.source_bytes = 1;
    let mut budget = SemanticBudget::new(limits).expect("all semantic limits remain positive");

    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("budget exhaustion is an explicit semantic outcome");
    assert!(matches!(
        outcome,
        SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        } if exceeded.dimension() == SemanticBudgetDimension::SourceBytes
            && exceeded.limit() == 1
            && exceeded.attempted() > 1
            && work.source_bytes > 1
    ));
    assert_eq!(budget.used(), SemanticWork::default());
}
