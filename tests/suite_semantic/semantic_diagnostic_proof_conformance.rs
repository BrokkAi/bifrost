use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    Range, SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
    SemanticDiagnosticReportStatus,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::common::InlineTestProject;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedPublication {
    Error,
    Suppressed,
}

struct DiagnosticCase {
    name: &'static str,
    report: SemanticDiagnosticReport,
    expected_outcome: SemanticDiagnosticOutcome,
    expected_publication: ExpectedPublication,
}

#[derive(Deserialize)]
struct CorpusManifest {
    schema_version: u32,
    fixtures: Vec<CorpusFixture>,
}

#[derive(Deserialize)]
struct CorpusFixture {
    ecosystem: String,
    project: String,
    source: String,
    path: String,
    sha256: String,
}

fn range(start_byte: usize) -> Range {
    Range {
        start_byte,
        end_byte: start_byte + 7,
        start_line: 0,
        end_line: 0,
    }
}

fn diagnostic(range: Range, name: &str) -> SemanticDiagnostic {
    SemanticDiagnostic {
        range,
        source: "bifrost-conformance",
        kind: "unrecognized_symbol",
        message: format!("Unrecognized symbol `{name}`"),
    }
}

fn absent_case(
    name: &'static str,
    range: Range,
    domain: SemanticDiagnosticDomain,
    boundary: BoundaryStatus,
) -> DiagnosticCase {
    let mut report = SemanticDiagnosticReport::new();
    let proof = SemanticAbsenceProof {
        range,
        domain,
        boundary,
    };
    report.push_absent(proof.clone(), diagnostic(range, name));
    DiagnosticCase {
        name,
        report,
        expected_outcome: SemanticDiagnosticOutcome::Absent(proof),
        expected_publication: ExpectedPublication::Error,
    }
}

fn resolved_case(name: &'static str, range: Range, boundary: BoundaryStatus) -> DiagnosticCase {
    let mut report = SemanticDiagnosticReport::new();
    report.push_resolved(range, boundary);
    DiagnosticCase {
        name,
        report,
        expected_outcome: SemanticDiagnosticOutcome::Resolved { range, boundary },
        expected_publication: ExpectedPublication::Suppressed,
    }
}

fn incomplete_case(
    name: &'static str,
    range: Range,
    reasons: Vec<SemanticDiagnosticIncompleteReason>,
) -> DiagnosticCase {
    let mut report = SemanticDiagnosticReport::new();
    report.push_incomplete(Some(range), reasons.clone());
    DiagnosticCase {
        name,
        report,
        expected_outcome: SemanticDiagnosticOutcome::Incomplete {
            range: Some(range),
            reasons,
        },
        expected_publication: ExpectedPublication::Suppressed,
    }
}

fn conformance_cases() -> Vec<DiagnosticCase> {
    let project = InlineTestProject::new()
        .file("src/app/Consumer.java", "package app; class Consumer {}")
        .file("src/app/Helper.kt", "package app\nclass Helper")
        .build();
    let workspace_file = project.file("src/app/Consumer.java");

    let known = range(0);
    let missing = range(10);
    let external = range(20);
    let declared = range(30);
    let unknown = range(40);
    let ambiguous = range(50);
    let corrupt = range(60);
    let cancelled = range(70);
    let generated = range(80);
    let dynamic = range(90);
    let near_miss = range(100);

    let mut ambiguous_report = SemanticDiagnosticReport::new();
    let ambiguous_boundaries = vec![
        BoundaryStatus::WorkspaceLocal,
        BoundaryStatus::ExternalIndexed,
    ];
    ambiguous_report.push_ambiguous(ambiguous, ambiguous_boundaries.clone());

    vec![
        resolved_case(
            "known_workspace_symbol",
            known,
            BoundaryStatus::WorkspaceLocal,
        ),
        absent_case(
            "missing_workspace_local_symbol",
            missing,
            SemanticDiagnosticDomain::LexicalScope {
                file: workspace_file.rel_path().to_path_buf(),
                range: missing,
            },
            BoundaryStatus::WorkspaceLocal,
        ),
        resolved_case(
            "indexed_external_symbol",
            external,
            BoundaryStatus::ExternalIndexed,
        ),
        incomplete_case(
            "declared_but_unindexed_dependency",
            declared,
            vec![
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalDeclaredUnindexed,
                },
            ],
        ),
        incomplete_case(
            "unknown_boundary",
            unknown,
            vec![
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                },
            ],
        ),
        DiagnosticCase {
            name: "ambiguous_import_candidates",
            report: ambiguous_report,
            expected_outcome: SemanticDiagnosticOutcome::Ambiguous {
                range: ambiguous,
                boundaries: ambiguous_boundaries,
            },
            expected_publication: ExpectedPublication::Suppressed,
        },
        incomplete_case(
            "corrupt_or_incomplete_pack",
            corrupt,
            vec![SemanticDiagnosticIncompleteReason::CorruptSemanticPack {
                detail: "pack manifest hash does not match its payload".to_string(),
            }],
        ),
        incomplete_case(
            "cancelled_or_stale_activation",
            cancelled,
            vec![
                SemanticDiagnosticIncompleteReason::Cancelled,
                SemanticDiagnosticIncompleteReason::StaleGeneration {
                    expected: 12,
                    actual: 11,
                },
            ],
        ),
        incomplete_case(
            "unsupported_generated_surface",
            generated,
            vec![
                SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface {
                    detail: "annotation processor output is not indexed".to_string(),
                },
            ],
        ),
        incomplete_case(
            "language_specific_dynamic_behavior",
            dynamic,
            vec![SemanticDiagnosticIncompleteReason::DynamicBehavior {
                detail: "Ruby method_missing can provide this member".to_string(),
            }],
        ),
        resolved_case(
            "realistic_same_name_near_miss",
            near_miss,
            BoundaryStatus::ExternalIndexed,
        ),
    ]
}

#[test]
fn semantic_proof_matrix_keeps_errors_and_suppressions_exact() {
    let cases = conformance_cases();
    assert_eq!(cases.len(), 11);

    for case in cases {
        assert_eq!(
            case.report.outcomes(),
            std::slice::from_ref(&case.expected_outcome),
            "{} has the wrong proof or suppression reason",
            case.name
        );
        match case.expected_publication {
            ExpectedPublication::Error => {
                assert_eq!(case.report.diagnostics().len(), 1, "{}", case.name);
                assert_eq!(
                    case.report.status(),
                    SemanticDiagnosticReportStatus::Complete
                );
            }
            ExpectedPublication::Suppressed => {
                assert!(case.report.diagnostics().is_empty(), "{}", case.name);
            }
        }
    }
}

#[test]
fn lsp_projection_can_publish_only_complete_absence_errors() {
    let cases = conformance_cases();
    let published: Vec<_> = cases
        .into_iter()
        .flat_map(|case| {
            case.report
                .into_iter()
                .map(move |diagnostic| (case.name, diagnostic.kind, diagnostic.message))
        })
        .collect();

    assert_eq!(
        published,
        vec![(
            "missing_workspace_local_symbol",
            "unrecognized_symbol",
            "Unrecognized symbol `missing_workspace_local_symbol`".to_string(),
        )]
    );
}

#[test]
fn member_absence_requires_a_complete_owner_surface() {
    let location = range(110);
    let complete = absent_case(
        "missing_member",
        location,
        SemanticDiagnosticDomain::MemberSurface {
            owner: "java.util.List".to_string(),
            member: "definitelyMissing".to_string(),
        },
        BoundaryStatus::ExternalIndexed,
    );
    assert_eq!(complete.report.diagnostics().len(), 1);

    let incomplete = incomplete_case(
        "unindexed_owner_surface",
        location,
        vec![
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalDeclaredUnindexed,
            },
        ],
    );
    assert!(incomplete.report.diagnostics().is_empty());
}

#[test]
fn complete_absence_identifies_each_checked_domain() {
    let project = InlineTestProject::new()
        .file("src/app/Consumer.java", "package app; class Consumer {}")
        .build();
    let location = range(115);
    let domains = vec![
        SemanticDiagnosticDomain::LexicalScope {
            file: project
                .file("src/app/Consumer.java")
                .rel_path()
                .to_path_buf(),
            range: location,
        },
        SemanticDiagnosticDomain::Module {
            name: "app.module".to_string(),
        },
        SemanticDiagnosticDomain::Package {
            name: "app.package".to_string(),
        },
        SemanticDiagnosticDomain::Type {
            name: "app.Owner".to_string(),
        },
        SemanticDiagnosticDomain::MemberSurface {
            owner: "app.Owner".to_string(),
            member: "missing".to_string(),
        },
    ];

    for domain in domains {
        let case = absent_case(
            "missing",
            location,
            domain.clone(),
            BoundaryStatus::WorkspaceLocal,
        );
        assert!(matches!(
            case.report.outcomes(),
            [SemanticDiagnosticOutcome::Absent(SemanticAbsenceProof {
                domain: observed,
                ..
            })] if observed == &domain
        ));
    }
}

#[test]
fn incomplete_reports_keep_all_suppression_reasons_for_one_candidate() {
    let location = range(120);
    let reasons = vec![
        SemanticDiagnosticIncompleteReason::Truncated,
        SemanticDiagnosticIncompleteReason::UnsupportedSemantics {
            detail: "Scala macro expansion is unavailable".to_string(),
        },
        SemanticDiagnosticIncompleteReason::RuntimeUnavailable {
            detail: "semantic model runtime did not start".to_string(),
        },
    ];
    let case = incomplete_case("multiple_incomplete_causes", location, reasons.clone());

    assert_eq!(
        case.report.outcomes(),
        &[SemanticDiagnosticOutcome::Incomplete {
            range: Some(location),
            reasons,
        }]
    );
    assert_eq!(
        case.report.status(),
        SemanticDiagnosticReportStatus::Incomplete
    );
    assert!(case.report.diagnostics().is_empty());
}

#[test]
fn pinned_real_project_witnesses_are_available_offline_and_immutable() {
    let manifest: CorpusManifest = serde_json::from_str(include_str!(
        "../fixtures/semantic-diagnostic-conformance-v1.json"
    ))
    .expect("valid conformance corpus manifest");

    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.fixtures.len(), 2);
    for fixture in manifest.fixtures {
        assert_eq!(fixture.ecosystem, "scala");
        assert!(!fixture.project.is_empty());
        assert!(!fixture.source.is_empty());
        let source = match fixture.path.as_str() {
            "tests/fixtures/scala-issue-1016/JobCtrl.scala" => {
                include_bytes!("../fixtures/scala-issue-1016/JobCtrl.scala").as_slice()
            }
            "tests/fixtures/scala-issue-1068/VCSSpec.scala" => {
                include_bytes!("../fixtures/scala-issue-1068/VCSSpec.scala").as_slice()
            }
            path => panic!("unregistered pinned fixture {path}"),
        };
        assert_eq!(format!("{:x}", Sha256::digest(source)), fixture.sha256);
    }
}
