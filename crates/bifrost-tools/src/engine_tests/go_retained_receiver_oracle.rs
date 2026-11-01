//! #8483: fresh large-budget answers are the reference; every non-stopped answer
//! must match them, and an Exceeded or Cancelled prefix must leave later retained
//! answers exactly as a plain retained run. A complete prepared structural file
//! amortizes setup, so a retained point may answer when a fresh default-budget
//! point stops; that difference alone is not an answer regression.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::structural::FileFacts;
use brokk_bifrost_analysis::analyzer::usages::receiver_query::{
    ReceiverQueryAnalysis, ReceiverQueryError, ReceiverQueryInput, ReceiverQueryOperation,
    ReceiverQueryReport, ReceiverQueryService,
};
use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
use brokk_bifrost_core::analyzer::model::{Language, ProjectFile, Range};
use brokk_bifrost_core::analyzer::project::TestProject;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverAnalysisWork,
};
use brokk_bifrost_core::analyzer::usages::reference_site::node_range;
use brokk_bifrost_core::cancellation::CancellationToken;

#[derive(Clone)]
struct Point {
    file: ProjectFile,
    range: Range,
    operation: ReceiverQueryOperation,
    facts: Option<Arc<FileFacts>>,
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("fixture directory") {
        let path = entry.expect("fixture entry").path();
        if path.is_dir() {
            files_under(&path, out);
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("go" | "mod")
        ) {
            out.push(path);
        }
    }
}

fn collect_points(file: &ProjectFile, source: &str, points: &mut Vec<Point>) {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("Go grammar");
    let tree = parser.parse(source, None).expect("parse Go fixture");
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "selector_expression" | "call_expression") {
            let range = node_range(node);
            for operation in [
                ReceiverQueryOperation::MemberTargets,
                ReceiverQueryOperation::ReceiverTargets,
            ] {
                points.push(Point {
                    file: file.clone(),
                    range,
                    operation,
                    facts: None,
                });
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
}

fn outcome<T: std::fmt::Debug>(value: &ReceiverAnalysisOutcome<T>) -> String {
    match value {
        ReceiverAnalysisOutcome::Precise(values) => format!("Precise({values:#?})"),
        ReceiverAnalysisOutcome::Ambiguous(values) => format!("Ambiguous({values:#?})"),
        ReceiverAnalysisOutcome::Unknown => "Unknown".into(),
        ReceiverAnalysisOutcome::Unsupported { reason } => format!("Unsupported({reason})"),
        ReceiverAnalysisOutcome::ExceededBudget { limit } => format!("ExceededBudget({limit})"),
    }
}

// The report's work ledger is intentionally excluded. All answer-bearing fields remain.
fn answer(report: &ReceiverQueryReport) -> String {
    let analysis = match &report.analysis {
        ReceiverQueryAnalysis::Values(value) => outcome(value),
        ReceiverQueryAnalysis::MemberTargets(value) => outcome(value),
    };
    format!(
        "operation={:?} site={:#?} analysis={} member_range={:?} candidates_truncated={} semantic_unsupported={:?} points_to={:#?}",
        report.operation,
        report.site,
        analysis,
        report.member_range,
        report.candidates_truncated,
        report.semantic_unsupported,
        report.points_to
    )
}

fn go_facts(workspace: &WorkspaceAnalyzer, file: &ProjectFile) -> Arc<FileFacts> {
    workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Go)
        .and_then(|provider| provider.structural_facts(file))
        .expect("Go structural facts")
}

fn query(
    service: &ReceiverQueryService<'_>,
    point: &Point,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<ReceiverQueryReport, ReceiverQueryError> {
    service.analyze_with_structural_facts(
        point.operation,
        &point.file,
        point.range,
        ReceiverQueryInput::ContainingSite,
        point.facts.as_ref().expect("Go structural facts installed"),
        budget,
        cancellation,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Observation {
    Answer(String),
    Stop(String),
    Error(String),
}

struct Reference {
    answer: String,
    work: ReceiverAnalysisWork,
}

fn observe(result: Result<ReceiverQueryReport, ReceiverQueryError>) -> Observation {
    match result {
        Ok(report) => {
            let stopped = match &report.analysis {
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::ExceededBudget {
                    limit,
                })
                | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                    limit,
                }) => Some(*limit),
                _ => None,
            };
            stopped.map_or_else(
                || Observation::Answer(answer(&report)),
                |limit| Observation::Stop(format!("ExceededBudget({limit})")),
            )
        }
        Err(ReceiverQueryError::Cancelled) => Observation::Stop("Cancelled".into()),
        Err(error) => Observation::Error(format!("{error:#?}")),
    }
}

fn run_forward(service: &ReceiverQueryService<'_>, points: &[Point]) -> Vec<Observation> {
    points
        .iter()
        .map(|point| {
            observe(query(
                service,
                point,
                ReceiverAnalysisBudget::default(),
                None,
            ))
        })
        .collect()
}

fn check_answers(
    name: &str,
    points: &[Point],
    actual: &[Observation],
    reference: &[Option<Reference>],
    mismatches: &mut Vec<String>,
) {
    for (index, observation) in actual.iter().enumerate() {
        let Some(expected) = &reference[index] else {
            continue;
        };
        if matches!(observation, Observation::Stop(_)) {
            continue;
        }
        if observation != &Observation::Answer(expected.answer.clone()) {
            mismatches.push(format!(
                "{name} point {index} {:?} {:?}\nexpected: {:#?}\nactual: {observation:#?}",
                points[index].file,
                points[index].operation,
                Observation::Answer(expected.answer.clone())
            ));
        }
    }
}

fn check_no_new_stops(
    name: &str,
    points: &[Point],
    fresh: &[Observation],
    retained: &[Observation],
    mismatches: &mut Vec<String>,
) {
    for (index, (expected, actual)) in fresh.iter().zip(retained).enumerate() {
        if matches!(expected, Observation::Answer(_)) && matches!(actual, Observation::Stop(_)) {
            mismatches.push(format!(
                "{name} point {index} {:?} {:?}: retained stopped after fresh answered\nfresh: {expected:#?}\nretained: {actual:#?}",
                points[index].file, points[index].operation
            ));
        }
    }
}

fn check_isolation(
    name: &str,
    points: &[Point],
    plain: &[Observation],
    after_prefix: &[Observation],
    mismatches: &mut Vec<String>,
) {
    for (index, (expected, actual)) in plain.iter().zip(after_prefix).enumerate() {
        if expected != actual {
            mismatches.push(format!(
                "{name} point {index} {:?} {:?}\nexpected: {expected:#?}\nactual: {actual:#?}",
                points[index].file, points[index].operation
            ));
        }
    }
}

fn large_budget() -> ReceiverAnalysisBudget {
    let default = ReceiverAnalysisBudget::default();
    ReceiverAnalysisBudget {
        max_targets: default.max_targets * 100,
        max_summary_expansions: default.max_summary_expansions * 100,
        max_resolution_rounds: default.max_resolution_rounds * 100,
        max_scope_nodes: default.max_scope_nodes * 100,
        max_hierarchy_order_steps: default.max_hierarchy_order_steps * 100,
        ..default
    }
}

// About a minute of analysis on a large host, so it runs in the release gate.
#[test]
#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
fn go_retained_receiver_oracle() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/golden");
    let families = [
        "go-binding-navigation",
        "go-index-receivers",
        "go-type-assertion-receivers",
        "go-receiver-storage",
    ];
    let mut cases = Vec::new();
    for family in families {
        for entry in std::fs::read_dir(fixture_root.join(family)).expect("golden family") {
            let path = entry.expect("golden case").path();
            if path.is_dir() {
                cases.push(path);
            }
        }
    }
    cases.sort();
    let mut mismatches = Vec::new();
    let mut total_points = 0;
    let mut per_case_counts = Vec::new();
    let mut all_dropped = Vec::new();
    for case in &cases {
        let temporary = tempfile::tempdir().expect("temporary Go project");
        let root = temporary.path().canonicalize().expect("canonical root");
        let mut source_files = Vec::new();
        files_under(case, &mut source_files);
        source_files.sort();
        let mut points = Vec::new();
        for source_file in source_files {
            let relative = source_file.strip_prefix(case).expect("case relative path");
            let target = ProjectFile::new(root.clone(), relative);
            std::fs::create_dir_all(target.abs_path().parent().expect("file parent"))
                .expect("create fixture directory");
            let source = std::fs::read_to_string(&source_file).expect("read Go fixture");
            target.write(&source).expect("copy Go fixture");
            if source_file
                .extension()
                .is_none_or(|extension| extension != "go")
            {
                continue;
            }
            collect_points(&target, &source, &mut points);
        }
        points.sort_by_key(|point| {
            (
                point.file.rel_path().to_path_buf(),
                point.range.start_line,
                point.range.start_byte,
                point.operation.as_str(),
            )
        });
        if points.len() > 12 {
            let stride = points.len().div_ceil(12);
            let mut chosen = std::collections::BTreeSet::new();
            // Include at least one point from each file, then sample the sorted
            // sequence at a fixed stride so later files and sites are visited.
            for (index, point) in points.iter().enumerate() {
                if index == 0 || point.file != points[index - 1].file {
                    chosen.insert(index);
                }
            }
            assert!(
                chosen.len() <= 12,
                "too many Go fixture files: {}",
                case.display()
            );
            for index in (0..points.len()).step_by(stride) {
                if chosen.len() == 12 {
                    break;
                }
                chosen.insert(index);
            }
            points = chosen
                .into_iter()
                .map(|index| points[index].clone())
                .collect();
        }
        total_points += points.len();
        if points.is_empty() {
            continue;
        }
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::Go)),
            AnalyzerConfig::default(),
        )
        .expect("Go workspace");
        for point in &mut points {
            point.facts = Some(go_facts(&workspace, &point.file));
        }
        let mut dropped = Vec::new();
        let reference: Vec<_> = points
            .iter()
            .enumerate()
            .map(|(index, point)| {
                let service = ReceiverQueryService::from_workspace(&workspace);
                let result = query(&service, point, large_budget(), None);
                let work = result.as_ref().ok().map(|report| report.work);
                match observe(result) {
                    Observation::Answer(answer) => Some(Reference {
                        answer,
                        work: work.expect("answered reference has work"),
                    }),
                    Observation::Stop(reason) => {
                        dropped.push(format!(
                            "{} point {index} {:?} {:?}: {reason}",
                            case.display(),
                            point.file,
                            point.operation
                        ));
                        None
                    }
                    Observation::Error(error) => {
                        mismatches.push(format!(
                            "large-budget reference {} point {index} {:?} {:?}: {error}",
                            case.display(),
                            point.file,
                            point.operation
                        ));
                        None
                    }
                }
            })
            .collect();
        let fresh: Vec<_> = points
            .iter()
            .map(|point| {
                let service = ReceiverQueryService::from_workspace(&workspace);
                observe(query(
                    &service,
                    point,
                    ReceiverAnalysisBudget::default(),
                    None,
                ))
            })
            .collect();
        check_answers(
            "fresh default",
            &points,
            &fresh,
            &reference,
            &mut mismatches,
        );
        all_dropped.extend(dropped);
        let forward = ReceiverQueryService::from_workspace(&workspace);
        let plain = run_forward(&forward, &points);
        check_answers(
            "retained forward",
            &points,
            &plain,
            &reference,
            &mut mismatches,
        );
        check_no_new_stops("retained forward", &points, &fresh, &plain, &mut mismatches);
        let reverse = ReceiverQueryService::from_workspace(&workspace);
        let mut reversed = vec![Observation::Error("unvisited".into()); points.len()];
        for index in (0..points.len()).rev() {
            reversed[index] = observe(query(
                &reverse,
                &points[index],
                ReceiverAnalysisBudget::default(),
                None,
            ));
        }
        check_answers(
            "retained reverse",
            &points,
            &reversed,
            &reference,
            &mut mismatches,
        );
        check_no_new_stops(
            "retained reverse",
            &points,
            &fresh,
            &reversed,
            &mut mismatches,
        );
        let compared = reference
            .iter()
            .enumerate()
            .filter(|(index, value)| {
                value.is_some()
                    && [&fresh, &plain, &reversed]
                        .iter()
                        .any(|run| matches!(&run[*index], Observation::Answer(_)))
            })
            .count();
        per_case_counts.push((case.display().to_string(), compared));
        eprintln!("ORACLE_CASE {} compared={compared}", case.display());
        let eligible: Vec<_> = reference
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                let work = value.as_ref()?.work;
                (work.setup_nodes.saturating_add(work.scope_nodes) > 1).then_some(index)
            })
            .collect();
        assert!(
            !eligible.is_empty(),
            "no point can stop after doing scope work: {}",
            case.display()
        );
        for desired in [
            eligible[0],
            eligible[eligible.len() / 2],
            *eligible.last().unwrap(),
        ] {
            let mut stopped_run = None;
            let mut attempts = Vec::new();
            for index in
                std::iter::once(desired).chain(eligible.iter().copied().filter(|&i| i != desired))
            {
                let work = reference[index].as_ref().expect("eligible reference").work;
                let mut budgets = Vec::new();
                if work.summary_expansions > 0 {
                    budgets.push((
                        "summary_expansions",
                        ReceiverAnalysisBudget {
                            max_summary_expansions: work.summary_expansions - 1,
                            ..large_budget()
                        },
                    ));
                }
                if work.resolution_rounds > 0 {
                    budgets.push((
                        "resolution_rounds",
                        ReceiverAnalysisBudget {
                            max_resolution_rounds: work.resolution_rounds - 1,
                            ..large_budget()
                        },
                    ));
                }
                let needed_scope = work.setup_nodes.saturating_add(work.scope_nodes);
                if needed_scope > 1 {
                    budgets.push((
                        "scope_nodes",
                        ReceiverAnalysisBudget {
                            max_scope_nodes: needed_scope - 1,
                            ..large_budget()
                        },
                    ));
                }
                for (limit, budget) in budgets {
                    let service = ReceiverQueryService::from_workspace(&workspace);
                    let stopped = query(&service, &points[index], budget, None);
                    let stopped_work = stopped.as_ref().ok().map(|report| report.work);
                    let result = observe(stopped);
                    let did_work = stopped_work.is_some_and(|work| {
                        work.setup_nodes > 0
                            || work.scope_nodes > 0
                            || work.resolution_rounds > 0
                            || work.summary_expansions > 0
                    });
                    if result == Observation::Stop(format!("ExceededBudget({limit})")) && did_work {
                        stopped_run =
                            Some((service, index, limit, stopped_work.expect("stopped report")));
                        break;
                    }
                    attempts.push(format!("point {index} {limit} need {work:#?} budget {budget:#?}: {result:#?}, work {stopped_work:#?}"));
                }
                if stopped_run.is_some() {
                    break;
                }
            }
            let (exceeded, index, limit, stopped_work) = stopped_run.unwrap_or_else(|| panic!("{} no measured mid-work exceeded prefix for desired point {desired}: {attempts:#?}", case.display()));
            eprintln!(
                "ORACLE_PREFIX {} desired={desired} actual={index} exceeded={limit} work={stopped_work:#?}",
                case.display()
            );
            let after_exceeded = run_forward(&exceeded, &points);
            check_isolation(
                &format!("after exceeded prefix {index}"),
                &points,
                &plain,
                &after_exceeded,
                &mut mismatches,
            );
            let mut cancelled_run = None;
            for checks in [32, 16, 8] {
                let service = ReceiverQueryService::from_workspace(&workspace);
                let token = CancellationToken::cancel_after_checks_for_test(checks);
                assert!(!token.is_cancelled(), "delayed cancellation starts active");
                let result = observe(query(
                    &service,
                    &points[index],
                    large_budget(),
                    Some(&token),
                ));
                if result == Observation::Stop("Cancelled".into()) {
                    assert!(
                        token.is_cancelled(),
                        "stopped point must consume the delayed cancellation checks"
                    );
                    // One check above plus at least `checks - 1` query checks
                    // occurred before the stopped result was returned.
                    assert!(checks > 1);
                    cancelled_run = Some((service, checks));
                    break;
                }
            }
            let (cancelled, checks) =
                cancelled_run.expect("a delayed token must cancel a started point");
            eprintln!(
                "ORACLE_PREFIX {} point {index} cancelled after at least {} query checks",
                case.display(),
                checks - 1
            );
            let after_cancelled = run_forward(&cancelled, &points);
            check_isolation(
                &format!("after cancelled prefix {index}"),
                &points,
                &plain,
                &after_cancelled,
                &mut mismatches,
            );
        }
    }
    assert!(
        all_dropped.is_empty(),
        "large-budget reference dropped points:\n{all_dropped:#?}"
    );
    assert!(
        cases.len() >= families.len()
            && per_case_counts.len() == cases.len()
            && per_case_counts.iter().all(|(_, compared)| *compared > 0),
        "every case must compare an answered point: {per_case_counts:#?}"
    );
    assert!(
        mismatches.is_empty(),
        "{} cases, {total_points} points; mismatches:\n{}",
        cases.len(),
        mismatches.join("\n\n")
    );
}

/// #8483: a retained definition request must pay for an owner frontier on every point.
#[test]
fn go_retained_definition_charges_repeated_owner() {
    let source = r#"package sample

type Base struct{}
func (Base) Method() {}
type Middle struct{ Base }
type Wrapper struct{ Middle }
func use(receiver Wrapper) {
    receiver.Method()
    receiver.Method()
}
"#;
    let temporary = tempfile::tempdir().expect("temporary Go project");
    let root = temporary.path().canonicalize().expect("canonical root");
    ProjectFile::new(root.clone(), "go.mod")
        .write("module example.com/sample\n\ngo 1.23\n")
        .expect("write module");
    let file = ProjectFile::new(root.clone(), "main.go");
    file.write(source).expect("write Go source");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("Go grammar");
    let tree = parser.parse(source, None).expect("parse source");
    let mut stack = vec![tree.root_node()];
    let mut ranges = Vec::new();
    while let Some(node) = stack.pop() {
        if node.kind() == "selector_expression" {
            ranges.push(node_range(node));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    ranges.sort_by_key(|range| range.start_byte);
    assert_eq!(ranges.len(), 2, "expected two selector points: {ranges:#?}");
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        Arc::new(TestProject::new(root, Language::Go)),
        AnalyzerConfig::default(),
    )
    .expect("Go workspace");
    let facts = go_facts(&workspace, &file);
    let first = Point {
        file: file.clone(),
        range: ranges[0],
        operation: ReceiverQueryOperation::MemberTargets,
        facts: Some(Arc::clone(&facts)),
    };
    let second = Point {
        file,
        range: ranges[1],
        operation: ReceiverQueryOperation::MemberTargets,
        facts: Some(facts),
    };
    let fresh = ReceiverQueryService::from_workspace(&workspace);
    let full = query(&fresh, &second, ReceiverAnalysisBudget::default(), None)
        .expect("fresh second definition point");
    let summary_expansions = full.work.summary_expansions;
    assert!(
        summary_expansions > 0,
        "second point must expand an owner: {full:#?}"
    );
    let budget = ReceiverAnalysisBudget {
        max_summary_expansions: summary_expansions - 1,
        ..ReceiverAnalysisBudget::default()
    };
    let bounded_fresh = ReceiverQueryService::from_workspace(&workspace);
    let fresh_result = query(&bounded_fresh, &second, budget, None)
        .expect("bounded fresh second definition point");
    assert!(
        matches!(
            &fresh_result.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget { .. })
        ),
        "fresh request must exceed the summary budget: {fresh_result:#?}"
    );
    let retained = ReceiverQueryService::from_workspace(&workspace);
    query(&retained, &first, ReceiverAnalysisBudget::default(), None)
        .expect("first definition point");
    let retained_result =
        query(&retained, &second, budget, None).expect("bounded retained second definition point");
    assert!(
        matches!(
            &retained_result.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget { .. })
        ),
        "retained request must exceed like fresh; fresh={fresh_result:#?}, retained={retained_result:#?}"
    );
}
