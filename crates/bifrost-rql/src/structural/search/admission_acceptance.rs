//! Real-query admission checks. Pressure begins only at the native finalizer.
//! Test fixtures are authored here, without product packs or persisted changes.

#[path = "admission_policy_acceptance.rs"]
mod policy_acceptance;

#[path = "admission_source_budget_acceptance.rs"]
mod source_budget_acceptance;

use super::tests::inline_project::InlineTestProject;
use super::*;
use crate::analyzer::AnalyzerConfig;
use brokk_bifrost_core::retention_budget::{RetentionBudget, SharedBackingLease};
use brokk_bifrost_test_macros::hardwon;
use brokk_bifrost_tools::site_context::{
    KnownValueView, SiteLocationView, SiteValueView, UnrenderedReason,
};
use std::cell::RefCell;
use std::sync::Weak;

#[derive(Default, Debug)]
struct WindowTrace {
    opened: Vec<ProjectFile>,
    source_loads: Vec<ProjectFile>,
    closed: Vec<ProjectFile>,
    active: usize,
    peak: usize,
    acquired: Vec<AcquiredFacts>,
    candidate_rows: usize,
    candidate_traces: usize,
    held_facts: usize,
}

#[derive(Debug)]
struct AcquiredFacts {
    file: ProjectFile,
    backing: Weak<FileFacts>,
    strong_at_acquire: usize,
    strong_after_close: Option<usize>,
}

thread_local! {
    static WINDOW_TRACE: RefCell<Option<WindowTrace>> = const { RefCell::new(None) };
}

struct ObserveWindows;

impl ObserveWindows {
    fn start() -> Self {
        WINDOW_TRACE.with(|trace| {
            assert!(trace.borrow().is_none(), "window observers cannot nest");
            *trace.borrow_mut() = Some(WindowTrace::default());
        });
        Self
    }

    fn finish(self) -> WindowTrace {
        let trace = WINDOW_TRACE.with(|trace| trace.borrow_mut().take().unwrap());
        assert_eq!(
            trace.active, 0,
            "a presentation file window escaped: {trace:?}"
        );
        trace
    }
}

impl Drop for ObserveWindows {
    fn drop(&mut self) {
        WINDOW_TRACE.with(|trace| {
            drop(trace.borrow_mut().take());
        });
    }
}

/// The hook is reached at the actual per-file loop, not inferred from results.
/// This guard is declared before `acquired`, so normal return and unwinding
/// drop the actual acquired Arc before observing the close event.
pub(super) struct ObservedFileWindow(Option<ProjectFile>);

pub(super) fn observe_file_window(file: &ProjectFile) -> ObservedFileWindow {
    let file = WINDOW_TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        let trace = trace.as_mut()?;
        trace.opened.push(file.clone());
        trace.active += 1;
        trace.peak = trace.peak.max(trace.active);
        Some(file.clone())
    });
    ObservedFileWindow(file)
}

// Count actual iterator visits, independent of elapsed time and output size.
pub(super) fn observe_source_load(file: &ProjectFile) {
    WINDOW_TRACE.with(|trace| {
        if let Some(trace) = trace.borrow_mut().as_mut() {
            trace.source_loads.push(file.clone());
        }
    });
}

pub(super) fn observe_candidate_row() {
    WINDOW_TRACE.with(|trace| {
        if let Some(trace) = trace.borrow_mut().as_mut() {
            trace.candidate_rows += 1;
        }
    });
}

pub(super) fn observe_candidate_trace() {
    WINDOW_TRACE.with(|trace| {
        if let Some(trace) = trace.borrow_mut().as_mut() {
            trace.candidate_traces += 1;
        }
    });
}

pub(super) fn observe_held_fact() {
    WINDOW_TRACE.with(|trace| {
        if let Some(trace) = trace.borrow_mut().as_mut() {
            trace.held_facts += 1;
        }
    });
}

pub(super) fn observe_acquired(file: &ProjectFile, facts: Option<&Arc<FileFacts>>) {
    WINDOW_TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if let (Some(trace), Some(facts)) = (trace.as_mut(), facts) {
            trace.acquired.push(AcquiredFacts {
                file: file.clone(),
                backing: Arc::downgrade(facts),
                strong_at_acquire: Arc::strong_count(facts),
                strong_after_close: None,
            });
        }
    });
}

impl Drop for ObservedFileWindow {
    fn drop(&mut self) {
        if let Some(file) = &self.0 {
            WINDOW_TRACE.with(|trace| {
                let mut trace = trace.borrow_mut();
                let trace = trace
                    .as_mut()
                    .expect("observer lives through its file windows");
                for acquired in trace.acquired.iter_mut().filter(|acquired| {
                    acquired.file == *file && acquired.strong_after_close.is_none()
                }) {
                    acquired.strong_after_close = Some(acquired.backing.strong_count());
                }
                trace.closed.push(file.clone());
                trace.active = trace.active.checked_sub(1).expect("balanced window close");
            });
        }
    }
}

/// Held grants on the real workspace owner, not a changed production limit.
/// Fill spare capacity and trigger normal eviction until even one byte cannot
/// be admitted, then release the separately held headroom grant. Thus a later
/// cache eviction cannot accidentally turn this into an unpressured test.
pub(super) struct HeldPressure {
    owner: RetentionBudget,
    grants: Vec<SharedBackingLease>,
    bytes: u64,
}

impl HeldPressure {
    pub(super) fn after_execution(owner: &RetentionBudget, headroom: u64) -> Self {
        assert!(headroom > 0);
        owner.run_pending_tasks();
        let release = owner
            .shared_backing(headroom)
            .expect("fixture leaves room for presentation pressure");
        let mut grants = Vec::new();
        let mut bytes = 0;
        loop {
            owner.run_pending_tasks();
            let spare = owner
                .capacity_bytes()
                .saturating_sub(owner.occupied_bytes());
            if spare > 0 {
                grants.push(owner.shared_backing(spare).unwrap_or_else(|| {
                    panic!(
                        "owner changed while holding its observed spare capacity: {:?}",
                        owner.snapshot()
                    )
                }));
                bytes += spare;
            }
            match owner.shared_backing(1) {
                Some(grant) => {
                    grants.push(grant);
                    bytes += 1;
                }
                None => break,
            }
        }
        drop(release);
        assert!(
            owner
                .capacity_bytes()
                .saturating_sub(owner.occupied_bytes())
                <= headroom
        );
        Self {
            owner: owner.clone(),
            grants,
            bytes,
        }
    }

    pub(super) fn assert_refund(self) {
        let before = self.owner.accounted_bytes();
        drop(self.grants);
        assert_eq!(
            self.owner.accounted_bytes(),
            before - self.bytes,
            "held grants refund without dropping native facts or changing capacity"
        );
    }
}

struct ObservePresentation {
    owner: RetentionBudget,
    headroom: Option<u64>,
}

struct Run {
    detailed: DetailedCodeQueryResult,
    native_keys: Vec<UnitRowKey>,
    published_keys: Vec<UnitRowKey>,
    native_trace_count: usize,
    trace: WindowTrace,
    pressure: Option<HeldPressure>,
}

impl QueryRowsFinalizer for ObservePresentation {
    type Output = Run;

    fn unexecuted(self, detailed: DetailedCodeQueryResult) -> Self::Output {
        panic!("acceptance fixture did not reach native execution: {detailed:?}")
    }

    fn finish(
        self,
        rows: ExecutedQueryRows<'_>,
        context: QueryFinalizationContext<'_, '_>,
    ) -> Self::Output {
        assert!(
            rows.owner
                .as_ref()
                .is_some_and(|owner| owner.ptr_eq(&self.owner)),
            "pressure must use the selected workspace owner"
        );
        assert!(!rows.execution.rows.is_empty());
        assert!(
            rows.diagnostics
                .iter()
                .all(|diagnostic| diagnostic.impact != CodeQueryDiagnosticImpact::Incomplete),
            "semantic execution was already incomplete: {:?}",
            rows.diagnostics
        );
        let native_keys = rows
            .execution
            .rows
            .iter()
            .map(|row| unit_row_key(&row.value.key()))
            .collect();
        let native_trace_count = rows.execution.rows.iter().map(|row| row.traces.len()).sum();
        // No pressure grant exists until the actual executor has supplied rows.
        let pressure = self
            .headroom
            .map(|headroom| HeldPressure::after_execution(&self.owner, headroom));
        let observer = ObserveWindows::start();
        let detailed = PresentQueryRows.finish(rows, context);
        let trace = observer.finish();
        assert!(detailed.result.diagnostics.iter().all(|diagnostic| !matches!(diagnostic, DiagnosticRef::Semantic(semantic) if semantic.impact == CodeQueryDiagnosticImpact::Incomplete)), "late semantic refusal confounds presentation pressure: {:?}", detailed.result.diagnostics);
        Run {
            detailed,
            native_keys,
            published_keys: Vec::new(),
            native_trace_count,
            trace,
            pressure,
        }
    }
}

fn run(workspace: &WorkspaceAnalyzer, query: &CodeQuery, headroom: Option<u64>) -> Run {
    let read_scope = AnalyzerQueryScope::new(workspace.analyzer());
    let mut published_keys = Vec::new();
    let mut run = execute_query_rows_with_finalizer(
        workspace.analyzer(),
        read_scope.token(),
        None,
        Some(workspace),
        None,
        None,
        0,
        query,
        CodeQueryExecutionLimits::default(),
        None,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        eager_structural_access_mode(),
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        None,
        CodeQueryExecutionScope::whole_workspace(),
        Some(&mut published_keys),
        None,
        EdgeTraversalCache::default(),
        ObservePresentation {
            owner: workspace.retention_budget().clone(),
            headroom,
        },
    );
    run.published_keys = published_keys;
    run.detailed.assert_invariants();
    run
}

fn argument_leaf(path: &str) -> serde_json::Value {
    serde_json::json!({
        "where": [path], "languages": ["python"],
        "match": {"kind": "call", "callee": {"name": "wrap"}},
        "steps": [{"op": "call_shape"}, {"op": "call_argument_groups"}, {"op": "call_arguments"}]
    })
}

fn arguments_query(paths: &[&str]) -> CodeQuery {
    assert!(!paths.is_empty());
    let mut query = match paths {
        [path] => argument_leaf(path),
        _ => serde_json::json!({
            "union": paths.iter().map(|path| argument_leaf(path)).collect::<Vec<_>>()
        }),
    };
    query["result_detail"] = serde_json::json!("compact");
    query["limit"] = serde_json::json!(200);
    CodeQuery::from_json(&query).unwrap()
}

fn argument(row: &CodeQueryResultItem) -> &CodeQueryCallShapeArgument {
    let CodeQueryResultValue::CallArgument { value } = &row.value else {
        panic!("expected call argument: {row:?}")
    };
    value
}

fn assert_presentation_refusal(run: &Run, expected: PresentationDiagnostic) {
    let presentation: Vec<_> = run
        .detailed
        .result
        .diagnostics
        .iter()
        .filter(|diagnostic| matches!(diagnostic, DiagnosticRef::Presentation(_)))
        .collect();
    assert_eq!(
        presentation.len(),
        1,
        "one bounded envelope: {:?}",
        run.detailed.result.diagnostics
    );
    assert!(matches!(presentation[0], DiagnosticRef::Presentation(kind) if kind == expected));
    let diagnostic = presentation[0];
    assert_eq!(
        diagnostic.code(),
        CodeQueryDiagnosticCode::PresentationRowsRefused
    );
    assert_eq!(diagnostic.impact(), CodeQueryDiagnosticImpact::Incomplete);
    assert_eq!(
        diagnostic.incompleteness(),
        Incompleteness::Operational(DiagnosticExecutionCause::Budget)
    );
    assert!(diagnostic.step_index().is_none() && diagnostic.step_op().is_none());
    assert!(diagnostic.cause_codes().is_empty());
    let wire = serde_json::to_value(&run.detailed.result.diagnostics).unwrap();
    let diagnostic = wire
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["code"] == "presentation_rows_refused")
        .unwrap();
    assert_eq!(
        diagnostic["exhausted_roots"],
        serde_json::json!([{
            "path": ".", "lane": "render/site_output/retained_bytes", "stage": "result_presentation"
        }])
    );
    assert!(diagnostic.get("step_index").is_none() && diagnostic.get("step_op").is_none());
    assert!(diagnostic["exhausted_roots"][0].get("budget").is_none());
    assert!(diagnostic["exhausted_roots"][0].get("charge").is_none());
    assert!(run.detailed.result.truncated);
    assert!(matches!(
        run.detailed.result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
    assert_ne!(run.detailed.reuse, ReuseVerdict::Content);
}

fn assert_aligned_prefix(actual: &Run, control: &Run, expected_len: usize) {
    assert_eq!(actual.detailed.result.results.len(), expected_len);
    assert_eq!(actual.detailed.evidence.len(), expected_len);
    assert_eq!(actual.published_keys.len(), expected_len);
    assert_eq!(
        actual.published_keys,
        control.published_keys[..expected_len]
    );
    assert_eq!(actual.published_keys, actual.native_keys[..expected_len]);
    assert_eq!(
        actual.detailed.evidence,
        control.detailed.evidence[..expected_len]
    );
    for (index, evidence) in actual.detailed.evidence.iter().enumerate() {
        assert_eq!(evidence.result_index, index);
    }
    for (actual, expected) in actual
        .detailed
        .result
        .results
        .iter()
        .zip(&control.detailed.result.results)
    {
        assert_eq!(actual.row_projection, expected.row_projection);
        assert_eq!(actual.provenance_truncated, expected.provenance_truncated);
        assert_eq!(
            serde_json::to_value(&actual.provenance).unwrap(),
            serde_json::to_value(&expected.provenance).unwrap()
        );
    }
}

#[test]
#[hardwon(
    "#14068: mandatory known values bypassed admission and refused rows could misalign evidence"
)]
fn real_query_pressure_keeps_atomic_prefix_and_typed_budget() {
    let body = format!(
        "\n{}{}\n",
        format!("{}\n", "A".repeat(1023)).repeat(191),
        "A".repeat(1022)
    );
    assert_eq!(body.len(), 192 * 1024);
    let mut nested = "def wrap(value):\n    return value\ndef entry():\n".to_owned();
    for _ in 0..128 {
        nested.push_str("    wrap(\n");
    }
    nested.push_str("    \"\"\"");
    nested.push_str(&body);
    nested.push_str("\"\"\"\n");
    for _ in 0..128 {
        nested.push_str("    )\n");
    }
    assert!(nested.lines().all(|line| line.len() < 16_000));
    let project = InlineTestProject::with_language(Language::Python)
        .file("prefix.py", "def wrap(value):\n    return value\ndef entry(dynamic):\n    wrap(\"prefix\")\n    wrap(dynamic)\n")
        .file("nested.py", nested).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = arguments_query(&["prefix.py", "nested.py"]);
    let control = run(&workspace, &query, None);
    assert_eq!(
        control.detailed.result.completion(),
        CodeQueryCompletion::Complete
    );
    assert_eq!(control.detailed.result.results.len(), 130);
    assert_eq!(control.published_keys, control.native_keys);
    let large = control
        .detailed
        .result
        .results
        .iter()
        .position(|row| {
            argument(row)
                .site
                .value
                .known_str()
                .is_some_and(|value| value.as_ref() == body)
        })
        .unwrap();
    assert!(
        large >= 2,
        "the authored union keeps its small prefix first"
    );
    assert_eq!(
        control
            .detailed
            .result
            .results
            .iter()
            .filter(|row| argument(row)
                .site
                .value
                .known_str()
                .is_some_and(|value| value.as_ref() == body))
            .count(),
        1
    );
    for row in &control.detailed.result.results {
        let SiteLocationView::Source { text, .. } = &argument(row).site.site else {
            panic!("unpressured source was withheld")
        };
        assert!(!text.is_empty());
    }
    let SiteLocationView::Source { text, .. } =
        &argument(&control.detailed.result.results[large]).site.site
    else {
        unreachable!()
    };
    assert_eq!(text.as_ref(), format!("\"\"\"{body}\"\"\""));
    let mut pressured = run(&workspace, &query, Some(128 * 1024));
    assert_presentation_refusal(&pressured, PresentationDiagnostic::RowsRefused);
    assert_aligned_prefix(&pressured, &control, large);
    for (actual, expected) in pressured
        .detailed
        .result
        .results
        .iter()
        .zip(&control.detailed.result.results)
    {
        let (actual, expected) = (argument(actual), argument(expected));
        assert_eq!(
            (
                &actual.id,
                &actual.group_id,
                &actual.site_id,
                &actual.path,
                actual.range,
                actual.argument_index,
                &actual.name,
                actual.spread
            ),
            (
                &expected.id,
                &expected.group_id,
                &expected.site_id,
                &expected.path,
                expected.range,
                expected.argument_index,
                &expected.name,
                expected.spread
            )
        );
        assert_eq!(actual.site.role, expected.site.role);
        assert_eq!(actual.site.value, expected.site.value);
        assert_eq!(actual.literal_value, expected.literal_value);
        if let SiteLocationView::Source { text, .. } = &actual.site.site {
            let SiteLocationView::Source {
                text: expected_text,
                ..
            } = &expected.site.site
            else {
                unreachable!()
            };
            assert_eq!(text, expected_text);
        }
    }
    pressured.pressure.take().unwrap().assert_refund();
}

#[test]
fn real_query_source_only_pressure_preserves_exact_known_value() {
    let expected = format!("\n{}", format!("{}\n", "A".repeat(1023)).repeat(64));
    let raw = format!("\n{}", format!("{}\n", "\\x41".repeat(1023)).repeat(64));
    let source =
        format!("def wrap(value):\n    return value\ndef entry():\n    wrap(\"\"\"{raw}\"\"\")\n");
    assert!(source.lines().all(|line| line.len() < 16_000));
    let project = InlineTestProject::with_language(Language::Python)
        .file("escaped.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = arguments_query(&["escaped.py"]);
    let control = run(&workspace, &query, None);
    assert_eq!(
        control.detailed.result.completion(),
        CodeQueryCompletion::Complete
    );
    assert_eq!(control.detailed.result.results.len(), 1);
    assert_eq!(
        argument(&control.detailed.result.results[0])
            .site
            .value
            .known_str()
            .unwrap()
            .as_ref(),
        expected
    );
    let mut pressured = run(&workspace, &query, Some(192 * 1024));
    assert_presentation_refusal(&pressured, PresentationDiagnostic::SourceTextRefused);
    assert_aligned_prefix(&pressured, &control, 1);
    let actual = argument(&pressured.detailed.result.results[0]);
    assert!(matches!(
        &actual.site.site,
        SiteLocationView::Unrendered {
            reason: UnrenderedReason::RenderBudget,
            ..
        }
    ));
    assert_eq!(
        actual.site.role,
        argument(&control.detailed.result.results[0]).site.role
    );
    assert!(
        matches!(&actual.site.value, SiteValueView::Known { value: KnownValueView::Str { value } } if value.as_ref() == expected)
    );
    assert_eq!(actual.literal_value.as_deref(), Some(expected.as_str()));
    // The flat column and the site keep the same real decoded allocation.
    assert_eq!(
        actual.literal_value.as_ref().unwrap().as_ptr(),
        actual.site.value.known_str().unwrap().as_ptr()
    );
    pressured.pressure.take().unwrap().assert_refund();
}

fn call_sites_query(paths: &[(&str, &str)]) -> CodeQuery {
    CodeQuery::from_json(&serde_json::json!({
        "union": paths.iter().map(|(path, name)| serde_json::json!({
            "where": [path], "languages": ["python"],
            "match": {"kind": "function", "name": name},
            "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}]
        })).collect::<Vec<_>>(), "limit": 200, "result_detail": "compact"
    }))
    .unwrap()
}

fn assert_actual_windows(trace: &WindowTrace, expected: &[ProjectFile]) {
    assert_eq!(trace.opened, expected);
    assert_eq!(trace.closed, expected);
    assert_eq!(
        trace.peak, 1,
        "only one actual file window is active: {trace:?}"
    );
    assert_eq!(trace.active, 0);
    assert_eq!(
        trace.acquired.len(),
        expected.len(),
        "call-site spans exercise actual provider acquisitions: {trace:?}"
    );
    for acquired in &trace.acquired {
        assert!(
            acquired
                .strong_after_close
                .is_some_and(|after| after < acquired.strong_at_acquire),
            "the window's acquired Arc was not released: {acquired:?}"
        );
    }
    // We deliberately do NOT assert Weak::upgrade() == None: semantic rows,
    // existing provider cache entries and the workspace may still own facts.
}

#[test]
#[hardwon(
    "#14068: presentation accumulated all-file facts and span indexes across demanded windows"
)]
fn real_query_two_demanded_files_exclude_sentinel_and_close_refused_windows() {
    let body = format!("\n{}", format!("{}\n", "A".repeat(1023)).repeat(32));
    let project = InlineTestProject::with_language(Language::Python)
        .file("definitions.py", "def consume_left(value):\n    return value\ndef consume_right(value):\n    return value\n")
        .file("left.py", "from definitions import consume_left\ndef entry_left():\n    consume_left(\"left\")\n")
        .file("right.py", format!("from definitions import consume_right\ndef entry_right():\n    consume_right(\"\"\"{body}\"\"\")\n"))
        .file("sentinel.py", "def unrelated_sentinel():\n    return \"not a demanded site\"\n").build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let files = [project.file("left.py"), project.file("right.py")];
    // Transient source windows follow actual source preparation; public rows
    // and their compact slots retain authored union order.
    let reversed = run(
        &workspace,
        &call_sites_query(&[
            ("definitions.py", "consume_right"),
            ("definitions.py", "consume_left"),
        ]),
        None,
    );
    assert_eq!(
        reversed.detailed.result.completion(),
        CodeQueryCompletion::Complete
    );
    let paths = reversed
        .detailed
        .result
        .results
        .iter()
        .map(|row| {
            let CodeQueryResultValue::CallSite { value } = &row.value else {
                panic!("expected call site")
            };
            value.path.as_str()
        })
        .collect::<Vec<_>>();
    assert_eq!(paths, ["right.py", "left.py"]);
    for (row, expected) in reversed
        .detailed
        .result
        .results
        .iter()
        .zip([body.as_str(), "left"])
    {
        let CodeQueryResultValue::CallSite { value } = &row.value else {
            unreachable!()
        };
        assert_eq!(
            value.arguments[0].site.value.known_str().unwrap().as_ref(),
            expected
        );
    }
    assert_actual_windows(&reversed.trace, &[files[1].clone(), files[0].clone()]);
    let query = call_sites_query(&[
        ("definitions.py", "consume_left"),
        ("definitions.py", "consume_right"),
    ]);
    let control = run(&workspace, &query, None);
    assert_eq!(
        control.detailed.result.completion(),
        CodeQueryCompletion::Complete
    );
    let mut pressured = run(&workspace, &query, Some(16 * 1024));
    assert_presentation_refusal(&pressured, PresentationDiagnostic::RowsRefused);
    assert_aligned_prefix(&pressured, &control, 1);
    assert_actual_windows(&pressured.trace, &files);
    for actual in [&reversed, &control, &pressured] {
        assert!(
            actual.trace.candidate_rows <= 6 * actual.native_keys.len(),
            "{:?}",
            actual.trace
        );
        assert!(
            actual.trace.candidate_traces <= 3 * actual.native_trace_count,
            "{:?}",
            actual.trace
        );
    }
    let CodeQueryResultValue::CallSite { value } = &pressured.detailed.result.results[0].value
    else {
        panic!("expected retained left call site")
    };
    assert_eq!(value.arguments.len(), 1);
    assert_eq!(
        value.arguments[0].site.value.known_str().unwrap().as_ref(),
        "left"
    );
    pressured.pressure.take().unwrap().assert_refund();
}

#[test]
#[hardwon("#14068: per-file presentation repeatedly scanned all response rows and traces")]
fn real_query_many_file_windows_bound_candidate_work() {
    let mut project = InlineTestProject::with_language(Language::Python)
        .file("definitions.py", "def consume(value):\n    return value\n")
        .file("sentinel.py", "def unrelated():\n    return \"sentinel\"\n");
    for index in 0..24 {
        project = project.file(
            format!("caller_{index:02}.py"),
            format!(
                "from definitions import consume\ndef entry():\n    consume(\"known_{index:02}\")\n"
            ),
        );
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&serde_json::json!({
        "where": ["definitions.py"], "languages": ["python"],
        "match": {"kind": "function", "name": "consume"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}],
        "limit": 200, "result_detail": "compact"
    }))
    .unwrap();
    let control = run(&workspace, &query, None);
    let mut pressured = run(&workspace, &query, Some(128 * 1024));
    for actual in [&control, &pressured] {
        assert_eq!(
            actual.detailed.result.completion(),
            CodeQueryCompletion::Complete
        );
        assert_eq!(actual.detailed.result.results.len(), 24);
        let expected_files = (0..24)
            .map(|index| project.file(format!("caller_{index:02}.py")))
            .collect::<Vec<_>>();
        assert_actual_windows(&actual.trace, &expected_files);
        let mut observed_values = Vec::new();
        for row in &actual.detailed.result.results {
            let CodeQueryResultValue::CallSite { value } = &row.value else {
                panic!("expected call site: {row:?}")
            };
            observed_values.push(value.arguments[0].site.value.known_str().unwrap().as_ref());
        }
        observed_values.sort_unstable();
        assert_eq!(
            observed_values,
            (0..24)
                .map(|index| format!("known_{index:02}"))
                .collect::<Vec<_>>()
        );
        let row_count = actual.native_keys.len();
        assert!(
            actual.native_trace_count > 0,
            "the query must exercise real traces"
        );
        // A small constant number of response passes is allowed. A pass for
        // each of the 24 files would exceed both bounds by a wide margin.
        assert!(
            actual.trace.candidate_rows > 0 && actual.trace.candidate_rows <= 6 * row_count,
            "{:?}",
            actual.trace
        );
        assert!(
            actual.trace.candidate_traces > 0
                && actual.trace.candidate_traces <= 3 * actual.native_trace_count,
            "{:?}",
            actual.trace
        );
        assert!(
            actual.trace.held_facts <= 24 + actual.native_trace_count,
            "{:?}",
            actual.trace
        );
    }
    assert_aligned_prefix(&pressured, &control, 24);
    pressured.pressure.take().unwrap().assert_refund();
}

#[path = "admission_flow_prefix_acceptance.rs"]
mod flow_prefix_acceptance;
