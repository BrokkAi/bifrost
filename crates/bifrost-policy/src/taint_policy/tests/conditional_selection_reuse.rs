//! Count binding-prefetch candidates instead of imposing a timing threshold.
//! The direct binder can decline optional carrier proofs without a prepared
//! flow; compare admissions separately from the candidate-work assertion.
use super::*;
use crate::taint_policy::BoundConditionalSanitizer;
#[cfg(feature = "test-support")]
use crate::taint_policy::FrontierEndpointBinder;
#[cfg(feature = "test-support")]
use brokk_bifrost_flow::taint::{SourceClassId, TaintUniverse};
use std::collections::HashMap;

#[cfg(feature = "test-support")]
fn conditional_binding_candidates(handlers: usize) -> (u64, Vec<Result<(), String>>) {
    let mut source = String::from(
        "fn source() -> &'static str { \"input\" }\n\
         fn check(_path: &str, _mode: i32) -> bool { true }\n\
         fn sink(_path: &str) {}\n",
    );
    for index in 0..handlers {
        source.push_str(&format!(
            "pub fn handler_{index}() {{ let path: &str = source(); \
             if check(path, 1) {{ sink(path); }} }}\n"
        ));
    }
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig {
        parallelism: Some(1),
        ..AnalyzerConfig::default()
    });
    let text = COMPOSED_POLICY.replacen(
        ":sinks",
        ":sanitizers (endpoint-set :entries [\
           (sanitizer :id guard :selector (rql :schema-version 1 \
             (language rust (call-argument :formal-index 0 (call-bindings (call-shape (call :callee (name \"check\"))))))) \
             :when (result true) :sanitizes (argument :index 0) \
             :requires [(argument :index 1 :constant true)] \
             :removes [attacker-controlled])]) :sinks",
        1,
    );
    let mut registry = crate::registry::test_registry_for_workspace(project.root());
    let policy = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:conditional-selection-count.rqlp"),
            text.as_bytes(),
        )
        .expect("the conditional policy registers");
    let spec = policy.resolved_taint().expect("a taint policy");
    let cancellation = CancellationToken::default();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let mut compiler = TaintPolicyCompiler::new(
        &workspace,
        &flow,
        None,
        CodeQueryExecutionLimits::default(),
        64,
        &cancellation,
    );
    let artifact = compiler
        .selectors
        .materialize(&ProjectFile::new(project.root(), "src/lib.rs"))
        .expect("the source fixture materializes without executing it");
    let mut procedures = artifact
        .procedures()
        .iter()
        .filter(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                .is_some_and(|name| name.starts_with("handler_"))
        })
        .map(|procedure| artifact.procedure_handle(procedure.id()).unwrap())
        .collect::<Vec<_>>();
    procedures.sort_by_key(|procedure| procedure.durable_key());
    assert_eq!(procedures.len(), handlers, "visit every distinct handler");
    let universe = TaintUniverse::new(vec![
        SourceClassId::new("attacker-controlled").expect("test label"),
    ])
    .expect("test universe");
    let mut binder = FrontierEndpointBinder::new(compiler, policy, spec, universe);
    let before = binder.binding_candidate_count_for_test();
    let mut admissions = Vec::new();
    for procedure in &procedures {
        let selected = binder
            .conditional_in(procedure)
            .expect("the handler's guard binds");
        assert_eq!(selected.len(), 1, "one guard belongs to this handler");
        let guard = &selected[0];
        assert_eq!(guard.procedure.durable_key(), procedure.durable_key());
        admissions.push(guard.admission.clone());
    }
    (
        binder.binding_candidate_count_for_test() - before,
        admissions,
    )
}

#[cfg(feature = "test-support")]
#[test]
#[hardwon("#10759: each procedure resolved every guard candidate in the file")]
fn conditional_binding_candidate_work_is_linear_in_owned_calls() {
    let (single, single_admissions) = conditional_binding_candidates(1);
    assert_eq!(single, 1);
    let (eight, eight_admissions) = conditional_binding_candidates(8);
    assert_eq!(eight_admissions, vec![single_admissions[0].clone(); 8]);
    assert_eq!(
        eight, 8,
        "each visit resolves only its owned guard, not every guard in the file"
    );
}

#[derive(Debug, PartialEq, Eq)]
struct ConditionalGuardSnapshot {
    owner: String,
    guard: String,
    admission: Result<(), String>,
}

fn guard_snapshots(guards: &[BoundConditionalSanitizer]) -> Vec<ConditionalGuardSnapshot> {
    guards
        .iter()
        .map(|guard| ConditionalGuardSnapshot {
            owner: format!("{:?}", guard.procedure.durable_key()),
            guard: format!("{}:{:?}:{:?}", guard.id, guard.guard, guard.removes),
            admission: guard.admission.clone(),
        })
        .collect()
}

/// Compare each visit, including its ordered admission declines, with the
/// legacy whole-file selection followed by the existing durable-owner filter.
/// Reversing visits must not change any procedure's result.
fn compare_conditional_visits_with_legacy(
    source: &str,
    selector: &str,
    requirement: &str,
) -> Vec<Vec<ConditionalGuardSnapshot>> {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig {
        parallelism: Some(1),
        ..AnalyzerConfig::default()
    });
    let text = COMPOSED_POLICY.replacen(
        ":sinks",
        &format!(
            ":sanitizers (endpoint-set :entries [\
             (sanitizer :id guard :selector (rql :schema-version 1 {selector}) \
             :when (result true) :sanitizes (argument :index 0) \
             :requires [{requirement}] :removes [attacker-controlled])]) :sinks"
        ),
        1,
    );
    let mut registry = crate::registry::test_registry_for_workspace(project.root());
    let policy = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:conditional-owned-equivalence.rqlp"),
            text.as_bytes(),
        )
        .expect("test conditional policy registers");
    let spec = policy.resolved_taint().expect("taint policy");
    let selectors = policy
        .resolved_selectors()
        .iter()
        .map(|selector| (&selector.path, selector))
        .collect::<HashMap<_, _>>();
    let cancellation = CancellationToken::default();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let mut compiler = TaintPolicyCompiler::new(
        &workspace,
        &flow,
        None,
        CodeQueryExecutionLimits::default(),
        64,
        &cancellation,
    );
    let file = ProjectFile::new(project.root(), "src/lib.rs");
    let artifact = compiler.selectors.materialize(&file).expect("artifact");
    let mut procedures = artifact
        .procedures()
        .iter()
        .map(|procedure| artifact.procedure_handle(procedure.id()).unwrap())
        .collect::<Vec<_>>();
    procedures.sort_by_key(|procedure| procedure.durable_key());
    let legacy = compiler
        .bind_conditional_sanitizers(spec, &selectors, None)
        .expect("legacy file selection binds");
    let mut expected = Vec::new();
    for procedure in &procedures {
        let owned = legacy
            .iter()
            .filter(|guard| guard.procedure.durable_key() == procedure.durable_key())
            .cloned()
            .collect::<Vec<_>>();
        let scoped = compiler
            .bind_conditional_sanitizers(
                spec,
                &selectors,
                Some((&file, std::slice::from_ref(&file), procedure)),
            )
            .expect("owned selection binds");
        let snapshot = guard_snapshots(&owned);
        assert_eq!(
            guard_snapshots(&scoped),
            snapshot,
            "per-procedure ordered guards and declines"
        );
        expected.push(snapshot);
    }
    for (procedure, expected) in procedures.iter().zip(&expected).rev() {
        let scoped = compiler
            .bind_conditional_sanitizers(
                spec,
                &selectors,
                Some((&file, std::slice::from_ref(&file), procedure)),
            )
            .expect("reverse owned selection binds");
        assert_eq!(&guard_snapshots(&scoped), expected, "reverse visit order");
    }
    expected
}

const CHECK_ARGUMENT_SELECTOR: &str = "(language rust (call-argument :formal-index 0 (call-bindings (call-shape (call :callee (name \"check\"))))))";
const MULTIPLE_AND_CLOSURE_GUARDS: &str = r#"
fn source() -> &'static str { "input" }
fn check(_path: &str, _mode: i32) -> bool { true }
fn sink(_path: &str) {}
pub fn handler_0() {
    let path: &str = source();
    if check(path, 1) { sink(path); }
    if check(path, 2) { sink(path); }
    let closure = || { if check(path, 1) { sink(path); } };
    closure();
}
pub fn handler_1() {
    let path: &str = source();
    if check(path, 1) { sink(path); }
}
"#;

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: early ownership pruning must preserve two guards, closure ownership and ordered per-procedure requirement declines"
)]
fn conditional_owned_selection_matches_legacy_guards_and_declines() {
    for requirement in [
        "(argument :index 1 :constant true)",
        "(argument :index 1 :equals 1)",
    ] {
        let groups = compare_conditional_visits_with_legacy(
            MULTIPLE_AND_CLOSURE_GUARDS,
            CHECK_ARGUMENT_SELECTOR,
            requirement,
        );
        let mut sizes = groups
            .iter()
            .filter(|group| !group.is_empty())
            .map(Vec::len)
            .collect::<Vec<_>>();
        sizes.sort_unstable();
        assert_eq!(
            sizes,
            [1, 1, 2],
            "closure and enclosing function own separate guards"
        );
        if requirement.contains(":equals") {
            assert!(
                groups
                    .iter()
                    .flatten()
                    .any(|guard| guard
                        .admission
                        .as_ref()
                        .is_err_and(|reason| reason
                            == "required operand does not equal the authored literal"))
            );
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: sibling-set selectors must keep the legacy file query rather than narrowing their input"
)]
fn conditional_non_site_local_selection_matches_legacy() {
    for operation in ["except", "intersect"] {
        let branch = "(call-argument :formal-index 0 (call-bindings (call-shape (call :callee (name \"check\")))))";
        let other = if operation == "except" {
            "(call-argument :formal-index 0 (call-bindings (call-shape (call :callee (name \"absent\")))))"
        } else {
            branch
        };
        let selector = format!("(language rust ({operation} {branch} {other}))");
        let groups = compare_conditional_visits_with_legacy(
            MULTIPLE_AND_CLOSURE_GUARDS,
            &selector,
            "(argument :index 1 :constant true)",
        );
        assert_eq!(groups.iter().map(Vec::len).sum::<usize>(), 4);
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: a result-of call in another procedure cannot satisfy this guard's dominating-writer requirement"
)]
fn conditional_result_of_membership_stays_in_the_guard_procedure() {
    let source = r#"
fn source() -> &'static str { "input" }
fn token() -> i32 { 1 }
fn check(_path: &str, _mode: i32) -> bool { true }
fn sink(_path: &str) {}
pub fn handler_0() { let path = source(); let mode = token(); if check(path, mode) { sink(path); } }
pub fn handler_1() { let path = source(); if check(path, 2) { sink(path); } }
"#;
    let groups = compare_conditional_visits_with_legacy(
        source,
        CHECK_ARGUMENT_SELECTOR,
        "(argument :index 1 :result-of (rql :schema-version 1 (language rust (call :callee (name \"token\")))))",
    );
    assert_eq!(groups.iter().map(Vec::len).sum::<usize>(), 2);
    assert_eq!(
        groups
            .iter()
            .flatten()
            .filter(|guard| guard.admission.as_ref().is_err_and(
                |reason| reason == "required operand is not the result of the selected call"
            ))
            .count(),
        1
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: a procedure-owned guard unit must not retain another procedure's declaration dependencies"
)]
fn conditional_owned_reads_exclude_foreign_guard_declarations() {
    use brokk_bifrost_analysis::analyzer::{
        ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
        capture_query_reads, verify_read_set,
    };
    let original_source = "mod a; mod b;\npub fn p1(x: a::A) { x.check(\"one\"); }\npub fn p2(x: b::B) { x.check(\"two\"); }\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname='guard_reads'\nversion='0.1.0'\nedition='2021'\n")
        .file("src/lib.rs", "mod a; mod b;\npub fn p1(x: a::A) { x.check(\"one\"); }\npub fn p2(x: b::B) { x.check(\"two\"); }\n")
        .file("src/a.rs", "pub struct A; impl A { pub fn check(&self, _x: &str) -> bool { true } }\n")
        .file("src/b.rs", "pub struct B; impl B { pub fn check(&self, _x: &str) -> bool { true } }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let text = COMPOSED_POLICY.replacen(":sinks", &format!(":sanitizers (endpoint-set :entries [(sanitizer :id guard :selector (rql :schema-version 1 {CHECK_ARGUMENT_SELECTOR}) :when (result true) :sanitizes (argument :index 0) :removes [attacker-controlled])]) :sinks"), 1);
    let mut registry = crate::registry::test_registry_for_workspace(project.root());
    let policy = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:owned-reads.rqlp"),
            text.as_bytes(),
        )
        .expect("policy");
    let spec = policy.resolved_taint().unwrap();
    let selector = policy
        .resolved_selectors()
        .iter()
        .find(|selector| selector.path == spec.sanitizers[0].selector_path)
        .unwrap();
    let cancellation = CancellationToken::default();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let file = project.file("src/lib.rs");
    let select = |workspace: &WorkspaceAnalyzer, scoped: bool| {
        let mut compiler = TaintPolicyCompiler::new(
            workspace,
            &flow,
            None,
            CodeQueryExecutionLimits::default(),
            64,
            &cancellation,
        );
        let files = workspace.analyzer().analyzed_files();
        let artifact = compiler.selectors.materialize(&file).expect("artifact");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("p1")
            })
            .map(|procedure| artifact.procedure_handle(procedure.id()).unwrap())
            .expect("p1");
        let (rows, reads) = capture_query_reads(workspace.analyzer(), || {
            if scoped {
                compiler
                    .selectors
                    .select_taint_in_procedure(selector, &file, &files, &procedure)
            } else {
                compiler
                    .selectors
                    .select_taint_in_file(selector, &file, &files)
            }
        });
        let rows = rows.expect("guard selection");
        assert_eq!(reads.unattributed_reads(), 0, "complete receipts");
        (
            rows.into_iter()
                .map(|row| {
                    (
                        row.span,
                        format!("{:?}", row.proof),
                        format!("{:?}", row.completeness),
                    )
                })
                .collect::<Vec<_>>(),
            reads.keys(),
        )
    };
    let (before, owned_reads) = select(&workspace, true);
    assert_eq!(before.len(), 1);
    let (_, legacy_reads) = select(&workspace, false);
    let digest =
        brokk_bifrost_analysis::analyzer::semantic::StableDigest::sha256(b"guard read test");
    let inputs = HeadInputs {
        // Verify against the actual pinned model receipt, not the placeholder
        // used for policy inputs this selector-only capture does not record.
        models: owned_reads
            .iter()
            .find_map(|key| match key {
                ReadKey::Models(digest) => Some(*digest),
                _ => None,
            })
            .unwrap_or(digest),
        policy_semantic_hash: digest,
        policy_source: digest,
        configuration: digest,
        epoch: digest,
    };
    let verify = |head: &WorkspaceAnalyzer, keys: &[ReadKey]| {
        verify_read_set(
            head,
            &ChangedFacts::between(&workspace, head),
            &inputs,
            keys,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        )
    };
    let b = project.file("src/b.rs");
    b.write("pub struct B; impl B { pub fn check(&self, _x: &str) -> bool { false } }\n")
        .unwrap();
    let warm = workspace.update(&std::collections::BTreeSet::from([b]));
    let cold = project.workspace_analyzer(AnalyzerConfig::default());
    assert!(
        verify(&warm, &owned_reads).is_unchanged(),
        "P1 foreign edit: {:?}\nreads={owned_reads:#?}",
        verify(&warm, &owned_reads)
    );
    assert!(
        !verify(&warm, &legacy_reads).is_unchanged(),
        "legacy must retain P2 declaration reads"
    );
    assert_eq!(select(&warm, true).0, before);
    assert_eq!(
        select(&warm, true).0,
        select(&cold, true).0,
        "warm equals cold"
    );
    file.write("mod a; mod b;\npub fn p1(_x: a::A) {}\npub fn p2(x: b::B) { x.check(\"two\"); let y = a::A; y.check(\"one\"); }\n").unwrap();
    let moved = warm.update(&std::collections::BTreeSet::from([file.clone()]));
    assert!(
        !verify(&moved, &owned_reads).is_unchanged(),
        "same-file ownership edit invalidates P1"
    );
    assert!(
        select(&moved, true).0.is_empty(),
        "P1 no longer owns a guard"
    );
    let moved_cold = project.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(
        select(&moved, true).0,
        select(&moved_cold, true).0,
        "moved call warm equals cold"
    );
    file.write(original_source).unwrap();
    let a = project.file("src/a.rs");
    a.write("pub struct A; impl A { pub fn check(&self, _x: &str) -> bool { false } }\n")
        .unwrap();
    let own_edit = warm.update(&std::collections::BTreeSet::from([a]));
    assert!(
        !verify(&own_edit, &owned_reads).is_unchanged(),
        "P1 own declaration edit must invalidate"
    );
}
