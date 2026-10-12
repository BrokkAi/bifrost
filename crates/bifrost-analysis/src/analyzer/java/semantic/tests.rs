use super::syntax::{
    body_contains_free_this, is_sole_initializer_fragment, java_field_access_is_type_qualifier,
    java_field_access_segments, java_type_name_prefix_len,
};
use super::*;
use crate::analyzer::semantic::floating_value_for_test as floating;
use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxSource};
use crate::analyzer::{Language, LanguageDialect};
use crate::test_support::procedure_named as method;
use std::sync::Arc;

fn parse_java(source: &str) -> tree_sitter::Tree {
    brokk_bifrost_jvm::java::declarations::parse_tree(source).expect("Java source must parse")
}

fn first_kind<'a>(root: tree_sitter::Node<'a>, kind: &str) -> tree_sitter::Node<'a> {
    brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive(root, kind)
        .unwrap_or_else(|| panic!("missing {kind}"))
}

use brokk_bifrost_test_macros::hardwon;
#[test]
#[hardwon(
    "#2363: A package-qualified type name used as a call object must not be lowered as heap memory"
)]
fn qualified_stdlib_method_object_is_a_type_qualifier() {
    let source = r#"class App {
  void run(String value) {
    java.net.URLDecoder.decode(value, "UTF-8");
  }
}
"#;
    let tree = parse_java(source);
    let invocation = first_kind(tree.root_node(), "method_invocation");
    let access = invocation
        .child_by_field_name("object")
        .expect("qualified call object");
    let segments = java_field_access_segments(access, source);
    assert_eq!(segments, ["java", "net", "URLDecoder"]);
    assert!(java_field_access_is_type_qualifier(
        access,
        source,
        |_| false,
        |_| false,
    ));
}

/// #2452: an uppercase field inherited from another file is invisible to the
/// intrafile value inventory. Unknown roots must retain heap identity; positive
/// type evidence may still classify the same spelling as a qualifier.
#[test]
#[hardwon(
    "#2452: Parses real Java source with Tree-sitter and checks semantic lowerer output; fix regression: a cross-file uppercase field chain lost heap identity because its spelling was mistaken for a type qualifier"
)]
fn uppercase_cross_file_inherited_field_requires_positive_type_evidence() {
    let source = r#"class App {
  void run() {
    CONFIG.DEFAULTS.value();
  }
}
"#;
    let tree = parse_java(source);
    let invocation = first_kind(tree.root_node(), "method_invocation");
    let access = invocation
        .child_by_field_name("object")
        .expect("selector object");
    assert!(
        !java_field_access_is_type_qualifier(access, source, |_| false, |_| false),
        "an unknown uppercase root must keep its Field lowering"
    );
    assert!(
        !java_field_access_is_type_qualifier(access, source, |root| root == "CONFIG", |_| false,),
        "a root the scope knows as a value must keep its Field lowering"
    );
    assert!(
        java_field_access_is_type_qualifier(access, source, |_| false, |root| root == "CONFIG",),
        "a root proven to be a type may omit qualifier-only Field lowering"
    );
}

#[test]
#[hardwon("#2363: An inherited field chain must remain heap memory when type evidence is absent")]
fn inherited_field_chain_is_not_a_type_qualifier() {
    let source = r#"class App {
  void run() {
    inheritedField.nested.method();
  }
}
"#;
    let tree = parse_java(source);
    let access = first_kind(tree.root_node(), "field_access");
    assert!(
        !java_field_access_is_type_qualifier(access, source, |_| false, |_| false),
        "an inherited field chain must keep Field lowering"
    );
}

/// The `variable_declarator` node that declares `name`, found anywhere in
/// the tree. Distinguishes sibling field declarations by their declared
/// name, since `first_kind` alone cannot pick a specific one among several.
fn declarator_named<'a>(
    root: tree_sitter::Node<'a>,
    source: &str,
    name: &str,
) -> tree_sitter::Node<'a> {
    let mut found = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .is_some_and(|id| &source[id.byte_range()] == name)
        {
            found = Some(node);
            WalkControl::Break
        } else {
            WalkControl::Continue
        }
    });
    found.unwrap_or_else(|| panic!("missing variable_declarator named {name}"))
}

// #2553: `is_sole_initializer_fragment` is the structural predicate that
// decides whether the whole-procedure `DeferredExecution` gap still applies
// to one initializer fragment. These cases pin its documented contract
// directly, independent of the gap-emission wiring in `control.rs`.

#[test]
#[hardwon(
    "#2480: Parses real Java source with Tree-sitter and checks semantic lowerer output; regression: the ubiquitous lone serialVersionUID initializer incorrectly carried a DeferredExecution gap"
)]
fn a_lone_static_field_initializer_is_the_sole_fragment_in_its_group() {
    // The corpus's own dominant shape (#2545's census): boilerplate
    // `serialVersionUID`, nothing else in the static group.
    let source = "class App {\n  private static final long serialVersionUID = 1L;\n}\n";
    let tree = parse_java(source);
    let declarator = declarator_named(tree.root_node(), source, "serialVersionUID");
    assert!(is_sole_initializer_fragment(declarator, true));
}

#[test]
#[hardwon(
    "#2480: Parses real Java source with Tree-sitter and checks semantic lowerer output; regression: interacting static initializer fragments must retain their source-order DeferredExecution gap"
)]
fn two_static_field_initializers_are_not_sole_in_their_shared_group() {
    // A genuine source-order-composition case: `b`'s value can depend on
    // `a` having already run. Both fragments must keep the gap.
    let source = "class App {\n  private static int a = 1;\n  private static int b = a + 1;\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let b = declarator_named(tree.root_node(), source, "b");
    assert!(!is_sole_initializer_fragment(a, true));
    assert!(!is_sole_initializer_fragment(b, true));
}

#[test]
#[hardwon(
    "#2480: Parses real Java source with Tree-sitter and checks semantic lowerer output; regression: a static field and static block compose in the same initializer order group"
)]
fn a_static_field_and_a_static_initializer_block_share_one_group() {
    let source = "class App {\n  private static int a = 1;\n  static { a = a + 1; }\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let block = first_kind(tree.root_node(), "static_initializer");
    assert!(!is_sole_initializer_fragment(a, true));
    assert!(!is_sole_initializer_fragment(block, true));
}

#[test]
#[hardwon(
    "#2480: Parses real Java source with Tree-sitter and checks semantic lowerer output; regression: static and instance initializer fragments belong to separate ordering groups"
)]
fn static_and_instance_groups_are_independent() {
    // One member in each group: neither fragment has a sibling to compose
    // with, even though the class has two initializer fragments overall.
    let source = "class App {\n  private static final long serialVersionUID = 1L;\n  private int count = 0;\n}\n";
    let tree = parse_java(source);
    let statik = declarator_named(tree.root_node(), source, "serialVersionUID");
    let instance = declarator_named(tree.root_node(), source, "count");
    assert!(is_sole_initializer_fragment(statik, true));
    assert!(is_sole_initializer_fragment(instance, false));
}

#[test]
#[hardwon(
    "#2480: Parses real Java source with Tree-sitter and checks semantic lowerer output; regression: interacting instance initializer fragments must retain their source-order gap"
)]
fn two_instance_field_initializers_are_not_sole_in_their_shared_group() {
    let source = "class App {\n  private int a = 1;\n  private int b = a + 1;\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let b = declarator_named(tree.root_node(), source, "b");
    assert!(!is_sole_initializer_fragment(a, false));
    assert!(!is_sole_initializer_fragment(b, false));
}

#[test]
#[hardwon(
    "#2480: Parses real Java source with Tree-sitter and checks semantic lowerer output; regression: a field with no initializer must not make a lone initialized field look compositional"
)]
fn an_uninitialized_sibling_field_does_not_count_as_a_fragment() {
    // `plain` has no `value`, so `callable_shape` never lowers it as an
    // Initializer procedure at all; it must not inflate the group count
    // either.
    let source = "class App {\n  private static final long serialVersionUID = 1L;\n  private static String plain;\n}\n";
    let tree = parse_java(source);
    let declarator = declarator_named(tree.root_node(), source, "serialVersionUID");
    assert!(is_sole_initializer_fragment(declarator, true));
}

#[test]
#[hardwon(
    "#2480: Parses real Java source with Tree-sitter and checks semantic lowerer output; regression: one field declaration can contain multiple ordered initializer fragments"
)]
fn multiple_declarators_in_one_field_declaration_each_count() {
    // `private static int a = 1, b = 2;` is two composed fragments in JLS
    // source order, even though they share one `field_declaration`.
    let source = "class App {\n  private static int a = 1, b = 2;\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let b = declarator_named(tree.root_node(), source, "b");
    assert!(!is_sole_initializer_fragment(a, true));
    assert!(!is_sole_initializer_fragment(b, true));
}

/// Materialize and validate the Java artifact for `source`.
fn java_semantics(source: &str) -> std::sync::Arc<SemanticArtifact> {
    let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file("Fixture.java", source)
        .build();
    let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    workspace
        .materialize_program_semantics(
            &project.file("Fixture.java"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Java semantic materialization")
        .available_value()
        .cloned()
        .expect("Java semantic artifact")
}

fn java_semantic_outcome(
    source: &str,
    limits: SemanticWork,
) -> SemanticOutcome<Vec<ProcedureSemanticsParts>> {
    let prepared = PreparedSyntaxTree::new(
        PreparedSyntaxSource::Exact(Arc::from(source)),
        parse_java(source),
        crate::text_utils::compute_line_starts(source),
        LanguageDialect::Standard(Language::Java),
        PreparedSourceOrigin::Disk,
        None,
    );
    let file = ProjectFile::new(std::env::temp_dir(), "semantic-java-budget.java");
    let budget = SemanticBudget::new(limits).expect("test budget limits are positive");
    let cancellation = CancellationToken::default();
    JavaSemanticLowerer
        .lower(&file, &prepared, &budget, &cancellation)
        .expect("Java semantic lowering must report its bounded outcome")
}

#[test]
fn synthetic_constructor_budget_failure_retains_pre_drive_composition_work() {
    let uninitialized = java_semantic_outcome(
        "class Fixture { int first; int second; }",
        SemanticWork::default_limits(),
    );
    let SemanticOutcome::Complete {
        work: baseline_work,
        ..
    } = uninitialized
    else {
        panic!("uninitialized synthetic constructor must complete");
    };
    assert!(baseline_work.program_points > 0);

    // The first synthesized initializer entry fits. The second entry is
    // allocated by schedule_field_initializers before the work driver runs,
    // so this limit isolates the new pre-drive composition path.
    let mut limits = SemanticWork::default_limits();
    limits.program_points = baseline_work.program_points + 1;
    let outcome = java_semantic_outcome("class Fixture { int first = 1; int second = 2; }", limits);
    let SemanticOutcome::ExceededBudget { exceeded, work, .. } = outcome else {
        panic!("second synthesized initializer entry must exhaust the point budget");
    };
    assert_eq!(exceeded.dimension(), SemanticBudgetDimension::ProgramPoints);
    assert_eq!(work.program_points, baseline_work.program_points + 1);
    assert!(work.program_points > 0);
}

#[test]
fn written_constructor_default_store_budget_retains_pre_drive_work() {
    let mut limits = SemanticWork::default_limits();
    limits.memory_locations = 1;
    let outcome = java_semantic_outcome(
        "class Fixture { int first; int second; Fixture() {} }",
        limits,
    );
    let SemanticOutcome::ExceededBudget { exceeded, work, .. } = outcome else {
        panic!("the second distinct field store must exhaust the memory-location budget");
    };
    assert_eq!(
        exceeded.dimension(),
        SemanticBudgetDimension::MemoryLocations
    );
    assert_eq!(work.memory_locations, 1);
    assert!(work.program_points > 0);
    assert!(work.values > 0);
}

fn mapping_text<'s>(
    procedure: &ProcedureSemantics,
    source: &'s str,
    mapping: SourceMappingId,
) -> &'s str {
    crate::analyzer::test_support::source_mapping_text(
        &procedure.source_mappings()[mapping.index()],
        source,
    )
}

/// Constructor call sites anchor their callee value at the target token
/// (`this`/`super`); arguments are separate IR values and are not part of
/// that target identity.
fn constructor_call_point(
    procedure: &ProcedureSemantics,
    source: &str,
    target: &str,
) -> Option<ProgramPointId> {
    procedure.call_sites().iter().find_map(|call| {
        (value_text(procedure, source, call.callee) == target).then_some(call.point)
    })
}

#[test]
fn assertion_control_skips_disabled_and_successful_detail_evaluation() {
    let source = "class Fixture { void run() { assert test() : detail(); after(); } void literal() { assert true : detail(); after(); } }";
    let artifact = java_semantics(source);
    let run = method(&artifact, "run");
    let reaches =
        |procedure: &ProcedureSemantics, start: ProgramPointId, target: ProgramPointId| {
            let mut visited = HashSet::default();
            let mut pending = vec![start];
            while let Some(point) = pending.pop() {
                if point == target {
                    return true;
                }
                if visited.insert(point) {
                    pending.extend(
                        procedure
                            .control_edges()
                            .iter()
                            .filter(|edge| edge.source_point == point)
                            .map(|edge| edge.target_point),
                    );
                }
            }
            false
        };
    let call_point = |procedure: &ProcedureSemantics, text| {
        procedure
            .call_sites()
            .iter()
            .find(|call| mapping_text(procedure, source, call.source) == text)
            .unwrap_or_else(|| panic!("missing call {text}"))
            .point
    };
    let status = run
        .guard_facts()
        .iter()
        .find(|guard| {
            guard.subject.is_none()
                && mapping_text(run, source, guard.source).starts_with("assert ")
        })
        .expect("assertion enablement");
    let disabled = run
        .control_edge(status.false_edge.expect("disabled edge"))
        .unwrap()
        .target_point;
    assert!(reaches(run, disabled, call_point(run, "after()")));
    assert!(!reaches(run, disabled, call_point(run, "test()")));
    assert!(!reaches(run, disabled, call_point(run, "detail()")));
    let condition = run
        .guard_facts()
        .iter()
        .find(|guard| mapping_text(run, source, guard.source) == "test()")
        .expect("assertion condition");
    let success = run
        .control_edge(condition.true_edge.unwrap())
        .unwrap()
        .target_point;
    let failure = run
        .control_edge(condition.false_edge.unwrap())
        .unwrap()
        .target_point;
    assert!(!reaches(run, success, call_point(run, "detail()")));
    assert!(reaches(run, failure, call_point(run, "detail()")));
    assert!(!reaches(run, failure, call_point(run, "after()")));
    let literal = method(&artifact, "literal");
    assert!(!reaches(
        literal,
        literal.entry_point(),
        call_point(literal, "detail()")
    ));
    assert!(reaches(
        literal,
        literal.entry_point(),
        call_point(literal, "after()")
    ));
    assert!(run.gaps().iter().all(|gap| !matches!(
        gap.capability,
        SemanticCapability::NormalControlFlow | SemanticCapability::ExceptionalControlFlow
    )));
    assert!(
        run.gaps()
            .iter()
            .any(|gap| gap.capability == SemanticCapability::Calls)
    );
}

#[test]
fn assertion_unboxing_aborts_after_evaluating_the_condition() {
    let source = "class Fixture { void boxed(Boolean flag) { Boolean x; assert (x = flag); } void primitive(boolean flag) { assert flag; } void conjunction(Boolean left, Boolean right) { assert left && right; } void disjunction(Boolean left, Boolean right) { assert left || right; } }";
    let artifact = java_semantics(source);
    let boxed = method(&artifact, "boxed");
    let decision = boxed
        .guard_facts()
        .iter()
        .find(|guard| guard.subject.is_some())
        .expect("condition decision")
        .point;
    assert!(
        boxed
            .control_edges()
            .iter()
            .any(|edge| edge.source_point == decision && edge.kind == ControlEdgeKind::Exceptional)
    );
    let write = boxed
        .points()
        .iter()
        .find(|point| {
            point
                .events
                .iter()
                .any(|event| matches!(event.effect, SemanticEffect::Assignment { .. }))
        })
        .expect("condition assignment")
        .id;
    let mut visited = HashSet::default();
    let mut pending = vec![boxed.entry_point()];
    while let Some(point) = pending.pop() {
        if point == write || !visited.insert(point) {
            continue;
        }
        assert_ne!(point, decision, "unboxing must not precede the assignment");
        pending.extend(
            boxed
                .control_edges()
                .iter()
                .filter(|edge| edge.source_point == point)
                .map(|edge| edge.target_point),
        );
    }
    for name in ["conjunction", "disjunction"] {
        let procedure = method(&artifact, name);
        for operand in ["left", "right"] {
            let decision = procedure
                .guard_facts()
                .iter()
                .find(|guard| mapping_text(procedure, source, guard.source) == operand)
                .expect("short-circuit operand decision")
                .point;
            assert!(
                procedure
                    .control_edges()
                    .iter()
                    .any(|edge| edge.source_point == decision
                        && edge.kind == ControlEdgeKind::Exceptional),
                "{name}: {operand} must unbox after evaluation"
            );
        }
    }
    let primitive = method(&artifact, "primitive");
    let decision = primitive
        .guard_facts()
        .iter()
        .find(|guard| guard.subject.is_some())
        .unwrap()
        .point;
    assert!(
        !primitive
            .control_edges()
            .iter()
            .any(|edge| edge.source_point == decision && edge.kind == ControlEdgeKind::Exceptional)
    );
}

#[test]
fn lambda_captures_snapshot_exact_bindings_without_running_the_body() {
    let source = "class Fixture { Runnable f(int parameter) { int local = 1; return () -> { int observed = local + parameter; deferred(); }; } Runnable names(Object target) { int member = 1; return () -> target.member(); } Runnable empty() { int deferred = 1; return () -> deferred(); } Runnable mixed(int value) { return () -> { Object receiver = this; int observed = value; }; } Runnable loop(int[] values) { for (int value : values) { return () -> { int observed = value; }; } return null; } Runnable caught() { try { fail(); } catch (RuntimeException problem) { return () -> { Object observed = problem; }; } return null; } }";
    let artifact = java_semantics(source);
    let outer = method(&artifact, "f");
    let mixed = method(&artifact, "mixed");
    assert_eq!(mixed.captures().len(), 2);
    assert_ne!(
        mixed.captures()[0].destination,
        mixed.captures()[1].destination,
        "receiver and lexical inputs need distinct slots"
    );
    assert_eq!(outer.captures().len(), 2);
    assert_eq!(
        method(&artifact, "loop").captures().len(),
        1,
        "enhanced-for binder"
    );
    assert_eq!(
        method(&artifact, "caught").captures().len(),
        1,
        "catch binder"
    );
    assert!(
        outer.call_sites().is_empty(),
        "lambda body must remain deferred"
    );
    let mut values = HashSet::default();
    for capture in outer.captures() {
        assert_eq!(capture.mode, CaptureMode::Value);
        let CaptureSource::Value(source) = capture.captured else {
            panic!("value snapshot")
        };
        assert!(
            values.insert(source),
            "distinct declarations remain distinct"
        );
        let lambda = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.id() == capture.target)
            .unwrap();
        let location = lambda.memory_location(capture.destination).unwrap();
        let MemoryLocationKind::Capture {
            lexical_parent,
            binding: None,
        } = location.kind
        else {
            panic!("capture input")
        };
        assert_eq!(lexical_parent, outer.id());
        let incoming = lambda
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Capture,
                    location,
                    result,
                } if location == capture.destination => Some(result),
                _ => None,
            })
            .expect("capture environment load");
        let value = lambda
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::Assignment { target, value } if value == incoming => Some(target),
                _ => None,
            })
            .expect("capture input establishes its local binding");
        assert!(lambda.points().iter().flat_map(|point| &point.events).any(|event|
            matches!(event.effect, SemanticEffect::ValueFlow { source, .. } if source == value)
        ), "the lambda reads its captured input");
        assert!(
            lambda
                .gaps()
                .iter()
                .all(|gap| gap.capability != SemanticCapability::Captures)
        );
    }
    assert!(
        outer
            .gaps()
            .iter()
            .all(|gap| gap.capability != SemanticCapability::Captures)
    );
    assert_eq!(
        method(&artifact, "names").captures().len(),
        1,
        "member names are not local reads"
    );
    assert!(
        method(&artifact, "empty").captures().is_empty(),
        "method names use a separate namespace"
    );
    assert!(
        method(&artifact, "empty")
            .gaps()
            .iter()
            .all(|gap| gap.capability != SemanticCapability::Captures)
    );
}

#[test]
fn lambda_captures_relay_through_lambdas_and_keep_unsupported_binders_open() {
    let source = "class Fixture { java.util.function.Supplier<java.util.function.IntSupplier> nested(int value) { return () -> () -> value; } void siblings() { { int x = 1; consume(() -> x); } { int x = 2; consume(() -> x); } } java.util.function.Supplier<String> pattern(Object value) { if (value instanceof String text) return () -> text; return null; } Object localClass(int value) { class Local { java.util.function.IntSupplier factory() { return () -> value; } } return new Local(); } void reassigned() { int value = 1; Runnable task = () -> { int observed = value; }; value = 2; } Runnable assignedParameter(int value) { value++; return () -> { int observed = value; }; } }";
    let artifact = java_semantics(source);
    let outer = method(&artifact, "nested");
    let [first] = outer.captures() else {
        panic!("outer capture: {:?}", outer.captures())
    };
    let middle = artifact
        .procedures()
        .iter()
        .find(|procedure| procedure.id() == first.target)
        .unwrap();
    let [second] = middle.captures() else {
        panic!("relay capture: {:?}", middle.captures())
    };
    let incoming = middle
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .find_map(|event| match event.effect {
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Capture,
                location,
                result,
            } if location == first.destination => Some(result),
            _ => None,
        })
        .expect("relay environment load");
    assert!(
        middle.points().iter().flat_map(|point| &point.events).any(
            |event| matches!(event.effect, SemanticEffect::Assignment { target, value }
            if value == incoming && second.captured == CaptureSource::Value(target))
        ),
        "the relay snapshots its established input"
    );
    assert_ne!(first.target, second.target);
    let siblings = method(&artifact, "siblings");
    assert_eq!(siblings.captures().len(), 2);
    assert_ne!(
        siblings.captures()[0].captured,
        siblings.captures()[1].captured
    );
    for name in ["pattern", "factory", "reassigned", "assignedParameter"] {
        assert!(
            method(&artifact, name)
                .gaps()
                .iter()
                .any(|gap| gap.capability == SemanticCapability::Captures),
            "{name} must retain its missing capture proof"
        );
    }
}

#[test]
fn labeled_loop_header_keeps_its_own_source_mapping() {
    let source =
        "class Fixture { void f(boolean again) { outer: while (again) { continue outer; } } }";
    let artifact = java_semantics(source);
    let procedure = method(&artifact, "f");
    let edge = procedure
        .control_edges()
        .iter()
        .find(|edge| edge.kind == ControlEdgeKind::LoopBack)
        .expect("continue returns to the loop header");
    let header = procedure.point(edge.target_point).unwrap();
    assert_eq!(
        mapping_text(procedure, source, header.source),
        "while (again) { continue outer; }"
    );
    assert!(
        procedure.control_edges().iter().any(|incoming| {
            let point = procedure.point(incoming.source_point).unwrap();
            incoming.kind == ControlEdgeKind::Normal
                && incoming.target_point == header.id
                && mapping_text(procedure, source, point.source)
                    == "outer: while (again) { continue outer; }"
        }),
        "the label enters its separately mapped loop header"
    );
}

#[test]
fn free_this_scan_honors_cancellation() {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must load");
    let tree = parser
        .parse(
            "class Example { Object value() { int first = 1; int second = 2; return this; } }",
            None,
        )
        .expect("Java source must parse");
    let mut body = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "block" {
                body = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let cancellation = CancellationToken::cancel_after_checks_for_test(2);
    assert_eq!(
        body_contains_free_this(body.expect("method body"), &cancellation),
        Err(LoweringCancelled)
    );
}

fn value_text<'s>(procedure: &ProcedureSemantics, source: &'s str, value: ValueId) -> &'s str {
    mapping_text(procedure, source, procedure.values()[value.index()].source)
}

fn value_kind(procedure: &ProcedureSemantics, value: ValueId) -> SemanticValueKind {
    procedure.values()[value.index()].kind.clone()
}

fn default_field_stores(
    procedure: &ProcedureSemantics,
    source: &str,
) -> Vec<(String, (usize, usize), SemanticValueKind, ValueId)> {
    let normal_reaches = |start: ProgramPointId, target: ProgramPointId| {
        let mut visited = HashSet::default();
        let mut pending = vec![start];
        while let Some(point) = pending.pop() {
            if point == target {
                return true;
            }
            if visited.insert(point) {
                pending.extend(
                    procedure
                        .successor_edges(point)
                        .filter(|(_, edge)| edge.kind == ControlEdgeKind::Normal)
                        .map(|(_, edge)| edge.target_point),
                );
            }
        }
        false
    };
    let mut stores = procedure
        .points()
        .iter()
        .flat_map(|point| {
            point
                .events
                .iter()
                .enumerate()
                .filter_map(move |(event_index, event)| {
                    let SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Field,
                        location,
                        value,
                    } = &event.effect
                    else {
                        return None;
                    };
                    let MemoryLocationKind::Field { base, member } =
                        &procedure.memory_locations()[location.index()].kind
                    else {
                        panic!("field store must use a field location")
                    };
                    assert!(matches!(
                        procedure.values()[base.index()].kind,
                        SemanticValueKind::Receiver { dispatch: true }
                    ));
                    let span = member.anchor().span();
                    let start = span.start_byte() as usize;
                    let end = span.end_byte() as usize;
                    Some((
                        point.id,
                        event_index,
                        source[start..end].to_owned(),
                        (start, end),
                        value_kind(procedure, *value),
                        *value,
                    ))
                })
        })
        .collect::<Vec<_>>();
    for (point, _, _, _, _, _) in &stores {
        assert!(
            normal_reaches(procedure.entry_point(), *point),
            "field store point {point:?} is unreachable from the constructor entry"
        );
    }
    stores.sort_by(|left, right| {
        if left.0 == right.0 {
            return left.3.cmp(&right.3).then_with(|| left.1.cmp(&right.1));
        }
        if normal_reaches(left.0, right.0) {
            std::cmp::Ordering::Less
        } else if normal_reaches(right.0, left.0) {
            std::cmp::Ordering::Greater
        } else {
            panic!(
                "field store points are incomparable on the normal CFG: {:?} and {:?}",
                left.0, right.0
            );
        }
    });
    stores
        .into_iter()
        .map(|(_, _, name, span, kind, value)| (name, span, kind, value))
        .collect()
}

fn normal_cfg_reaches(
    procedure: &ProcedureSemantics,
    start: ProgramPointId,
    target: ProgramPointId,
) -> bool {
    let mut visited = HashSet::default();
    let mut pending = vec![start];
    while let Some(point) = pending.pop() {
        if point == target {
            return true;
        }
        if visited.insert(point) {
            pending.extend(
                procedure
                    .control_edges()
                    .iter()
                    .filter(|edge| {
                        edge.source_point == point && edge.kind == ControlEdgeKind::Normal
                    })
                    .map(|edge| edge.target_point),
            );
        }
    }
    false
}

fn field_store_points(procedure: &ProcedureSemantics) -> Vec<(ProgramPointId, SemanticValueKind)> {
    procedure
        .points()
        .iter()
        .flat_map(|point| {
            point.events.iter().filter_map(move |event| {
                let SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Field,
                    value,
                    ..
                } = &event.effect
                else {
                    return None;
                };
                Some((point.id, value_kind(procedure, *value)))
            })
        })
        .collect()
}

/// The normalized shape of one guard, with its constant resolved to the
/// published value kind.
#[derive(Debug, PartialEq)]
enum Shape {
    Integer(IntegerComparison, SemanticValueKind),
    Float(IntegerComparison, SemanticValueKind),
    Equality(bool, SemanticValueKind),
    Nan(bool),
    Constant(bool),
    Opaque,
}

/// The one guard recorded for `condition`, and its subject's spelling.
fn guard_shape<'s>(
    procedure: &ProcedureSemantics,
    source: &'s str,
    condition: &str,
) -> (Shape, Option<&'s str>) {
    let guards = procedure
        .guard_facts()
        .iter()
        .filter(|guard| mapping_text(procedure, source, guard.source) == condition)
        .collect::<Vec<_>>();
    let [guard] = guards[..] else {
        panic!("expected one guard for {condition}: {guards:?}");
    };
    let shape = match guard.predicate {
        GuardPredicate::OrderedIntegerComparison { relation, constant } => {
            Shape::Integer(relation, value_kind(procedure, constant))
        }
        GuardPredicate::OrderedFloatComparison { relation, constant } => {
            Shape::Float(relation, value_kind(procedure, constant))
        }
        GuardPredicate::ConstantEquality { negated, constant } => {
            Shape::Equality(negated, value_kind(procedure, constant))
        }
        GuardPredicate::NanComparison { nan_on_true } => Shape::Nan(nan_on_true),
        GuardPredicate::ConstantBoolean { value } => Shape::Constant(value),
        GuardPredicate::Opaque { .. } => Shape::Opaque,
        ref other => panic!("unexpected guard for {condition}: {other:?}"),
    };
    let subject = match shape {
        Shape::Opaque | Shape::Constant(_) => None,
        _ => guard
            .subject
            .map(|subject| value_text(procedure, source, subject)),
    };
    (shape, subject)
}

/// The control-edge kind of the arm on which `condition`'s predicate holds.
fn true_arm_kind(procedure: &ProcedureSemantics, source: &str, condition: &str) -> ControlEdgeKind {
    let guard = procedure
        .guard_facts()
        .iter()
        .find(|guard| mapping_text(procedure, source, guard.source) == condition)
        .unwrap_or_else(|| panic!("no guard for {condition}"));
    procedure
        .control_edge(guard.true_edge.expect("true arm"))
        .expect("guard arm edge")
        .kind
}

#[test]
fn primitive_integral_comparisons_publish_typed_integer_guards() {
    use IntegerComparison::*;
    use SemanticValueKind::{SignedInteger, UnsignedInteger};
    let source = r#"class Fixture {
  int count;
  void run(int x, long y, byte b, char c, Integer boxed, int[] values) {
    var inferred = 1;
    if (x < -1L) {}
    if (5 >= x) {}
    if (!(x < 3)) {}
    if (y > 0x7FFFFFFFFFFFFFFFL) {}
    if (x <= 0xFFFFFFFF) {}
    if (b == 0xF) {}
    if (c != 65) {}
    if (y == -9223372036854775808L) {}
    if (x < 1.5) {}
    if (x == 1.5) {}
    if (boxed < 5) {}
    if (inferred < 5) {}
    if (count < 5) {}
    if (values.length < 5) {}
    if (x < x) {}
    if (x <= x) {}
  }
}
"#;
    let artifact = java_semantics(source);
    let run = method(&artifact, "run");
    let guard = |condition| guard_shape(run, source, condition);
    assert_eq!(
        guard("x < -1L"),
        (Shape::Integer(LessThan, SignedInteger(-1)), Some("x"))
    );
    assert_eq!(
        guard("5 >= x"),
        (
            Shape::Integer(LessThanOrEqual, UnsignedInteger(5)),
            Some("x")
        )
    );
    assert_eq!(
        guard("!(x < 3)"),
        (
            Shape::Integer(GreaterThanOrEqual, UnsignedInteger(3)),
            Some("x")
        )
    );
    assert_eq!(
        guard("y > 0x7FFFFFFFFFFFFFFFL"),
        (
            Shape::Integer(GreaterThan, UnsignedInteger(i64::MAX as u128)),
            Some("y")
        )
    );
    assert_eq!(
        guard("x <= 0xFFFFFFFF"),
        (
            Shape::Integer(LessThanOrEqual, SignedInteger(-1)),
            Some("x")
        )
    );
    assert_eq!(
        guard("b == 0xF"),
        (Shape::Equality(false, UnsignedInteger(15)), Some("b"))
    );
    assert_eq!(
        guard("c != 65"),
        (Shape::Equality(true, UnsignedInteger(65)), Some("c"))
    );
    assert_eq!(
        guard("y == -9223372036854775808L"),
        (
            Shape::Equality(false, SignedInteger(i128::from(i64::MIN))),
            Some("y")
        )
    );
    // A floating literal promotes the integral subject: no integer guard,
    // and equality keeps an unrepresented constant.
    assert_eq!(guard("x < 1.5"), (Shape::Opaque, None));
    assert_eq!(
        guard("x == 1.5"),
        (
            Shape::Equality(false, SemanticValueKind::Constant),
            Some("x")
        )
    );
    // An ordering unboxes a boxed subject to its primitive type; a null one
    // throws before the guard decides.
    assert_eq!(
        guard("boxed < 5"),
        (Shape::Integer(LessThan, UnsignedInteger(5)), Some("boxed"))
    );
    // Inferred, field and array-length subjects stay open.
    for condition in ["inferred < 5", "count < 5", "values.length < 5"] {
        assert_eq!(guard(condition), (Shape::Opaque, None), "{condition}");
    }
    assert_eq!(guard("x < x"), (Shape::Constant(false), None));
    assert_eq!(guard("x <= x"), (Shape::Constant(true), None));
}

#[test]
fn primitive_floating_comparisons_publish_float_and_nan_guards() {
    use IntegerComparison::*;
    let source = r#"class Fixture {
  void run(double d, float f, Double boxed, double[] values) {
    if (d < 0.5) {}
    if (2 < d) {}
    if (f <= 0.1f) {}
    if (f < 16777216) {}
    if (f < 16777217) {}
    if (d < 16777217) {}
    if (d < 9007199254740993L) {}
    if (!(d < 1.0)) {}
    if (d == 1.5) {}
    if (f != 3) {}
    if (d != d) {}
    if (d == d) {}
    if (!(f <= f)) {}
    if (d >= d) {}
    if (d < d) {}
    if (boxed == boxed) {}
    if (boxed < 1.0) {}
    if (boxed <= boxed) {}
    if (values[0] < 1.0) {}
  }
}
"#;
    let artifact = java_semantics(source);
    let run = method(&artifact, "run");
    let guard = |condition| guard_shape(run, source, condition);
    assert_eq!(
        guard("d < 0.5"),
        (Shape::Float(LessThan, floating(0.5)), Some("d"))
    );
    assert_eq!(
        guard("2 < d"),
        (Shape::Float(GreaterThan, floating(2.0)), Some("d"))
    );
    assert_eq!(
        guard("f <= 0.1f"),
        (
            Shape::Float(LessThanOrEqual, floating(f64::from(0.1_f32))),
            Some("f")
        )
    );
    assert_eq!(
        guard("f < 16777216"),
        (Shape::Float(LessThan, floating(16_777_216.0)), Some("f"))
    );
    // `float` promotion would round 2^24 + 1; `double` holds it exactly but
    // not 2^53 + 1.
    assert_eq!(guard("f < 16777217"), (Shape::Opaque, None));
    assert_eq!(
        guard("d < 16777217"),
        (Shape::Float(LessThan, floating(16_777_217.0)), Some("d"))
    );
    assert_eq!(guard("d < 9007199254740993L"), (Shape::Opaque, None));
    // NaN fails both `d < 1.0` and `d >= 1.0`, so the negation keeps the
    // un-negated predicate on swapped arms: it holds on the false successor.
    assert_eq!(
        guard("!(d < 1.0)"),
        (Shape::Float(LessThan, floating(1.0)), Some("d"))
    );
    assert_eq!(
        true_arm_kind(run, source, "!(d < 1.0)"),
        ControlEdgeKind::ConditionalFalse
    );
    assert_eq!(
        true_arm_kind(run, source, "d < 0.5"),
        ControlEdgeKind::ConditionalTrue
    );
    assert_eq!(
        guard("d == 1.5"),
        (Shape::Equality(false, floating(1.5)), Some("d"))
    );
    assert_eq!(
        guard("f != 3"),
        (Shape::Equality(true, floating(3.0)), Some("f"))
    );
    assert_eq!(guard("d != d"), (Shape::Nan(true), Some("d")));
    assert_eq!(guard("d == d"), (Shape::Nan(false), Some("d")));
    assert_eq!(guard("!(f <= f)"), (Shape::Nan(true), Some("f")));
    assert_eq!(guard("d >= d"), (Shape::Nan(false), Some("d")));
    assert_eq!(guard("d < d"), (Shape::Constant(false), None));
    // A boxed value compares by reference identity under `==` and unboxes
    // under an ordering, where a null one throws before the guard decides.
    assert_eq!(guard("boxed == boxed"), (Shape::Constant(true), None));
    assert_eq!(
        guard("boxed < 1.0"),
        (Shape::Float(LessThan, floating(1.0)), Some("boxed"))
    );
    assert_eq!(guard("boxed <= boxed"), (Shape::Nan(false), Some("boxed")));
    assert_eq!(guard("values[0] < 1.0"), (Shape::Opaque, None));
}

#[test]
#[hardwon("#2363: qualified external Java calls lost their owner type prefix")]
fn type_name_prefix_recognizes_qualified_stdlib_types() {
    assert_eq!(java_type_name_prefix_len(&["java", "net", "URLDecoder"]), 3);
    assert_eq!(
        java_type_name_prefix_len(&["java", "net", "URLDecoder", "SOME_CONST"]),
        3
    );
    assert_eq!(java_type_name_prefix_len(&["inheritedField", "nested"]), 0);
    assert_eq!(java_type_name_prefix_len(&["Outer", "Inner"]), 2);
}

#[test]
fn default_constructors_publish_source_backed_bodies_and_keep_execution_boundaries() {
    for (source, complete) in [
        ("class Fixture {}", true),
        ("class Fixture { static class Nested {} }", true),
        ("class Fixture extends Base {} class Base {}", false),
        (
            "class Fixture implements Action {} interface Action { default void run() {} }",
            false,
        ),
        (
            "class Fixture { int value = compute(); int compute() { return 1; } }",
            false,
        ),
        ("class Fixture { int value; }", true),
        ("class Fixture { { compute(); } void compute() {} }", false),
        (
            "class Fixture { static { compute(); } static void compute() {} }",
            false,
        ),
        ("class Outer { class Fixture {} }", false),
        ("class Outer { void run() { class Fixture {} } }", false),
    ] {
        let artifact = java_semantics(source);
        let constructor = method(&artifact, "Fixture");
        assert_eq!(constructor.kind(), ProcedureKind::Constructor, "{source}");
        assert!(constructor.properties().is_synthetic, "{source}");
        assert_eq!(
            constructor.properties().construction_return,
            ConstructionReturn::PreservesAllocation
        );
        assert_eq!(
            constructor.gaps().is_empty(),
            complete,
            "{source}: {:?}",
            constructor.gaps()
        );
    }
    let interface = java_semantics(
        "class Fixture implements Action {} interface Action { default void run() {} }",
    );
    assert!(method(&interface, "Fixture").gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::DeferredExecution
            && gap.impacts == SemanticGapImpacts::CALL_EVALUATION
    }));
    let artifact = java_semantics("class Fixture { Fixture() {} void run() {} }");
    let constructors = artifact
        .procedures()
        .iter()
        .filter(|procedure| procedure.kind() == ProcedureKind::Constructor)
        .collect::<Vec<_>>();
    assert_eq!(constructors.len(), 1);
    assert!(!constructors[0].properties().is_synthetic);
    assert!(method(&artifact, "run").lexical_parent().is_none());
}

#[test]
fn explicit_constructor_emits_defaults_and_retains_only_uncomposed_gap() {
    let source = "class Fixture { int initialized = 1; int plain; Fixture() { super(); } }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert_eq!(constructor.kind(), ProcedureKind::Constructor);
    assert!(!constructor.properties().is_synthetic);
    assert_eq!(
        default_field_stores(constructor, source)
            .into_iter()
            .map(|(name, _, _, _)| name)
            .collect::<Vec<_>>(),
        vec!["initialized".to_owned(), "plain".to_owned()]
    );
    assert_eq!(
        constructor
            .gaps()
            .iter()
            .filter(|gap| {
                gap.capability == SemanticCapability::DeferredExecution
                    && gap.impacts == SemanticGapImpacts::CALL_EVALUATION
                    && gap.kind == SemanticGapKind::Unsupported
                    && gap.subject == SemanticGapSubject::Procedure
            })
            .count(),
        1
    );

    for source in [
        "class Fixture { int plain; Fixture() { super(); } }",
        "class Fixture { int plain; Fixture() { plain = 1; } }",
    ] {
        let artifact = java_semantics(source);
        let constructor = method(&artifact, "Fixture");
        assert_eq!(constructor.kind(), ProcedureKind::Constructor, "{source}");
        assert!(!constructor.properties().is_synthetic, "{source}");
        assert_eq!(
            default_field_stores(constructor, source)
                .into_iter()
                .map(|(name, _, _, _)| name)
                .next(),
            Some("plain".into()),
            "{source}"
        );
        assert!(
            !constructor.gaps().iter().any(|gap| {
                gap.capability == SemanticCapability::DeferredExecution
                    && gap.impacts == SemanticGapImpacts::CALL_EVALUATION
                    && gap.kind == SemanticGapKind::Unsupported
                    && gap.subject == SemanticGapSubject::Procedure
            }),
            "{source}: {:?}",
            constructor.gaps()
        );
    }

    let source = "class Fixture { { setup(); } int plain; Fixture() { super(); } void setup() {} }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert_eq!(default_field_stores(constructor, source).len(), 1);
    assert!(constructor.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::DeferredExecution
            && gap.impacts == SemanticGapImpacts::CALL_EVALUATION
            && gap.kind == SemanticGapKind::Unsupported
            && gap.subject == SemanticGapSubject::Procedure
    }));
}

#[test]
fn explicit_constructor_defaults_follow_normal_cfg_before_super_and_body_write() {
    let source = "class Base { Base() {} Base(int seed) {} } class Fixture extends Base { int value; Fixture() { super(7); value = 1; } }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    let stores = field_store_points(constructor);
    let default_point = stores
        .iter()
        .find(|(_, kind)| matches!(kind, SemanticValueKind::UnsignedInteger(0)))
        .map(|(point, _)| *point)
        .expect("default field store");
    let body_point = stores
        .iter()
        .find(|(_, kind)| matches!(kind, SemanticValueKind::Constant))
        .map(|(point, _)| *point)
        .expect("constructor body field write");
    let super_point =
        constructor_call_point(constructor, source, "super").expect("explicit super callee anchor");
    assert!(normal_cfg_reaches(constructor, default_point, super_point));
    assert!(normal_cfg_reaches(constructor, super_point, body_point));
    assert!(!normal_cfg_reaches(constructor, body_point, super_point));
}

#[test]
fn explicit_constructor_implicit_super_runs_after_default_store() {
    let source = "class Fixture { int value; Fixture() { value = 1; } }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    let stores = field_store_points(constructor);
    let default_point = stores
        .iter()
        .find(|(_, kind)| matches!(kind, SemanticValueKind::UnsignedInteger(0)))
        .map(|(point, _)| *point)
        .expect("default field store");
    let body_point = stores
        .iter()
        .find(|(_, kind)| matches!(kind, SemanticValueKind::Constant))
        .map(|(point, _)| *point)
        .expect("constructor body field write");
    let implicit_gaps = constructor
        .gaps()
        .iter()
        .filter(|gap| {
            gap.capability == SemanticCapability::Calls
                && gap.subject == SemanticGapSubject::Point
                && gap.detail.as_ref()
                    == "implicit super-constructor invocation is not yet represented as a call site"
        })
        .collect::<Vec<_>>();
    assert_eq!(implicit_gaps.len(), 1);
    let super_gap = implicit_gaps[0];
    assert!(normal_cfg_reaches(
        constructor,
        constructor.entry_point(),
        default_point
    ));
    assert!(normal_cfg_reaches(
        constructor,
        default_point,
        super_gap.point
    ));
    assert!(normal_cfg_reaches(constructor, super_gap.point, body_point));
    assert!(constructor.control_edges().iter().any(|edge| {
        edge.source_point == super_gap.point && edge.kind == ControlEdgeKind::Exceptional
    }));
}

#[test]
fn synthetic_constructor_superclass_gap_follows_defaults_and_has_exception_edge() {
    let source = "class Base { Base() {} } class Fixture extends Base { int value; }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert!(constructor.properties().is_synthetic);
    let default_point = field_store_points(constructor)
        .into_iter()
        .find(|(_, kind)| matches!(kind, SemanticValueKind::UnsignedInteger(0)))
        .map(|(point, _)| point)
        .expect("synthetic default field store");
    let superclass_gaps = constructor
        .gaps()
        .iter()
        .filter(|gap| {
            gap.capability == SemanticCapability::Calls
                && gap.subject == SemanticGapSubject::Point
                && gap.detail.as_ref()
                    == "default constructor superclass invocation is not yet modeled"
        })
        .collect::<Vec<_>>();
    assert_eq!(superclass_gaps.len(), 1);
    let superclass_gap = superclass_gaps[0];
    assert_eq!(superclass_gap.impacts, SemanticGapImpacts::CALL_EVALUATION);
    assert_ne!(superclass_gap.point, constructor.entry_point());
    assert!(
        constructor
            .successor_edges(constructor.entry_point())
            .any(|(_, edge)| {
                edge.kind == ControlEdgeKind::Normal && edge.target_point == default_point
            })
    );
    assert!(normal_cfg_reaches(
        constructor,
        default_point,
        superclass_gap.point
    ));
    assert!(normal_cfg_reaches(
        constructor,
        superclass_gap.point,
        constructor.normal_exit_point()
    ));
    assert!(constructor.control_edges().iter().any(|edge| {
        edge.source_point == superclass_gap.point && edge.kind == ControlEdgeKind::Exceptional
    }));
}

#[test]
fn explicit_constructor_default_locator_ignores_parameter_shadowing() {
    let source = "class Fixture { int value; Fixture(int value) { super(); } }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert_eq!(
        default_field_stores(constructor, source)
            .into_iter()
            .map(|(name, _, kind, _)| (name, kind))
            .collect::<Vec<_>>(),
        vec![("value".into(), SemanticValueKind::UnsignedInteger(0))]
    );
    assert!(!constructor.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::FieldMemory
            && gap.kind == SemanticGapKind::Unsupported
    }));
}

#[test]
fn delegating_constructor_does_not_reset_target_default_stores() {
    let source = "class Fixture { int value; Fixture() { /* delegate */ this(1); } Fixture(int value) { /* superclass */ super(); } }";
    let artifact = java_semantics(source);
    let constructors = artifact
        .procedures()
        .iter()
        .filter(|procedure| procedure.kind() == ProcedureKind::Constructor)
        .collect::<Vec<_>>();
    let delegating = constructors
        .iter()
        .copied()
        .find(|procedure| constructor_call_point(procedure, source, "this").is_some())
        .expect("delegating constructor");
    let target = constructors
        .iter()
        .copied()
        .find(|procedure| constructor_call_point(procedure, source, "super").is_some())
        .expect("nondelegating target constructor");
    assert!(default_field_stores(delegating, source).is_empty());
    assert_eq!(default_field_stores(target, source).len(), 1);
    assert!(!delegating.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::DeferredExecution
            && gap.impacts == SemanticGapImpacts::CALL_EVALUATION
            && gap.kind == SemanticGapKind::Unsupported
            && gap.subject == SemanticGapSubject::Procedure
    }));
}

#[test]
fn explicit_constructor_reference_field_defaults_to_null_without_resolution() {
    let source = "class Fixture { Missing value; Fixture() { super(); } }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert_eq!(
        default_field_stores(constructor, source)
            .into_iter()
            .map(|(name, _, kind, _)| (name, kind))
            .collect::<Vec<_>>(),
        vec![("value".into(), SemanticValueKind::Null)]
    );
    assert!(!constructor.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::FieldMemory
            && gap.kind == SemanticGapKind::Unsupported
            && matches!(gap.subject, SemanticGapSubject::Value(_))
    }));
}

#[test]
fn explicit_constructor_without_fields_keeps_existing_gap_shape() {
    let source = "class Fixture { Fixture() { super(); } }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert!(default_field_stores(constructor, source).is_empty());
    assert!(!constructor.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::DeferredExecution
            && gap.impacts == SemanticGapImpacts::CALL_EVALUATION
            && gap.kind == SemanticGapKind::Unsupported
            && gap.subject == SemanticGapSubject::Procedure
    }));
}

#[test]
fn explicit_enum_and_record_constructors_do_not_panic_on_class_guard() {
    let enum_artifact = java_semantics("enum Fixture { A; Fixture() { } }");
    assert!(
        enum_artifact
            .procedures()
            .iter()
            .any(|procedure| procedure.kind() == ProcedureKind::Constructor)
    );

    let record_artifact = java_semantics("record Fixture(int value) { Fixture { } }");
    assert!(
        record_artifact
            .procedures()
            .iter()
            .any(|procedure| procedure.kind() == ProcedureKind::Constructor)
    );
}

#[test]
fn explicit_nested_constructor_defaults_keep_field_declaration_boundary() {
    let source = "class Outer { int outer; class Inner { int inner; Inner() { super(); } } }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Inner");
    assert_eq!(
        default_field_stores(constructor, source)
            .into_iter()
            .map(|(name, _, _, _)| name)
            .collect::<Vec<_>>(),
        vec!["inner".to_owned()]
    );
}

fn only_lambda_creation(procedure: &ProcedureSemantics) -> (ProcedureId, Option<AllocationId>) {
    let creations = procedure
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter_map(|event| {
            let SemanticEffect::CallableCreation { callable, .. } = &event.effect else {
                return None;
            };
            assert_eq!(callable.kind, CallableReferenceKind::Lambda);
            let CallableTargetResolution::Proven(CallableTarget::Local(target)) = &callable.targets
            else {
                panic!("lambda creation must have a proven local target: {callable:?}");
            };
            Some((*target, callable.environment))
        })
        .collect::<Vec<_>>();
    let [creation] = creations.as_slice() else {
        panic!("expected one lambda creation, found {creations:?}");
    };
    *creation
}

#[test]
fn synthetic_default_constructor_owns_non_capturing_instance_field_lambda() {
    let source = r#"
        import java.util.function.Supplier;
        class Fixture {
            Supplier<Integer> value = () -> 1;
            void run() {}
        }
    "#;
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert_eq!(constructor.kind(), ProcedureKind::Constructor);
    assert!(constructor.properties().is_synthetic);

    let (target, environment) = only_lambda_creation(constructor);
    assert!(environment.is_none());
    let lambda = artifact
        .procedure(target)
        .expect("instance field lambda target");
    assert_eq!(lambda.kind(), ProcedureKind::Lambda);
    assert_eq!(lambda.lexical_parent(), Some(constructor.id()));
    assert_eq!(
        artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure.kind() == ProcedureKind::Lambda)
            .count(),
        1
    );
    assert!(
        artifact
            .procedures()
            .iter()
            .all(|procedure| procedure.kind() != ProcedureKind::Initializer)
    );

    let run = method(&artifact, "run");
    assert_eq!(run.kind(), ProcedureKind::Method);
    assert!(run.lexical_parent().is_none());
    assert_ne!(run.id(), constructor.id());
}

#[test]
fn synthetic_default_constructor_owns_capturing_instance_field_lambda() {
    let source = r#"
        class Fixture {
            Runnable action = () -> this.run();
            void run() {}
        }
    "#;
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert_eq!(constructor.kind(), ProcedureKind::Constructor);
    assert!(constructor.properties().is_synthetic);

    let (target, environment) = only_lambda_creation(constructor);
    assert!(environment.is_some());
    let lambda = artifact
        .procedure(target)
        .expect("capturing instance field lambda target");
    assert_eq!(lambda.kind(), ProcedureKind::Lambda);
    assert_eq!(lambda.lexical_parent(), Some(constructor.id()));
    let [capture] = constructor.captures() else {
        panic!("receiver capture: {:?}", constructor.captures());
    };
    assert_eq!(capture.target, lambda.id());
    assert_eq!(capture.mode, CaptureMode::Value);
    let location = lambda
        .memory_location(capture.destination)
        .expect("receiver capture destination");
    let MemoryLocationKind::Capture {
        lexical_parent,
        binding: None,
    } = &location.kind
    else {
        panic!("receiver capture location: {:?}", location.kind);
    };
    assert_eq!(*lexical_parent, constructor.id());
    assert_eq!(
        artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure.kind() == ProcedureKind::Lambda)
            .count(),
        1
    );
    assert!(
        artifact
            .procedures()
            .iter()
            .all(|procedure| procedure.kind() != ProcedureKind::Initializer)
    );

    let run = method(&artifact, "run");
    assert_eq!(run.kind(), ProcedureKind::Method);
    assert!(run.lexical_parent().is_none());
    assert_ne!(run.id(), constructor.id());

    let boundary = java_semantics(
        "class Boundary { static Runnable shared = () -> {}; Runnable value = () -> {}; Boundary() {} }",
    );
    let explicit_constructor = boundary
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Constructor && !procedure.properties().is_synthetic
        })
        .expect("written constructor");
    let initializer_lambdas = boundary
        .procedures()
        .iter()
        .filter(|procedure| procedure.kind() == ProcedureKind::Initializer)
        .map(|initializer| {
            let (target, _) = only_lambda_creation(initializer);
            let lambda = boundary
                .procedure(target)
                .expect("initializer lambda target");
            assert_eq!(lambda.lexical_parent(), Some(initializer.id()));
            lambda.id()
        })
        .collect::<Vec<_>>();
    assert_eq!(initializer_lambdas.len(), 2);
    assert!(
        explicit_constructor
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .all(|event| !matches!(
                event.effect,
                SemanticEffect::CallableCreation {
                    callable: CallableValue {
                        kind: CallableReferenceKind::Lambda,
                        ..
                    },
                    ..
                }
            ))
    );
}

#[test]
fn synthetic_default_constructor_stores_typed_jls_defaults_without_locals() {
    let source = r#"
        class Fixture {
            byte signedByte;
            short signedShort;
            int count;
            long total;
            char letter;
            boolean ready;
            float ratio;
            double scale;
            Integer boxed;
            int[] primitiveArray;
            Integer[] boxedArray;
            String label;
            static int shared;
            static class Nested {
                long nestedCount;
                Object nestedObject;
                static boolean ignored;
            }
        }
    "#;
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    let positive_zero = SemanticValueKind::FloatingPoint {
        bits: 0.0_f64.to_bits(),
    };
    assert_eq!(
        default_field_stores(constructor, source)
            .into_iter()
            .map(|(name, _, kind, _)| (name, kind))
            .collect::<Vec<_>>(),
        vec![
            ("signedByte".into(), SemanticValueKind::UnsignedInteger(0)),
            ("signedShort".into(), SemanticValueKind::UnsignedInteger(0)),
            ("count".into(), SemanticValueKind::UnsignedInteger(0)),
            ("total".into(), SemanticValueKind::UnsignedInteger(0)),
            ("letter".into(), SemanticValueKind::UnsignedInteger(0)),
            ("ready".into(), SemanticValueKind::Boolean(false)),
            ("ratio".into(), positive_zero.clone()),
            ("scale".into(), positive_zero),
            ("boxed".into(), SemanticValueKind::Null),
            ("primitiveArray".into(), SemanticValueKind::Null),
            ("boxedArray".into(), SemanticValueKind::Null),
            ("label".into(), SemanticValueKind::Null),
        ]
    );
    assert!(
        constructor
            .values()
            .iter()
            .all(|value| !matches!(value.kind, SemanticValueKind::Local))
    );

    let nested = method(&artifact, "Nested");
    assert_eq!(
        default_field_stores(nested, source)
            .into_iter()
            .map(|(name, _, kind, _)| (name, kind))
            .collect::<Vec<_>>(),
        vec![
            ("nestedCount".into(), SemanticValueKind::UnsignedInteger(0)),
            ("nestedObject".into(), SemanticValueKind::Null),
        ]
    );
    assert!(
        nested
            .values()
            .iter()
            .all(|value| !matches!(value.kind, SemanticValueKind::Local))
    );
}

#[test]
fn synthetic_default_constructor_keeps_declarator_and_owner_field_identity() {
    let source = r#"
        class Fixture {
            int value, sibling;
            String label;
            static int ignored;
            void run() { int value = 1; }
            static class Nested { int value; }
        }
    "#;
    let artifact = java_semantics(source);
    let fixture = method(&artifact, "Fixture");
    let fixture_stores = default_field_stores(fixture, source);
    assert_eq!(
        fixture_stores
            .iter()
            .map(|(name, _, _, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["value", "sibling", "label"]
    );
    assert!(
        fixture
            .values()
            .iter()
            .all(|value| !matches!(value.kind, SemanticValueKind::Local))
    );

    let nested = method(&artifact, "Nested");
    let nested_stores = default_field_stores(nested, source);
    assert_eq!(nested_stores.len(), 1);
    assert_eq!(nested_stores[0].0, "value");
    assert_ne!(fixture_stores[0].1, nested_stores[0].1);
}

#[test]
fn synthetic_default_constructor_orders_defaults_before_instance_initializers() {
    let source = r#"
        class Fixture {
            int value = 1;
            Integer boxed = new Integer(2);
            String spare = "";
        }
    "#;
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    let stores = default_field_stores(constructor, source);
    assert_eq!(
        stores
            .iter()
            .map(|(name, _, kind, _)| (name.as_str(), kind.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("value", SemanticValueKind::UnsignedInteger(0)),
            ("boxed", SemanticValueKind::Null),
            ("spare", SemanticValueKind::Null),
            ("value", SemanticValueKind::Constant),
            ("boxed", SemanticValueKind::Temporary),
            ("spare", SemanticValueKind::Constant),
        ]
    );
    assert_eq!(value_text(constructor, source, stores[3].3), "1");
    assert!(
        constructor
            .values()
            .iter()
            .all(|value| !matches!(value.kind, SemanticValueKind::Local))
    );
}

#[test]
fn synthetic_default_constructor_retains_field_memory_gap_for_ambiguous_locator() {
    let source = "class Fixture { int value; int value; }";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    assert!(default_field_stores(constructor, source).is_empty());
    let field_gaps = constructor
        .gaps()
        .iter()
        .filter(|gap| {
            gap.capability == SemanticCapability::FieldMemory
                && gap.kind == SemanticGapKind::Unsupported
        })
        .collect::<Vec<_>>();
    assert_eq!(field_gaps.len(), 2);
    assert!(
        field_gaps
            .iter()
            .all(|gap| matches!(gap.subject, SemanticGapSubject::Value(_)))
    );
    assert_eq!(
        field_gaps
            .iter()
            .map(|gap| &gap.subject)
            .collect::<HashSet<_>>()
            .len(),
        2
    );
}

#[test]
fn default_constructor_owns_the_type_anchor_and_preserves_distinct_typed_gaps() {
    let source = "class Outer { class Fixture extends Base { int value = 1; String label; static int shared; { setup(); } void setup() {} void run() {} } } class Base {}";
    let artifact = java_semantics(source);
    let constructor = method(&artifact, "Fixture");
    let stores = default_field_stores(constructor, source);
    assert_eq!(
        stores
            .iter()
            .map(|(name, _, kind, _)| (name.as_str(), kind.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("value", SemanticValueKind::UnsignedInteger(0)),
            ("label", SemanticValueKind::Null),
            ("value", SemanticValueKind::Constant),
        ]
    );
    assert_eq!(value_text(constructor, source, stores[2].3), "1");
    assert!(!constructor.values().iter().any(|value| {
        value.kind == SemanticValueKind::Local
            && ["value", "label"].contains(&value_text(constructor, source, value.id))
    }));
    let locator = constructor.locator();
    let segments = locator.declaration().segments();
    assert_eq!(
        segments.last().unwrap().kind(),
        DeclarationSegmentKind::Constructor
    );
    assert_eq!(
        segments[segments.len() - 2].kind(),
        DeclarationSegmentKind::Type
    );
    assert_eq!(segments.last().unwrap().name(), Some("Fixture"));
    let tree = parse_java(source);
    let inner = first_kind(tree.root_node(), "class_body")
        .named_child(0)
        .unwrap();
    assert_eq!(
        locator.anchor().span().start_byte() as usize,
        inner.start_byte()
    );
    assert_eq!(
        locator.anchor().span().end_byte() as usize,
        inner.end_byte()
    );
    assert!(method(&artifact, "run").lexical_parent().is_none());
    let caps = constructor
        .gaps()
        .iter()
        .map(|gap| gap.capability)
        .collect::<HashSet<_>>();
    let expected_caps = [
        SemanticCapability::Calls,
        SemanticCapability::DeferredExecution,
        SemanticCapability::FieldMemory,
        SemanticCapability::Captures,
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    assert_eq!(constructor.gaps().len(), expected_caps.len());
    assert_eq!(caps, expected_caps);
    assert!(
        constructor
            .gaps()
            .iter()
            .all(|gap| gap.impacts != SemanticGapImpacts::NONE)
    );
    assert!(constructor.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::DeferredExecution
            && gap.impacts == SemanticGapImpacts::CALL_EVALUATION
    }));
    assert!(constructor.gaps().iter().any(|gap| {
        gap.capability == SemanticCapability::FieldMemory
            && gap.impacts == SemanticGapImpacts::DEFERRED_EFFECTS
    }));
    let malformed = java_semantics("class Fixture { void broken( }");
    assert!(
        malformed
            .procedures()
            .iter()
            .all(|p| !p.properties().is_synthetic)
    );
}
