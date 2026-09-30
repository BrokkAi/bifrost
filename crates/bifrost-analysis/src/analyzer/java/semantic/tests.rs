use super::syntax::{
    body_contains_free_this, is_sole_initializer_fragment, java_field_access_is_type_qualifier,
    java_field_access_segments, java_type_name_prefix_len,
};
use super::*;

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

fn parse_java(source: &str) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must load");
    parser.parse(source, None).expect("Java source must parse")
}

fn first_kind<'a>(root: tree_sitter::Node<'a>, kind: &str) -> tree_sitter::Node<'a> {
    let mut found = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(root, true, |node| {
        if node.kind() == kind && found.is_none() {
            found = Some(node);
            WalkControl::Break
        } else {
            WalkControl::Continue
        }
    });
    found.unwrap_or_else(|| panic!("missing {kind}"))
}

#[test]
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
fn a_lone_static_field_initializer_is_the_sole_fragment_in_its_group() {
    // The corpus's own dominant shape (#2545's census): boilerplate
    // `serialVersionUID`, nothing else in the static group.
    let source = "class App {\n  private static final long serialVersionUID = 1L;\n}\n";
    let tree = parse_java(source);
    let declarator = declarator_named(tree.root_node(), source, "serialVersionUID");
    assert!(is_sole_initializer_fragment(declarator, true));
}

#[test]
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
fn a_static_field_and_a_static_initializer_block_share_one_group() {
    let source = "class App {\n  private static int a = 1;\n  static { a = a + 1; }\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let block = first_kind(tree.root_node(), "static_initializer");
    assert!(!is_sole_initializer_fragment(a, true));
    assert!(!is_sole_initializer_fragment(block, true));
}

#[test]
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
fn two_instance_field_initializers_are_not_sole_in_their_shared_group() {
    let source = "class App {\n  private int a = 1;\n  private int b = a + 1;\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let b = declarator_named(tree.root_node(), source, "b");
    assert!(!is_sole_initializer_fragment(a, false));
    assert!(!is_sole_initializer_fragment(b, false));
}

#[test]
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

fn method<'a>(artifact: &'a SemanticArtifact, name: &str) -> &'a ProcedureSemantics {
    artifact
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some(name)
        })
        .unwrap_or_else(|| panic!("missing procedure {name}"))
}

fn mapping_text<'s>(
    procedure: &ProcedureSemantics,
    source: &'s str,
    mapping: SourceMappingId,
) -> &'s str {
    let span = procedure.source_mappings()[mapping.index()]
        .locator
        .anchor()
        .span();
    &source[span.start_byte() as usize..span.end_byte() as usize]
}

fn value_text<'s>(procedure: &ProcedureSemantics, source: &'s str, value: ValueId) -> &'s str {
    mapping_text(procedure, source, procedure.values()[value.index()].source)
}

fn value_kind(procedure: &ProcedureSemantics, value: ValueId) -> SemanticValueKind {
    procedure.values()[value.index()].kind.clone()
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

fn floating(value: f64) -> SemanticValueKind {
    SemanticValueKind::FloatingPoint {
        bits: value.to_bits(),
    }
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

/// Every value flow into the value of the expression spelled `target`, as
/// its kind and source spelling.
fn flows_into<'s>(
    procedure: &ProcedureSemantics,
    source: &'s str,
    target: &str,
) -> Vec<(ValueFlowKind, &'s str)> {
    procedure
        .points()
        .iter()
        .flat_map(|point| point.events.iter())
        .filter_map(|event| match event.effect {
            SemanticEffect::ValueFlow {
                kind,
                source: from,
                target: to,
            } if value_text(procedure, source, to) == target => {
                Some((kind, value_text(procedure, source, from)))
            }
            _ => None,
        })
        .collect()
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
fn numeric_literal_assignments_publish_typed_constants() {
    use SemanticValueKind::{Constant, SignedInteger, UnsignedInteger};
    // `wide`, `narrowed` and `single` do not compile; they check that a
    // literal the assignment cannot convert stays unrepresented.
    let source = r#"class Fixture {
  void run() {
    int min = -2147483648;
    long top = 0x8000000000000000L;
    char letter = 65;
    byte small = -0x80;
    short wide = 0x8000;
    int narrowed = 5L;
    double tenth = 0.1f;
    double three = 3;
    float single = 0.1;
    float exact = 2.5f;
    Integer boxed = 5;
    var inferred = 5;
    long later;
    later = -1L;
  }
}
"#;
    let artifact = java_semantics(source);
    let run = method(&artifact, "run");
    let assigned = |name: &str| {
        let values = run
            .points()
            .iter()
            .flat_map(|point| point.events.iter())
            .filter_map(|event| match event.effect {
                SemanticEffect::Assignment { target, value }
                    if value_text(run, source, target) == name =>
                {
                    Some(value_kind(run, value))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [value] = &values[..] else {
            panic!("expected one assignment to {name}: {values:?}");
        };
        value.clone()
    };
    assert_eq!(assigned("min"), SignedInteger(i128::from(i32::MIN)));
    assert_eq!(assigned("top"), SignedInteger(i128::from(i64::MIN)));
    assert_eq!(assigned("letter"), UnsignedInteger(65));
    assert_eq!(assigned("small"), SignedInteger(-128));
    assert_eq!(assigned("wide"), Constant);
    assert_eq!(assigned("narrowed"), Constant);
    assert_eq!(assigned("tenth"), floating(f64::from(0.1_f32)));
    assert_eq!(assigned("three"), UnsignedInteger(3));
    assert_eq!(assigned("single"), Constant);
    assert_eq!(assigned("exact"), floating(2.5));
    // Boxing keeps the literal's value.
    assert_eq!(assigned("boxed"), UnsignedInteger(5));
    assert_eq!(assigned("inferred"), Constant);
    assert_eq!(assigned("later"), SignedInteger(-1));
}

#[test]
fn integral_literal_offsets_publish_integer_offset_flows() {
    let offset = |negative, magnitude| ValueFlowKind::IntegerOffset {
        offset: SignedIntegerMagnitude::new(negative, magnitude),
    };
    let source = r#"class Fixture {
  void run(int x, byte b, Integer boxed, double d, int[] values) {
    int a = x + 1;
    int c = 2 + x;
    int e = x - -3;
    int f = x - 7;
    long m = b + 4294967296L;
    int g = 5 - x;
    int h = boxed + 1;
    double k = d + 1;
    int n = x + x;
    int p = x * 2;
    int q = values[0] + 1;
  }
}
"#;
    let artifact = java_semantics(source);
    let run = method(&artifact, "run");
    let flows = |expression| flows_into(run, source, expression);
    assert_eq!(flows("x + 1"), [(offset(false, 1), "x")]);
    assert_eq!(flows("2 + x"), [(offset(false, 2), "x")]);
    assert_eq!(flows("x - -3"), [(offset(false, 3), "x")]);
    assert_eq!(flows("x - 7"), [(offset(true, 7), "x")]);
    assert_eq!(flows("b + 4294967296L"), [(offset(false, 1 << 32), "b")]);
    for (expression, operands) in [
        ("5 - x", ["5", "x"]),
        ("boxed + 1", ["boxed", "1"]),
        ("d + 1", ["d", "1"]),
        ("x + x", ["x", "x"]),
        ("x * 2", ["x", "2"]),
        ("values[0] + 1", ["values[0]", "1"]),
    ] {
        assert_eq!(
            flows(expression),
            operands.map(|operand| (ValueFlowKind::LanguageDefined, operand)),
            "{expression}"
        );
    }
}

#[test]
fn integral_updates_and_literal_compound_assignments_publish_offsets() {
    let offset = |negative, magnitude| ValueFlowKind::IntegerOffset {
        offset: SignedIntegerMagnitude::new(negative, magnitude),
    };
    let source = r#"class Fixture {
  void run(int x, long y, Integer boxed, int[] a) {
    x++;
    ++x;
    x--;
    --x;
    y += 3;
    y -= 2L;
    x += -1;
    boxed++;
    a[0]++;
    x *= 2;
    x += y;
  }
}
"#;
    let artifact = java_semantics(source);
    let run = method(&artifact, "run");
    let flows = |expression| flows_into(run, source, expression);
    for (expression, negative, magnitude, operand) in [
        ("x++", false, 1, "x"),
        ("++x", false, 1, "x"),
        ("x--", true, 1, "x"),
        ("--x", true, 1, "x"),
        ("y += 3", false, 3, "y"),
        ("y -= 2L", true, 2, "y"),
        ("x += -1", true, 1, "x"),
    ] {
        assert_eq!(
            flows(expression),
            [(offset(negative, magnitude), operand)],
            "{expression}"
        );
    }
    assert_eq!(
        flows("boxed++"),
        [(ValueFlowKind::LanguageDefined, "boxed")]
    );
    assert_eq!(flows("a[0]++"), [(ValueFlowKind::LanguageDefined, "a[0]")]);
    for (expression, operands) in [("x *= 2", ["x", "2"]), ("x += y", ["x", "y"])] {
        assert_eq!(
            flows(expression),
            operands.map(|operand| (ValueFlowKind::LanguageDefined, operand)),
            "{expression}"
        );
    }
    // A literal offset on a primitive cannot unbox, throw or call; general
    // compound arithmetic keeps its gaps.
    let gapped = run
        .gaps()
        .iter()
        .map(|gap| mapping_text(run, source, gap.source))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        gapped,
        ["x *= 2", "x += y"].into_iter().collect(),
        "{:?}",
        run.gaps()
    );
}

#[test]
fn value_preserving_primitive_casts_publish_local_flows() {
    let source = r#"class Fixture {
  void run(int x, long w, char c, byte b, float f, double d, Integer boxed, Object o) {
    long a = (long) x;
    int l = (int) x;
    int e = (int) c;
    short s = (short) b;
    double g = (double) f;
    int i = (int) w;
    short t = (short) c;
    char u = (char) b;
    float h = (float) d;
    double v = (double) x;
    int j = (int) boxed;
    Integer k = (Integer) o;
  }
}
"#;
    let artifact = java_semantics(source);
    let run = method(&artifact, "run");
    for (cast, operand) in [
        ("(long) x", "x"),
        ("(int) x", "x"),
        ("(int) c", "c"),
        ("(short) b", "b"),
        ("(double) f", "f"),
    ] {
        assert_eq!(
            flows_into(run, source, cast),
            [(ValueFlowKind::Local, operand)],
            "{cast}"
        );
    }
    // Narrowing, sign-changing, rounding, unboxing and reference casts keep
    // an unknown result.
    for cast in [
        "(int) w",
        "(short) c",
        "(char) b",
        "(float) d",
        "(double) x",
        "(int) boxed",
        "(Integer) o",
    ] {
        assert_eq!(flows_into(run, source, cast), [], "{cast}");
    }
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
