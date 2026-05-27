use super::exceptions::named_child_by_kind;
use super::*;
use crate::path_utils::rel_path_string;
use tree_sitter::Node;

const TEST_ASSERTION_EXCERPT_MAX_LEN: usize = 180;

const TEST_ANNOTATIONS: &[&str] = &[
    "Test",
    "ParameterizedTest",
    "RepeatedTest",
    "TestFactory",
    "TestTemplate",
];
const JUNIT_ASSERTION_NAMES: &[&str] = &[
    "assertArrayEquals",
    "assertDoesNotThrow",
    "assertEquals",
    "assertFalse",
    "assertInstanceOf",
    "assertIterableEquals",
    "assertLinesMatch",
    "assertNotEquals",
    "assertNotNull",
    "assertNotSame",
    "assertNull",
    "assertSame",
    "assertThrows",
    "assertThrowsExactly",
    "assertTimeout",
    "assertTimeoutPreemptively",
    "assertTrue",
    "fail",
];
const SHALLOW_ASSERTION_NAMES: &[&str] = &["assertNotNull", "assertNull", "assertInstanceOf"];
const ASSERTJ_TERMINAL_NAMES: &[&str] = &[
    "isEqualTo",
    "isSameAs",
    "isNotEqualTo",
    "isTrue",
    "isFalse",
    "isNull",
    "isNotNull",
    "isInstanceOf",
    "hasMessage",
    "hasMessageContaining",
    "containsExactly",
    "containsExactlyInAnyOrder",
];
const ASSERTJ_SHALLOW_TERMINAL_NAMES: &[&str] = &["isNull", "isNotNull", "isInstanceOf"];
const MOCKITO_VERIFY_NAMES: &[&str] = &[
    "verify",
    "verifyNoInteractions",
    "verifyNoMoreInteractions",
    "verifyZeroInteractions",
    "inOrder",
];
const CONSTANT_LITERAL_TYPES: &[&str] = &[
    "string_literal",
    "character_literal",
    "decimal_integer_literal",
    "hex_integer_literal",
    "octal_integer_literal",
    "binary_integer_literal",
    "decimal_floating_point_literal",
    "hex_floating_point_literal",
    "true",
    "false",
    "null_literal",
];

const TEST_ASSERTION_KIND_JUNIT: &str = "junit-assertion";
const TEST_ASSERTION_KIND_ASSERTJ: &str = "assertj-assertion";
const TEST_ASSERTION_KIND_MOCK_VERIFICATION: &str = "mock-verification";
const TEST_ASSERTION_KIND_NO_ASSERTIONS: &str = "no-assertions";
const TEST_ASSERTION_KIND_CONSTANT_TRUTH: &str = "constant-truth";
const TEST_ASSERTION_KIND_CONSTANT_EQUALITY: &str = "constant-equality";
const TEST_ASSERTION_KIND_SELF_COMPARISON: &str = "self-comparison";
const TEST_ASSERTION_KIND_NULLNESS_ONLY: &str = "nullness-only";
const TEST_ASSERTION_KIND_SHALLOW_ONLY: &str = "shallow-assertions-only";
const TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL: &str = "overspecified-literal";
const TEST_ASSERTION_KIND_ANONYMOUS_TEST_DOUBLE: &str = "anonymous-test-double";
const TEST_ASSERTION_REASON_REUSABLE_TEST_DOUBLE: &str = "reusable-test-double-candidate";

fn compact_test_assertion_excerpt(text: &str) -> String {
    let compact = compact_whitespace_for_excerpt(text);
    if compact.chars().count() <= TEST_ASSERTION_EXCERPT_MAX_LEN {
        return compact;
    }
    let mut truncated: String = compact
        .chars()
        .take(TEST_ASSERTION_EXCERPT_MAX_LEN)
        .collect();
    truncated.push_str("...");
    truncated
}

fn compact_whitespace_for_excerpt(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut seen_non_ws = false;
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if seen_non_ws {
                pending_space = true;
            }
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        out.push(ch);
        pending_space = false;
        seen_non_ws = true;
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

pub(super) fn java_source_contains_tests(source: &str) -> bool {
    source.contains("@Test")
        || source.contains(".Test")
        || source.contains("@ParameterizedTest")
        || source.contains("@RepeatedTest")
        || source.contains("@Rule")
        || source.contains("@ClassRule")
        || source.contains("@Ignore")
        || (source.contains("TestCase")
            && (contains_ignoring_whitespace(source, "extendsTestCase")
                || contains_ignoring_whitespace(source, "extendsjunit.framework.TestCase")))
}

fn contains_ignoring_whitespace(source: &str, needle: &str) -> bool {
    let mut needle_chars = needle.chars();
    let Some(first) = needle_chars.next() else {
        return true;
    };

    for (start, ch) in source.char_indices() {
        if ch.is_whitespace() || ch != first {
            continue;
        }

        let mut chars = source[start + ch.len_utf8()..]
            .chars()
            .filter(|ch| !ch.is_whitespace());
        if needle_chars
            .clone()
            .all(|expected| chars.next() == Some(expected))
        {
            return true;
        }
    }

    false
}

pub(super) fn detect_test_assertion_smells_java(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let mut methods = Vec::new();
    collect_nodes_by_kind(tree.root_node(), "method_declaration", &mut methods);
    let anonymous_shape_counts = anonymous_test_double_shape_counts(&methods, source);
    let mut findings = Vec::new();
    for method in methods {
        if is_test_method(method, source) {
            analyze_test_method_assertions(analyzer, file, source, method, weights, &mut findings);
            analyze_anonymous_test_doubles(
                analyzer,
                file,
                source,
                method,
                weights,
                &anonymous_shape_counts,
                &mut findings,
            );
        }
    }
    findings.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.to_string().cmp(&b.file.to_string()))
            .then_with(|| a.enclosing_fq_name.cmp(&b.enclosing_fq_name))
            .then_with(|| a.start_byte.cmp(&b.start_byte))
    });
    findings
}

pub(super) fn collect_nodes_by_kind<'tree>(
    node: Node<'tree>,
    kind: &str,
    out: &mut Vec<Node<'tree>>,
) {
    if node.kind() == kind {
        out.push(node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_nodes_by_kind(child, kind, out);
        }
    }
}

fn is_test_method(method: Node<'_>, source: &str) -> bool {
    let Some(modifiers) = named_child_by_kind(method, "modifiers") else {
        return false;
    };
    let mut cursor = modifiers.walk();
    modifiers
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "annotation" || child.kind() == "marker_annotation")
        .filter_map(|annotation| annotation_name(annotation, source))
        .any(|name| TEST_ANNOTATIONS.contains(&name.as_str()))
}

fn annotation_name(annotation: Node<'_>, source: &str) -> Option<String> {
    let raw = if let Some(name_node) = annotation.child_by_field_name("name") {
        source.get(name_node.start_byte()..name_node.end_byte())?
    } else {
        source.get(annotation.start_byte()..annotation.end_byte())?
    };
    let trimmed = raw.trim().trim_start_matches('@');
    let short = trimmed.rsplit('.').next().unwrap_or(trimmed).trim();
    if short.is_empty() {
        None
    } else {
        Some(short.to_string())
    }
}

fn analyze_test_method_assertions(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: Node<'_>,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let Some(body) = method.child_by_field_name("body") else {
        return;
    };
    let mut invocations = Vec::new();
    collect_nodes_by_kind(body, "method_invocation", &mut invocations);
    let assertions: Vec<AssertionSignal> = invocations
        .into_iter()
        .filter_map(|invocation| assertion_signal(invocation, source, weights))
        .collect();
    let enclosing = analyzer
        .enclosing_code_unit_for_lines(file, method.start_position().row, method.end_position().row)
        .map(|cu| cu.fq_name())
        .unwrap_or_else(|| rel_path_string(file));
    let assertion_count = assertions.len() as i32;

    if assertion_count == 0 {
        add_test_smell(
            file,
            &enclosing,
            PendingTestSmell {
                assertion_kind: TEST_ASSERTION_KIND_NO_ASSERTIONS,
                score: weights.no_assertion_weight,
                assertion_count: 0,
                reasons: vec![TEST_ASSERTION_KIND_NO_ASSERTIONS.to_string()],
                excerpt_source: source
                    .get(method.start_byte()..method.end_byte())
                    .unwrap_or(""),
                start_byte: method.start_byte(),
            },
            out,
        );
        return;
    }

    for assertion in &assertions {
        add_test_smell(
            file,
            &enclosing,
            PendingTestSmell {
                assertion_kind: &assertion.kind,
                score: assertion.base_score,
                assertion_count,
                reasons: assertion.reasons.clone(),
                excerpt_source: &assertion.excerpt,
                start_byte: assertion.start_byte,
            },
            out,
        );
    }

    if assertions.iter().all(|a| a.shallow) {
        let score = weights.shallow_assertion_only_weight
            - meaningful_assertion_credit(assertions.iter(), weights, |a| a.meaningful);
        add_test_smell(
            file,
            &enclosing,
            PendingTestSmell {
                assertion_kind: TEST_ASSERTION_KIND_SHALLOW_ONLY,
                score,
                assertion_count,
                reasons: vec![TEST_ASSERTION_KIND_SHALLOW_ONLY.to_string()],
                excerpt_source: source
                    .get(method.start_byte()..method.end_byte())
                    .unwrap_or(""),
                start_byte: method.start_byte(),
            },
            out,
        );
    }
}

fn analyze_anonymous_test_doubles(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: Node<'_>,
    weights: &TestAssertionWeights,
    anonymous_shape_counts: &HashMap<String, i32>,
    out: &mut Vec<TestAssertionSmell>,
) {
    let mut creations = Vec::new();
    collect_nodes_by_kind(method, "object_creation_expression", &mut creations);
    let enclosing = analyzer
        .enclosing_code_unit_for_lines(file, method.start_position().row, method.end_position().row)
        .map(|cu| cu.fq_name())
        .unwrap_or_else(|| rel_path_string(file));
    for creation in creations {
        if named_child_by_kind(creation, "class_body").is_none()
            || creation.child_by_field_name("type").is_none()
        {
            continue;
        }
        let shape = anonymous_test_double_shape(creation, source);
        let repeated = anonymous_shape_counts.get(&shape).copied().unwrap_or(0) > 1;
        let score = if repeated {
            weights.repeated_anonymous_test_double_weight
        } else {
            weights.anonymous_test_double_weight
        };
        let mut reasons = vec![TEST_ASSERTION_KIND_ANONYMOUS_TEST_DOUBLE.to_string()];
        if repeated {
            reasons.push(TEST_ASSERTION_REASON_REUSABLE_TEST_DOUBLE.to_string());
        }
        add_test_smell(
            file,
            &enclosing,
            PendingTestSmell {
                assertion_kind: TEST_ASSERTION_KIND_ANONYMOUS_TEST_DOUBLE,
                score,
                assertion_count: 0,
                reasons,
                excerpt_source: source
                    .get(creation.start_byte()..creation.end_byte())
                    .unwrap_or(""),
                start_byte: creation.start_byte(),
            },
            out,
        );
    }
}

fn assertion_signal(
    invocation: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Option<AssertionSignal> {
    let method_name = method_invocation_name(invocation, source)?;
    let text = source
        .get(invocation.start_byte()..invocation.end_byte())?
        .trim()
        .to_string();
    if text.is_empty() {
        return None;
    }
    if JUNIT_ASSERTION_NAMES.contains(&method_name.as_str()) {
        return Some(classify_junit_assertion(
            invocation,
            &method_name,
            source,
            &text,
            weights,
        ));
    }
    if MOCKITO_VERIFY_NAMES.contains(&method_name.as_str()) {
        return Some(AssertionSignal {
            kind: TEST_ASSERTION_KIND_MOCK_VERIFICATION.to_string(),
            base_score: 0,
            shallow: false,
            meaningful: true,
            start_byte: invocation.start_byte(),
            reasons: Vec::new(),
            excerpt: text,
        });
    }
    if ASSERTJ_TERMINAL_NAMES.contains(&method_name.as_str())
        && assert_that_argument(invocation, source).is_some()
    {
        return Some(classify_assertj_assertion(
            invocation,
            &method_name,
            source,
            &text,
            weights,
        ));
    }
    None
}

fn classify_junit_assertion(
    invocation: Node<'_>,
    method_name: &str,
    source: &str,
    text: &str,
    weights: &TestAssertionWeights,
) -> AssertionSignal {
    let args = argument_nodes(invocation);
    let mut score = 0;
    let mut reasons = Vec::new();
    let shallow = SHALLOW_ASSERTION_NAMES.contains(&method_name);
    let mut meaningful = !shallow && method_name != "fail";
    let mut kind = TEST_ASSERTION_KIND_JUNIT.to_string();

    if (method_name == "assertTrue" || method_name == "assertFalse") && !args.is_empty() {
        let arg = *args.last().unwrap();
        let constant_truth = (method_name == "assertTrue" && arg.kind() == "true")
            || (method_name == "assertFalse" && arg.kind() == "false");
        if constant_truth {
            score += weights.constant_truth_weight;
            reasons.push(TEST_ASSERTION_KIND_CONSTANT_TRUTH.to_string());
            kind = TEST_ASSERTION_KIND_CONSTANT_TRUTH.to_string();
            meaningful = false;
        }
        if is_self_comparison(arg, source) {
            score += weights.tautological_assertion_weight;
            reasons.push(TEST_ASSERTION_KIND_SELF_COMPARISON.to_string());
            kind = TEST_ASSERTION_KIND_SELF_COMPARISON.to_string();
            meaningful = false;
        }
    }

    if (method_name == "assertEquals" || method_name == "assertSame") && args.len() >= 2 {
        let comparable_args = comparable_assertion_args(&args);
        let expected = comparable_args[0];
        let actual = comparable_args[1];
        if is_constant_expression(expected) && is_constant_expression(actual) {
            score += weights.constant_equality_weight;
            reasons.push(TEST_ASSERTION_KIND_CONSTANT_EQUALITY.to_string());
            kind = TEST_ASSERTION_KIND_CONSTANT_EQUALITY.to_string();
            meaningful = false;
        } else if same_expression(expected, actual, source) {
            score += weights.tautological_assertion_weight;
            reasons.push(TEST_ASSERTION_KIND_SELF_COMPARISON.to_string());
            kind = TEST_ASSERTION_KIND_SELF_COMPARISON.to_string();
            meaningful = false;
        }
    }

    if (method_name == "assertNotNull" || method_name == "assertNull") && args.len() <= 2 {
        score += weights.nullness_only_weight;
        reasons.push(TEST_ASSERTION_KIND_NULLNESS_ONLY.to_string());
        kind = TEST_ASSERTION_KIND_NULLNESS_ONLY.to_string();
        meaningful = false;
    }

    if contains_overspecified_literal(&args, source, weights) {
        score += weights.overspecified_literal_weight;
        reasons.push(TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL.to_string());
        kind = TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL.to_string();
    }

    AssertionSignal {
        kind,
        base_score: score,
        shallow,
        meaningful,
        start_byte: invocation.start_byte(),
        reasons,
        excerpt: text.to_string(),
    }
}

fn classify_assertj_assertion(
    invocation: Node<'_>,
    method_name: &str,
    source: &str,
    text: &str,
    weights: &TestAssertionWeights,
) -> AssertionSignal {
    let args = argument_nodes(invocation);
    let mut score = 0;
    let mut reasons = Vec::new();
    let shallow = ASSERTJ_SHALLOW_TERMINAL_NAMES.contains(&method_name);
    let mut meaningful = !shallow;
    let mut kind = TEST_ASSERTION_KIND_ASSERTJ.to_string();

    if let Some(expected) = assert_that_argument(invocation, source)
        && args.len() == 1
    {
        let actual = args[0];
        if (method_name == "isEqualTo" || method_name == "isSameAs")
            && is_constant_expression(expected)
            && is_constant_expression(actual)
        {
            score += weights.constant_equality_weight;
            reasons.push(TEST_ASSERTION_KIND_CONSTANT_EQUALITY.to_string());
            kind = TEST_ASSERTION_KIND_CONSTANT_EQUALITY.to_string();
            meaningful = false;
        } else if (method_name == "isEqualTo" || method_name == "isSameAs")
            && same_expression(expected, actual, source)
        {
            score += weights.tautological_assertion_weight;
            reasons.push(TEST_ASSERTION_KIND_SELF_COMPARISON.to_string());
            kind = TEST_ASSERTION_KIND_SELF_COMPARISON.to_string();
            meaningful = false;
        }
    }

    if let Some(arg) = assert_that_argument(invocation, source)
        && ((method_name == "isTrue" && arg.kind() == "true")
            || (method_name == "isFalse" && arg.kind() == "false"))
    {
        score += weights.constant_truth_weight;
        reasons.push(TEST_ASSERTION_KIND_CONSTANT_TRUTH.to_string());
        kind = TEST_ASSERTION_KIND_CONSTANT_TRUTH.to_string();
        meaningful = false;
    }

    if shallow {
        score += weights.nullness_only_weight;
        reasons.push(TEST_ASSERTION_KIND_NULLNESS_ONLY.to_string());
        kind = TEST_ASSERTION_KIND_NULLNESS_ONLY.to_string();
        meaningful = false;
    }

    if contains_overspecified_literal(&args, source, weights) {
        score += weights.overspecified_literal_weight;
        reasons.push(TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL.to_string());
        kind = TEST_ASSERTION_KIND_OVERSPECIFIED_LITERAL.to_string();
    }

    AssertionSignal {
        kind,
        base_score: score,
        shallow,
        meaningful,
        start_byte: invocation.start_byte(),
        reasons,
        excerpt: text.to_string(),
    }
}

fn add_test_smell(
    file: &ProjectFile,
    enclosing: &str,
    smell: PendingTestSmell<'_>,
    out: &mut Vec<TestAssertionSmell>,
) {
    if smell.score <= 0 || smell.reasons.is_empty() {
        return;
    }
    out.push(TestAssertionSmell {
        file: file.clone(),
        enclosing_fq_name: enclosing.to_string(),
        assertion_kind: smell.assertion_kind.to_string(),
        score: smell.score,
        assertion_count: smell.assertion_count,
        reasons: smell.reasons,
        excerpt: compact_test_assertion_excerpt(smell.excerpt_source),
        start_byte: smell.start_byte,
    });
}

fn method_invocation_name(invocation: Node<'_>, source: &str) -> Option<String> {
    let name_node = invocation.child_by_field_name("name")?;
    let text = source
        .get(name_node.start_byte()..name_node.end_byte())?
        .trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn argument_nodes(invocation: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = invocation.child_by_field_name("arguments") else {
        return Vec::new();
    };
    if arguments.kind() != "argument_list" {
        return Vec::new();
    }
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).collect()
}

fn comparable_assertion_args<'tree>(args: &'tree [Node<'tree>]) -> &'tree [Node<'tree>] {
    if args.len() >= 4 && is_string_literal(args[0]) {
        &args[1..3]
    } else {
        &args[0..args.len().min(2)]
    }
}

fn assert_that_argument<'tree>(invocation: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut candidate = invocation.child_by_field_name("object");
    while let Some(node) = candidate {
        if node.kind() != "method_invocation" {
            break;
        }
        let name_node = node.child_by_field_name("name")?;
        let name = source
            .get(name_node.start_byte()..name_node.end_byte())?
            .trim();
        if name == "assertThat" {
            return argument_nodes(node).into_iter().next();
        }
        candidate = node.child_by_field_name("object");
    }
    None
}

fn is_self_comparison(node: Node<'_>, source: &str) -> bool {
    if node.kind() == "binary_expression" {
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");
        return left
            .zip(right)
            .is_some_and(|(l, r)| same_expression(l, r, source));
    }
    if node.kind() == "method_invocation"
        && method_invocation_name(node, source).as_deref() == Some("equals")
    {
        let Some(object_node) = node.child_by_field_name("object") else {
            return false;
        };
        return argument_nodes(node)
            .into_iter()
            .next()
            .is_some_and(|arg| same_expression(object_node, arg, source));
    }
    false
}

fn same_expression(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    let left_text = source
        .get(left.start_byte()..left.end_byte())
        .unwrap_or("")
        .trim();
    let right_text = source
        .get(right.start_byte()..right.end_byte())
        .unwrap_or("")
        .trim();
    left_text == right_text
}

fn is_constant_expression(node: Node<'_>) -> bool {
    CONSTANT_LITERAL_TYPES.contains(&node.kind())
}

fn is_string_literal(node: Node<'_>) -> bool {
    node.kind() == "string_literal"
}

fn contains_overspecified_literal(
    args: &[Node<'_>],
    source: &str,
    weights: &TestAssertionWeights,
) -> bool {
    let threshold = weights.large_literal_length_threshold.max(0) as usize;
    args.iter().any(|arg| {
        is_string_literal(*arg)
            && source
                .get(arg.start_byte()..arg.end_byte())
                .is_some_and(|text| text.len() >= threshold)
    })
}

fn meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a AssertionSignal>,
    weights: &TestAssertionWeights,
    predicate: impl Fn(&AssertionSignal) -> bool,
) -> i32 {
    let count = assertions.filter(|assertion| predicate(assertion)).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn anonymous_test_double_shape_counts(
    test_methods: &[Node<'_>],
    source: &str,
) -> HashMap<String, i32> {
    let mut counts = HashMap::default();
    for method in test_methods
        .iter()
        .copied()
        .filter(|m| is_test_method(*m, source))
    {
        let mut creations = Vec::new();
        collect_nodes_by_kind(method, "object_creation_expression", &mut creations);
        for creation in creations
            .into_iter()
            .filter(|creation| named_child_by_kind(*creation, "class_body").is_some())
        {
            let shape = anonymous_test_double_shape(creation, source);
            *counts.entry(shape).or_insert(0) += 1;
        }
    }
    counts
}

fn anonymous_test_double_shape(creation: Node<'_>, source: &str) -> String {
    let type_name = creation
        .child_by_field_name("type")
        .and_then(|node| source.get(node.start_byte()..node.end_byte()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("<unknown>");
    let mut methods = Vec::new();
    collect_nodes_by_kind(creation, "method_declaration", &mut methods);
    let method_names = methods
        .into_iter()
        .filter_map(|method| {
            method
                .child_by_field_name("name")
                .and_then(|name| source.get(name.start_byte()..name.end_byte()))
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(ToString::to_string)
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{type_name}#{method_names}")
}

#[derive(Debug, Clone)]
struct AssertionSignal {
    kind: String,
    base_score: i32,
    shallow: bool,
    meaningful: bool,
    start_byte: usize,
    reasons: Vec<String>,
    excerpt: String,
}

struct PendingTestSmell<'a> {
    assertion_kind: &'a str,
    score: i32,
    assertion_count: i32,
    reasons: Vec<String>,
    excerpt_source: &'a str,
    start_byte: usize,
}
