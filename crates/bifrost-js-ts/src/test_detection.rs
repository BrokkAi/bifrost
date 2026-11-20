use super::model::node_text;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::common::collapse_whitespace;
use brokk_bifrost_core::analyzer::model::{TestAssertionSmell, TestAssertionWeights};
use brokk_bifrost_core::analyzer::test_assertions::{
    CommonTestAssertionKind, TestAssertionSignal, append_test_assertion_findings,
    classify_common_test_assertion, oversized_quoted_literal,
};
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use tree_sitter::{Language as TsLanguage, Node, Parser};

struct JsTsTestCase<'tree> {
    name: String,
    callback: Node<'tree>,
    start_byte: usize,
}

pub fn detect_js_ts_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    parser_language: TsLanguage,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut parser = Parser::new();
    parser
        .set_language(&parser_language)
        .expect("failed to set js/ts parser language");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut test_cases = Vec::new();
    collect_js_ts_test_cases(tree.root_node(), source, &mut test_cases);

    let mut findings = Vec::new();
    for test_case in test_cases {
        analyze_js_ts_test_case(file, &test_case, source, weights, &mut findings);
    }
    findings
}

fn collect_js_ts_test_cases<'tree>(
    root: Node<'tree>,
    source: &str,
    out: &mut Vec<JsTsTestCase<'tree>>,
) {
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "call_expression"
            && is_js_ts_test_invocation(node, source)
            && let Some(arguments) = node.child_by_field_name("arguments")
        {
            let mut name: Option<String> = None;
            let mut callback: Option<Node<'_>> = None;
            let mut cursor = arguments.walk();
            for child in arguments.named_children(&mut cursor) {
                match child.kind() {
                    "string" | "template_string" if name.is_none() => {
                        name = Some(trim_js_ts_string_literal(node_text(child, source)));
                    }
                    "arrow_function" | "function" | "generator_function" => {
                        callback = Some(child);
                    }
                    _ => {}
                }
            }
            if let Some(callback) = callback {
                out.push(JsTsTestCase {
                    name: name.unwrap_or_else(|| "anonymous".to_string()),
                    callback,
                    start_byte: node.start_byte(),
                });
            }
        }

        WalkControl::Continue
    });
}

fn is_js_ts_test_invocation(node: Node<'_>, source: &str) -> bool {
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    match function.kind() {
        "identifier" => is_js_ts_test_root(function, source),
        "member_expression" => {
            let Some(object) = function.child_by_field_name("object") else {
                return false;
            };
            let Some(property) = function.child_by_field_name("property") else {
                return false;
            };
            match node_text(property, source).trim() {
                "only" | "skip" | "each" => is_js_ts_test_root(object, source),
                // A subtest (`t.test(name, fn)` in node:test and tap) passes a
                // callback; a RegExp `pattern.test(text)` never does.
                "test" | "it" => call_passes_callback(node),
                _ => false,
            }
        }
        "call_expression" => {
            let Some(factory) = function.child_by_field_name("function") else {
                return false;
            };
            if factory.kind() != "member_expression" {
                return false;
            }
            let Some(object) = factory.child_by_field_name("object") else {
                return false;
            };
            let Some(property) = factory.child_by_field_name("property") else {
                return false;
            };
            is_js_ts_test_root(object, source) && node_text(property, source).trim() == "each"
        }
        _ => false,
    }
}

fn call_passes_callback(call: Node<'_>) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "arrow_function" | "function" | "generator_function"
        )
    })
}

fn is_js_ts_test_root(node: Node<'_>, source: &str) -> bool {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" => {
                return matches!(node_text(current, source).trim(), "it" | "test");
            }
            "member_expression" => {
                let Some(object) = current.child_by_field_name("object") else {
                    return false;
                };
                current = object;
            }
            _ => return false,
        }
    }
}

fn analyze_js_ts_test_case(
    file: &ProjectFile,
    test_case: &JsTsTestCase<'_>,
    source: &str,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let body = test_case
        .callback
        .child_by_field_name("body")
        .unwrap_or(test_case.callback);
    let assertions = collect_js_ts_assertions(body, source, weights);
    append_test_assertion_findings(
        file,
        format!("{}::{}", file, test_case.name),
        collapse_whitespace(node_text(body, source)),
        test_case.start_byte,
        &assertions,
        weights,
        out,
    );
}

fn collect_js_ts_assertions(
    body: Node<'_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSignal> {
    let mut assertions = Vec::new();
    walk_named_tree_preorder(body, true, |node| {
        let shape = match node.kind() {
            "call_expression" => js_ts_call_assertion(node, source),
            // A chai property assertion such as `expect(x).to.be.true` is a
            // member expression with no call. A member that is the callee of
            // a call belongs to that call, so no chain is read twice.
            "member_expression" if !is_call_callee(node) => js_ts_property_assertion(node, source),
            _ => None,
        };
        if let Some(shape) = shape
            && let Some(assertion) = js_ts_assertion_signal(node, shape, source, weights)
        {
            assertions.push(assertion);
        }
        // Helper arrows inside a test retain their assertions. String and
        // comment contents are never interpreted as calls.
        WalkControl::Continue
    });
    assertions
}

/// An assertion chain read from the syntax tree, before it is classified.
struct JsTsAssertionShape<'tree, 'src> {
    /// `expect` for Jest, Vitest and chai's expect and should styles; `assert`
    /// for node:assert and chai's assert.
    root: &'static str,
    matcher: &'src str,
    actual: Node<'tree>,
    expected: Option<Node<'tree>>,
}

/// What a chain starts from, once its chain words are stripped.
enum JsTsAssertionRoot<'tree> {
    /// `expect(actual)` or chai's `actual.should`.
    Subject(Node<'tree>),
    /// The `assert` namespace, which takes the actual value as an argument.
    Assert,
}

fn js_ts_call_assertion<'tree, 'src>(
    call: Node<'tree>,
    source: &'src str,
) -> Option<JsTsAssertionShape<'tree, 'src>> {
    let function = call.child_by_field_name("function")?;
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut args = arguments
        .named_children(&mut cursor)
        .filter(|n| !n.is_extra());
    match function.kind() {
        // node:assert's default export, `assert(value, message)`, is `assert.ok`.
        "identifier" if node_text(function, source) == "assert" => Some(JsTsAssertionShape {
            root: "assert",
            matcher: "ok",
            actual: args.next()?,
            expected: None,
        }),
        "member_expression" => {
            let matcher = node_text(function.child_by_field_name("property")?, source);
            let object = function.child_by_field_name("object")?;
            match js_ts_assertion_root(object, source)? {
                JsTsAssertionRoot::Subject(actual) => Some(JsTsAssertionShape {
                    root: "expect",
                    matcher,
                    actual,
                    expected: args.next(),
                }),
                JsTsAssertionRoot::Assert => Some(JsTsAssertionShape {
                    root: "assert",
                    matcher,
                    actual: args.next()?,
                    expected: args.next(),
                }),
            }
        }
        _ => None,
    }
}

fn js_ts_property_assertion<'tree, 'src>(
    member: Node<'tree>,
    source: &'src str,
) -> Option<JsTsAssertionShape<'tree, 'src>> {
    let matcher = node_text(member.child_by_field_name("property")?, source);
    if !JS_TS_CHAI_PROPERTY_MATCHERS.contains(&matcher) {
        return None;
    }
    // `assert.ok` read as a value is not an assertion, so only a subject counts.
    let JsTsAssertionRoot::Subject(actual) =
        js_ts_assertion_root(member.child_by_field_name("object")?, source)?
    else {
        return None;
    };
    Some(JsTsAssertionShape {
        root: "expect",
        matcher,
        actual,
        expected: None,
    })
}

/// Walk from the object of a matcher down through chain words to the root of
/// the assertion: `expect(actual)`, `actual.should` or `assert`.
///
/// A chai word such as `property(...)` or `length` makes the rest of the
/// chain assert on another value. The subject is then the chain expression
/// up to the outermost such word, which selects that value; it is never a
/// literal or a copy of the expected operand, so operand classification does
/// not compare the original value with the expected one.
fn js_ts_assertion_root<'tree>(
    mut object: Node<'tree>,
    source: &str,
) -> Option<JsTsAssertionRoot<'tree>> {
    // Set once the walk passes a chai matcher; only a chai subject chains
    // that way, never the `assert` namespace.
    let mut past_matcher = false;
    let mut changed_subject = None;
    loop {
        match object.kind() {
            "member_expression" => {
                let property = node_text(object.child_by_field_name("property")?, source);
                let inner = object.child_by_field_name("object")?;
                if property == "should" {
                    return Some(JsTsAssertionRoot::Subject(changed_subject.unwrap_or(inner)));
                }
                // A property assertion returns the assertion too, as in
                // `expect(x).to.be.true.and.equal(y)`; the property is read
                // as an assertion of its own when the walk visits it.
                if JS_TS_CHAI_PROPERTY_MATCHERS.contains(&property) {
                    past_matcher = true;
                } else if !is_js_ts_chain_word(property) {
                    return None;
                }
                if is_js_ts_chai_subject_change(property) {
                    changed_subject.get_or_insert(object);
                }
                object = inner;
            }
            "call_expression" => {
                let callee = object.child_by_field_name("function")?;
                // Every chai assertion returns the assertion, so a chain can
                // go on after a called matcher, as in
                // `expect(x).to.be.a("number").and.equal(y)`. The inner call
                // is an assertion of its own, read when the walk visits it.
                if callee.kind() == "member_expression" {
                    let property = node_text(callee.child_by_field_name("property")?, source);
                    if !is_js_ts_chai_called_matcher(property) {
                        return None;
                    }
                    if is_js_ts_chai_subject_change(property) {
                        changed_subject.get_or_insert(object);
                    }
                    past_matcher = true;
                    object = callee.child_by_field_name("object")?;
                    continue;
                }
                if callee.kind() != "identifier" || node_text(callee, source) != "expect" {
                    return None;
                }
                let arguments = object.child_by_field_name("arguments")?;
                let mut cursor = arguments.walk();
                let actual = arguments
                    .named_children(&mut cursor)
                    .find(|n| !n.is_extra())?;
                return Some(JsTsAssertionRoot::Subject(
                    changed_subject.unwrap_or(actual),
                ));
            }
            "identifier" if !past_matcher && node_text(object, source) == "assert" => {
                return Some(JsTsAssertionRoot::Assert);
            }
            _ => return None,
        }
    }
}

fn is_call_callee(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call_expression" && parent.child_by_field_name("function") == Some(node)
    })
}

/// Words that join a chain without choosing the assertion: Jest's promise
/// modifiers, `not` (the classification ignores negation, as it does for
/// Jest), and chai's language chains and its `deep`, `own`, `nested`, `any`,
/// `all`, `ordered` and `itself` flags. `a`, `an`, `include`,
/// `contain`, `length` and `lengthOf` are also chai methods, which the matcher
/// table reads when one ends a chain; in the middle of a chain they are
/// chainable, as in `expect(a).to.have.length.above(n)`.
fn is_js_ts_chain_word(word: &str) -> bool {
    matches!(
        word,
        "not"
            | "resolves"
            | "rejects"
            | "to"
            | "be"
            | "been"
            | "is"
            | "that"
            | "which"
            | "and"
            | "has"
            | "have"
            | "with"
            | "at"
            | "of"
            | "same"
            | "but"
            | "does"
            | "still"
            | "also"
            | "deep"
            | "own"
            | "nested"
            | "any"
            | "all"
            | "ordered"
            | "itself"
            | "a"
            | "an"
            | "include"
            | "includes"
            | "contain"
            | "contains"
            | "length"
            | "lengthOf"
    )
}

/// A chai word after which the chain asserts on another value: a property,
/// the length, or the error a function throws.
fn is_js_ts_chai_subject_change(word: &str) -> bool {
    matches!(
        word,
        "property"
            | "ownProperty"
            | "haveOwnProperty"
            | "ownPropertyDescriptor"
            | "haveOwnPropertyDescriptor"
            | "length"
            | "lengthOf"
            | "throw"
            | "throws"
            | "Throw"
    )
}

/// A chai method or equality matcher, whose call returns the assertion for a
/// chain to continue.
fn is_js_ts_chai_called_matcher(name: &str) -> bool {
    JS_TS_CHAI_METHOD_MATCHERS.contains(&name)
        || matches!(name, "equal" | "equals" | "eq" | "eql" | "eqls")
}

/// Chai's assertions that are properties, with no call: `expect(x).to.be.true`.
const JS_TS_CHAI_PROPERTY_MATCHERS: &[&str] = &[
    "ok",
    "true",
    "false",
    "null",
    "undefined",
    "NaN",
    "exist",
    "empty",
    "arguments",
    "Arguments",
    "extensible",
    "sealed",
    "frozen",
    "finite",
];

/// Chai's core assertion methods, other than equality, which is classified by
/// its operands. Plugin matchers are not listed.
const JS_TS_CHAI_METHOD_MATCHERS: &[&str] = &[
    "a",
    "an",
    "include",
    "includes",
    "contain",
    "contains",
    "above",
    "gt",
    "greaterThan",
    "least",
    "gte",
    "below",
    "lt",
    "lessThan",
    "most",
    "lte",
    "within",
    "instanceof",
    "instanceOf",
    "property",
    "ownProperty",
    "haveOwnProperty",
    "ownPropertyDescriptor",
    "haveOwnPropertyDescriptor",
    "length",
    "lengthOf",
    "match",
    "matches",
    "string",
    "key",
    "keys",
    "throw",
    "throws",
    "Throw",
    "respondTo",
    "respondsTo",
    "satisfy",
    "satisfies",
    "closeTo",
    "approximately",
    "members",
    "oneOf",
    "change",
    "changes",
    "increase",
    "increases",
    "decrease",
    "decreases",
];

fn js_ts_assertion_signal(
    node: Node<'_>,
    shape: JsTsAssertionShape<'_, '_>,
    source: &str,
    weights: &TestAssertionWeights,
) -> Option<TestAssertionSignal> {
    let JsTsAssertionShape {
        root,
        matcher,
        actual,
        expected,
    } = shape;

    let mut operands = None;
    let mut kind = match (root, matcher) {
        (
            "expect",
            "toBe" | "toEqual" | "toStrictEqual" | "equal" | "equals" | "eq" | "eql" | "eqls",
        )
        | ("assert", "strictEqual" | "equal" | "deepEqual") => {
            operands = Some((actual, expected?));
            CommonTestAssertionKind::Meaningful
        }
        ("expect", "toBeTruthy" | "ok" | "true") | ("assert", "ok" | "isTrue")
            if actual.kind() == "true" =>
        {
            CommonTestAssertionKind::ConstantTruth
        }
        ("expect", "toBeFalsy" | "false") | ("assert", "isFalse") if actual.kind() == "false" => {
            CommonTestAssertionKind::ConstantTruth
        }
        (
            "expect",
            "toBeNull" | "toBeUndefined" | "toBeDefined" | "null" | "undefined" | "exist",
        )
        | ("assert", "isNotNull" | "isNull") => CommonTestAssertionKind::NullnessOnly,
        ("expect", "toBeTruthy" | "toBeFalsy" | "ok") => CommonTestAssertionKind::Meaningful,
        (
            "expect",
            "toThrow"
            | "toThrowError"
            | "toHaveBeenCalled"
            | "toHaveBeenCalledTimes"
            | "toHaveBeenCalledWith"
            | "toMatchSnapshot"
            | "toMatchInlineSnapshot",
        )
        | ("assert", "ok" | "isTrue" | "isFalse") => CommonTestAssertionKind::Meaningful,
        // An uncalled chain reaches here only through `js_ts_property_assertion`,
        // which admits property matchers alone, so an unfinished
        // `expect(x).to.be.a` is not an assertion.
        ("expect", name)
            if JS_TS_CHAI_PROPERTY_MATCHERS.contains(&name)
                || JS_TS_CHAI_METHOD_MATCHERS.contains(&name) =>
        {
            CommonTestAssertionKind::Meaningful
        }
        _ => return None,
    };
    let mut oversized = None;
    if let Some((left, right)) = operands {
        if js_ts_operands_equal(left, right, source) {
            kind = if is_js_ts_literal(left, source) {
                CommonTestAssertionKind::ConstantEquality
            } else {
                CommonTestAssertionKind::SelfComparison
            };
        } else {
            // Only selected string literal nodes can supply a large literal.
            let literal_text = |node: Node<'_>| {
                if node.kind() == "string" {
                    node_text(node, source)
                } else {
                    ""
                }
            };
            oversized = oversized_quoted_literal(
                literal_text(left),
                literal_text(right),
                weights,
                &['"', '\''],
            );
        }
    }
    let classification = classify_common_test_assertion(kind, weights);
    let (kind, score, shallow, meaningful, reason) = if let Some(literal) = oversized {
        (
            "overspecified-literal",
            weights.overspecified_literal_weight,
            false,
            false,
            format!("overspecified-literal:{literal}"),
        )
    } else if root == "expect" && matches!(matcher, "toMatchSnapshot" | "toMatchInlineSnapshot") {
        (
            "snapshot-assertion",
            weights.overspecified_literal_weight,
            false,
            false,
            "snapshot-assertion".to_string(),
        )
    } else if root == "expect"
        && matches!(matcher, "toBeTruthy" | "toBeFalsy" | "ok")
        && matches!(kind, CommonTestAssertionKind::Meaningful)
    {
        (
            "shallow-assertion",
            0,
            true,
            false,
            "shallow-assertion".to_string(),
        )
    } else {
        (
            classification.kind,
            classification.score,
            classification.shallow,
            matches!(kind, CommonTestAssertionKind::Meaningful)
                || (root == "assert" && operands.is_none() && classification.score == 0),
            classification.kind.to_string(),
        )
    };
    Some(TestAssertionSignal {
        kind: kind.to_string(),
        score,
        shallow,
        meaningful,
        reasons: vec![reason],
        excerpt: collapse_whitespace(node_text(node, source)),
        start_byte: node.start_byte(),
    })
}

// Compare tree shape and leaf tokens, including punctuation and string data.
// Formatting and comments between tokens do not change expression identity.
fn js_ts_operands_equal(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    let mut pending = vec![(left, right)];
    while let Some((left, right)) = pending.pop() {
        if left.kind() != right.kind() {
            return false;
        }
        if left.child_count() == 0 && right.child_count() == 0 {
            if node_text(left, source) != node_text(right, source) {
                return false;
            }
            continue;
        }
        let mut left_cursor = left.walk();
        let mut right_cursor = right.walk();
        let mut left_children = left.children(&mut left_cursor).filter(|n| !n.is_extra());
        let mut right_children = right.children(&mut right_cursor).filter(|n| !n.is_extra());
        loop {
            match (left_children.next(), right_children.next()) {
                (Some(left), Some(right)) => pending.push((left, right)),
                (None, None) => break,
                _ => return false,
            }
        }
    }
    true
}

fn is_js_ts_literal(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "string" | "number" | "true" | "false" | "null" | "undefined" => true,
        "identifier" => node_text(node, source) == "undefined",
        "unary_expression" => {
            node.child_by_field_name("operator")
                .is_some_and(|operator| matches!(node_text(operator, source), "+" | "-"))
                && node
                    .child_by_field_name("argument")
                    .is_some_and(|argument| argument.kind() == "number")
        }
        _ => false,
    }
}

fn trim_js_ts_string_literal(raw: &str) -> String {
    raw.trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}
