//! Structured call-shape rows (issue #1478).
//!
//! A call shape is the complete ordered structure of one call-shaped
//! occurrence: its [`CallKind`], its ordered argument-list groups, and each
//! group's ordered arguments. The facts arena already records every call with
//! [`Role::Arg`], [`Role::Kwarg`], and [`Role::Receiver`] targets, spread
//! flags, and keyword spans; today only get-definition consumes that structure
//! and discards it after filtering overload candidates. These rows keep it.
//!
//! One call site produces exactly one mandatory [`CallShapeOutcome`] plus zero
//! or more [`ArgumentGroupRow`]/[`ArgumentRow`] rows keyed to it by stable
//! IDs, following the receiver-outcome/evidence discipline: an empty argument
//! set is distinguishable from an unreadable one because the outcome's
//! [`CallShapeCoverage`] says which it is. Facts-derived shapes are `Exact`;
//! languages whose lowering cannot see a macro- or configuration-derived list
//! report the incomplete coverages when their per-language enrichment lands.
//!
//! Per-language enrichment reaches this module through
//! [`NormalizedNode::call_site`], which each language spec fills from its own
//! grammar node during extraction: a refined [`CallKind`] (a Java
//! `object_creation_expression` is a constructor call, a Scala
//! `infix_expression` is an infix application), a [`CallShapeCoverage`] below
//! `Exact` when the lowering cannot read the argument list at all (a C call
//! whose arguments come from a function-like macro), and a flag marking an
//! application that continues its callee's argument-list sequence, which is
//! how a Scala curried call `f(a)(b)` becomes one site with two ordered
//! groups. A language that fills nothing keeps the baseline.
//!
//! This module is derivation only: it never re-parses source, and it never
//! guesses arguments a language's structural lowering did not record.

use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::structural::facts::NormalizedNode;
use crate::analyzer::structural::occurrence_rows::ast_id;
use crate::analyzer::structural::{FileFacts, NormalizedKind, Role};
use crate::analyzer::{ProjectFile, Range};
use brokk_bifrost_core::analyzer::structural::callable::{
    ArgumentListKind, CallKind, CallShapeCoverage,
};

const CALL_SHAPE_SITE_ID_DOMAIN: &[u8] = b"bifrost.code_query.call_shape_site.v1";
const CALL_SHAPE_GROUP_ID_DOMAIN: &[u8] = b"bifrost.code_query.call_shape_group.v1";
const CALL_SHAPE_ARGUMENT_ID_DOMAIN: &[u8] = b"bifrost.code_query.call_shape_argument.v1";

/// The mandatory terminal row for one analyzed call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallShapeOutcome {
    /// Stable row ID; equal to `site_id` because the outcome is one-per-site.
    pub id: String,
    /// Content-scoped stable site identity shared by group and argument rows.
    pub site_id: String,
    /// The facts-arena AST identity of the exact call node.
    pub site_ast_id: String,
    pub file: ProjectFile,
    pub range: Range,
    /// The span of the token that names the callee, where the lowering
    /// recorded one. A callable-object call (`proc.(x)`) has none.
    pub callee_range: Option<Range>,
    /// The callee token recorded by the language lowering. This is decoded
    /// from the facts arena, not reparsed from the call's source text.
    pub callee_name: Option<String>,
    /// The span of the receiver expression the call is written against, where
    /// the lowering recorded one. A curried sequence names it on its innermost
    /// application, which is where the receiver is written. This is the actual
    /// a `receiver` binding row binds (issue #2499); whether it binds anything
    /// is the callee's answer, not the shape's.
    pub receiver_range: Option<Range>,
    pub call_kind: CallKind,
    pub coverage: CallShapeCoverage,
}

/// One ordered argument-list group of a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentGroupRow {
    pub id: String,
    pub site_id: String,
    /// Zero-based position of this group in the call's group sequence.
    pub group_index: usize,
    pub kind: ArgumentListKind,
    pub argument_count: usize,
}

/// One ordered argument inside one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentRow {
    pub id: String,
    pub group_id: String,
    /// Zero-based position of this argument within its group.
    pub argument_index: usize,
    /// The parameter name this argument is matched by, for named groups.
    pub name: Option<String>,
    /// Whether the argument expands a pack (`*args`, `xs: _*`, `...xs`).
    pub spread: bool,
    pub range: Range,
}

/// The complete shape of one call site: one outcome plus its ordered groups
/// and arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallShapeReport {
    pub outcome: CallShapeOutcome,
    pub groups: Vec<ArgumentGroupRow>,
    pub arguments: Vec<ArgumentRow>,
}

/// Derive the call shape of the call site `call_id` belongs to.
///
/// Returns `None` when `call_id` is not a call node. When `call_id` is one
/// application of a curried sequence, the report describes the whole sequence:
/// `f(a)(b)` is one call site with two ordered `Ordinary` groups, whichever of
/// its two arena nodes was asked for.
///
/// The facts arena models positional arguments, named arguments, spread flags,
/// receiver, and callee, so each application in the sequence contributes at
/// most one `Ordinary` group followed by at most one `Named` group. Type
/// arguments, contextual (`using`) lists, and trailing blocks are not recorded
/// by the shared lowering and are therefore never emitted; approximating them
/// from source text is forbidden.
pub fn call_shape_for_call(
    facts: &FileFacts,
    file: &ProjectFile,
    call_id: u32,
) -> Option<CallShapeReport> {
    if facts.node(call_id).kind != NormalizedKind::Call {
        return None;
    }
    // The site is the outermost application of the curried sequence, and its
    // argument lists are the sequence's lists in source order.
    let site_call_id = application_root(facts, call_id);
    let applications = application_sequence(facts, site_call_id);
    let call = facts.node(site_call_id);

    let content_identity = facts.source_identity();
    let mut digest = LengthDelimitedDigest::new(CALL_SHAPE_SITE_ID_DOMAIN);
    digest.push(content_identity.as_bytes());
    digest.push(&call.range.start_byte.to_le_bytes());
    digest.push(&call.range.end_byte.to_le_bytes());
    let site_id = digest.finish().to_string();
    let site_ast_id = ast_id(content_identity, site_call_id);

    let callee_range = call
        .name
        .map(|span| range_for_bytes(facts, span.start_byte, span.end_byte));
    let callee_name = call.name.map(|span| span.text(facts.source()).to_owned());
    // The receiver is written on the innermost application: `a.f(x)(y)` reads
    // its receiver at `a`, and the outer application has none of its own.
    let receiver_range = applications
        .iter()
        .find_map(|&id| facts.role_targets(id, Role::Receiver).next())
        .map(|target| range_for_bytes(facts, target.span.start_byte, target.span.end_byte));
    // Coverage is the least complete answer any application in the sequence
    // gave: one unreadable list makes the whole site's shape unreadable.
    let coverage = applications
        .iter()
        .map(|&id| site_coverage(facts.node(id)))
        .max_by_key(|coverage| coverage_rank(*coverage))
        .unwrap_or(CallShapeCoverage::Exact);
    let call_kind = call_kind_for(facts, &applications);

    let mut groups = Vec::new();
    let mut arguments = Vec::new();
    // An unreadable shape emits no group and no argument row. A fabricated
    // empty list would be indistinguishable from a real zero-argument call,
    // which is exactly the confusion the coverage field exists to prevent.
    if coverage == CallShapeCoverage::Exact {
        let mut group_index = 0usize;
        for &application in &applications {
            for (kind, members) in argument_groups_of(facts, application) {
                // A call with no positional arguments still has one empty
                // `Ordinary` group: "applied to zero arguments" is a shape,
                // while a missing `Named` group means "no named arguments
                // exist", not "zero named arguments were passed".
                if members.is_empty() && kind != ArgumentListKind::Ordinary {
                    continue;
                }
                let mut digest = LengthDelimitedDigest::new(CALL_SHAPE_GROUP_ID_DOMAIN);
                digest.push(site_id.as_bytes());
                digest.push(&group_index.to_le_bytes());
                let group_id = digest.finish().to_string();
                for (argument_index, member) in members.iter().enumerate() {
                    let mut digest = LengthDelimitedDigest::new(CALL_SHAPE_ARGUMENT_ID_DOMAIN);
                    digest.push(group_id.as_bytes());
                    digest.push(&argument_index.to_le_bytes());
                    arguments.push(ArgumentRow {
                        id: digest.finish().to_string(),
                        group_id: group_id.clone(),
                        argument_index,
                        name: member.name.clone(),
                        spread: member.spread,
                        range: member.range,
                    });
                }
                groups.push(ArgumentGroupRow {
                    id: group_id,
                    site_id: site_id.clone(),
                    group_index,
                    kind,
                    argument_count: members.len(),
                });
                group_index += 1;
            }
        }
    }

    Some(CallShapeReport {
        outcome: CallShapeOutcome {
            id: site_id.clone(),
            site_id,
            site_ast_id,
            file: file.clone(),
            range: call.range,
            callee_range,
            callee_name,
            receiver_range,
            call_kind,
            coverage,
        },
        groups,
        arguments,
    })
}

/// Derive the shapes of every call site in one file's facts, in arena order,
/// up to `limit` sites.
///
/// An application that only continues a curried sequence is not a site of its
/// own: `f(a)(b)` reports once, not twice.
pub fn call_shapes_in_file(
    facts: &FileFacts,
    file: &ProjectFile,
    limit: usize,
) -> Vec<CallShapeReport> {
    let _scope = crate::profiling::scope("call_shapes_in_file");
    let mut reports = Vec::new();
    for (id, node) in facts.nodes().iter().enumerate() {
        if reports.len() >= limit {
            break;
        }
        if node.kind != NormalizedKind::Call {
            continue;
        }
        let call_id = u32::try_from(id).expect("facts arena node IDs fit u32");
        if application_root(facts, call_id) != call_id {
            continue;
        }
        if let Some(report) = call_shape_for_call(facts, file, call_id) {
            reports.push(report);
        }
    }
    reports
}

/// One argument of one group, before it is given a row identity.
struct ArgumentMember {
    range: Range,
    name: Option<String>,
    spread: bool,
}

/// The positional and named groups one application node contributes.
fn argument_groups_of(
    facts: &FileFacts,
    call_id: u32,
) -> [(ArgumentListKind, Vec<ArgumentMember>); 2] {
    let mut positional = Vec::new();
    let mut named = Vec::new();
    for target in facts.roles(call_id) {
        let member = ArgumentMember {
            range: range_for_bytes(facts, target.span.start_byte, target.span.end_byte),
            name: target
                .keyword
                .map(|keyword| keyword.text(facts.source()).to_owned()),
            spread: target.spread,
        };
        match target.role {
            Role::Arg => positional.push(member),
            Role::Kwarg => named.push(member),
            _ => {}
        }
    }
    [
        (ArgumentListKind::Ordinary, positional),
        (ArgumentListKind::Named, named),
    ]
}

/// The outermost application of the curried sequence `call_id` belongs to.
///
/// Walks up the containment chain while the enclosing call declares that its
/// own argument list continues this call's sequence. The walk is iterative and
/// bounded by the arena's parent chain, which is strictly decreasing in id.
fn application_root(facts: &FileFacts, call_id: u32) -> u32 {
    let mut current = call_id;
    while let Some(parent) = facts.node(current).parent {
        if continued_application_of(facts, parent) != Some(current) {
            break;
        }
        current = parent;
    }
    current
}

/// The applications of the curried sequence rooted at `root`, in source order
/// (the innermost application, whose list is written first, comes first).
fn application_sequence(facts: &FileFacts, root: u32) -> Vec<u32> {
    let mut sequence = vec![root];
    let mut current = root;
    while let Some(inner) = continued_application_of(facts, current) {
        sequence.push(inner);
        current = inner;
    }
    sequence.reverse();
    sequence
}

/// The application `call_id` continues, when its language says it continues
/// one: the call node directly below it that starts at the same byte.
///
/// The callee role edge points at the callee's *name* token, not at the inner
/// application, so the inner application is found through the arena's own
/// containment structure. Only one direct child call can begin where its
/// parent call begins, and that child is exactly the callee expression, so no
/// source text is consulted.
fn continued_application_of(facts: &FileFacts, call_id: u32) -> Option<u32> {
    let call = facts.node(call_id);
    if call.kind != NormalizedKind::Call
        || !call
            .call_site
            .is_some_and(|site| site.continues_callee_groups)
    {
        return None;
    }
    let mut child = call_id + 1;
    while child < call.subtree_end {
        let node = facts.node(child);
        if node.parent == Some(call_id)
            && node.kind == NormalizedKind::Call
            && node.range.start_byte == call.range.start_byte
        {
            return Some(child);
        }
        // Skip the whole subtree of a child that is not the continued
        // application: only direct children can be it.
        child = if node.parent == Some(call_id) {
            node.subtree_end
        } else {
            child + 1
        };
    }
    None
}

fn site_coverage(node: &NormalizedNode) -> CallShapeCoverage {
    node.call_site
        .map_or(CallShapeCoverage::Exact, |facts| facts.coverage)
}

/// How incomplete a coverage is, so the least complete one wins.
fn coverage_rank(coverage: CallShapeCoverage) -> u8 {
    match coverage {
        CallShapeCoverage::Exact => 0,
        CallShapeCoverage::Partial => 1,
        CallShapeCoverage::UnknownDynamic => 2,
        CallShapeCoverage::UnknownMacroDerived => 3,
    }
}

/// The call kind of a site: the language's own classification when it made
/// one, otherwise the receiver-derived baseline. A curried sequence is named
/// by its innermost application, which is where the callee and its receiver
/// are written.
fn call_kind_for(facts: &FileFacts, applications: &[u32]) -> CallKind {
    let innermost = *applications.first().expect("a site has one application");
    if let Some(kind) = facts.node(innermost).call_site.and_then(|f| f.call_kind) {
        return kind;
    }
    if applications
        .iter()
        .any(|&id| facts.role_targets(id, Role::Receiver).next().is_some())
    {
        CallKind::Method
    } else {
        CallKind::Function
    }
}

fn range_for_bytes(facts: &FileFacts, start_byte: usize, end_byte: usize) -> Range {
    Range {
        start_byte,
        end_byte,
        start_line: facts.line_of_byte(start_byte),
        end_line: facts.line_of_byte(end_byte),
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::analyzer::structural::extract::extract_file_facts;
    use brokk_bifrost_cpp::structural::CPP_STRUCTURAL_SPEC;
    use brokk_bifrost_jvm::java::structural::JAVA_STRUCTURAL_SPEC;
    use brokk_bifrost_jvm::scala::structural::SCALA_STRUCTURAL_SPEC;
    use brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC;

    fn file(name: &str) -> ProjectFile {
        ProjectFile::new(env::temp_dir().join("bifrost-call-shape"), name)
    }

    fn python_facts(source: &str) -> FileFacts {
        let grammar = tree_sitter_python::LANGUAGE.into();
        extract_file_facts(&PYTHON_STRUCTURAL_SPEC, &grammar, source)
            .expect("Python structural facts")
    }

    fn shape_for(source: &str, facts: &FileFacts, call_text: &str) -> CallShapeReport {
        let start = source.rfind(call_text).expect("call text exists");
        let end = start + call_text.len();
        let call_id = facts
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.kind == NormalizedKind::Call
                    && node.range.start_byte == start
                    && node.range.end_byte == end
            })
            .map(|(id, _)| u32::try_from(id).expect("node id fits u32"))
            .expect("call node exists at the text span");
        call_shape_for_call(facts, &file("shape.py"), call_id).expect("call shape")
    }

    #[test]
    fn positional_call_yields_one_ordered_ordinary_group() {
        let source = "def target(a, b): pass\ntarget(1, 2)\n";
        let facts = python_facts(source);
        let report = shape_for(source, &facts, "target(1, 2)");

        assert_eq!(report.outcome.call_kind, CallKind::Function);
        assert_eq!(report.outcome.coverage, CallShapeCoverage::Exact);
        assert_eq!(report.outcome.id, report.outcome.site_id);
        let callee = report.outcome.callee_range.expect("callee range");
        assert_eq!(&source[callee.start_byte..callee.end_byte], "target");

        assert_eq!(report.groups.len(), 1);
        let group = &report.groups[0];
        assert_eq!(group.kind, ArgumentListKind::Ordinary);
        assert_eq!(group.group_index, 0);
        assert_eq!(group.argument_count, 2);
        assert_eq!(group.site_id, report.outcome.site_id);

        let texts: Vec<_> = report
            .arguments
            .iter()
            .map(|argument| {
                assert_eq!(argument.group_id, group.id);
                &source[argument.range.start_byte..argument.range.end_byte]
            })
            .collect();
        assert_eq!(texts, ["1", "2"]);
        assert_eq!(
            report
                .arguments
                .iter()
                .map(|argument| argument.argument_index)
                .collect::<Vec<_>>(),
            [0, 1]
        );
    }

    #[test]
    fn named_arguments_form_a_separate_ordered_named_group() {
        let source = "def target(a, width=0): pass\ntarget(1, width=3)\n";
        let facts = python_facts(source);
        let report = shape_for(source, &facts, "target(1, width=3)");

        assert_eq!(report.groups.len(), 2);
        assert_eq!(report.groups[0].kind, ArgumentListKind::Ordinary);
        assert_eq!(report.groups[0].argument_count, 1);
        assert_eq!(report.groups[1].kind, ArgumentListKind::Named);
        assert_eq!(report.groups[1].group_index, 1);
        assert_eq!(report.groups[1].argument_count, 1);

        let named: Vec<_> = report
            .arguments
            .iter()
            .filter(|argument| argument.group_id == report.groups[1].id)
            .collect();
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].name.as_deref(), Some("width"));
        assert!(!named[0].spread);
    }

    #[test]
    fn spread_arguments_keep_their_pack_flag() {
        let source = "def target(*items): pass\nvalues = [1]\ntarget(*values)\n";
        let facts = python_facts(source);
        let report = shape_for(source, &facts, "target(*values)");

        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.arguments.len(), 1);
        assert!(report.arguments[0].spread);
    }

    #[test]
    fn zero_argument_call_still_has_one_empty_ordinary_group() {
        let source = "def target(): pass\ntarget()\n";
        let facts = python_facts(source);
        let report = shape_for(source, &facts, "target()");

        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].kind, ArgumentListKind::Ordinary);
        assert_eq!(report.groups[0].argument_count, 0);
        assert!(report.arguments.is_empty());
    }

    #[test]
    fn receiver_qualified_call_is_a_method_shape() {
        let source = "class Owner:\n    def target(self): pass\nOwner().target()\n";
        let facts = python_facts(source);
        let report = shape_for(source, &facts, "Owner().target()");
        assert_eq!(report.outcome.call_kind, CallKind::Method);
    }

    #[test]
    fn site_group_and_argument_ids_are_stable_and_distinct() {
        let source = "def target(a, b): pass\ntarget(1, 2)\ntarget(1, 2)\n";
        let facts = python_facts(source);
        let reports = call_shapes_in_file(&facts, &file("shape.py"), usize::MAX);
        assert_eq!(reports.len(), 2);
        // Same spelling at different positions must mint different site IDs.
        assert_ne!(reports[0].outcome.site_id, reports[1].outcome.site_id);
        assert_ne!(
            reports[0].outcome.site_ast_id,
            reports[1].outcome.site_ast_id
        );

        // Re-derivation is deterministic.
        let again = call_shapes_in_file(&facts, &file("shape.py"), usize::MAX);
        assert_eq!(reports, again);

        // Row IDs never collide across domains or rows.
        let mut ids = std::collections::HashSet::new();
        for report in &reports {
            assert!(ids.insert(report.outcome.id.clone()));
            for group in &report.groups {
                assert!(ids.insert(group.id.clone()));
            }
            for argument in &report.arguments {
                assert!(ids.insert(argument.id.clone()));
            }
        }
    }

    /// A Scala curried application is one call site whose argument lists are
    /// the sequence's lists in source order, not two sites.
    #[test]
    fn scala_curried_application_is_one_site_with_ordered_groups() {
        let source =
            "object App {\n  def f(a: Int)(b: Int): Int = a + b\n  def g: Int = f(1)(2)\n}\n";
        let grammar = brokk_bifrost_jvm::scala::language::LANGUAGE.into();
        let facts = extract_file_facts(&SCALA_STRUCTURAL_SPEC, &grammar, source)
            .expect("Scala structural facts");
        let reports = call_shapes_in_file(&facts, &file("App.scala"), usize::MAX);

        let curried: Vec<_> = reports
            .iter()
            .filter(|report| {
                let range = report.outcome.range;
                &source[range.start_byte..range.end_byte] == "f(1)(2)"
            })
            .collect();
        assert_eq!(curried.len(), 1, "one site, not one per argument list");
        let report = curried[0];
        assert_eq!(report.outcome.call_kind, CallKind::Function);
        assert_eq!(report.groups.len(), 2, "{:?}", report.groups);
        assert!(
            report
                .groups
                .iter()
                .all(|group| group.kind == ArgumentListKind::Ordinary)
        );
        assert_eq!(
            report
                .groups
                .iter()
                .map(|group| group.group_index)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        let texts: Vec<_> = report
            .arguments
            .iter()
            .map(|argument| &source[argument.range.start_byte..argument.range.end_byte])
            .collect();
        assert_eq!(texts, ["1", "2"], "lists stay in source order");

        // Asking for the inner application answers for the whole site.
        let inner_id = facts
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.kind == NormalizedKind::Call
                    && &source[node.range.start_byte..node.range.end_byte] == "f(1)"
            })
            .map(|(id, _)| u32::try_from(id).expect("node id fits u32"))
            .expect("inner application is a call fact");
        let from_inner =
            call_shape_for_call(&facts, &file("App.scala"), inner_id).expect("call shape");
        assert_eq!(&from_inner, report);
    }

    /// Scala infix applications carry the grammar's own distinction between a
    /// symbolic operator and a named infix method.
    #[test]
    fn scala_infix_and_operator_applications_are_classified() {
        let source = "object App {\n  def g(a: Int, b: Int): Int = a max b\n  def h(a: Int, b: Int): Int = a + b\n}\n";
        let grammar = brokk_bifrost_jvm::scala::language::LANGUAGE.into();
        let facts = extract_file_facts(&SCALA_STRUCTURAL_SPEC, &grammar, source)
            .expect("Scala structural facts");
        let kinds: Vec<_> = call_shapes_in_file(&facts, &file("App.scala"), usize::MAX)
            .into_iter()
            .map(|report| {
                let range = report.outcome.range;
                (
                    source[range.start_byte..range.end_byte].to_owned(),
                    report.outcome.call_kind,
                )
            })
            .collect();
        assert!(
            kinds.contains(&("a max b".to_owned(), CallKind::Infix)),
            "{kinds:?}"
        );
        assert!(
            kinds.contains(&("a + b".to_owned(), CallKind::Operator)),
            "{kinds:?}"
        );
    }

    /// A Java `new T(...)` site is a constructor call, and an ordinary
    /// invocation beside it is not.
    #[test]
    fn java_object_creation_is_a_constructor_call() {
        let source = "class Widget { Widget(int size) {} static void build() { new Widget(2); helper(3); } static void helper(int a) {} }\n";
        let grammar = tree_sitter_java::LANGUAGE.into();
        let facts = extract_file_facts(&JAVA_STRUCTURAL_SPEC, &grammar, source)
            .expect("Java structural facts");
        let kinds: Vec<_> = call_shapes_in_file(&facts, &file("Widget.java"), usize::MAX)
            .into_iter()
            .map(|report| {
                let range = report.outcome.range;
                (
                    source[range.start_byte..range.end_byte].to_owned(),
                    report.outcome.call_kind,
                )
            })
            .collect();
        assert!(
            kinds.contains(&("new Widget(2)".to_owned(), CallKind::Constructor)),
            "{kinds:?}"
        );
        assert!(
            kinds.contains(&("helper(3)".to_owned(), CallKind::Function)),
            "{kinds:?}"
        );
    }

    /// A C++ call of a function-like macro defined in the same file reports
    /// unknown coverage and no argument rows: its source arguments are the
    /// macro's, not the callable's.
    #[test]
    fn cpp_macro_derived_call_has_unknown_coverage_and_no_arguments() {
        let source = "#define CALL_TWICE(a) helper(a, 1)\nint helper(int a, int b);\nint main() { CALL_TWICE(2); helper(1, 2); return 0; }\n";
        let grammar = tree_sitter_cpp::LANGUAGE.into();
        let facts = extract_file_facts(&CPP_STRUCTURAL_SPEC, &grammar, source).expect("C++ facts");
        let reports = call_shapes_in_file(&facts, &file("main.cpp"), usize::MAX);
        let by_text = |text: &str| {
            reports
                .iter()
                .find(|report| {
                    let range = report.outcome.range;
                    &source[range.start_byte..range.end_byte] == text
                })
                .unwrap_or_else(|| panic!("no call shape for `{text}`"))
        };

        let macro_call = by_text("CALL_TWICE(2)");
        assert_eq!(
            macro_call.outcome.coverage,
            CallShapeCoverage::UnknownMacroDerived
        );
        assert!(
            macro_call.groups.is_empty() && macro_call.arguments.is_empty(),
            "an unreadable shape must fabricate no rows: {macro_call:?}"
        );

        let ordinary = by_text("helper(1, 2)");
        assert_eq!(ordinary.outcome.coverage, CallShapeCoverage::Exact);
        assert_eq!(ordinary.groups.len(), 1);
        assert_eq!(ordinary.arguments.len(), 2);
    }

    #[test]
    fn limit_bounds_per_file_enumeration() {
        let source = "def target(): pass\ntarget()\ntarget()\ntarget()\n";
        let facts = python_facts(source);
        let reports = call_shapes_in_file(&facts, &file("shape.py"), 2);
        assert_eq!(reports.len(), 2);
    }
}
