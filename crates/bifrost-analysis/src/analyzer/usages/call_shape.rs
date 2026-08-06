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
//! This module is derivation only: it never re-parses source, and it never
//! guesses arguments a language's structural lowering did not record.

use crate::analyzer::semantic::LengthDelimitedDigest;
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

/// Derive the call shape of one exact facts-arena call node.
///
/// Returns `None` when `call_id` is not a call node. The facts arena models
/// positional arguments, named arguments, spread flags, receiver, and callee
/// today, so this derivation emits at most one `Ordinary` group followed by
/// at most one `Named` group, and classifies the site as `Method` or
/// `Function` by receiver presence. Constructor, extractor, infix,
/// method-value, and curried/contextual/block/type-argument groups need
/// structure the shared lowering does not record; they arrive with the
/// per-language enrichment milestones and must never be inferred here from
/// source text.
pub fn call_shape_for_call(
    facts: &FileFacts,
    file: &ProjectFile,
    call_id: u32,
) -> Option<CallShapeReport> {
    let call = facts.node(call_id);
    if call.kind != NormalizedKind::Call {
        return None;
    }
    let content_identity = facts.source_identity();
    let mut digest = LengthDelimitedDigest::new(CALL_SHAPE_SITE_ID_DOMAIN);
    digest.push(content_identity.as_bytes());
    digest.push(&call.range.start_byte.to_le_bytes());
    digest.push(&call.range.end_byte.to_le_bytes());
    let site_id = digest.finish().to_string();
    let site_ast_id = ast_id(content_identity, call_id);

    let receiver = facts.role_targets(call_id, Role::Receiver).next();
    let callee_range = call
        .name
        .map(|span| range_for_bytes(facts, span.start_byte, span.end_byte));

    let mut positional = Vec::new();
    let mut named = Vec::new();
    for target in facts.roles(call_id) {
        match target.role {
            Role::Arg => positional.push((
                range_for_bytes(facts, target.span.start_byte, target.span.end_byte),
                None,
                target.spread,
            )),
            Role::Kwarg => named.push((
                range_for_bytes(facts, target.span.start_byte, target.span.end_byte),
                target
                    .keyword
                    .map(|keyword| keyword.text(facts.source()).to_owned()),
                target.spread,
            )),
            _ => {}
        }
    }

    let mut groups = Vec::new();
    let mut arguments = Vec::new();
    let mut group_index = 0usize;
    for (kind, members) in [
        (ArgumentListKind::Ordinary, positional),
        (ArgumentListKind::Named, named),
    ] {
        // A call with no positional arguments still has one empty `Ordinary`
        // group: "called with zero arguments" is a shape, while a missing
        // `Named` group means "no named arguments exist", not "zero named
        // arguments were passed".
        if members.is_empty() && kind != ArgumentListKind::Ordinary {
            continue;
        }
        let mut digest = LengthDelimitedDigest::new(CALL_SHAPE_GROUP_ID_DOMAIN);
        digest.push(site_id.as_bytes());
        digest.push(&group_index.to_le_bytes());
        let group_id = digest.finish().to_string();
        for (argument_index, (range, name, spread)) in members.iter().enumerate() {
            let mut digest = LengthDelimitedDigest::new(CALL_SHAPE_ARGUMENT_ID_DOMAIN);
            digest.push(group_id.as_bytes());
            digest.push(&argument_index.to_le_bytes());
            arguments.push(ArgumentRow {
                id: digest.finish().to_string(),
                group_id: group_id.clone(),
                argument_index,
                name: name.clone(),
                spread: *spread,
                range: *range,
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

    let call_kind = if receiver.is_some() {
        CallKind::Method
    } else {
        CallKind::Function
    };
    Some(CallShapeReport {
        outcome: CallShapeOutcome {
            id: site_id.clone(),
            site_id,
            site_ast_id,
            file: file.clone(),
            range: call.range,
            callee_range,
            call_kind,
            coverage: CallShapeCoverage::Exact,
        },
        groups,
        arguments,
    })
}

/// Derive the shapes of every call node in one file's facts, in arena order,
/// up to `limit` sites.
pub fn call_shapes_in_file(
    facts: &FileFacts,
    file: &ProjectFile,
    limit: usize,
) -> Vec<CallShapeReport> {
    let mut reports = Vec::new();
    for (id, node) in facts.nodes().iter().enumerate() {
        if reports.len() >= limit {
            break;
        }
        if node.kind != NormalizedKind::Call {
            continue;
        }
        let call_id = u32::try_from(id).expect("facts arena node IDs fit u32");
        if let Some(report) = call_shape_for_call(facts, file, call_id) {
            reports.push(report);
        }
    }
    reports
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
    use crate::analyzer::python::structural::PYTHON_STRUCTURAL_SPEC;
    use crate::analyzer::structural::extract::extract_file_facts;

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

    #[test]
    fn limit_bounds_per_file_enumeration() {
        let source = "def target(): pass\ntarget()\ntarget()\ntarget()\n";
        let facts = python_facts(source);
        let reports = call_shapes_in_file(&facts, &file("shape.py"), 2);
        assert_eq!(reports.len(), 2);
    }
}
