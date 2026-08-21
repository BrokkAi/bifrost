//! Normalized actual-to-formal binding rows (issue #2438, first slice).
//!
//! Two disjoint pipelines used to hold half of this answer each. The facts
//! arena derives [`crate::analyzer::usages::call_shape`] rows, which carry
//! stable site, group and argument identities but say nothing about the
//! callable's parameter list. Tree-sitter call-relation binding
//! ([`crate::analyzer::usages::call_relations::bind_call_site_arguments`])
//! computes the formal index, formal name and variadic state of every actual,
//! but only ever surfaced them through a nested presentation value and through
//! id-less expression-site rows. Nothing joined the two.
//!
//! This module is that join. One [`CallBindingReport`] describes one exact call
//! site: it reuses the call-shape row identities for the actual side and the
//! shared formal-slot matcher below for the formal side, so a binding row joins
//! `call_shape.site_id`, `call_argument_group.id` and `call_argument.id`
//! directly, with no range or text comparison anywhere.
//!
//! Three rules are load-bearing.
//!
//! - The report is mandatory. A call whose shape is unreadable, whose callee
//!   does not resolve, or whose formals nobody recorded still produces exactly
//!   one row stating the typed reason, so zero rows can never be read as "this
//!   call passes no arguments". This is the same discipline
//!   [`crate::analyzer::usages::call_shape`] applies to its own outcome row.
//! - The matcher is never a second computation. The positional, keyword and
//!   variadic rules live in [`OrdinaryFormalSlots::slot_for`], which is the
//!   exact function the production call-relation binder calls, so a row can
//!   never disagree with what `call_input` binds.
//! - Overload selection is inherited, never redone. The callee identity handed
//!   to [`call_binding_report`] comes from the production definition resolver,
//!   which is the consumer of
//!   [`crate::analyzer::usages::applicability::ApplicabilityOutcome::winners`].
//!   This module never measures arity to pick between overloads.

use crate::analyzer::lexical_definitions::{FormalParameterLayout, FormalParameterSlot};
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::usages::call_shape::CallShapeReport;
use crate::analyzer::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::analyzer::structural::callable::{ArgumentListKind, CallShapeCoverage};

/// Domain separator for one actual-to-formal binding row id.
const CALL_BINDING_ID_DOMAIN: &[u8] = b"bifrost.code_query.call_binding.v1";

macro_rules! call_binding_enum {
    ($(#[$meta:meta])* $name:ident, $all:ident { $($variant:ident => $label:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant,)+
        }

        pub const $all: &[$name] = &[$($name::$variant,)+];

        impl $name {
            pub const fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<$name> {
                $all.iter().copied().find(|value| value.label() == label)
            }
        }
    };
}

call_binding_enum! {
    /// How one actual reached the formal it is bound to.
    ///
    /// The whole vocabulary is declared now even though the first slice only
    /// ever mints `Positional`, `Named`, `Variadic` and `Spread`: a later slice
    /// that adds defaults, receivers or implicit arguments must add rows, not
    /// columns, and a policy written today against `binding_kind` must not need
    /// rewriting when it does.
    ///
    /// - `Positional`: an actual matched by its ordinal.
    /// - `Named`: an actual matched by the parameter name written at the call.
    /// - `Defaulted`: a formal with no source actual, bound by its declared
    ///   default. Not emitted in the first slice.
    /// - `Variadic`: an actual absorbed by a repeating formal.
    /// - `Spread`: an actual that expands a pack (`*args`, `xs: _*`, `...xs`).
    ///   The pack's members are not individually known, so the mapping status
    ///   of such a row is never `Exact`.
    /// - `Receiver`: the receiver expression bound to a receiver formal. Not
    ///   emitted in the first slice.
    /// - `Implicit`: an argument the language supplies without source syntax.
    ///   Not emitted in the first slice.
    CallBindingKind, ALL_CALL_BINDING_KINDS {
        Positional => "positional",
        Named => "named",
        Defaulted => "defaulted",
        Variadic => "variadic",
        Spread => "spread",
        Receiver => "receiver",
        Implicit => "implicit",
    }
}

call_binding_enum! {
    /// How well established one binding row's own mapping is.
    ///
    /// - `Exact`: this actual is bound to exactly this formal.
    /// - `Ambiguous`: several formals or several callees could accept it.
    /// - `Incomplete`: the analyzer could not establish the mapping here, and
    ///   says why through [`CallBindingRow::reason`].
    /// - `Unsupported`: the source shape or the language adapter cannot carry
    ///   the mapping at all.
    CallBindingMapping, ALL_CALL_BINDING_MAPPINGS {
        Exact => "exact",
        Ambiguous => "ambiguous",
        Incomplete => "incomplete",
        Unsupported => "unsupported",
    }
}

call_binding_enum! {
    /// Coverage of the whole actual/formal partition of one call site.
    ///
    /// Repeated on every row of the site, exactly as `dispatch_target` repeats
    /// its site's candidate coverage, so one row alone is enough to reject an
    /// exact-set claim over the call's arguments.
    ///
    /// - `Exhaustive`: every actual of this call is bound exactly. A call that
    ///   passes no arguments is exhaustive.
    /// - `Partial`: some actuals are bound exactly and some are not.
    /// - `Unknown`: no actual could be bound, because the callee or its formals
    ///   could not be established.
    /// - `Unsupported`: the call's own argument structure is unreadable.
    CallBindingCoverage, ALL_CALL_BINDING_COVERAGES {
        Exhaustive => "exhaustive",
        Partial => "partial",
        Unknown => "unknown",
        Unsupported => "unsupported",
    }
}

call_binding_enum! {
    /// Why a row's mapping is not `Exact`. An exact row states none.
    ///
    /// - `ShapeUnreadable`: the call site's own [`CallShapeCoverage`] is below
    ///   `Exact`, so its arguments were never enumerated.
    /// - `CalleeUnresolved`: no callee declaration could be named for the site.
    /// - `CalleeAmbiguous`: the callee reference named several declarations.
    /// - `FormalsUnrecorded`: the callee resolves, but nothing recorded its
    ///   formal parameter list.
    /// - `NoMatchingFormal`: this actual matched no formal slot -- an arity or
    ///   name mismatch against the bound callable.
    /// - `SpreadNotExpanded`: this actual expands a pack whose members are not
    ///   statically known.
    /// - `ReceiverBindingUnsupported`: the language binds a receiver into the
    ///   declared parameter list, and this seam does not carry the receiver
    ///   evidence needed to decide whether it did.
    CallBindingReason, ALL_CALL_BINDING_REASONS {
        ShapeUnreadable => "shape_unreadable",
        CalleeUnresolved => "callee_unresolved",
        CalleeAmbiguous => "callee_ambiguous",
        FormalsUnrecorded => "formals_unrecorded",
        NoMatchingFormal => "no_matching_formal",
        SpreadNotExpanded => "spread_not_expanded",
        ReceiverBindingUnsupported => "receiver_binding_unsupported",
    }
}

/// One actual/formal pair of one call site, or one call's terminal statement
/// that no pair could be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallBindingRow {
    /// Stable row id, domain-separated over the site identity and either the
    /// call-shape argument id this row binds or the terminal marker.
    pub id: String,
    /// The `call_shape` row this binding belongs to.
    pub site_id: String,
    /// The argument-list group of the actual. Absent on a terminal row and on
    /// a defaulted formal, neither of which has a source group.
    pub group_id: Option<String>,
    /// The `call_argument` row of the actual. Absent for the same two reasons.
    pub argument_id: Option<String>,
    /// The actual's position inside its own group.
    pub actual_index: Option<usize>,
    /// The parameter name written at the call site, when one was written.
    pub actual_name: Option<String>,
    /// Zero-based position of the bound formal in the callable's ordinary
    /// (non-receiver) parameter list.
    pub formal_index: Option<usize>,
    /// The bound formal's canonical declared name.
    pub formal_name: Option<String>,
    pub binding_kind: Option<CallBindingKind>,
    pub mapping: CallBindingMapping,
    pub reason: Option<CallBindingReason>,
    /// The actual's own span, or the whole call's span for a terminal row.
    pub range: Range,
    /// Whether this row states the call's status instead of one bound pair.
    pub terminal: bool,
}

/// Every binding row of one exact call site, with the per-call partition
/// coverage each row repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallBindingReport {
    pub file: ProjectFile,
    pub site_id: String,
    pub site_ast_id: String,
    /// The whole call expression's span.
    pub range: Range,
    /// The exact callee declaration, when one was established.
    pub target: Option<CodeUnit>,
    pub coverage: CallBindingCoverage,
    /// Actual argument rows the call shape enumerated.
    pub actual_count: usize,
    /// Actuals bound to a formal with an exact mapping.
    pub bound_count: usize,
    /// At least one row, always.
    pub rows: Vec<CallBindingRow>,
}

/// What the caller established about the callee before asking for the rows.
///
/// This is deliberately an input rather than something this module derives:
/// resolving a callee is the production definition resolver's job, and doing it
/// here would be the second overload computation issue #2438 forbids.
#[derive(Debug, Clone)]
pub enum CallBindingTarget {
    /// The callee resolves to exactly this declaration, whose ordinary formal
    /// slots are `layout`.
    Resolved {
        unit: CodeUnit,
        layout: FormalParameterLayout,
    },
    /// The callee resolves, but nothing recorded its formal parameter list.
    FormalsUnrecorded { unit: CodeUnit },
    /// The callee reference named several declarations.
    Ambiguous,
    /// No callee declaration could be named for this site.
    Unresolved,
    /// The language binds a receiver into the declared parameter list, which
    /// this seam cannot decide.
    ReceiverBindingUnsupported { unit: CodeUnit },
}

/// Derive every binding row of one call site.
///
/// The actual side is exactly the call shape's own argument rows, in group and
/// then argument order, so the result is a deterministic function of the report
/// and never of result order. The formal side is [`OrdinaryFormalSlots`].
pub fn call_binding_report(
    file: &ProjectFile,
    shape: &CallShapeReport,
    target: CallBindingTarget,
) -> CallBindingReport {
    let outcome = &shape.outcome;
    let site_id = outcome.site_id.clone();
    let base = |target: Option<CodeUnit>,
                coverage: CallBindingCoverage,
                actual_count: usize,
                bound_count: usize,
                rows: Vec<CallBindingRow>| CallBindingReport {
        file: file.clone(),
        site_id: site_id.clone(),
        site_ast_id: outcome.site_ast_id.clone(),
        range: outcome.range,
        target,
        coverage,
        actual_count,
        bound_count,
        rows,
    };

    // An unreadable shape enumerated no argument, so there is nothing to bind
    // and nothing to claim. The mandatory row says exactly that.
    if outcome.coverage != CallShapeCoverage::Exact {
        return base(
            None,
            CallBindingCoverage::Unsupported,
            0,
            0,
            vec![terminal_row(
                &site_id,
                outcome.range,
                CallBindingMapping::Unsupported,
                Some(CallBindingReason::ShapeUnreadable),
            )],
        );
    }

    let actual_count = shape.arguments.len();
    let (unit, layout) = match target {
        CallBindingTarget::Resolved { unit, layout } => (unit, layout),
        CallBindingTarget::FormalsUnrecorded { unit } => {
            return base(
                Some(unit),
                CallBindingCoverage::Unknown,
                actual_count,
                0,
                vec![terminal_row(
                    &site_id,
                    outcome.range,
                    CallBindingMapping::Incomplete,
                    Some(CallBindingReason::FormalsUnrecorded),
                )],
            );
        }
        CallBindingTarget::ReceiverBindingUnsupported { unit } => {
            return base(
                Some(unit),
                CallBindingCoverage::Unsupported,
                actual_count,
                0,
                vec![terminal_row(
                    &site_id,
                    outcome.range,
                    CallBindingMapping::Unsupported,
                    Some(CallBindingReason::ReceiverBindingUnsupported),
                )],
            );
        }
        CallBindingTarget::Ambiguous => {
            return base(
                None,
                CallBindingCoverage::Unknown,
                actual_count,
                0,
                vec![terminal_row(
                    &site_id,
                    outcome.range,
                    CallBindingMapping::Ambiguous,
                    Some(CallBindingReason::CalleeAmbiguous),
                )],
            );
        }
        CallBindingTarget::Unresolved => {
            return base(
                None,
                CallBindingCoverage::Unknown,
                actual_count,
                0,
                vec![terminal_row(
                    &site_id,
                    outcome.range,
                    CallBindingMapping::Incomplete,
                    Some(CallBindingReason::CalleeUnresolved),
                )],
            );
        }
    };

    // A call that passes nothing still states its partition: exhaustively
    // empty, with the exact callee named. Emitting no row here would make
    // "binds no argument" indistinguishable from "was never analyzed".
    if shape.arguments.is_empty() {
        return base(
            Some(unit),
            CallBindingCoverage::Exhaustive,
            0,
            0,
            vec![terminal_row(
                &site_id,
                outcome.range,
                CallBindingMapping::Exact,
                None,
            )],
        );
    }

    let slots = OrdinaryFormalSlots::of(&layout, false);
    let mut rows = Vec::with_capacity(shape.arguments.len());
    let mut bound_count = 0usize;
    // The positional ordinal is a running count over the ordinary groups in
    // group order, which is exactly the `position` the production call-site
    // syntax assigns to `Role::Arg` targets.
    let mut position = 0usize;
    for group in &shape.groups {
        for argument in shape
            .arguments
            .iter()
            .filter(|argument| argument.group_id == group.id)
        {
            let named = group.kind == ArgumentListKind::Named || argument.name.is_some();
            let ordinal = if named || argument.spread {
                None
            } else {
                let current = position;
                position += 1;
                Some(current)
            };
            let slot = slots.slot_for(argument.name.as_deref(), ordinal, argument.spread);
            let (binding_kind, mapping, reason) = if argument.spread {
                (
                    CallBindingKind::Spread,
                    CallBindingMapping::Incomplete,
                    Some(CallBindingReason::SpreadNotExpanded),
                )
            } else if let Some((_, slot)) = slot {
                let kind = if slot.variadic.is_some() {
                    CallBindingKind::Variadic
                } else if named {
                    CallBindingKind::Named
                } else {
                    CallBindingKind::Positional
                };
                bound_count += 1;
                (kind, CallBindingMapping::Exact, None)
            } else {
                (
                    if named {
                        CallBindingKind::Named
                    } else {
                        CallBindingKind::Positional
                    },
                    CallBindingMapping::Incomplete,
                    Some(CallBindingReason::NoMatchingFormal),
                )
            };
            rows.push(CallBindingRow {
                id: row_id(&site_id, RowAnchor::Argument(&argument.id)),
                site_id: site_id.clone(),
                group_id: Some(group.id.clone()),
                argument_id: Some(argument.id.clone()),
                actual_index: Some(argument.argument_index),
                actual_name: argument.name.clone(),
                formal_index: slot.map(|(index, _)| index),
                formal_name: slot
                    .and_then(|(_, slot)| slot.names.first())
                    .map(|name| canonical_parameter_name(name)),
                binding_kind: Some(binding_kind),
                mapping,
                reason,
                range: argument.range,
                terminal: false,
            });
        }
    }

    let coverage = if bound_count == rows.len() {
        CallBindingCoverage::Exhaustive
    } else if bound_count == 0 {
        CallBindingCoverage::Unknown
    } else {
        CallBindingCoverage::Partial
    };
    base(Some(unit), coverage, actual_count, bound_count, rows)
}

enum RowAnchor<'a> {
    Argument(&'a str),
    Terminal,
}

fn row_id(site_id: &str, anchor: RowAnchor<'_>) -> String {
    let mut digest = LengthDelimitedDigest::new(CALL_BINDING_ID_DOMAIN);
    digest.push(site_id.as_bytes());
    match anchor {
        RowAnchor::Argument(argument_id) => {
            digest.push(b"argument");
            digest.push(argument_id.as_bytes());
        }
        RowAnchor::Terminal => digest.push(b"terminal"),
    }
    digest.finish().to_string()
}

/// The one row a call emits when it produces no actual/formal pair.
///
/// `reason` is `None` only for the benign case: a call that passes nothing and
/// whose callee is known, which is an exhaustively empty partition rather than
/// a failure.
fn terminal_row(
    site_id: &str,
    range: Range,
    mapping: CallBindingMapping,
    reason: Option<CallBindingReason>,
) -> CallBindingRow {
    CallBindingRow {
        id: row_id(site_id, RowAnchor::Terminal),
        site_id: site_id.to_owned(),
        group_id: None,
        argument_id: None,
        actual_index: None,
        actual_name: None,
        formal_index: None,
        formal_name: None,
        binding_kind: None,
        mapping,
        reason,
        range,
        terminal: true,
    }
}

/// The ordinary (non-receiver) formal slots of one callable, in declaration
/// order, together with the rule that maps one actual onto one of them.
///
/// This is the single computation the production call-relation binder and the
/// `call_binding` rows both read. Changing the rule here changes both, which is
/// what keeps a row from ever claiming a binding `call_input` does not make.
pub(crate) struct OrdinaryFormalSlots<'a> {
    slots: Vec<(usize, &'a FormalParameterSlot)>,
}

impl<'a> OrdinaryFormalSlots<'a> {
    /// `bind_first` drops the first ordinary slot, which is how a Python
    /// instance method's `self` is already consumed by the receiver.
    pub(crate) fn of(layout: &'a FormalParameterLayout, bind_first: bool) -> Self {
        let mut slots = layout
            .slots
            .iter()
            .filter(|slot| !slot.receiver)
            .collect::<Vec<_>>();
        if bind_first && !slots.is_empty() {
            slots.remove(0);
        }
        Self {
            slots: slots.into_iter().enumerate().collect(),
        }
    }

    /// The formal slot one actual binds, or `None` when it binds none.
    ///
    /// A spread actual binds nothing: its members are not statically known, so
    /// naming one slot for the whole pack would be a claim nobody checked. A
    /// named actual takes the slot whose declared names match, otherwise the
    /// last keyword-accepting variadic slot. A positional actual takes the slot
    /// at its ordinal, otherwise the last positional-accepting variadic slot.
    pub(crate) fn slot_for(
        &self,
        name: Option<&str>,
        position: Option<usize>,
        spread: bool,
    ) -> Option<(usize, &'a FormalParameterSlot)> {
        if spread {
            return None;
        }
        if let Some(name) = name {
            return self
                .slots
                .iter()
                .copied()
                .find(|(_, slot)| {
                    slot.names
                        .iter()
                        .any(|candidate| names_match(candidate, name))
                })
                .or_else(|| {
                    self.slots
                        .iter()
                        .copied()
                        .rev()
                        .find(|(_, slot)| slot.variadic.is_some_and(|kind| kind.accepts_keyword()))
                });
        }
        position.and_then(|position| {
            self.slots.get(position).copied().or_else(|| {
                self.slots
                    .iter()
                    .copied()
                    .rev()
                    .find(|(_, slot)| slot.variadic.is_some_and(|kind| kind.accepts_positional()))
            })
        })
    }
}

pub(crate) fn names_match(formal: &str, argument: &str) -> bool {
    formal == argument
        || formal.strip_prefix('$') == Some(argument)
        || argument.strip_prefix('$') == Some(formal)
}

pub(crate) fn canonical_parameter_name(name: &str) -> String {
    name.strip_prefix('$').unwrap_or(name).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::extract::extract_file_facts;
    use crate::analyzer::structural::{FileFacts, NormalizedKind};
    use crate::analyzer::usages::call_shape::call_shape_for_call;
    use brokk_bifrost_core::analyzer::model::CodeUnitType;
    use brokk_bifrost_jvm::java::structural::JAVA_STRUCTURAL_SPEC;
    use std::env;

    fn file(name: &str) -> ProjectFile {
        ProjectFile::new(env::temp_dir().join("bifrost-call-binding"), name)
    }

    fn java_facts(source: &str) -> FileFacts {
        let grammar = tree_sitter_java::LANGUAGE.into();
        extract_file_facts(&JAVA_STRUCTURAL_SPEC, &grammar, source).expect("Java structural facts")
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
        call_shape_for_call(facts, &file("Main.java"), call_id).expect("call shape")
    }

    fn unit(name: &str) -> CodeUnit {
        CodeUnit::new(file("Main.java"), CodeUnitType::Function, "app", name)
    }

    fn slot(name: &str) -> FormalParameterSlot {
        FormalParameterSlot {
            names: vec![name.to_owned()],
            declaration_range: Range {
                start_byte: 0,
                end_byte: 0,
                start_line: 0,
                end_line: 0,
            },
            receiver: false,
            variadic: None,
        }
    }

    fn layout(names: &[&str]) -> FormalParameterLayout {
        FormalParameterLayout {
            slots: names.iter().map(|name| slot(name)).collect(),
            python_binding: None,
        }
    }

    /// Every positional actual of an ordinary Java call binds the formal at its
    /// own ordinal, and the site's partition is exhaustive.
    #[test]
    fn positional_actuals_bind_their_ordinal_formals() {
        let source =
            "class App { static void target(int a, int b) {} static void run() { target(1, 2); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target(1, 2)");
        let report = call_binding_report(
            &file("Main.java"),
            &shape,
            CallBindingTarget::Resolved {
                unit: unit("App.target"),
                layout: layout(&["a", "b"]),
            },
        );

        assert_eq!(report.coverage, CallBindingCoverage::Exhaustive);
        assert_eq!(report.actual_count, 2);
        assert_eq!(report.bound_count, 2);
        assert_eq!(report.rows.len(), 2);
        assert_eq!(
            report
                .rows
                .iter()
                .map(|row| (row.formal_index, row.formal_name.as_deref(), row.mapping))
                .collect::<Vec<_>>(),
            [
                (Some(0), Some("a"), CallBindingMapping::Exact),
                (Some(1), Some("b"), CallBindingMapping::Exact),
            ]
        );
        assert!(report.rows.iter().all(|row| !row.terminal));
        assert!(
            report
                .rows
                .iter()
                .all(|row| row.binding_kind == Some(CallBindingKind::Positional))
        );
        // Every row joins the call-shape rows it came from.
        for row in &report.rows {
            assert_eq!(row.site_id, shape.outcome.site_id);
            assert!(
                shape
                    .arguments
                    .iter()
                    .any(|argument| Some(&argument.id) == row.argument_id.as_ref())
            );
        }
    }

    /// An actual the callable's parameter list cannot accept is reported as an
    /// unbound row, and the site's partition stops being exhaustive.
    #[test]
    fn an_actual_beyond_the_declared_arity_is_reported_unbound() {
        let source =
            "class App { static void target(int a) {} static void run() { target(1, 2); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target(1, 2)");
        let report = call_binding_report(
            &file("Main.java"),
            &shape,
            CallBindingTarget::Resolved {
                unit: unit("App.target"),
                layout: layout(&["a"]),
            },
        );

        assert_eq!(report.coverage, CallBindingCoverage::Partial);
        assert_eq!(report.bound_count, 1);
        assert_eq!(report.rows.len(), 2);
        assert_eq!(report.rows[1].mapping, CallBindingMapping::Incomplete);
        assert_eq!(
            report.rows[1].reason,
            Some(CallBindingReason::NoMatchingFormal)
        );
        assert_eq!(report.rows[1].formal_index, None);
    }

    /// A call that passes nothing still emits one row, so "binds no argument"
    /// stays distinguishable from "was never analyzed".
    #[test]
    fn a_zero_argument_call_emits_one_exhaustive_terminal_row() {
        let source = "class App { static void target() {} static void run() { target(); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target()");
        let report = call_binding_report(
            &file("Main.java"),
            &shape,
            CallBindingTarget::Resolved {
                unit: unit("App.target"),
                layout: layout(&[]),
            },
        );

        assert_eq!(report.rows.len(), 1);
        assert!(report.rows[0].terminal);
        assert_eq!(report.rows[0].mapping, CallBindingMapping::Exact);
        assert_eq!(report.rows[0].reason, None);
        assert_eq!(report.coverage, CallBindingCoverage::Exhaustive);
    }

    /// An unresolvable callee still emits its mandatory row, and the row says
    /// why rather than vanishing.
    #[test]
    fn an_unresolved_callee_emits_a_terminal_incomplete_row() {
        let source = "class App { static void target(int a) {} static void run() { target(1); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target(1)");
        let report = call_binding_report(&file("Main.java"), &shape, CallBindingTarget::Unresolved);

        assert_eq!(report.rows.len(), 1);
        assert!(report.rows[0].terminal);
        assert_eq!(report.rows[0].mapping, CallBindingMapping::Incomplete);
        assert_eq!(
            report.rows[0].reason,
            Some(CallBindingReason::CalleeUnresolved)
        );
        assert_eq!(report.coverage, CallBindingCoverage::Unknown);
        assert_eq!(report.actual_count, 1);
        assert_eq!(report.bound_count, 0);
    }

    /// Row identities are a function of the site and the argument row, never
    /// of derivation order, and no two rows of one site collide.
    #[test]
    fn row_identities_are_stable_and_distinct() {
        let source =
            "class App { static void target(int a, int b) {} static void run() { target(1, 2); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target(1, 2)");
        let build = || {
            call_binding_report(
                &file("Main.java"),
                &shape,
                CallBindingTarget::Resolved {
                    unit: unit("App.target"),
                    layout: layout(&["a", "b"]),
                },
            )
        };
        assert_eq!(build(), build());
        let report = build();
        let ids = report
            .rows
            .iter()
            .map(|row| row.id.clone())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), report.rows.len());
    }

    /// The declared vocabularies round-trip through their labels, so a policy
    /// spelling is never a second source of truth.
    #[test]
    fn every_declared_label_round_trips() {
        for kind in ALL_CALL_BINDING_KINDS {
            assert_eq!(CallBindingKind::from_label(kind.label()), Some(*kind));
        }
        for mapping in ALL_CALL_BINDING_MAPPINGS {
            assert_eq!(
                CallBindingMapping::from_label(mapping.label()),
                Some(*mapping)
            );
        }
        for coverage in ALL_CALL_BINDING_COVERAGES {
            assert_eq!(
                CallBindingCoverage::from_label(coverage.label()),
                Some(*coverage)
            );
        }
        for reason in ALL_CALL_BINDING_REASONS {
            assert_eq!(CallBindingReason::from_label(reason.label()), Some(*reason));
        }
    }
}
