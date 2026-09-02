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
//!
//! Issue #2499 added the three rows the first slice named but never minted.
//! None of them is an actual of the written argument list, and all three are
//! therefore outside the site's `coverage` partition, which stays a statement
//! about the actuals the call shape enumerated:
//!
//! - a `receiver` row for the receiver expression a call is written against,
//!   minted only where the resolved callee establishes a receiver position for
//!   it, so an owner-qualified static call's scope qualifier is never reported
//!   as a bound value;
//! - an `implicit` row where the language fills that position with no source
//!   syntax at all, which today is a Python constructor call binding the
//!   object it allocates to `__init__`'s declared `self`;
//! - a `defaulted` row for each ordinary formal that no actual bound and whose
//!   declaration carries a default expression, located at that expression.
//!
//! What decides those facts is the caller's, not this module's: this module
//! mints rows from [`CallReceiverBinding`] and from the layout's own
//! `default_range`, and never re-derives receiver evidence.

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
            /// Every label of this vocabulary, in declaration order: the value
            /// domain the matching row field publishes (issue #2515).
            pub const LABELS: &'static [&'static str] = &[$($label,)+];

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
    /// The conversion or coercion the language applies to this actual before it
    /// reaches the formal, when an adapter establishes one (issue #2438's
    /// "conversion/coercion fact when established").
    ///
    /// No adapter publishes one today, so this is `None` on every row Bifrost
    /// mints. The column exists so a language that gains the fact adds a value,
    /// not a column, and its published domain is deliberately open: the
    /// vocabulary is each language's own -- Java widening and boxing, Rust
    /// deref and unsizing coercions, TypeScript structural assignability -- and
    /// enumerating it across languages before any adapter records one would be
    /// a table nobody produces. A row never carries a conversion derivable from
    /// [`CallBindingRow::binding_kind`]; "packed into the variadic formal" is
    /// already what a `variadic` row says.
    pub conversion: Option<String>,
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
    /// slots are `layout` and whose receiver position this site fills as
    /// `receiver` says.
    Resolved {
        unit: CodeUnit,
        layout: FormalParameterLayout,
        receiver: CallReceiverBinding,
    },
    /// The callee is an exact structured target outside the source workspace.
    ///
    /// A model-backed target can still publish a complete formal layout, but
    /// it has no source [`CodeUnit`] to render or join. Keeping this case
    /// separate from [`Self::Resolved`] prevents callers from manufacturing a
    /// source declaration merely to reuse the shared binder.
    ResolvedExternal {
        layout: FormalParameterLayout,
        receiver: CallReceiverBinding,
    },
    /// The callee resolves, but nothing recorded its formal parameter list.
    FormalsUnrecorded { unit: CodeUnit },
    /// The callee reference named several declarations.
    Ambiguous,
    /// No callee declaration could be named for this site.
    Unresolved,
    /// The language binds a receiver into the declared parameter list, and the
    /// caller could not decide whether this call did.
    ReceiverBindingUnsupported { unit: CodeUnit },
}

/// How the resolved callee's receiver position is filled at one call site.
///
/// The caller decides this, because deciding it needs the workspace: the
/// callee's declared receiver contract, and -- in a language that writes the
/// receiver as an ordinary parameter -- what the receiver expression resolves
/// to. This module only mints the row the answer implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallReceiverBinding {
    /// The callee establishes no receiver position at this site: a free
    /// function or a static-like callable. An owner-qualified static call
    /// writes a receiver *token*, but that token is a scope rather than a
    /// value, so it binds nothing and no row claims it does.
    Absent,
    /// The receiver expression written at `range` fills the position.
    Actual {
        range: Range,
        /// The callee declares its receiver as the first ordinary parameter
        /// (Python's `self` and `cls`), so that slot is not available to the
        /// written actuals.
        declared_first_ordinary: bool,
    },
    /// The language fills the position with no source syntax: a Python
    /// constructor call binds the object it allocates to `__init__`'s `self`.
    Implicit { declared_first_ordinary: bool },
    /// A receiver expression is written at `range`, and nothing the callee
    /// publishes establishes whether it binds a receiver: the language's
    /// adapter records no receiver contract and the declaration names no
    /// receiver slot. The row exists and states that, because a silent absence
    /// would read as "this call has no receiver".
    Unestablished { range: Range },
}

impl CallReceiverBinding {
    /// Whether the callee's receiver consumes the first declared ordinary
    /// slot, which is exactly the `bind_first` the production binder passes to
    /// [`OrdinaryFormalSlots::of`].
    pub fn consumes_first_ordinary(self) -> bool {
        match self {
            Self::Absent | Self::Unestablished { .. } => false,
            Self::Actual {
                declared_first_ordinary,
                ..
            }
            | Self::Implicit {
                declared_first_ordinary,
            } => declared_first_ordinary,
        }
    }
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
    let (unit, layout, receiver) = match target {
        CallBindingTarget::Resolved {
            unit,
            layout,
            receiver,
        } => (Some(unit), layout, receiver),
        CallBindingTarget::ResolvedExternal { layout, receiver } => (None, layout, receiver),
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

    let slots = OrdinaryFormalSlots::of(&layout, receiver.consumes_first_ordinary());
    let mut rows = Vec::new();
    // The receiver row comes first, before the written actuals, because that is
    // the order the call is evaluated in and it makes the row sequence of one
    // site a deterministic function of the site alone.
    if let Some(row) = receiver_row(&site_id, outcome.range, &layout, receiver) {
        rows.push(row);
    }
    let mut bound_count = 0usize;
    let mut bound_slots = Vec::new();
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
            } else if let Some((index, slot)) = slot {
                let kind = if slot.variadic.is_some() {
                    CallBindingKind::Variadic
                } else if named {
                    CallBindingKind::Named
                } else {
                    CallBindingKind::Positional
                };
                bound_count += 1;
                bound_slots.push(index);
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
                conversion: None,
                range: argument.range,
                terminal: false,
            });
        }
    }

    // The partition is over the actuals the shape enumerated, and over nothing
    // else: a receiver, an implicit argument and a defaulted formal are all
    // facts about this call that no written actual accounts for, so counting
    // them here would make `exhaustive` mean something different depending on
    // the language's calling convention.
    let coverage = if bound_count == actual_count {
        CallBindingCoverage::Exhaustive
    } else if bound_count == 0 {
        CallBindingCoverage::Unknown
    } else {
        CallBindingCoverage::Partial
    };

    // A formal nobody passed and whose declaration carries a default is bound
    // by that default. The claim is only made over a partition that came out
    // exhaustive: when some actual failed to bind, which formal it should have
    // reached is exactly what is unknown, and calling the rest defaulted would
    // dress that up as an answer.
    if coverage == CallBindingCoverage::Exhaustive {
        for (index, slot) in slots.slots() {
            let Some(default_range) = slot.default_range else {
                continue;
            };
            if slot.variadic.is_some() || bound_slots.contains(index) {
                continue;
            }
            rows.push(CallBindingRow {
                id: row_id(&site_id, RowAnchor::Formal(*index)),
                site_id: site_id.clone(),
                group_id: None,
                argument_id: None,
                actual_index: None,
                actual_name: None,
                formal_index: Some(*index),
                formal_name: slot
                    .names
                    .first()
                    .map(|name| canonical_parameter_name(name)),
                binding_kind: Some(CallBindingKind::Defaulted),
                mapping: CallBindingMapping::Exact,
                reason: None,
                conversion: None,
                range: default_range,
                terminal: false,
            });
        }
    }

    // A call that produced no pair at all still states its partition on the
    // mandatory row: exhaustively empty, with the exact callee named. Emitting
    // no row would make "binds no argument" indistinguishable from "was never
    // analyzed".
    if rows.is_empty() {
        rows.push(terminal_row(
            &site_id,
            outcome.range,
            CallBindingMapping::Exact,
            None,
        ));
    }
    base(unit, coverage, actual_count, bound_count, rows)
}

/// The row for the receiver expression a call is written against, when the
/// caller established that the resolved callee has a receiver position for it.
///
/// A receiver binds no ordinary formal, so `formal_index` is absent even in a
/// language that writes the receiver as the first declared parameter: the
/// ordinary ordinals a bound actual reports are re-based past it, and reporting
/// the receiver as ordinal 0 would collide with the first real parameter.
fn receiver_row(
    site_id: &str,
    call_range: Range,
    layout: &FormalParameterLayout,
    receiver: CallReceiverBinding,
) -> Option<CallBindingRow> {
    let (kind, range, mapping, reason) = match receiver {
        CallReceiverBinding::Absent => return None,
        CallReceiverBinding::Actual { range, .. } => (
            CallBindingKind::Receiver,
            range,
            CallBindingMapping::Exact,
            None,
        ),
        CallReceiverBinding::Implicit { .. } => (
            CallBindingKind::Implicit,
            call_range,
            CallBindingMapping::Exact,
            None,
        ),
        CallReceiverBinding::Unestablished { range } => (
            CallBindingKind::Receiver,
            range,
            CallBindingMapping::Incomplete,
            Some(CallBindingReason::ReceiverBindingUnsupported),
        ),
    };
    // The receiver formal is the declared receiver slot where a language has
    // one (Rust's `self`, Java's and Go's receiver parameter), and otherwise
    // the first ordinary slot in a language that writes the receiver there.
    let formal = layout
        .slots
        .iter()
        .find(|slot| slot.receiver)
        .or_else(|| {
            receiver
                .consumes_first_ordinary()
                .then(|| layout.slots.iter().find(|slot| !slot.receiver))
                .flatten()
        })
        .and_then(|slot| slot.names.first())
        .map(|name| canonical_parameter_name(name));
    Some(CallBindingRow {
        id: row_id(site_id, RowAnchor::Receiver),
        site_id: site_id.to_owned(),
        group_id: None,
        argument_id: None,
        actual_index: None,
        actual_name: None,
        formal_index: None,
        formal_name: formal,
        binding_kind: Some(kind),
        mapping,
        reason,
        conversion: None,
        range,
        terminal: false,
    })
}

enum RowAnchor<'a> {
    Argument(&'a str),
    /// A formal with no source actual: the defaulted rows.
    Formal(usize),
    Receiver,
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
        RowAnchor::Formal(index) => {
            digest.push(b"formal");
            digest.push(&index.to_le_bytes());
        }
        RowAnchor::Receiver => digest.push(b"receiver"),
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
        conversion: None,
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

    /// Every ordinary slot with the ordinal an actual binding it reports.
    pub(crate) fn slots(&self) -> &[(usize, &'a FormalParameterSlot)] {
        &self.slots
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
                    slot.passing_mode.accepts_named()
                        && slot
                            .names
                            .iter()
                            .any(|candidate| names_match(candidate, name))
                })
                .or_else(|| {
                    self.slots.iter().copied().rev().find(|(_, slot)| {
                        slot.passing_mode.accepts_named()
                            && slot.variadic.is_some_and(|kind| kind.accepts_keyword())
                    })
                });
        }
        position.and_then(|position| {
            self.slots
                .iter()
                .copied()
                .filter(|(_, slot)| slot.passing_mode.accepts_positional())
                .nth(position)
                .or_else(|| {
                    self.slots.iter().copied().rev().find(|(_, slot)| {
                        slot.passing_mode.accepts_positional()
                            && slot.variadic.is_some_and(|kind| kind.accepts_positional())
                    })
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
    use crate::analyzer::lexical_definitions::{FormalParameterPassingMode, FormalVariadicKind};
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

    fn zero_range() -> Range {
        Range {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            end_line: 0,
        }
    }

    fn slot(name: &str) -> FormalParameterSlot {
        FormalParameterSlot {
            names: vec![name.to_owned()],
            declaration_range: zero_range(),
            receiver: false,
            variadic: None,
            passing_mode: Default::default(),
            default_range: None,
        }
    }

    fn layout(names: &[&str]) -> FormalParameterLayout {
        FormalParameterLayout {
            slots: names.iter().map(|name| slot(name)).collect(),
            python_binding: None,
        }
    }

    #[test]
    fn formal_slots_enforce_positional_only_and_named_only_modes() {
        let mut modes = layout(&["args", "shell"]);
        modes.slots[0].passing_mode = FormalParameterPassingMode::PositionalOnly;
        modes.slots[1].passing_mode = FormalParameterPassingMode::NamedOnly;
        let slots = OrdinaryFormalSlots::of(&modes, false);

        assert_eq!(
            slots.slot_for(None, Some(0), false).map(|slot| slot.0),
            Some(0)
        );
        assert_eq!(slots.slot_for(None, Some(1), false), None);
        assert_eq!(slots.slot_for(Some("args"), None, false), None);
        assert_eq!(
            slots
                .slot_for(Some("shell"), None, false)
                .map(|slot| slot.0),
            Some(1)
        );
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
                receiver: CallReceiverBinding::Absent,
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
                receiver: CallReceiverBinding::Absent,
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
                receiver: CallReceiverBinding::Absent,
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

    /// A receiver row is a fact about the call that no written actual accounts
    /// for, so it is outside the partition: the site's `coverage`,
    /// `actual_count` and `bound_count` are the same with it as without it.
    #[test]
    fn a_receiver_row_stays_outside_the_actual_partition() {
        let source = "class App { static void target(int a) {} static void run() { target(1); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target(1)");
        let with_receiver = call_binding_report(
            &file("Main.java"),
            &shape,
            CallBindingTarget::Resolved {
                unit: unit("App.target"),
                layout: layout(&["a"]),
                receiver: CallReceiverBinding::Actual {
                    range: shape.outcome.range,
                    declared_first_ordinary: false,
                },
            },
        );

        assert_eq!(with_receiver.rows.len(), 2);
        assert_eq!(
            with_receiver.rows[0].binding_kind,
            Some(CallBindingKind::Receiver)
        );
        assert_eq!(with_receiver.rows[0].formal_index, None);
        assert!(with_receiver.rows[0].argument_id.is_none());
        assert_eq!(with_receiver.coverage, CallBindingCoverage::Exhaustive);
        assert_eq!(with_receiver.actual_count, 1);
        assert_eq!(with_receiver.bound_count, 1);
    }

    /// A language that writes its receiver as the first declared formal has
    /// that slot dropped from the ordinary list, so the written actual binds
    /// ordinal 0 and the receiver row names the declared slot by name only.
    #[test]
    fn a_receiver_that_consumes_the_first_formal_re_bases_the_ordinals() {
        let source =
            "class App { static void target(int a, int b) {} static void run() { target(1); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target(1)");
        let report = call_binding_report(
            &file("Main.java"),
            &shape,
            CallBindingTarget::Resolved {
                unit: unit("App.target"),
                layout: layout(&["self", "b"]),
                receiver: CallReceiverBinding::Actual {
                    range: shape.outcome.range,
                    declared_first_ordinary: true,
                },
            },
        );

        assert_eq!(
            report
                .rows
                .iter()
                .map(|row| (row.binding_kind, row.formal_index, row.formal_name.clone()))
                .collect::<Vec<_>>(),
            [
                (
                    Some(CallBindingKind::Receiver),
                    None,
                    Some("self".to_owned())
                ),
                (
                    Some(CallBindingKind::Positional),
                    Some(0),
                    Some("b".to_owned())
                ),
            ]
        );
    }

    /// A formal no actual bound and whose declaration carries a default is
    /// reported bound by that default, located at the default expression.
    #[test]
    fn an_unpassed_formal_with_a_default_is_reported_defaulted() {
        let source =
            "class App { static void target(int a, int b) {} static void run() { target(1); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target(1)");
        let default_range = Range {
            start_byte: 7,
            end_byte: 9,
            start_line: 1,
            end_line: 1,
        };
        let mut slots = layout(&["a", "b"]);
        slots.slots[1].default_range = Some(default_range);
        let report = call_binding_report(
            &file("Main.java"),
            &shape,
            CallBindingTarget::Resolved {
                unit: unit("App.target"),
                layout: slots,
                receiver: CallReceiverBinding::Absent,
            },
        );

        assert_eq!(report.rows.len(), 2);
        assert_eq!(
            report.rows[1].binding_kind,
            Some(CallBindingKind::Defaulted)
        );
        assert_eq!(report.rows[1].formal_index, Some(1));
        assert_eq!(report.rows[1].mapping, CallBindingMapping::Exact);
        assert_eq!(report.rows[1].range, default_range);
        assert!(report.rows[1].argument_id.is_none());
        // The defaulted formal is not an actual, so it changes no count.
        assert_eq!(report.actual_count, 1);
        assert_eq!(report.bound_count, 1);
        assert_eq!(report.coverage, CallBindingCoverage::Exhaustive);
    }

    /// A complete external/model layout uses the same matcher as a source
    /// declaration but deliberately has no source target to render. Optional
    /// and variadic formals remain ordinary binding facts, not model-specific
    /// approximations.
    #[test]
    fn an_external_layout_binds_defaults_and_variadics_without_a_source_target() {
        let source = "class App { static void run() { target(1); target(1, 2, 3); } }";
        let facts = java_facts(source);
        let first_shape = shape_for(source, &facts, "target(1)");
        let mut default_layout = layout(&["a", "b", "rest"]);
        default_layout.slots[1].default_range = Some(first_shape.outcome.range);
        default_layout.slots[2].variadic = Some(FormalVariadicKind::Positional);
        let defaulted = call_binding_report(
            &file("Main.java"),
            &first_shape,
            CallBindingTarget::ResolvedExternal {
                layout: default_layout,
                receiver: CallReceiverBinding::Absent,
            },
        );

        assert!(defaulted.target.is_none());
        assert_eq!(defaulted.coverage, CallBindingCoverage::Exhaustive);
        assert_eq!(defaulted.rows[0].mapping, CallBindingMapping::Exact);
        assert_eq!(
            defaulted.rows[1].binding_kind,
            Some(CallBindingKind::Defaulted)
        );
        assert_eq!(defaulted.rows[1].formal_name.as_deref(), Some("b"));

        let variadic_shape = shape_for(source, &facts, "target(1, 2, 3)");
        let mut variadic_layout = layout(&["a", "rest"]);
        variadic_layout.slots[1].variadic = Some(FormalVariadicKind::Positional);
        let variadic = call_binding_report(
            &file("Main.java"),
            &variadic_shape,
            CallBindingTarget::ResolvedExternal {
                layout: variadic_layout,
                receiver: CallReceiverBinding::Absent,
            },
        );

        assert!(variadic.target.is_none());
        assert_eq!(variadic.coverage, CallBindingCoverage::Exhaustive);
        assert!(variadic.rows.iter().any(|row| {
            row.binding_kind == Some(CallBindingKind::Variadic)
                && row.mapping == CallBindingMapping::Exact
        }));
    }

    /// Row identities are a function of the site and the argument row, never
    /// of derivation order, and no two rows of one site collide.
    #[test]
    fn row_identities_are_stable_and_distinct() {
        let source =
            "class App { static void target(int a, int b) {} static void run() { target(1, 2); } }";
        let facts = java_facts(source);
        let shape = shape_for(source, &facts, "target(1, 2)");
        let mut defaults = layout(&["a", "b", "c"]);
        defaults.slots[2].default_range = Some(Range {
            start_byte: 7,
            end_byte: 9,
            start_line: 1,
            end_line: 1,
        });
        let with_every_row_kind = call_binding_report(
            &file("Main.java"),
            &shape,
            CallBindingTarget::Resolved {
                unit: unit("App.target"),
                layout: defaults,
                receiver: CallReceiverBinding::Actual {
                    range: shape.outcome.range,
                    declared_first_ordinary: false,
                },
            },
        );
        let mixed = with_every_row_kind
            .rows
            .iter()
            .map(|row| row.id.clone())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(with_every_row_kind.rows.len(), 4);
        assert_eq!(mixed.len(), 4, "receiver, actual and defaulted ids differ");

        let build = || {
            call_binding_report(
                &file("Main.java"),
                &shape,
                CallBindingTarget::Resolved {
                    unit: unit("App.target"),
                    layout: layout(&["a", "b"]),
                    receiver: CallReceiverBinding::Absent,
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
