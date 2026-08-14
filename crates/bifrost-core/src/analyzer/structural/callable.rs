//! The callable-applicability vocabulary: what shape a call site has, and why
//! a candidate callable was applicable or not (issue #1478).
//!
//! Today a resolver checks arity, argument-list shape, named arguments, and
//! generic arity, then discards every losing overload. These enums are the
//! typed values that discard becomes: a [`CallKind`] and per-list
//! [`ArgumentListKind`]s for the ordered call shape, a [`CallShapeCoverage`]
//! stating how much of that shape the analyzer could actually see, an
//! [`ApplicabilityVerdict`] with a typed [`CallableRejectionReason`] per
//! candidate, and a [`SelectionResolution`] for the whole site.
//!
//! Two rules from the issue's contract are load-bearing here. First, candidate
//! order is never a semantic tie breaker: several equally applicable winners
//! stay [`SelectionResolution::Ambiguous`], and zero applicable winners stay
//! [`SelectionResolution::Unresolved`]. Second, a macro- or
//! configuration-derived argument list the analyzer cannot read is preserved
//! as incomplete evidence ([`CallShapeCoverage::UnknownMacroDerived`] or
//! [`CallShapeCoverage::UnknownDynamic`]), so an exact-cardinality assertion
//! over it can never be silently clean.

use super::occurrences::labelled_enum;
use crate::hash::HashSet;
use serde::{Deserialize, Serialize};
use std::fmt;

labelled_enum! {
    /// The role a call-shaped occurrence plays at its site.
    ///
    /// - `Function`: a bare callable application (`f(x)`).
    /// - `Method`: a receiver-qualified application (`r.f(x)`).
    /// - `Constructor`: an instance-creating application (`new T(x)`, `T(x)`
    ///   where the language routes it to a constructor, implicit struct
    ///   construction).
    /// - `Extractor`: a pattern-position application (`case T(x)`, an unapply).
    /// - `Infix`: an infix application whose operator token names the callable
    ///   (`a op b` in Scala or Kotlin).
    /// - `Operator`: a symbolic operator application resolved to a declared
    ///   operator callable (`a + b` routed to `operator+`/`plus`).
    /// - `MethodValue`: a reference to a callable without applying it (a
    ///   method value, eta-expansion, or method reference such as `T::f`).
    CallKind, ALL_CALL_KINDS {
        Function => "function",
        Method => "method",
        Constructor => "constructor",
        Extractor => "extractor",
        Infix => "infix",
        Operator => "operator",
        MethodValue => "method_value",
    }
}

labelled_enum! {
    /// What kind of argument-list group one parenthesized (or implicit) list
    /// is. A call site owns an ordered sequence of groups: a Java call has one
    /// `Ordinary` group, a curried Scala call has several, a Scala contextual
    /// call ends with a `Contextual` group, and a Ruby or Kotlin trailing
    /// block is a `Block` group.
    ///
    /// - `Ordinary`: positional value arguments.
    /// - `TypeArguments`: explicit generic/type arguments (`f<Int>(x)`).
    /// - `Named`: a group whose arguments are matched by parameter name, not
    ///   position (`f(width: 3)`).
    /// - `Contextual`: an implicit/contextual group the compiler may fill
    ///   (`(using ctx)`).
    /// - `Block`: a trailing block/lambda group supplied outside the
    ///   parentheses.
    /// - `ReceiverBound`: the bound-receiver group of a method value or
    ///   extension application, occupying an argument position.
    /// - `VariadicPack`: a group that expands a pack into the parameter list
    ///   (`f(*args)`, `f(xs: _*)`).
    ArgumentListKind, ALL_ARGUMENT_LIST_KINDS {
        Ordinary => "ordinary",
        TypeArguments => "type_arguments",
        Named => "named",
        Contextual => "contextual",
        Block => "block",
        ReceiverBound => "receiver_bound",
        VariadicPack => "variadic_pack",
    }
}

labelled_enum! {
    /// How much of the call shape the analyzer could actually see.
    ///
    /// - `Exact`: every group and argument is read from source structure.
    /// - `Partial`: some groups or arguments are known, but the shape is not
    ///   complete (for example, one argument's structure is unreadable).
    /// - `UnknownMacroDerived`: the argument list is produced by a macro or
    ///   generated expansion the analyzer does not expand.
    /// - `UnknownDynamic`: the argument list is assembled dynamically
    ///   (splatted from a runtime value, configuration-derived) and has no
    ///   static shape.
    CallShapeCoverage, ALL_CALL_SHAPE_COVERAGES {
        Exact => "exact",
        Partial => "partial",
        UnknownMacroDerived => "unknown_macro_derived",
        UnknownDynamic => "unknown_dynamic",
    }
}

labelled_enum! {
    /// Whether one candidate callable accepts the complete ordered call shape.
    ///
    /// `Unknown` is never equal to `Applicable`: a resolver that cannot decide
    /// (unknown shape, unsupported language capability) says so, and an exact
    /// assertion over it becomes unreliable rather than clean.
    ApplicabilityVerdict, ALL_APPLICABILITY_VERDICTS {
        Applicable => "applicable",
        Inapplicable => "inapplicable",
        Unknown => "unknown",
    }
}

labelled_enum! {
    /// Why a candidate callable was inapplicable to the call shape. Each
    /// variant names a check a resolver already performs today and throws
    /// away.
    ///
    /// These are the callable-axis counterparts of
    /// [`super::resolution::RejectionReason`], which names the scope,
    /// namespace, and visibility checks shared by all reference resolution.
    /// The two axes stay separate enums so each stays exhaustive for its
    /// domain.
    CallableRejectionReason, ALL_CALLABLE_REJECTION_REASONS {
        ArityBelowRequired => "arity_below_required",
        ArityAboveTotal => "arity_above_total",
        ListShapeMismatch => "list_shape_mismatch",
        UnknownNamedArgument => "unknown_named_argument",
        MissingRequiredArgument => "missing_required_argument",
        TypeArgumentArityMismatch => "type_argument_arity_mismatch",
        ReceiverContractMismatch => "receiver_contract_mismatch",
        CallKindMismatch => "call_kind_mismatch",
        ShapeUnknown => "shape_unknown",
    }
}

labelled_enum! {
    /// The outcome of overload selection for one call site, computed from the
    /// applicability verdicts alone. Candidate order must never influence it.
    ///
    /// - `ResolvedUnique`: exactly one applicable candidate in the winning
    ///   precedence tier.
    /// - `Ambiguous`: more than one equally applicable winner; all are
    ///   retained.
    /// - `Unresolved`: zero applicable candidates; all rejections are
    ///   retained.
    /// - `UnknownShape`: the call shape is not `Exact`, so no candidate has a
    ///   decidable verdict and the selection is incomplete evidence.
    SelectionResolution, ALL_SELECTION_RESOLUTIONS {
        ResolvedUnique => "resolved_unique",
        Ambiguous => "ambiguous",
        Unresolved => "unresolved",
        UnknownShape => "unknown_shape",
    }
}

labelled_enum! {
    /// The receiver contract a callable declares: what, if anything, must be
    /// bound in receiver position for the callable to apply.
    ///
    /// - `None`: a free function or static-like callable with no receiver.
    /// - `Instance`: an ordinary instance method requiring a receiver of the
    ///   owning type.
    /// - `StaticOrCompanion`: owner-qualified but not instance-bound (a
    ///   static method, companion-object member, or class method).
    /// - `Extension`: an extension callable whose receiver is its first bound
    ///   argument.
    ReceiverContract, ALL_RECEIVER_CONTRACTS {
        None => "none",
        Instance => "instance",
        StaticOrCompanion => "static_or_companion",
        Extension => "extension",
    }
}

labelled_enum! {
    /// How much of one callable's declared shape the persisted signature
    /// contract actually holds (issue #1478, Milestone 2).
    ///
    /// The declaration side of overload selection is read from the
    /// `SignatureMetadata`/`CallableArity` facts the analyzer already
    /// persists. Not every language records every fact, and a missing fact
    /// must never read as a proven zero.
    ///
    /// - `Exact`: the language published an arity, so the required and total
    ///   counts and the repeated flag are the adapter's own answer.
    /// - `ArityUnrecorded`: signature metadata exists but records no arity.
    ///   Parameter evidence may still exist; an exact-arity assertion over
    ///   such a signature must not come out clean.
    /// - `Unrecorded`: the analyzer publishes no signature metadata at all for
    ///   the declaration. This is the mandatory row that keeps an empty
    ///   relation from reading as a proven-empty signature.
    SignatureCoverage, ALL_SIGNATURE_COVERAGES {
        Exact => "exact",
        ArityUnrecorded => "arity_unrecorded",
        Unrecorded => "unrecorded",
    }
}

labelled_enum! {
    /// What a declaration is, as the declaration-side counterpart of a call
    /// site's [`CallKind`]. A policy joins the two to ask whether a
    /// constructor call reached a constructor, or whether a method value
    /// referenced a method.
    ///
    /// The categories are the analyzer's own coarse unit classification plus
    /// the persisted constructor flag and structural ownership: a callable
    /// with a structural owner is a `Method`, one without is a `Function`.
    DeclarationRole, ALL_DECLARATION_ROLES {
        Function => "function",
        Method => "method",
        Constructor => "constructor",
        Field => "field",
        Class => "class",
        Module => "module",
        Macro => "macro",
        FileScope => "file_scope",
    }
}

/// What one language's structural lowering says about a call site beyond the
/// receiver and argument roles the shared fact arena already records.
///
/// The shared arena models one positional group, one named group, a receiver
/// and a callee. That is enough to say `Function` versus `Method` and nothing
/// else, so every refinement here comes from the grammar node itself: a Java
/// `object_creation_expression` is a constructor call, a Scala
/// `infix_expression` is an infix application, and a Scala `call_expression`
/// whose own function is another `call_expression` continues that call's
/// argument-list sequence rather than starting a new call site.
///
/// Every field is a refinement of an honest baseline, never a replacement for
/// missing structure. A language that says nothing keeps the baseline: kind
/// from receiver presence, [`CallShapeCoverage::Exact`] coverage, and one
/// call site per call node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSiteFacts {
    /// The refined call kind. `None` keeps the receiver-derived baseline.
    pub call_kind: Option<CallKind>,
    /// How much of this site's argument structure the lowering could read.
    pub coverage: CallShapeCoverage,
    /// Whether this call's argument list continues the argument-list sequence
    /// of the call in its own callee position, as a Scala curried application
    /// `f(a)(b)` does. False everywhere the outer application applies the
    /// *result* of the inner one, which is what `f(a)(b)` means in JavaScript.
    pub continues_callee_groups: bool,
}

impl CallSiteFacts {
    /// The baseline: kind from receiver presence, readable arguments, one
    /// site per call node. Chain [`CallSiteFacts::continuing`] off this to
    /// refine only the argument-list sequence.
    pub const fn unrefined() -> Self {
        Self {
            call_kind: None,
            coverage: CallShapeCoverage::Exact,
            continues_callee_groups: false,
        }
    }

    /// A site whose kind the grammar names exactly, with readable arguments.
    pub const fn of_kind(call_kind: CallKind) -> Self {
        Self {
            call_kind: Some(call_kind),
            coverage: CallShapeCoverage::Exact,
            continues_callee_groups: false,
        }
    }

    /// A site whose kind stays at the receiver-derived baseline but whose
    /// argument structure the lowering could only partly (or not at all) read.
    pub const fn of_coverage(coverage: CallShapeCoverage) -> Self {
        Self {
            call_kind: None,
            coverage,
            continues_callee_groups: false,
        }
    }

    /// Mark this application as one more argument list of the call in its
    /// callee position.
    pub const fn continuing(mut self) -> Self {
        self.continues_callee_groups = true;
        self
    }
}

/// Per-file knowledge a language spec gathers once, before any call site is
/// classified, because the answer for one call lives elsewhere in the file.
///
/// It carries two axes. C and C++ record the callee names whose argument list
/// is produced by a macro this analyzer does not expand — `FOO(a, b)` where
/// `FOO` is a function-like macro has a source argument count that is not the
/// called callable's arity, and the answer is the set of function-like macro
/// definitions in the translation unit. Ruby records the start bytes of the
/// bare identifier nodes that are zero-argument call sites — whether `x` reads
/// a local variable or calls a method depends on the assignments and
/// parameters lexically before it in the enclosing callable. Both are one
/// scan of the tree rather than one scan per node.
#[derive(Debug, Default, Clone)]
pub struct CallSiteContext {
    macro_derived_callees: HashSet<String>,
    identifier_call_starts: HashSet<usize>,
}

impl CallSiteContext {
    pub fn with_macro_derived_callees(names: HashSet<String>) -> Self {
        Self {
            macro_derived_callees: names,
            ..Self::default()
        }
    }

    pub fn with_identifier_call_starts(starts: HashSet<usize>) -> Self {
        Self {
            identifier_call_starts: starts,
            ..Self::default()
        }
    }

    /// Whether a call to `callee` expands a macro, so its source argument list
    /// is not the callable's argument list.
    pub fn is_macro_derived_callee(&self, callee: &str) -> bool {
        self.macro_derived_callees.contains(callee)
    }

    /// Whether the identifier node starting at `start_byte` is a call site.
    pub fn is_identifier_call_at(&self, start_byte: usize) -> bool {
        self.identifier_call_starts.contains(&start_byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every vocabulary must have unique labels that round-trip through both
    /// `label()`/`from_label` and serde, so the persisted contract and the
    /// rendered surface never disagree about a name.
    #[test]
    fn callable_vocabularies_are_unique_and_round_trip() {
        macro_rules! check {
            ($all:expr, $type:ty) => {{
                let mut labels = HashSet::new();
                for &value in $all {
                    assert!(labels.insert(value.label()), "duplicate label {value:?}");
                    assert_eq!(<$type>::from_label(value.label()), Some(value));
                    let json = serde_json::to_value(value).expect("serialize");
                    assert_eq!(
                        json,
                        serde_json::Value::String(value.label().to_owned()),
                        "serde label diverges from label() for {value:?}"
                    );
                    let back: $type = serde_json::from_value(json).expect("deserialize");
                    assert_eq!(back, value);
                }
                assert_eq!(labels.len(), $all.len());
            }};
        }

        check!(ALL_CALL_KINDS, CallKind);
        check!(ALL_ARGUMENT_LIST_KINDS, ArgumentListKind);
        check!(ALL_CALL_SHAPE_COVERAGES, CallShapeCoverage);
        check!(ALL_APPLICABILITY_VERDICTS, ApplicabilityVerdict);
        check!(ALL_CALLABLE_REJECTION_REASONS, CallableRejectionReason);
        check!(ALL_SELECTION_RESOLUTIONS, SelectionResolution);
        check!(ALL_RECEIVER_CONTRACTS, ReceiverContract);
        check!(ALL_SIGNATURE_COVERAGES, SignatureCoverage);
        check!(ALL_DECLARATION_ROLES, DeclarationRole);

        assert!(CallKind::from_label("not_a_kind").is_none());
        assert!(CallableRejectionReason::from_label("not_a_reason").is_none());
    }
}
