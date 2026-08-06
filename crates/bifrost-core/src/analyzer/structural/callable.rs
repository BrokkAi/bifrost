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

        assert!(CallKind::from_label("not_a_kind").is_none());
        assert!(CallableRejectionReason::from_label("not_a_reason").is_none());
    }
}
