//! Procedure-local finite scalar refinement over normalized semantic IR.
//!
//! The derivation deliberately consumes only semantic values, effects, guard
//! facts, and CFG edges. It never reparses source text. The iterative worklist
//! makes loops stack safe, and explicit widening at a documented per-point
//! join limit makes the integer lattice finite, so every procedure converges.

#[cfg(test)]
use crate::analyzer::semantic::MoveInvalidation;
use crate::analyzer::semantic::{
    CallSiteId, CaptureMode, CaptureSource, ControlEdgeId, GuardFact, GuardPredicate,
    IntegerComparison, MemoryLocationKind, ProcedureHandle, ProcedureId, ProcedureSemantics,
    ProgramPointId, SemanticCapability, SemanticEffect, SemanticGapDischarge, SemanticGapImpact,
    SemanticGapSubject, SemanticValueKind, TransferKind, TransferOperation, ValueFlowKind, ValueId,
    ValuePreservation, ValueTransfer,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_analysis::analyzer::java_integral_parameter::{
    JavaIntegralDomain, JavaScalarType, java_scalar_binding_types,
};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use std::cmp::Ordering;
use std::collections::VecDeque;

/// A signed integer that can represent `-u128::MAX` through `u128::MAX`
/// without host-language casts or overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarIntegerValue {
    negative: bool,
    magnitude: u128,
}

impl ScalarIntegerValue {
    pub const fn new(negative: bool, magnitude: u128) -> Self {
        Self {
            negative: negative && magnitude != 0,
            magnitude,
        }
    }

    pub const fn unsigned(value: u128) -> Self {
        Self::new(false, value)
    }

    pub const fn negative(self) -> bool {
        self.negative
    }

    pub const fn magnitude(self) -> u128 {
        self.magnitude
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        if self.negative == other.negative {
            return self
                .magnitude
                .checked_add(other.magnitude)
                .map(|magnitude| Self::new(self.negative, magnitude));
        }
        Some(match self.magnitude.cmp(&other.magnitude) {
            Ordering::Greater => Self::new(self.negative, self.magnitude - other.magnitude),
            Ordering::Less => Self::new(other.negative, other.magnitude - self.magnitude),
            Ordering::Equal => Self::unsigned(0),
        })
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.checked_add(Self::new(!other.negative, other.magnitude))
    }
}

impl PartialOrd for ScalarIntegerValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScalarIntegerValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self.magnitude.cmp(&other.magnitude),
            (true, true) => other.magnitude.cmp(&self.magnitude),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScalarIntegerDomain {
    Mathematical,
    Signed { bits: u16 },
    Unsigned { bits: u16 },
}

impl ScalarIntegerDomain {
    pub fn signed(bits: u16) -> Self {
        assert!((1..=128).contains(&bits), "signed integer width is 1..=128");
        Self::Signed { bits }
    }

    pub fn unsigned(bits: u16) -> Self {
        assert!(
            (1..=128).contains(&bits),
            "unsigned integer width is 1..=128"
        );
        Self::Unsigned { bits }
    }

    pub fn contains(self, value: ScalarIntegerValue) -> bool {
        match self {
            Self::Mathematical => true,
            Self::Unsigned { bits } => {
                assert_integer_width(bits);
                !value.negative && value.magnitude <= unsigned_max(bits)
            }
            Self::Signed { bits } if value.negative => {
                assert_integer_width(bits);
                value.magnitude <= signed_min_magnitude(bits)
            }
            Self::Signed { bits } => {
                assert_integer_width(bits);
                value.magnitude <= signed_max(bits)
            }
        }
    }

    pub fn finite_bounds(self) -> Option<(ScalarIntegerValue, ScalarIntegerValue)> {
        match self {
            Self::Mathematical => None,
            Self::Signed { bits } => {
                assert_integer_width(bits);
                Some((
                    ScalarIntegerValue::new(true, signed_min_magnitude(bits)),
                    ScalarIntegerValue::unsigned(signed_max(bits)),
                ))
            }
            Self::Unsigned { bits } => {
                assert_integer_width(bits);
                Some((
                    ScalarIntegerValue::unsigned(0),
                    ScalarIntegerValue::unsigned(unsigned_max(bits)),
                ))
            }
        }
    }
}

fn assert_integer_width(bits: u16) {
    assert!((1..=128).contains(&bits), "integer width is 1..=128");
}

const fn unsigned_max(bits: u16) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << bits) - 1
    }
}

const fn signed_min_magnitude(bits: u16) -> u128 {
    1_u128 << (bits - 1)
}

const fn signed_max(bits: u16) -> u128 {
    signed_min_magnitude(bits) - 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalarIntegerInterval {
    lower: ScalarIntegerValue,
    upper: ScalarIntegerValue,
    domain: ScalarIntegerDomain,
}

impl ScalarIntegerInterval {
    pub fn new(
        lower: ScalarIntegerValue,
        upper: ScalarIntegerValue,
        domain: ScalarIntegerDomain,
    ) -> Self {
        assert!(lower <= upper, "integer interval bounds are ordered");
        assert!(
            domain.contains(lower) && domain.contains(upper),
            "integer interval bounds belong to their domain"
        );
        Self {
            lower,
            upper,
            domain,
        }
    }

    pub fn exact(value: ScalarIntegerValue, domain: ScalarIntegerDomain) -> Self {
        Self::new(value, value, domain)
    }

    pub const fn lower(self) -> ScalarIntegerValue {
        self.lower
    }

    pub const fn upper(self) -> ScalarIntegerValue {
        self.upper
    }

    pub const fn domain(self) -> ScalarIntegerDomain {
        self.domain
    }

    pub fn exact_value(self) -> Option<ScalarIntegerValue> {
        if self.lower == self.upper {
            Some(self.lower)
        } else {
            None
        }
    }

    /// The same values in `domain`, when every one of them belongs to it.
    pub fn in_domain(self, domain: ScalarIntegerDomain) -> Option<Self> {
        (domain.contains(self.lower) && domain.contains(self.upper))
            .then(|| Self::new(self.lower, self.upper, domain))
    }

    pub fn hull(self, other: Self) -> Option<Self> {
        (self.domain == other.domain).then(|| {
            Self::new(
                self.lower.min(other.lower),
                self.upper.max(other.upper),
                self.domain,
            )
        })
    }

    pub fn add_interval(self, other: Self) -> ScalarIntegerArithmetic {
        self.binary_operation(other, ScalarIntegerValue::checked_add)
    }

    pub fn subtract_interval(self, other: Self) -> ScalarIntegerArithmetic {
        if self.domain != other.domain {
            return ScalarIntegerArithmetic::UnknownDomain;
        }
        let Some(lower) = self.lower.checked_sub(other.upper) else {
            return ScalarIntegerArithmetic::MagnitudeExceeded;
        };
        let Some(upper) = self.upper.checked_sub(other.lower) else {
            return ScalarIntegerArithmetic::MagnitudeExceeded;
        };
        if !self.domain.contains(lower) || !self.domain.contains(upper) {
            return ScalarIntegerArithmetic::Overflow;
        }
        ScalarIntegerArithmetic::Interval(Self::new(lower, upper, self.domain))
    }

    pub fn widen(self, next: Self) -> ScalarIntegerWidening {
        if self.domain != next.domain {
            return ScalarIntegerWidening::UnknownDomain;
        }
        let expands_lower = next.lower < self.lower;
        let expands_upper = next.upper > self.upper;
        if !expands_lower && !expands_upper {
            return ScalarIntegerWidening::Interval(self);
        }
        let Some((domain_lower, domain_upper)) = self.domain.finite_bounds() else {
            return ScalarIntegerWidening::Unbounded;
        };
        ScalarIntegerWidening::Interval(Self::new(
            if expands_lower {
                domain_lower
            } else {
                self.lower
            },
            if expands_upper {
                domain_upper
            } else {
                self.upper
            },
            self.domain,
        ))
    }

    fn binary_operation(
        self,
        other: Self,
        operation: fn(ScalarIntegerValue, ScalarIntegerValue) -> Option<ScalarIntegerValue>,
    ) -> ScalarIntegerArithmetic {
        if self.domain != other.domain {
            return ScalarIntegerArithmetic::UnknownDomain;
        }
        let Some(lower) = operation(self.lower, other.lower) else {
            return ScalarIntegerArithmetic::MagnitudeExceeded;
        };
        let Some(upper) = operation(self.upper, other.upper) else {
            return ScalarIntegerArithmetic::MagnitudeExceeded;
        };
        if !self.domain.contains(lower) || !self.domain.contains(upper) {
            return ScalarIntegerArithmetic::Overflow;
        }
        ScalarIntegerArithmetic::Interval(Self::new(lower, upper, self.domain))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarIntegerArithmetic {
    Interval(ScalarIntegerInterval),
    Overflow,
    MagnitudeExceeded,
    UnknownDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarIntegerWidening {
    Interval(ScalarIntegerInterval),
    Unbounded,
    UnknownDomain,
}

/// One bound of a floating range. The value is never NaN; infinities are
/// ordinary bounds. Negative zero is stored as positive zero, because IEEE
/// comparison does not distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarFloatBound {
    bits: u64,
    inclusive: bool,
}

impl ScalarFloatBound {
    pub fn new(value: f64, inclusive: bool) -> Self {
        assert!(!value.is_nan(), "a floating bound is never NaN");
        let value = if value == 0.0 { 0.0 } else { value };
        Self {
            bits: value.to_bits(),
            inclusive,
        }
    }

    pub fn value(self) -> f64 {
        f64::from_bits(self.bits)
    }

    pub const fn inclusive(self) -> bool {
        self.inclusive
    }

    /// The stricter of two lower bounds: the larger value, and at one value
    /// the exclusive bound.
    fn tighter_lower(self, other: Self) -> Self {
        match self.value().total_cmp(&other.value()) {
            Ordering::Greater => self,
            Ordering::Less => other,
            Ordering::Equal if self.inclusive => other,
            Ordering::Equal => self,
        }
    }

    fn tighter_upper(self, other: Self) -> Self {
        match self.value().total_cmp(&other.value()) {
            Ordering::Less => self,
            Ordering::Greater => other,
            Ordering::Equal if self.inclusive => other,
            Ordering::Equal => self,
        }
    }

    fn looser_lower(self, other: Self) -> Self {
        if self.tighter_lower(other) == self {
            other
        } else {
            self
        }
    }

    fn looser_upper(self, other: Self) -> Self {
        if self.tighter_upper(other) == self {
            other
        } else {
            self
        }
    }
}

/// The values one floating scalar can hold: a possibly empty ordered range of
/// non-NaN values, and whether NaN is also possible. At least one part is
/// nonempty. An exclusive bound is exact: the range holds every real number
/// strictly beyond it, so no rounding to a neighboring float is involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarFloatRange {
    ordered: Option<(ScalarFloatBound, ScalarFloatBound)>,
    nan: bool,
}

impl ScalarFloatRange {
    /// `None` when both parts are empty.
    pub fn new(ordered: Option<(ScalarFloatBound, ScalarFloatBound)>, nan: bool) -> Option<Self> {
        let ordered =
            ordered.filter(
                |(lower, upper)| match lower.value().total_cmp(&upper.value()) {
                    Ordering::Less => true,
                    Ordering::Equal => lower.inclusive && upper.inclusive,
                    Ordering::Greater => false,
                },
            );
        (ordered.is_some() || nan).then_some(Self { ordered, nan })
    }

    pub fn exact(value: f64) -> Self {
        let bound = ScalarFloatBound::new(value, true);
        Self {
            ordered: Some((bound, bound)),
            nan: false,
        }
    }

    /// Every value of an IEEE binary floating type, including NaN.
    pub fn any() -> Self {
        Self {
            ordered: Some((
                ScalarFloatBound::new(f64::NEG_INFINITY, true),
                ScalarFloatBound::new(f64::INFINITY, true),
            )),
            nan: true,
        }
    }

    pub const fn ordered(self) -> Option<(ScalarFloatBound, ScalarFloatBound)> {
        self.ordered
    }

    pub const fn may_be_nan(self) -> bool {
        self.nan
    }

    pub fn exact_value(self) -> Option<f64> {
        match self.ordered {
            Some((lower, upper)) if !self.nan && lower == upper => Some(lower.value()),
            _ => None,
        }
    }

    pub fn hull(self, other: Self) -> Self {
        let ordered = match (self.ordered, other.ordered) {
            (Some((a_lower, a_upper)), Some((b_lower, b_upper))) => {
                Some((a_lower.looser_lower(b_lower), a_upper.looser_upper(b_upper)))
            }
            (Some(range), None) | (None, Some(range)) => Some(range),
            (None, None) => None,
        };
        Self {
            ordered,
            nan: self.nan || other.nan,
        }
    }

    /// The ordered part intersected with `[lower, upper]`, when nonempty.
    fn intersect(
        self,
        lower: ScalarFloatBound,
        upper: ScalarFloatBound,
    ) -> Option<(ScalarFloatBound, ScalarFloatBound)> {
        let (current_lower, current_upper) = self.ordered?;
        let range = (
            current_lower.tighter_lower(lower),
            current_upper.tighter_upper(upper),
        );
        Self::new(Some(range), false).and_then(|range| range.ordered)
    }

    /// Refine by `self relation constant` holding (`truth`) or failing. An
    /// ordered comparison with NaN is false, so the true arm excludes NaN and
    /// the false arm keeps it beside the negated relation's ordered values.
    pub fn refine_order(
        self,
        relation: IntegerComparison,
        constant: f64,
        truth: bool,
    ) -> Option<Self> {
        let relation = if truth { relation } else { relation.negate() };
        let infinity = ScalarFloatBound::new(f64::INFINITY, true);
        let negative_infinity = ScalarFloatBound::new(f64::NEG_INFINITY, true);
        let (lower, upper) = match relation {
            IntegerComparison::LessThan => {
                (negative_infinity, ScalarFloatBound::new(constant, false))
            }
            IntegerComparison::LessThanOrEqual => {
                (negative_infinity, ScalarFloatBound::new(constant, true))
            }
            IntegerComparison::GreaterThan => (ScalarFloatBound::new(constant, false), infinity),
            IntegerComparison::GreaterThanOrEqual => {
                (ScalarFloatBound::new(constant, true), infinity)
            }
        };
        Self::new(self.intersect(lower, upper), self.nan && !truth)
    }

    /// Refine by `self == constant` holding (`equal`) or failing. NaN equals
    /// nothing. An excluded constant is removed only at an inclusive bound,
    /// because a range cannot represent an interior hole.
    pub fn refine_equality(self, constant: f64, equal: bool) -> Option<Self> {
        let bound = ScalarFloatBound::new(constant, true);
        if equal {
            return Self::new(self.intersect(bound, bound), false);
        }
        let excluded = ScalarFloatBound::new(constant, false);
        let ordered = self.ordered.map(|(lower, upper)| {
            (
                if lower == bound { excluded } else { lower },
                if upper == bound { excluded } else { upper },
            )
        });
        Self::new(ordered, self.nan)
    }

    /// Refine by the value being NaN (`nan`) or not.
    pub fn refine_nan(self, nan: bool) -> Option<Self> {
        if nan {
            Self::new(None, self.nan)
        } else {
            Self::new(self.ordered, false)
        }
    }
}

/// `2^bits` as an exact binary64 value.
fn power_of_two(bits: u32) -> f64 {
    assert!(bits < 64, "exact float thresholds are below 2^64");
    (1_u64 << bits) as f64
}

/// The exact floating range of an integer interval whose bounds lie within
/// `2^exact_bits`, where every integer converts to a float without rounding.
fn integer_as_float(interval: ScalarIntegerInterval, exact_bits: u32) -> Option<ScalarFloatRange> {
    let bound = |value: ScalarIntegerValue| {
        (value.magnitude() <= 1_u128 << exact_bits).then(|| {
            let magnitude = value.magnitude() as f64;
            ScalarFloatBound::new(
                if value.negative() {
                    -magnitude
                } else {
                    magnitude
                },
                true,
            )
        })
    };
    ScalarFloatRange::new(
        Some((bound(interval.lower())?, bound(interval.upper())?)),
        false,
    )
}

/// The binary64 value of an integer constant that is also exactly a binary32
/// value. Comparing a floating operand with such a constant is exact in every
/// language: whichever format the constant converts to, it does not round.
fn binary32_exact_integer(value: ScalarIntegerValue) -> Option<f64> {
    let magnitude = value.magnitude();
    let significant_bits = if magnitude == 0 {
        0
    } else {
        128 - magnitude.leading_zeros() - magnitude.trailing_zeros()
    };
    (significant_bits <= 24).then(|| {
        let magnitude = magnitude as f64;
        if value.negative() {
            -magnitude
        } else {
            magnitude
        }
    })
}

/// Whether comparing any integer operand with the floating `constant` has
/// the mathematical outcome. The integer converts to the constant's format.
/// A format with a `p`-bit significand converts every integer within `2^p`
/// exactly and rounds larger ones monotonically to values of magnitude at
/// least `2^p`, so their order against a constant below `2^p` is unchanged.
/// A constant that is exactly binary32 may be a binary32 literal (as in
/// Java), so it must lie below `2^24`; any other constant is binary64.
fn float_constant_compares_integers_exactly(constant: f64) -> bool {
    let magnitude = constant.abs();
    magnitude < power_of_two(24)
        || (f64::from(constant as f32) != constant && magnitude < power_of_two(53))
}

/// The integer a float constant equals, when it is an integer within 2^53.
fn float_as_integer(value: f64) -> Option<ScalarIntegerValue> {
    (value.fract() == 0.0 && value.abs() <= power_of_two(53))
        .then(|| ScalarIntegerValue::new(value < 0.0, value.abs() as u128))
}

/// How one binding stores a number. Semantic values carry binding identity
/// independently of type, so a language consumer supplies this from the same
/// source snapshot, the way it supplies entry facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarBindingType {
    /// A fixed-width integer binding. An integer write takes this domain, and
    /// a value outside it is not representable here and becomes unknown.
    MachineInteger(ScalarIntegerDomain),
    /// An IEEE binary64 binding. An integer write within 2^53 converts
    /// exactly to a floating range; a larger one may round and is unknown.
    Binary64,
    /// An IEEE binary32 binding, whose exact integers span 2^24.
    Binary32,
    /// A dynamically typed binding whose numbers are binary64, as in
    /// JavaScript. Integer facts stay exact only within 2^53; every other
    /// fact is stored unchanged.
    DynamicBinary64,
    /// A statically typed Boolean binding, which holds no number.
    Boolean,
}

/// Numeric typing for one procedure's bindings: explicit per-value types and
/// an optional type for every other local or parameter.
#[derive(Debug, Clone, Default)]
pub struct ScalarTyping {
    bindings: HashMap<ValueId, ScalarBindingType>,
    default_binding: Option<ScalarBindingType>,
}

impl ScalarTyping {
    pub fn with_bindings(bindings: impl IntoIterator<Item = (ValueId, ScalarBindingType)>) -> Self {
        Self {
            bindings: bindings.into_iter().collect(),
            default_binding: None,
        }
    }

    /// Every local and parameter is a JavaScript-style binary64 number
    /// whenever it holds a number.
    pub fn dynamic_binary64() -> Self {
        Self {
            bindings: HashMap::default(),
            default_binding: Some(ScalarBindingType::DynamicBinary64),
        }
    }

    fn binding_type(
        &self,
        semantics: &ProcedureSemantics,
        target: ValueId,
    ) -> Option<ScalarBindingType> {
        self.bindings.get(&target).copied().or_else(|| {
            self.default_binding.filter(|_| {
                semantics.value(target).is_some_and(|value| {
                    matches!(
                        value.kind,
                        SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
                    )
                })
            })
        })
    }

    /// The fact `target` holds after storing a value described by `fact`.
    fn store(
        &self,
        semantics: &ProcedureSemantics,
        target: ValueId,
        fact: ScalarFact,
    ) -> ScalarFact {
        self.binding_type(semantics, target)
            .map_or(fact, |binding_type| binding_type.store(fact))
    }
}

impl ScalarBindingType {
    /// Every value a binding of this statically typed representation can
    /// hold. A dynamically typed binding can hold anything, so it has none.
    fn static_domain(self) -> Option<ScalarFact> {
        match self {
            ScalarBindingType::MachineInteger(domain) => {
                let (lower, upper) = domain
                    .finite_bounds()
                    .expect("machine integer domains are finite");
                Some(ScalarFact::Integer(ScalarIntegerInterval::new(
                    lower, upper, domain,
                )))
            }
            ScalarBindingType::Binary64 | ScalarBindingType::Binary32 => {
                Some(ScalarFact::Float(ScalarFloatRange::any()))
            }
            ScalarBindingType::Boolean => Some(ScalarFact::EitherBoolean),
            ScalarBindingType::DynamicBinary64 => None,
        }
    }

    /// Whether `predicate` tests a value of this type as that type, so a
    /// decided guard has an operand within [`Self::static_domain`].
    fn tested_by(self, semantics: &ProcedureSemantics, predicate: GuardPredicate) -> bool {
        match self {
            ScalarBindingType::Boolean => matches!(predicate, GuardPredicate::Truthy { .. }),
            _ => numeric_predicate(semantics, predicate),
        }
    }

    /// The fact a binding of this type holds after storing a value described
    /// by `fact`.
    fn store(self, fact: ScalarFact) -> ScalarFact {
        match (self, fact) {
            (ScalarBindingType::MachineInteger(domain), ScalarFact::Integer(interval)) => interval
                .in_domain(domain)
                .map_or(ScalarFact::Unknown, ScalarFact::Integer),
            (
                ScalarBindingType::MachineInteger(_),
                ScalarFact::Float(_) | ScalarFact::NonExactInteger,
            ) => ScalarFact::Unknown,
            (ScalarBindingType::Binary64, ScalarFact::Integer(interval)) => {
                integer_as_float(interval, 53).map_or(ScalarFact::Unknown, ScalarFact::Float)
            }
            (ScalarBindingType::Binary32, ScalarFact::Integer(interval)) => {
                integer_as_float(interval, 24).map_or(ScalarFact::Unknown, ScalarFact::Float)
            }
            (
                ScalarBindingType::Binary64 | ScalarBindingType::Binary32,
                ScalarFact::NonExactInteger,
            ) => ScalarFact::Unknown,
            (ScalarBindingType::DynamicBinary64, ScalarFact::Integer(interval)) => interval
                .in_domain(ScalarIntegerDomain::signed(54))
                .map_or(ScalarFact::Unknown, ScalarFact::Integer),
            (ScalarBindingType::DynamicBinary64, ScalarFact::NonExactInteger) => {
                ScalarFact::Unknown
            }
            (
                ScalarBindingType::Boolean,
                ScalarFact::Integer(_) | ScalarFact::NonExactInteger | ScalarFact::Float(_),
            ) => ScalarFact::Unknown,
            _ => fact,
        }
    }
}

/// One finite scalar statement at a program point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarFact {
    /// The point or value has no executable incoming path.
    Unreachable,
    Nil,
    NonNil,
    /// A complete join contains both nil and non-nil paths.
    MaybeNil,
    True,
    False,
    EitherBoolean,
    Integer(ScalarIntegerInterval),
    NonExactInteger,
    /// A number whose values are exactly the members of this range, compared
    /// by IEEE order.
    Float(ScalarFloatRange),
    /// Required structured information is absent or an operation is outside
    /// the bounded scalar vocabulary.
    Unknown,
}

impl ScalarFact {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Nil => "nil",
            Self::NonNil => "non_nil",
            Self::MaybeNil => "maybe_nil",
            Self::True => "true",
            Self::False => "false",
            Self::EitherBoolean => "either_boolean",
            Self::Integer(interval) if interval.exact_value().is_some() => "exact_integer",
            Self::Integer(_) => "integer_interval",
            Self::NonExactInteger => "non_exact_integer",
            Self::Float(range) if range.exact_value().is_some() => "exact_float",
            Self::Float(_) => "float_range",
            Self::Unknown => "unknown",
        }
    }

    pub fn join(self, other: Self) -> Self {
        use ScalarFact::{
            EitherBoolean, False, Float, Integer, MaybeNil, Nil, NonExactInteger, NonNil, True,
            Unknown, Unreachable,
        };
        match (self, other) {
            (Unreachable, value) | (value, Unreachable) => value,
            (left, right) if left == right => left,
            (Nil, NonNil | MaybeNil) | (NonNil, Nil | MaybeNil) | (MaybeNil, Nil | NonNil) => {
                MaybeNil
            }
            (True, False | EitherBoolean)
            | (False, True | EitherBoolean)
            | (EitherBoolean, True | False) => EitherBoolean,
            (Integer(left), Integer(right)) => left.hull(right).map_or(NonExactInteger, Integer),
            (Integer(_), NonExactInteger) | (NonExactInteger, Integer(_)) => NonExactInteger,
            (Float(left), Float(right)) => Float(left.hull(right)),
            // An integer joins a floating value as the same real numbers
            // only while each of them is exactly a binary64 value.
            (Integer(integer), Float(float)) | (Float(float), Integer(integer)) => {
                integer_as_float(integer, 53).map_or(Unknown, |integer| Float(integer.hull(float)))
            }
            _ => Unknown,
        }
    }

    /// Join `other` into `self` and give up an integer bound that still moves.
    ///
    /// Every other part of this lattice has finite height, so widening them
    /// is the ordinary join. A floating range has finite height too: without
    /// floating arithmetic its bounds come only from procedure constants,
    /// infinities, and bounds of integer facts, which widen themselves. Only
    /// an integer interval can grow one value per loop iteration, so a bound
    /// that the join expanded jumps to its machine
    /// domain's bound, and a value whose domain has no finite bound becomes a
    /// non-exact integer. Both outcomes are reached only through this
    /// operation, which is what makes the derivation finite.
    pub fn widen(self, other: Self) -> Self {
        let joined = self.join(other);
        let (Self::Integer(current), Self::Integer(joined)) = (self, joined) else {
            return joined;
        };
        match current.widen(joined) {
            ScalarIntegerWidening::Interval(widened) => Self::Integer(widened),
            ScalarIntegerWidening::Unbounded | ScalarIntegerWidening::UnknownDomain => {
                Self::NonExactInteger
            }
        }
    }
}

/// How many times one program point may join an incoming predecessor state
/// before its integer facts widen instead.
///
/// The mathematical integer domain has no finite bounds, so a counting loop
/// would otherwise grow its interval by one value per iteration and never
/// reach a fixed point. This is the documented per-point limit: a loop that
/// settles within it keeps exact bounds, and a longer one widens and says so
/// by losing the bound. It also caps a join of many distinct constants, such
/// as a wide switch, at the same place.
const POINT_JOIN_WIDENING_LIMIT: usize = 16;

/// A complete procedure-local scalar solution. Point states describe values
/// after the ordered effects at that point have executed.
#[derive(Debug, Clone)]
pub struct ScalarStateDerivation {
    procedure: ProcedureId,
    states: Box<[Option<Box<[ScalarFact]>>]>,
    feasible_edges: HashSet<ControlEdgeId>,
    /// Per guard, the value whose fact its refinement reads and narrows.
    guard_operands: Box<[Option<GuardOperand>]>,
}

/// One exact caller-supplied scalar fact at procedure entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarEntryFact {
    pub target: ValueId,
    pub fact: ScalarFact,
}

/// Java's declared numeric types for one procedure: full-domain entry facts
/// for its primitive numeric formal parameters and a binding type for every
/// primitive or boxed numeric formal and local, so each write takes the
/// declared type.
#[derive(Debug, Clone)]
pub struct JavaScalarSeeds {
    pub entry_facts: Vec<ScalarEntryFact>,
    pub typing: ScalarTyping,
}

/// Derive [`JavaScalarSeeds`] from declarations. The source tree must be
/// acquired from the same analyzer snapshot as `procedure`; unsupported
/// declaration shapes have no seed and stay untyped and unknown.
pub fn java_scalar_seeds(
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> JavaScalarSeeds {
    let semantics = procedure.semantics();
    let mut entry_facts = Vec::new();
    let mut bindings = Vec::new();
    for binding in java_scalar_binding_types(procedure, prepared) {
        let target = binding.value;
        let (binding_type, entry) = match binding.scalar_type {
            JavaScalarType::Integral(primitive) => {
                let domain = match primitive {
                    JavaIntegralDomain::Signed(bits) => ScalarIntegerDomain::signed(bits),
                    JavaIntegralDomain::Unsigned(bits) => ScalarIntegerDomain::unsigned(bits),
                };
                let (lower, upper) = domain
                    .finite_bounds()
                    .expect("Java primitive integral domains are finite");
                (
                    ScalarBindingType::MachineInteger(domain),
                    ScalarFact::Integer(ScalarIntegerInterval::new(lower, upper, domain)),
                )
            }
            JavaScalarType::Float => (
                ScalarBindingType::Binary32,
                ScalarFact::Float(ScalarFloatRange::any()),
            ),
            JavaScalarType::Double => (
                ScalarBindingType::Binary64,
                ScalarFact::Float(ScalarFloatRange::any()),
            ),
            JavaScalarType::Boolean => (ScalarBindingType::Boolean, ScalarFact::EitherBoolean),
        };
        bindings.push((target, binding_type));
        // A boxed formal may be `null`, so only a primitive one starts in
        // its full domain.
        if !binding.boxed
            && semantics
                .value(target)
                .is_some_and(|value| matches!(value.kind, SemanticValueKind::Parameter { .. }))
        {
            entry_facts.push(ScalarEntryFact {
                target,
                fact: entry,
            });
        }
    }
    JavaScalarSeeds {
        entry_facts,
        typing: ScalarTyping::with_bindings(bindings),
    }
}

/// One outcome-sensitive scalar mutation applied while traversing a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarEdgeWrite {
    pub edge: ControlEdgeId,
    pub target: ValueId,
    pub fact: ScalarFact,
}

/// Exact call-side mutation facts supplied by a model-aware consumer.
///
/// Calls absent from `modeled_address_calls` conservatively invalidate each
/// local whose address is passed directly. A present call has complete
/// mutation coverage; its outcome-specific changes are represented by
/// `edge_writes`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScalarCallEffects<'a> {
    pub modeled_address_calls: &'a [CallSiteId],
    pub edge_writes: &'a [ScalarEdgeWrite],
    /// CFG edges whose execution is disproved by an exact call model, such as
    /// the normal continuation of a terminating procedure.
    pub infeasible_edges: &'a [ControlEdgeId],
}

impl ScalarStateDerivation {
    pub fn derive(procedure: &ProcedureHandle) -> Self {
        Self::derive_with_entry_facts(procedure, ScalarCallEffects::default(), &[])
    }

    pub fn derive_with_call_effects(
        procedure: &ProcedureHandle,
        call_effects: ScalarCallEffects<'_>,
    ) -> Self {
        Self::derive_with_entry_facts(procedure, call_effects, &[])
    }

    pub fn derive_with_entry_facts(
        procedure: &ProcedureHandle,
        call_effects: ScalarCallEffects<'_>,
        entry_facts: &[ScalarEntryFact],
    ) -> Self {
        Self::derive_typed(
            procedure,
            call_effects,
            entry_facts,
            &ScalarTyping::default(),
        )
    }

    /// Derive with numeric binding types: every write to a typed binding
    /// takes its declared representation, and a value it cannot represent
    /// exactly becomes unknown.
    pub fn derive_typed(
        procedure: &ProcedureHandle,
        call_effects: ScalarCallEffects<'_>,
        entry_facts: &[ScalarEntryFact],
        typing: &ScalarTyping,
    ) -> Self {
        let semantics = procedure.semantics();
        let value_count = semantics.values().len();
        let point_count = semantics.points().len();
        let closed_cells = closed_scalar_cells(procedure, call_effects.modeled_address_calls);
        let shared_captures = shared_capture_bindings(procedure);
        let mut states = vec![None::<Box<[ScalarFact]>>; point_count];
        let mut incoming = vec![None::<Box<[ScalarFact]>>; point_count];
        let mut entry = vec![ScalarFact::Unreachable; value_count];
        for value in semantics.values() {
            entry[value.id.index()] = match value.kind {
                SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. } => {
                    ScalarFact::Unknown
                }
                _ => intrinsic_fact(semantics, value.id),
            };
        }
        let mut seeded = HashSet::default();
        for seed in entry_facts {
            let value = semantics
                .value(seed.target)
                .expect("scalar entry fact belongs to its procedure");
            assert!(
                matches!(
                    value.kind,
                    SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. }
                ),
                "scalar entry facts target only parameters or receivers"
            );
            assert!(
                seeded.insert(seed.target),
                "one scalar entry fact exists per formal"
            );
            entry[seed.target.index()] = seed.fact;
        }
        incoming[semantics.entry_point().index()] = Some(entry.into_boxed_slice());

        let GuardRefinements {
            by_edge: guards_by_edge,
            operands: guard_operands,
        } = guards_by_edge(procedure, typing);
        let mut pending = VecDeque::from([semantics.entry_point()]);
        let mut queued = HashSet::default();
        let mut feasible_edges = HashSet::default();
        queued.insert(semantics.entry_point());
        let mut joins = vec![0_usize; point_count];
        let mut updates = 0_usize;
        while let Some(point) = pending.pop_front() {
            queued.remove(&point);
            let Some(mut state) = incoming[point.index()].clone() else {
                continue;
            };
            transfer_point(
                procedure,
                point,
                &mut state,
                call_effects.modeled_address_calls,
                &closed_cells,
                &shared_captures,
                typing,
            );
            if states[point.index()].as_ref() == Some(&state) {
                continue;
            }
            states[point.index()] = Some(state.clone());

            for (edge_id, edge) in semantics.successor_edges(point) {
                if call_effects.infeasible_edges.contains(&edge_id)
                    || semantics
                        .guard_facts()
                        .iter()
                        .any(|guard| guard.infeasible_edge() == Some(edge_id))
                {
                    continue;
                }
                let mut successor = state.clone();
                let mut feasible = true;
                if let Some(refinements) = guards_by_edge.get(&edge_id) {
                    for refinement in refinements {
                        if !apply_guard_refinement(semantics, refinement, typing, &mut successor) {
                            feasible = false;
                            break;
                        }
                    }
                }
                if !feasible {
                    continue;
                }
                feasible_edges.insert(edge_id);
                for write in call_effects
                    .edge_writes
                    .iter()
                    .filter(|write| write.edge == edge_id)
                {
                    successor[write.target.index()] = write.fact;
                }
                let target = edge.target_point.index();
                joins[target] = joins[target].saturating_add(1);
                let changed = if joins[target] > POINT_JOIN_WIDENING_LIMIT {
                    widen_into(&mut incoming[target], &successor)
                } else {
                    join_into(&mut incoming[target], &successor)
                };
                if changed && queued.insert(edge.target_point) {
                    pending.push_back(edge.target_point);
                }
            }
            updates = updates.saturating_add(1);
            debug_assert!(
                updates
                    <= point_count
                        .saturating_mul(value_count.saturating_add(1))
                        .saturating_mul(16),
                "finite scalar worklist exceeded its lattice-derived update bound"
            );
        }

        Self {
            procedure: procedure.id(),
            states: states.into_boxed_slice(),
            feasible_edges,
            guard_operands,
        }
    }

    pub const fn procedure(&self) -> ProcedureId {
        self.procedure
    }

    pub fn fact_at(&self, point: ProgramPointId, value: ValueId) -> ScalarFact {
        self.states
            .get(point.index())
            .and_then(Option::as_deref)
            .and_then(|state| state.get(value.index()))
            .copied()
            .unwrap_or(ScalarFact::Unreachable)
    }

    pub fn is_reachable(&self, point: ProgramPointId) -> bool {
        self.states.get(point.index()).is_some_and(Option::is_some)
    }

    pub fn edge_is_feasible(&self, edge: ControlEdgeId) -> bool {
        self.feasible_edges.contains(&edge)
    }

    /// The fact a guard's refinement reads at its decision point: the fact of
    /// the binding its operand reads, or of the operand itself when no unique
    /// binding exists. `None` when the guard has no operand or its decision
    /// point is unreachable. Pair it with [`guard_decides`].
    pub fn guard_operand_fact(
        &self,
        procedure: &ProcedureHandle,
        guard: &GuardFact,
    ) -> Option<ScalarFact> {
        assert_eq!(
            procedure.id(),
            self.procedure,
            "guard belongs to the derived procedure"
        );
        let operand = self.guard_operands[guard.id.index()]?;
        let state = self.states[guard.point.index()].as_deref()?;
        Some(operand.fact(fact_of(procedure.semantics(), state, operand.binding)))
    }
}

#[derive(Debug, Clone, Copy)]
struct EdgeRefinement {
    /// The value the condition tests.
    operand: ValueId,
    guard: GuardOperand,
    predicate: GuardPredicate,
    truth: bool,
}

/// The binding one guard's refinement reads, and the values its static type
/// admits when the guard tests it as that type.
#[derive(Debug, Clone, Copy)]
struct GuardOperand {
    /// The binding the guard's operand reads, or the operand itself.
    binding: ValueId,
    static_domain: Option<ScalarFact>,
}

impl GuardOperand {
    /// The fact the guard decides on. A guard that tests its operand as its
    /// static type decides only after the operand is a value of that type:
    /// in Java an unboxing comparison or condition throws on `null` before
    /// it decides. So an otherwise unknown or merely non-null operand holds
    /// a value of that type there.
    fn fact(self, current: ScalarFact) -> ScalarFact {
        match (current, self.static_domain) {
            (ScalarFact::Unknown | ScalarFact::NonNil, Some(domain)) => domain,
            _ => current,
        }
    }
}

/// Whether a predicate compares its operand as a number.
fn numeric_predicate(semantics: &ProcedureSemantics, predicate: GuardPredicate) -> bool {
    match predicate {
        GuardPredicate::OrderedIntegerComparison { .. }
        | GuardPredicate::OrderedFloatComparison { .. }
        | GuardPredicate::NanComparison { .. } => true,
        GuardPredicate::ConstantEquality { constant, .. } => matches!(
            intrinsic_fact(semantics, constant),
            ScalarFact::Integer(_) | ScalarFact::Float(_)
        ),
        _ => false,
    }
}

/// The value a guard's condition tests: a truth test names its value, and
/// every other predicate tests its subject.
fn guard_operand(guard: &GuardFact) -> Option<ValueId> {
    match guard.predicate {
        GuardPredicate::Truthy { value } => Some(value),
        _ => guard.subject,
    }
}

/// Every guard's refinements keyed by the edge that applies them, and per
/// guard ID the binding its refinement reads.
struct GuardRefinements {
    by_edge: HashMap<ControlEdgeId, Vec<EdgeRefinement>>,
    operands: Box<[Option<GuardOperand>]>,
}

fn guards_by_edge(procedure: &ProcedureHandle, typing: &ScalarTyping) -> GuardRefinements {
    let semantics = procedure.semantics();
    let origins = BindingOriginIndex::new(procedure);
    let mut result = HashMap::<ControlEdgeId, Vec<EdgeRefinement>>::default();
    let mut operands = Vec::with_capacity(procedure.semantics().guard_facts().len());
    for guard in procedure.semantics().guard_facts() {
        assert_eq!(guard.id.index(), operands.len(), "guard IDs are dense");
        let Some(operand) = guard_operand(guard) else {
            operands.push(None);
            continue;
        };
        let binding = origins.unique_binding_origin(operand).unwrap_or(operand);
        let guard_operand = GuardOperand {
            binding,
            static_domain: typing
                .binding_type(semantics, binding)
                .filter(|binding_type| binding_type.tested_by(semantics, guard.predicate))
                .and_then(ScalarBindingType::static_domain),
        };
        operands.push(Some(guard_operand));
        for (edge, truth) in [(guard.true_edge, true), (guard.false_edge, false)] {
            if let Some(edge) = edge {
                result.entry(edge).or_default().push(EdgeRefinement {
                    operand,
                    guard: guard_operand,
                    predicate: guard.predicate,
                    truth,
                });
            }
        }
    }
    GuardRefinements {
        by_edge: result,
        operands: operands.into_boxed_slice(),
    }
}

/// Local cells can reuse the binding lattice only while their payload has no
/// writer outside this procedure's explicit assignments and stores. The check
/// is procedure-wide: an escape keeps the cell open even before publication.
fn closed_scalar_cells(
    procedure: &ProcedureHandle,
    modeled_address_calls: &[CallSiteId],
) -> HashSet<ValueId> {
    let semantics = procedure.semantics();
    semantics
        .memory_locations()
        .iter()
        .filter_map(|location| {
            let MemoryLocationKind::LexicalCell { binding } = location.kind else {
                return None;
            };
            if semantics.captures().iter().any(|capture| {
                matches!(capture.captured, CaptureSource::Location(captured) if captured == location.id)
                    || matches!(capture.captured, CaptureSource::Value(value) if value == binding)
            }) {
                return None;
            }
            let aliases =
                crate::flow_state::address_alias_values(semantics, &HashSet::from_iter([binding]));
            let call_names_alias = |call_site| {
                semantics.call_site(call_site).is_none_or(|call| {
                    aliases.contains(&call.callee)
                        || call
                            .receiver
                            .is_some_and(|receiver| aliases.contains(&receiver))
                        || call
                            .arguments
                            .iter()
                            .any(|argument| aliases.contains(&argument.value))
                })
            };
            if semantics.gaps().iter().any(|gap| {
                if !gap.impacts.contains(SemanticGapImpact::HeapWrite)
                    || gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
                {
                    return false;
                }
                match gap.subject {
                    SemanticGapSubject::Procedure
                    | SemanticGapSubject::Point
                    | SemanticGapSubject::AsyncContinuation { .. } => true,
                    SemanticGapSubject::Value(value) => {
                        value == binding || aliases.contains(&value)
                    }
                    SemanticGapSubject::MemoryLocation(candidate) => {
                        candidate == location.id
                            || semantics
                                .memory_location(candidate)
                                .is_none_or(|candidate| {
                                    aliases
                                        .iter()
                                        .any(|alias| candidate.kind.uses_value(*alias))
                                })
                    }
                    SemanticGapSubject::Capture(capture) => semantics
                        .capture(capture)
                        .is_none_or(|capture| match capture.captured {
                            CaptureSource::Value(value) => {
                                value == binding || aliases.contains(&value)
                            }
                            CaptureSource::Location(candidate) => candidate == location.id,
                        }),
                    SemanticGapSubject::CallSite(call_site) => {
                        !modeled_address_calls.contains(&call_site) && call_names_alias(call_site)
                    }
                    SemanticGapSubject::CallContinuation { call_site, .. } => {
                        !modeled_address_calls.contains(&call_site) && call_names_alias(call_site)
                    }
                }
            }) {
                return None;
            }
            crate::flow_state::address_escape_points(semantics, &aliases, modeled_address_calls)
                .is_empty()
                .then_some(binding)
        })
        .collect()
}

/// Bindings a closure in this procedure shares by reference rather than by
/// copy. The closure can rebind them whenever it runs. A copying capture, such
/// as Java's effectively final one, and a captured receiver cannot rebind the
/// caller's binding.
fn shared_capture_bindings(procedure: &ProcedureHandle) -> HashSet<ValueId> {
    let semantics = procedure.semantics();
    // A producer that cannot publish a nested write as a capture edge marks
    // the rebound binding with a Captures gap instead.
    let rebound = semantics.gaps().iter().filter_map(|gap| match gap.subject {
        SemanticGapSubject::Value(value)
            if gap.capability == SemanticCapability::Captures
                && gap.discharge == SemanticGapDischarge::RebindAtCallOrSuspension
                && semantics.value(value).is_some_and(|value| {
                    matches!(
                        value.kind,
                        SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
                    )
                }) =>
        {
            Some(value)
        }
        _ => None,
    });
    semantics
        .captures()
        .iter()
        .filter(|capture| {
            !matches!(
                capture.mode,
                CaptureMode::Value | CaptureMode::Move | CaptureMode::Receiver
            )
        })
        .filter_map(|capture| match capture.captured {
            CaptureSource::Value(value) => Some(value),
            CaptureSource::Location(location) => match semantics
                .memory_location(location)
                .map(|location| &location.kind)
            {
                Some(MemoryLocationKind::LexicalCell { binding }) => Some(*binding),
                _ => None,
            },
        })
        .chain(rebound)
        .collect()
}

fn transfer_point(
    procedure: &ProcedureHandle,
    point: ProgramPointId,
    state: &mut [ScalarFact],
    modeled_address_calls: &[CallSiteId],
    closed_cells: &HashSet<ValueId>,
    shared_captures: &HashSet<ValueId>,
    typing: &ScalarTyping,
) {
    let semantics = procedure.semantics();
    // Any call may run a closure, and a suspension lets other code run one.
    // A binding a closure shares by reference is then no longer known.
    let release_shared = |state: &mut [ScalarFact]| {
        for binding in shared_captures {
            state[binding.index()] = ScalarFact::Unknown;
        }
    };
    let write = |state: &mut [ScalarFact], target: ValueId, fact: ScalarFact| {
        state[target.index()] = typing.store(semantics, target, fact);
    };
    let point = semantics
        .point(point)
        .expect("scalar worklist point belongs to its procedure");
    for event in &point.events {
        match event.effect {
            SemanticEffect::Assignment { target, value } => {
                write(state, target, fact_of(semantics, state, value));
            }
            SemanticEffect::ValueFlow {
                kind:
                    ValueFlowKind::Local
                    | ValueFlowKind::BackingStore { .. }
                    | ValueFlowKind::Parameter
                    | ValueFlowKind::Receiver
                    | ValueFlowKind::Return
                    | ValueFlowKind::IndexedReturn { .. },
                source,
                target,
            } => {
                write(state, target, fact_of(semantics, state, source));
            }
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::IntegerOffset { offset },
                source,
                target,
            } => {
                let result = match fact_of(semantics, state, source) {
                    ScalarFact::Integer(interval) => {
                        let offset = ScalarIntegerValue::new(offset.negative(), offset.magnitude());
                        if !interval.domain().contains(offset) {
                            ScalarFact::Unknown
                        } else {
                            match interval.add_interval(ScalarIntegerInterval::exact(
                                offset,
                                interval.domain(),
                            )) {
                                ScalarIntegerArithmetic::Interval(result) => {
                                    ScalarFact::Integer(result)
                                }
                                ScalarIntegerArithmetic::Overflow
                                | ScalarIntegerArithmetic::MagnitudeExceeded
                                | ScalarIntegerArithmetic::UnknownDomain => ScalarFact::Unknown,
                            }
                        }
                    }
                    _ => ScalarFact::Unknown,
                };
                write(state, target, result);
            }
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Transfer(transfer),
                source,
                target,
            } => {
                let (target_fact, invalidates_source) =
                    transferred_scalar_fact(fact_of(semantics, state, source), transfer);
                write(state, target, target_fact);
                if invalidates_source {
                    state[source.index()] = ScalarFact::Unknown;
                }
            }
            SemanticEffect::ValueFlow {
                kind:
                    ValueFlowKind::LanguageDefined
                    | ValueFlowKind::ReferenceBoxing
                    | ValueFlowKind::ReferenceUnboxing
                    | ValueFlowKind::BackingStoreAlternative { .. },
                target,
                ..
            }
            | SemanticEffect::AsyncResume {
                result: Some(target),
                ..
            } => {
                release_shared(state);
                state[target.index()] = ScalarFact::Unknown;
            }
            SemanticEffect::MemoryLoad {
                location, result, ..
            } => {
                let loaded = match semantics
                    .memory_location(location)
                    .map(|location| &location.kind)
                {
                    Some(MemoryLocationKind::LexicalCell { binding })
                        if closed_cells.contains(binding) =>
                    {
                        fact_of(semantics, state, *binding)
                    }
                    _ => ScalarFact::Unknown,
                };
                write(state, result, loaded);
            }
            SemanticEffect::MemoryStore {
                location, value, ..
            } => {
                if let Some(MemoryLocationKind::LexicalCell { binding }) = semantics
                    .memory_location(location)
                    .map(|location| &location.kind)
                    && closed_cells.contains(binding)
                {
                    write(state, *binding, fact_of(semantics, state, value));
                }
            }
            SemanticEffect::Allocation { allocation } => {
                let allocation = semantics
                    .allocation(allocation)
                    .expect("validated allocation effect resolves");
                state[allocation.result.index()] = ScalarFact::NonNil;
            }
            SemanticEffect::CallableCreation { result, .. }
            | SemanticEffect::CallableReference { result, .. } => {
                state[result.index()] = ScalarFact::NonNil;
            }
            SemanticEffect::Invoke { call_site } => {
                release_shared(state);
                if modeled_address_calls.contains(&call_site) {
                    continue;
                }
                let call = semantics
                    .call_site(call_site)
                    .expect("validated scalar call effect resolves");
                for argument in &call.arguments {
                    if semantics
                        .value(argument.value)
                        .is_some_and(|value| matches!(value.kind, SemanticValueKind::Address))
                        && let Some(binding) = unique_binding_origin(procedure, argument.value)
                    {
                        state[binding.index()] = ScalarFact::Unknown;
                    }
                }
            }
            SemanticEffect::Gap { gap } => {
                let gap = semantics
                    .gap(gap)
                    .expect("validated scalar gap effect resolves");
                if gap.impacts.contains(SemanticGapImpact::ValueFlow)
                    && let SemanticGapSubject::Value(value) = gap.subject
                {
                    state[value.index()] = ScalarFact::Unknown;
                }
                // A suspension that is not lowered as a scaffold still lets
                // other code run before this point continues.
                if gap.subject == SemanticGapSubject::Point
                    && matches!(
                        gap.capability,
                        SemanticCapability::GeneratorSuspension
                            | SemanticCapability::AsyncSuspendResume
                    )
                {
                    release_shared(state);
                }
            }
            SemanticEffect::Entry
            | SemanticEffect::NormalExit
            | SemanticEffect::ExceptionalExit
            | SemanticEffect::ValueUse { .. }
            | SemanticEffect::AggregateInitializer { .. }
            | SemanticEffect::CaptureBind { .. }
            | SemanticEffect::Synchronization { .. }
            | SemanticEffect::CallContinuation { .. }
            | SemanticEffect::ProcedureReturn { .. }
            | SemanticEffect::Throw { .. } => {}
            SemanticEffect::AsyncSuspend { .. }
            | SemanticEffect::AsyncResume { result: None, .. } => {
                release_shared(state);
            }
        }
    }
}

fn transferred_scalar_fact(source: ScalarFact, transfer: ValueTransfer) -> (ScalarFact, bool) {
    if transfer.operation == TransferOperation::Unknown {
        return (
            ScalarFact::Unknown,
            matches!(transfer.kind, TransferKind::Move { .. }),
        );
    }
    let target = match transfer.kind {
        TransferKind::Copy
        | TransferKind::Move { .. }
        | TransferKind::Conversion {
            preservation: ValuePreservation::Identity | ValuePreservation::Preserving,
        } => source,
        TransferKind::AggregateCopy
        | TransferKind::Boxing
        | TransferKind::Unboxing
        | TransferKind::Conversion {
            preservation: ValuePreservation::Changing,
        } => ScalarFact::Unknown,
    };
    (target, matches!(transfer.kind, TransferKind::Move { .. }))
}

fn fact_of(semantics: &ProcedureSemantics, state: &[ScalarFact], value: ValueId) -> ScalarFact {
    let intrinsic = intrinsic_fact(semantics, value);
    if intrinsic != ScalarFact::Unreachable {
        intrinsic
    } else {
        match state[value.index()] {
            // A reachable transfer that consumes a value without a supported
            // scalar origin has an unknown value. `Unreachable` is the
            // control-flow bottom; propagating it through an assignment would
            // make the assignment disappear and incorrectly preserve an older
            // binding fact across opaque call results.
            ScalarFact::Unreachable => ScalarFact::Unknown,
            fact => fact,
        }
    }
}

fn intrinsic_fact(semantics: &ProcedureSemantics, value: ValueId) -> ScalarFact {
    let value = semantics
        .value(value)
        .expect("validated scalar value resolves in its procedure");
    match value.kind {
        SemanticValueKind::Null => ScalarFact::Nil,
        SemanticValueKind::Boolean(true) => ScalarFact::True,
        SemanticValueKind::Boolean(false) => ScalarFact::False,
        SemanticValueKind::UnsignedInteger(value) => {
            ScalarFact::Integer(ScalarIntegerInterval::exact(
                ScalarIntegerValue::unsigned(value),
                ScalarIntegerDomain::Mathematical,
            ))
        }
        SemanticValueKind::SignedInteger(value) => {
            ScalarFact::Integer(ScalarIntegerInterval::exact(
                ScalarIntegerValue::new(value < 0, value.unsigned_abs()),
                ScalarIntegerDomain::Mathematical,
            ))
        }
        SemanticValueKind::FloatingPoint { bits } => {
            ScalarFact::Float(ScalarFloatRange::exact(f64::from_bits(bits)))
        }
        SemanticValueKind::Address => ScalarFact::NonNil,
        _ if semantics
            .allocations()
            .iter()
            .any(|allocation| allocation.result == value.id) =>
        {
            ScalarFact::NonNil
        }
        _ => ScalarFact::Unreachable,
    }
}

fn join_into(slot: &mut Option<Box<[ScalarFact]>>, incoming: &[ScalarFact]) -> bool {
    merge_into(slot, incoming, ScalarFact::join)
}

fn widen_into(slot: &mut Option<Box<[ScalarFact]>>, incoming: &[ScalarFact]) -> bool {
    merge_into(slot, incoming, ScalarFact::widen)
}

fn merge_into(
    slot: &mut Option<Box<[ScalarFact]>>,
    incoming: &[ScalarFact],
    step: fn(ScalarFact, ScalarFact) -> ScalarFact,
) -> bool {
    let Some(current) = slot else {
        *slot = Some(incoming.to_vec().into_boxed_slice());
        return true;
    };
    assert_eq!(current.len(), incoming.len());
    let mut changed = false;
    for (current, incoming) in current.iter_mut().zip(incoming) {
        let merged = step(*current, *incoming);
        changed |= merged != *current;
        *current = merged;
    }
    changed
}

fn apply_guard_refinement(
    semantics: &ProcedureSemantics,
    refinement: &EdgeRefinement,
    typing: &ScalarTyping,
    state: &mut [ScalarFact],
) -> bool {
    let current = refinement
        .guard
        .fact(fact_of(semantics, state, refinement.guard.binding));
    let refined =
        match decided_refinement(semantics, refinement.predicate, refinement.truth, current) {
            GuardRefinement::Refined(fact) => fact,
            GuardRefinement::Infeasible => return false,
            // An undecided arm still narrows where the arm itself names the
            // value: a null test's arm states nullness, and an equality arm
            // states the constant. Neither makes the other arm infeasible.
            GuardRefinement::Undecided => match refinement.predicate {
                GuardPredicate::NullComparison { null_on_true } => {
                    if refinement.truth == null_on_true {
                        ScalarFact::Nil
                    } else {
                        ScalarFact::NonNil
                    }
                }
                GuardPredicate::ConstantEquality { negated, constant }
                    if refinement.truth != negated && current == ScalarFact::NonExactInteger =>
                {
                    match intrinsic_fact(semantics, constant) {
                        constant @ ScalarFact::Integer(_) => constant,
                        _ => return true,
                    }
                }
                _ => return true,
            },
        };
    for target in [refinement.operand, refinement.guard.binding] {
        state[target.index()] = typing.store(semantics, target, refined);
    }
    true
}

/// The outcome of one guard arm for a known operand fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardRefinement {
    /// The arm is feasible and the operand holds this fact on it.
    Refined(ScalarFact),
    Infeasible,
    /// The operand's fact does not decide this predicate.
    Undecided,
}

impl GuardRefinement {
    fn from_fact(fact: Option<ScalarFact>) -> Self {
        fact.map_or(Self::Infeasible, Self::Refined)
    }
}

/// Whether a scalar guard's outcome is decided by `operand_fact`, the fact
/// [`ScalarStateDerivation::guard_operand_fact`] reports: each arm is then
/// either infeasible or narrows the operand exactly as the predicate states.
/// A constant condition is always decided. When this is false, both arms stay
/// feasible because the fact is outside the predicate's modeled vocabulary,
/// not because the solver proved either arm possible.
pub fn guard_decides(
    semantics: &ProcedureSemantics,
    predicate: GuardPredicate,
    operand_fact: ScalarFact,
) -> bool {
    matches!(predicate, GuardPredicate::ConstantBoolean { .. })
        || decided_refinement(semantics, predicate, true, operand_fact)
            != GuardRefinement::Undecided
}

/// Refine the operand fact `current` on the arm where `predicate` has
/// `truth`. Whether the result is undecided does not depend on `truth`.
fn decided_refinement(
    semantics: &ProcedureSemantics,
    predicate: GuardPredicate,
    truth: bool,
    current: ScalarFact,
) -> GuardRefinement {
    match predicate {
        GuardPredicate::NullComparison { null_on_true } => match current {
            ScalarFact::Nil | ScalarFact::NonNil => {
                if (current == ScalarFact::Nil) == (truth == null_on_true) {
                    GuardRefinement::Refined(current)
                } else {
                    GuardRefinement::Infeasible
                }
            }
            // A known number or Boolean is never the null value (nor, in
            // JavaScript, `undefined`).
            ScalarFact::True
            | ScalarFact::False
            | ScalarFact::EitherBoolean
            | ScalarFact::Integer(_)
            | ScalarFact::NonExactInteger
            | ScalarFact::Float(_) => {
                if truth == null_on_true {
                    GuardRefinement::Infeasible
                } else {
                    GuardRefinement::Refined(current)
                }
            }
            _ => GuardRefinement::Undecided,
        },
        GuardPredicate::ConstantEquality { negated, constant } => {
            let equal = truth != negated;
            match (intrinsic_fact(semantics, constant), current) {
                (
                    constant @ (ScalarFact::True | ScalarFact::False),
                    ScalarFact::True | ScalarFact::False | ScalarFact::EitherBoolean,
                ) => {
                    let expected = if equal == (constant == ScalarFact::True) {
                        ScalarFact::True
                    } else {
                        ScalarFact::False
                    };
                    if current == expected || current == ScalarFact::EitherBoolean {
                        GuardRefinement::Refined(expected)
                    } else {
                        GuardRefinement::Infeasible
                    }
                }
                (constant @ (ScalarFact::Integer(_) | ScalarFact::Float(_)), current) => {
                    refine_numeric_equality(current, constant, equal)
                }
                // Equality with the null constant, including a loose
                // equality that `undefined` also satisfies: null equals
                // itself, and a known number or Boolean never equals null.
                // A not-null fact does not decide it, and neither arm
                // narrows an undecided subject.
                (ScalarFact::Nil, ScalarFact::Nil) => {
                    if equal {
                        GuardRefinement::Refined(current)
                    } else {
                        GuardRefinement::Infeasible
                    }
                }
                (
                    ScalarFact::Nil,
                    ScalarFact::True
                    | ScalarFact::False
                    | ScalarFact::EitherBoolean
                    | ScalarFact::Integer(_)
                    | ScalarFact::NonExactInteger
                    | ScalarFact::Float(_),
                ) => {
                    if equal {
                        GuardRefinement::Infeasible
                    } else {
                        GuardRefinement::Refined(current)
                    }
                }
                _ => GuardRefinement::Undecided,
            }
        }
        GuardPredicate::OrderedIntegerComparison { relation, constant }
        | GuardPredicate::OrderedFloatComparison { relation, constant } => refine_numeric_order(
            current,
            intrinsic_fact(semantics, constant),
            relation,
            truth,
        ),
        GuardPredicate::NanComparison { nan_on_true } => refine_nan(current, truth == nan_on_true),
        GuardPredicate::Truthy { .. } => refine_truth(current, truth),
        GuardPredicate::ConstantBoolean { .. }
        | GuardPredicate::InstanceOf { .. }
        | GuardPredicate::ExactClass { .. }
        | GuardPredicate::HasMember { .. }
        | GuardPredicate::Opaque { .. } => GuardRefinement::Undecided,
    }
}

/// Refine `current relation constant` on the arm where it has `truth`.
/// Integer and floating operands compare by exact value. A mixed comparison
/// is decided only where every language's numeric promotion keeps that
/// exact outcome; see [`binary32_exact_integer`] and
/// [`float_constant_compares_integers_exactly`].
fn refine_numeric_order(
    current: ScalarFact,
    constant: ScalarFact,
    relation: IntegerComparison,
    truth: bool,
) -> GuardRefinement {
    match (current, constant) {
        (ScalarFact::Integer(interval), ScalarFact::Integer(constant)) => {
            let constant = constant.exact_value().expect("intrinsic integer is exact");
            let relation = if truth { relation } else { relation.negate() };
            GuardRefinement::from_fact(
                refine_integer_interval(interval, relation, constant).map(ScalarFact::Integer),
            )
        }
        (ScalarFact::Float(range), ScalarFact::Integer(constant)) => {
            let constant = constant.exact_value().expect("intrinsic integer is exact");
            match binary32_exact_integer(constant) {
                Some(constant) => GuardRefinement::from_fact(
                    range
                        .refine_order(relation, constant, truth)
                        .map(ScalarFact::Float),
                ),
                None => GuardRefinement::Undecided,
            }
        }
        (ScalarFact::Float(range), ScalarFact::Float(constant)) => {
            let constant = constant.exact_value().expect("intrinsic float is exact");
            GuardRefinement::from_fact(
                range
                    .refine_order(relation, constant, truth)
                    .map(ScalarFact::Float),
            )
        }
        (ScalarFact::Integer(interval), ScalarFact::Float(constant)) => {
            let constant = constant.exact_value().expect("intrinsic float is exact");
            if !float_constant_compares_integers_exactly(constant) {
                return GuardRefinement::Undecided;
            }
            // An integer is never NaN, so the negated relation is exact.
            // Against an integer, `x < 2.5` is `x <= 2` and `x > 2.5` is
            // `x >= 3`; an integral constant keeps its relation.
            let relation = if truth { relation } else { relation.negate() };
            let (relation, bound) = if constant.fract() == 0.0 {
                (relation, constant)
            } else {
                match relation {
                    IntegerComparison::LessThan | IntegerComparison::LessThanOrEqual => {
                        (IntegerComparison::LessThanOrEqual, constant.floor())
                    }
                    IntegerComparison::GreaterThan | IntegerComparison::GreaterThanOrEqual => {
                        (IntegerComparison::GreaterThanOrEqual, constant.ceil())
                    }
                }
            };
            let bound = float_as_integer(bound).expect("an integral bound below 2^53 converts");
            GuardRefinement::from_fact(
                refine_integer_interval(interval, relation, bound).map(ScalarFact::Integer),
            )
        }
        _ => GuardRefinement::Undecided,
    }
}

/// Refine `current == constant` on its equal (`equal`) or unequal arm, under
/// the same exactness conditions as [`refine_numeric_order`].
fn refine_numeric_equality(
    current: ScalarFact,
    constant: ScalarFact,
    equal: bool,
) -> GuardRefinement {
    match (current, constant) {
        (ScalarFact::Integer(interval), ScalarFact::Integer(constant)) => {
            let constant = constant.exact_value().expect("intrinsic integer is exact");
            GuardRefinement::from_fact(
                refine_integer_equality(interval, constant, equal).map(ScalarFact::Integer),
            )
        }
        (ScalarFact::Float(range), ScalarFact::Integer(constant)) => {
            let constant = constant.exact_value().expect("intrinsic integer is exact");
            match binary32_exact_integer(constant) {
                Some(constant) => GuardRefinement::from_fact(
                    range
                        .refine_equality(constant, equal)
                        .map(ScalarFact::Float),
                ),
                None => GuardRefinement::Undecided,
            }
        }
        (ScalarFact::Float(range), ScalarFact::Float(constant)) => {
            let constant = constant.exact_value().expect("intrinsic float is exact");
            GuardRefinement::from_fact(
                range
                    .refine_equality(constant, equal)
                    .map(ScalarFact::Float),
            )
        }
        (ScalarFact::Integer(interval), ScalarFact::Float(constant)) => {
            let constant = constant.exact_value().expect("intrinsic float is exact");
            if !float_constant_compares_integers_exactly(constant) {
                return GuardRefinement::Undecided;
            }
            match float_as_integer(constant) {
                Some(constant) => GuardRefinement::from_fact(
                    refine_integer_equality(interval, constant, equal).map(ScalarFact::Integer),
                ),
                // A converted integer is integral, so it never equals a
                // fractional constant.
                None if equal => GuardRefinement::Infeasible,
                None => GuardRefinement::Refined(current),
            }
        }
        _ => GuardRefinement::Undecided,
    }
}

/// Refine a NaN test on the arm where the operand is NaN (`nan`) or not. An
/// integer is never NaN.
fn refine_nan(current: ScalarFact, nan: bool) -> GuardRefinement {
    match current {
        ScalarFact::Float(range) => {
            GuardRefinement::from_fact(range.refine_nan(nan).map(ScalarFact::Float))
        }
        ScalarFact::Integer(_) if nan => GuardRefinement::Infeasible,
        ScalarFact::Integer(_) => GuardRefinement::Refined(current),
        _ => GuardRefinement::Undecided,
    }
}

/// Refine a truth test of a known scalar. Nil, Booleans, integers, and
/// floats have the same truthiness in every language that publishes a truth
/// guard, except NaN, which is falsy in JavaScript and truthy in Python; a
/// float that may be NaN therefore stays undecided.
fn refine_truth(current: ScalarFact, truth: bool) -> GuardRefinement {
    match current {
        ScalarFact::Nil if truth => GuardRefinement::Infeasible,
        ScalarFact::Nil => GuardRefinement::Refined(current),
        ScalarFact::True | ScalarFact::False => {
            if (current == ScalarFact::True) == truth {
                GuardRefinement::Refined(current)
            } else {
                GuardRefinement::Infeasible
            }
        }
        ScalarFact::EitherBoolean => GuardRefinement::Refined(if truth {
            ScalarFact::True
        } else {
            ScalarFact::False
        }),
        ScalarFact::Integer(interval) => GuardRefinement::from_fact(
            refine_integer_equality(interval, ScalarIntegerValue::unsigned(0), !truth)
                .map(ScalarFact::Integer),
        ),
        ScalarFact::Float(range) if !range.may_be_nan() => {
            GuardRefinement::from_fact(range.refine_equality(0.0, !truth).map(ScalarFact::Float))
        }
        _ => GuardRefinement::Undecided,
    }
}

fn refine_integer_equality(
    interval: ScalarIntegerInterval,
    constant: ScalarIntegerValue,
    equality_arm: bool,
) -> Option<ScalarIntegerInterval> {
    let inside = interval.domain().contains(constant)
        && interval.lower() <= constant
        && constant <= interval.upper();
    if equality_arm {
        return inside.then(|| ScalarIntegerInterval::exact(constant, interval.domain()));
    }
    if !inside {
        return Some(interval);
    }
    if interval.exact_value().is_some() {
        return None;
    }
    if constant == interval.lower() {
        let lower = constant.checked_add(ScalarIntegerValue::unsigned(1))?;
        return Some(ScalarIntegerInterval::new(
            lower,
            interval.upper(),
            interval.domain(),
        ));
    }
    if constant == interval.upper() {
        let upper = constant.checked_sub(ScalarIntegerValue::unsigned(1))?;
        return Some(ScalarIntegerInterval::new(
            interval.lower(),
            upper,
            interval.domain(),
        ));
    }
    // An interior exclusion is a hole, which this interval cannot represent.
    Some(interval)
}

fn refine_integer_interval(
    interval: ScalarIntegerInterval,
    relation: IntegerComparison,
    constant: ScalarIntegerValue,
) -> Option<ScalarIntegerInterval> {
    let (lower, upper) = match relation {
        IntegerComparison::LessThan => {
            if interval.lower() >= constant {
                return None;
            }
            let upper_bound = constant
                .checked_sub(ScalarIntegerValue::unsigned(1))
                .expect("subtracting one from a represented nonnegative constant fits");
            (interval.lower(), interval.upper().min(upper_bound))
        }
        IntegerComparison::LessThanOrEqual => {
            if interval.lower() > constant {
                return None;
            }
            (interval.lower(), interval.upper().min(constant))
        }
        IntegerComparison::GreaterThan => {
            if interval.upper() <= constant {
                return None;
            }
            let lower_bound = constant.checked_add(ScalarIntegerValue::unsigned(1))?;
            (interval.lower().max(lower_bound), interval.upper())
        }
        IntegerComparison::GreaterThanOrEqual => {
            if interval.upper() < constant {
                return None;
            }
            (interval.lower().max(constant), interval.upper())
        }
    };
    Some(ScalarIntegerInterval::new(lower, upper, interval.domain()))
}

pub(crate) struct BindingOriginIndex<'procedure> {
    procedure: &'procedure ProcedureHandle,
    predecessors: HashMap<ValueId, Vec<ValueId>>,
}

impl<'procedure> BindingOriginIndex<'procedure> {
    pub(crate) fn new(procedure: &'procedure ProcedureHandle) -> Self {
        let semantics = procedure.semantics();
        let mut predecessors = HashMap::<ValueId, Vec<ValueId>>::default();
        for point in semantics.points() {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Assignment { target, value }
                        if !semantics.value(target).is_some_and(|value| {
                            matches!(
                                value.kind,
                                SemanticValueKind::Local
                                    | SemanticValueKind::Parameter { .. }
                                    | SemanticValueKind::Receiver { .. }
                            )
                        }) =>
                    {
                        predecessors.entry(target).or_default().push(value);
                    }
                    SemanticEffect::ValueFlow { source, target, .. } => {
                        predecessors.entry(target).or_default().push(source);
                    }
                    _ => {}
                }
            }
        }
        Self {
            procedure,
            predecessors,
        }
    }

    pub(crate) fn unique_binding_origin(&self, subject: ValueId) -> Option<ValueId> {
        let semantics = self.procedure.semantics();
        let mut pending = vec![subject];
        let mut visited = HashSet::default();
        let mut bindings = HashSet::default();
        while let Some(value) = pending.pop() {
            if !visited.insert(value) {
                continue;
            }
            match semantics.value(value)?.kind {
                SemanticValueKind::Local
                | SemanticValueKind::Parameter { .. }
                | SemanticValueKind::Receiver { .. } => {
                    bindings.insert(value);
                }
                _ => pending.extend(self.predecessors.get(&value).into_iter().flatten().copied()),
            }
        }
        (bindings.len() == 1).then(|| *bindings.iter().next().expect("one binding"))
    }
}

pub fn unique_binding_origin(procedure: &ProcedureHandle, subject: ValueId) -> Option<ValueId> {
    BindingOriginIndex::new(procedure).unique_binding_origin(subject)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        MemoryLocationKind, SemanticBudget, SemanticRequest, SemanticWork,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::cancellation::CancellationToken;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;
    use brokk_bifrost_core::analyzer::model::LanguageDialect;
    use brokk_bifrost_core::analyzer::prepared_syntax::{
        PreparedSourceOrigin, PreparedSyntaxSource, PreparedSyntaxTree,
    };
    use brokk_bifrost_core::text_utils::compute_line_starts;
    use std::sync::Arc;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

    fn exact_integer(value: u128) -> ScalarFact {
        ScalarFact::Integer(ScalarIntegerInterval::exact(
            ScalarIntegerValue::unsigned(value),
            ScalarIntegerDomain::Mathematical,
        ))
    }

    struct Fixture {
        _project: BuiltInlineTestProject,
        procedure: ProcedureHandle,
    }

    impl Fixture {
        fn go(source: &str, name: &str) -> Self {
            Self::source(Language::Go, "main.go", source, name)
        }

        fn java(source: &str, name: &str) -> Self {
            Self::source(Language::Java, "C.java", source, name)
        }

        /// Java declaration seeds from `source`, which built this fixture.
        fn java_seeds(&self, source: &str) -> JavaScalarSeeds {
            let file = self._project.file("C.java");
            let tree =
                parse_tree_for_language(&file, Language::Java, source).expect("Java source parses");
            let prepared = PreparedSyntaxTree::new(
                PreparedSyntaxSource::Exact(Arc::from(source)),
                tree,
                compute_line_starts(source),
                LanguageDialect::Standard(Language::Java),
                PreparedSourceOrigin::Disk,
                None,
            );
            java_scalar_seeds(&self.procedure, &prepared)
        }

        /// The derivation with Java's declared entry facts and binding types.
        fn java_typed(&self, source: &str) -> ScalarStateDerivation {
            let seeds = self.java_seeds(source);
            ScalarStateDerivation::derive_typed(
                &self.procedure,
                ScalarCallEffects::default(),
                &seeds.entry_facts,
                &seeds.typing,
            )
        }

        fn source(language: Language, filename: &str, source: &str, name: &str) -> Self {
            let project = InlineTestProject::with_language(language)
                .file(filename, source)
                .build();
            let file = project.file(filename);
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let cancellation = CancellationToken::default();
            let mut budget =
                SemanticBudget::new(SemanticWork::default_limits()).expect("valid test budget");
            let outcome = workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("semantics materialize");
            let artifact = outcome
                .available_value()
                .cloned()
                .unwrap_or_else(|| panic!("semantics are available: {outcome:#?}"));
            let procedure = artifact
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
                .map(|procedure| procedure.id())
                .and_then(|id| artifact.procedure_handle(id))
                .unwrap_or_else(|| panic!("missing procedure {name}"));
            Self {
                _project: project,
                procedure,
            }
        }

        /// The scalar facts of every call argument, in call-site order.
        ///
        /// A Go index expression is evaluated into a temporary before the
        /// memory location is built, so a call argument is the closest
        /// stand-in for the value a concurrency consumer asks about.
        fn call_argument_facts(&self) -> Vec<ScalarFact> {
            let derivation = ScalarStateDerivation::derive(&self.procedure);
            let semantics = self.procedure.semantics();
            semantics
                .call_sites()
                .iter()
                .flat_map(|call| {
                    call.arguments
                        .iter()
                        .map(|argument| derivation.fact_at(call.point, argument.value))
                        .collect::<Vec<_>>()
                })
                .collect()
        }

        fn field_base_facts(&self) -> Vec<ScalarFact> {
            let derivation = ScalarStateDerivation::derive(&self.procedure);
            self.field_base_facts_from(&derivation)
        }

        fn field_base_facts_from(&self, derivation: &ScalarStateDerivation) -> Vec<ScalarFact> {
            let semantics = self.procedure.semantics();
            semantics
                .points()
                .iter()
                .flat_map(|point| {
                    point.events.iter().filter_map(|event| match event.effect {
                        SemanticEffect::MemoryLoad { location, .. } => {
                            let (MemoryLocationKind::Field { base, .. }
                            | MemoryLocationKind::Property { base, .. }) =
                                &semantics.memory_location(location)?.kind
                            else {
                                return None;
                            };
                            Some(derivation.fact_at(point.id, *base))
                        }
                        _ => None,
                    })
                })
                .collect()
        }
    }

    #[test]
    fn java_integral_guards_prove_a_contradictory_inner_arm() {
        let source =
            "class C { boolean f(int x) { if (x > 5) { if (x < 3) return true; } return false; } }";
        let fixture = Fixture::java(source, "f");
        let semantics = fixture.procedure.semantics();
        assert_eq!(
            fixture.java_seeds(source).entry_facts.len(),
            1,
            "exact int parameter domain"
        );
        let derivation = fixture.java_typed(source);
        let inner = semantics
            .guard_facts()
            .iter()
            .find(|guard| {
                matches!(
                    guard.predicate,
                    GuardPredicate::OrderedIntegerComparison {
                        relation: IntegerComparison::LessThan,
                        constant,
                    } if semantics.value(constant).is_some_and(|value| value.kind == SemanticValueKind::UnsignedInteger(3))
                )
            })
            .expect("inner primitive integral comparison is normalized");
        assert!(derivation.is_reachable(inner.point));
        assert!(!derivation.edge_is_feasible(inner.true_edge.expect("true arm")));
        assert!(derivation.edge_is_feasible(inner.false_edge.expect("false arm")));
    }

    #[test]
    fn integer_equality_intersects_bounds_and_keeps_unrepresentable_holes_open() {
        let domain = ScalarIntegerDomain::signed(8);
        let value = |negative, magnitude| ScalarIntegerValue::new(negative, magnitude);
        let interval = ScalarIntegerInterval::new(value(true, 2), value(false, 8), domain);
        assert_eq!(
            refine_integer_equality(interval, value(false, 3), true),
            Some(ScalarIntegerInterval::exact(value(false, 3), domain))
        );
        assert_eq!(
            refine_integer_equality(interval, value(false, 9), true),
            None
        );
        assert_eq!(
            refine_integer_equality(interval, value(false, 3), false),
            Some(interval)
        );
        assert_eq!(
            refine_integer_equality(interval, value(true, 2), false),
            Some(ScalarIntegerInterval::new(
                value(true, 1),
                value(false, 8),
                domain
            ))
        );
        assert_eq!(
            refine_integer_equality(interval, value(false, 8), false),
            Some(ScalarIntegerInterval::new(
                value(true, 2),
                value(false, 7),
                domain
            ))
        );
        assert_eq!(
            refine_integer_equality(
                ScalarIntegerInterval::exact(value(false, 3), domain),
                value(false, 3),
                false
            ),
            None
        );
        assert_eq!(
            refine_integer_equality(interval, value(false, 200), false),
            Some(interval)
        );
    }

    fn float(value: f64) -> ScalarFact {
        ScalarFact::Float(ScalarFloatRange::exact(value))
    }

    fn signed32(lower: i128, upper: i128) -> ScalarFact {
        let value = |value: i128| ScalarIntegerValue::new(value < 0, value.unsigned_abs());
        ScalarFact::Integer(ScalarIntegerInterval::new(
            value(lower),
            value(upper),
            ScalarIntegerDomain::signed(32),
        ))
    }

    fn bound(value: f64, inclusive: bool) -> ScalarFloatBound {
        ScalarFloatBound::new(value, inclusive)
    }

    #[test]
    fn float_order_keeps_exclusive_bounds_and_sends_nan_to_the_false_arm() {
        let any = ScalarFloatRange::any();
        let below = any
            .refine_order(IntegerComparison::LessThan, 3.0, true)
            .expect("x < 3 is possible");
        assert_eq!(
            below.ordered(),
            Some((bound(f64::NEG_INFINITY, true), bound(3.0, false)))
        );
        assert!(
            !below.may_be_nan(),
            "an ordered comparison with NaN is false"
        );
        let not_below = any
            .refine_order(IntegerComparison::LessThan, 3.0, false)
            .expect("!(x < 3) is possible");
        assert_eq!(
            not_below.ordered(),
            Some((bound(3.0, true), bound(f64::INFINITY, true)))
        );
        assert!(not_below.may_be_nan(), "NaN takes the false arm");

        // `x < 3` excludes 3 itself, so `x >= 3` is infeasible, while
        // `x <= 3` and `x >= 3` meet at exactly 3.
        assert_eq!(
            below.refine_order(IntegerComparison::GreaterThanOrEqual, 3.0, true),
            None
        );
        let at_most = any
            .refine_order(IntegerComparison::LessThanOrEqual, 3.0, true)
            .expect("x <= 3");
        let exact = at_most
            .refine_order(IntegerComparison::GreaterThanOrEqual, 3.0, true)
            .expect("x <= 3 && x >= 3");
        assert_eq!(exact.exact_value(), Some(3.0));
        // The false arm of `x >= 3` below 3 still admits NaN only when the
        // range did.
        assert_eq!(
            exact.refine_order(IntegerComparison::GreaterThanOrEqual, 3.0, false),
            None
        );
        assert_eq!(
            any.refine_order(IntegerComparison::GreaterThanOrEqual, 3.0, false)
                .expect("NaN or below 3")
                .refine_nan(true)
                .map(ScalarFloatRange::ordered),
            Some(None)
        );
    }

    #[test]
    fn float_equality_removes_bounds_only_and_nan_tests_split_the_range() {
        let closed = ScalarFloatRange::new(Some((bound(3.0, true), bound(5.0, true))), false)
            .expect("nonempty");
        assert_eq!(
            closed
                .refine_equality(3.0, false)
                .map(ScalarFloatRange::ordered),
            Some(Some((bound(3.0, false), bound(5.0, true))))
        );
        assert_eq!(
            closed.refine_equality(4.0, false),
            Some(closed),
            "an interior hole is not representable"
        );
        assert_eq!(closed.refine_equality(6.0, true), None);
        assert_eq!(
            ScalarFloatRange::exact(3.0).refine_equality(3.0, false),
            None
        );
        // IEEE equality does not distinguish the zeros.
        assert_eq!(
            ScalarFloatRange::exact(-0.0).refine_equality(0.0, true),
            Some(ScalarFloatRange::exact(0.0))
        );

        let any = ScalarFloatRange::any();
        let nan = any.refine_nan(true).expect("any may be NaN");
        assert!(nan.may_be_nan() && nan.ordered().is_none());
        assert_eq!(
            nan.refine_order(IntegerComparison::LessThan, 1.0, true),
            None
        );
        assert_eq!(nan.refine_equality(1.0, true), None);
        assert_eq!(nan.refine_equality(1.0, false), Some(nan));
        assert_eq!(ScalarFloatRange::exact(1.0).refine_nan(true), None);
        assert_eq!(
            any.refine_nan(false).map(ScalarFloatRange::may_be_nan),
            Some(false)
        );
    }

    #[test]
    fn float_facts_join_as_hulls_and_integers_join_only_when_exact() {
        let hull = float(1.5).join(float(-2.0));
        let ScalarFact::Float(range) = hull else {
            panic!("floats join as a range: {hull:?}");
        };
        assert_eq!(range.ordered(), Some((bound(-2.0, true), bound(1.5, true))));
        assert_eq!(hull.label(), "float_range");
        assert_eq!(float(1.5).label(), "exact_float");

        let mixed = exact_integer(3).join(float(1.5));
        assert_eq!(
            mixed,
            ScalarFact::Float(
                ScalarFloatRange::new(Some((bound(1.5, true), bound(3.0, true))), false)
                    .expect("nonempty")
            )
        );
        assert_eq!(
            exact_integer((1 << 53) + 1).join(float(1.5)),
            ScalarFact::Unknown,
            "an integer beyond 2^53 is not exactly a binary64 value"
        );
        assert_eq!(float(1.5).widen(float(2.5)), float(1.5).join(float(2.5)));
    }

    #[test]
    fn typed_stores_take_the_declared_representation_or_become_unknown() {
        let byte = ScalarBindingType::MachineInteger(ScalarIntegerDomain::signed(8));
        assert_eq!(
            byte.store(exact_integer(100)),
            ScalarFact::Integer(ScalarIntegerInterval::exact(
                ScalarIntegerValue::unsigned(100),
                ScalarIntegerDomain::signed(8),
            ))
        );
        assert_eq!(byte.store(exact_integer(200)), ScalarFact::Unknown);
        assert_eq!(byte.store(float(1.0)), ScalarFact::Unknown);
        assert_eq!(byte.store(ScalarFact::Nil), ScalarFact::Nil);

        assert_eq!(
            ScalarBindingType::Binary64.store(exact_integer(1 << 53)),
            float((1_u64 << 53) as f64)
        );
        assert_eq!(
            ScalarBindingType::Binary64.store(exact_integer((1 << 53) + 1)),
            ScalarFact::Unknown,
            "binary64 would round 2^53 + 1"
        );
        assert_eq!(
            ScalarBindingType::Binary32.store(exact_integer(1 << 24)),
            float((1_u64 << 24) as f64)
        );
        assert_eq!(
            ScalarBindingType::Binary32.store(exact_integer((1 << 24) + 1)),
            ScalarFact::Unknown,
            "binary32 would round 2^24 + 1"
        );
        assert_eq!(ScalarBindingType::Binary64.store(float(0.5)), float(0.5));

        let safe = ScalarBindingType::DynamicBinary64.store(exact_integer((1 << 53) - 1));
        assert!(
            matches!(safe, ScalarFact::Integer(interval)
                if interval.domain() == ScalarIntegerDomain::signed(54)),
            "{safe:?}"
        );
        assert_eq!(
            ScalarBindingType::DynamicBinary64.store(exact_integer(1 << 60)),
            ScalarFact::Unknown
        );
        assert_eq!(
            ScalarBindingType::DynamicBinary64.store(ScalarFact::True),
            ScalarFact::True
        );

        // Overflow within the declared domain is unknown, never a wrapped or
        // mathematical value that could manufacture a contradiction.
        let ScalarFact::Integer(max) = byte.store(exact_integer(127)) else {
            panic!("127 is a byte");
        };
        assert_eq!(
            max.add_interval(ScalarIntegerInterval::exact(
                ScalarIntegerValue::unsigned(1),
                max.domain()
            )),
            ScalarIntegerArithmetic::Overflow
        );
    }

    #[test]
    fn mixed_comparisons_decide_only_where_promotion_is_exact() {
        let x = signed32(0, 10);
        assert_eq!(
            refine_numeric_order(x, float(2.5), IntegerComparison::LessThan, true),
            GuardRefinement::Refined(signed32(0, 2))
        );
        assert_eq!(
            refine_numeric_order(x, float(2.5), IntegerComparison::LessThan, false),
            GuardRefinement::Refined(signed32(3, 10))
        );
        assert_eq!(
            refine_numeric_order(x, float(-0.5), IntegerComparison::LessThan, true),
            GuardRefinement::Infeasible
        );
        assert_eq!(
            refine_numeric_equality(x, float(2.5), true),
            GuardRefinement::Infeasible,
            "an integer never equals a fractional constant"
        );
        assert_eq!(
            refine_numeric_equality(x, float(2.5), false),
            GuardRefinement::Refined(x)
        );
        // 2^24 may be a Java float literal, to which an int operand rounds.
        let full = signed32(i128::from(i32::MIN), i128::from(i32::MAX));
        assert_eq!(
            refine_numeric_order(
                full,
                float((1_u64 << 24) as f64),
                IntegerComparison::LessThan,
                true
            ),
            GuardRefinement::Undecided
        );
        // 2^24 + 1 is not a binary32 value, so it is a binary64 constant, to
        // which every int converts exactly.
        assert_eq!(
            refine_numeric_order(
                full,
                float(((1_u64 << 24) + 1) as f64),
                IntegerComparison::GreaterThan,
                true
            ),
            GuardRefinement::Refined(signed32((1 << 24) + 2, i128::from(i32::MAX)))
        );

        let any = ScalarFact::Float(ScalarFloatRange::any());
        assert_eq!(
            refine_numeric_order(
                any,
                exact_integer((1 << 24) + 1),
                IntegerComparison::LessThan,
                true
            ),
            GuardRefinement::Undecided,
            "a binary32 operand would round the constant"
        );
        let GuardRefinement::Refined(ScalarFact::Float(below)) = refine_numeric_order(
            any,
            exact_integer(100_000_000),
            IntegerComparison::LessThan,
            true,
        ) else {
            panic!("10^8 is exactly a binary32 value");
        };
        assert_eq!(
            below.ordered().map(|(_, upper)| upper),
            Some(bound(1e8, false))
        );
        assert_eq!(
            refine_numeric_order(any, ScalarFact::Unknown, IntegerComparison::LessThan, true),
            GuardRefinement::Undecided
        );
    }

    #[test]
    fn truthiness_decides_known_scalars_and_leaves_possible_nan_open() {
        let zero = exact_integer(0);
        assert_eq!(refine_truth(zero, true), GuardRefinement::Infeasible);
        assert_eq!(refine_truth(zero, false), GuardRefinement::Refined(zero));
        assert_eq!(
            refine_truth(exact_integer(2), false),
            GuardRefinement::Infeasible
        );
        assert_eq!(
            refine_truth(ScalarFact::Nil, true),
            GuardRefinement::Infeasible
        );
        assert_eq!(
            refine_truth(ScalarFact::EitherBoolean, false),
            GuardRefinement::Refined(ScalarFact::False)
        );
        assert_eq!(refine_truth(float(0.0), true), GuardRefinement::Infeasible);
        assert_eq!(
            refine_truth(float(-0.0), false),
            GuardRefinement::Refined(float(0.0))
        );
        assert_eq!(refine_truth(float(0.5), false), GuardRefinement::Infeasible);
        // NaN is falsy in JavaScript and truthy in Python.
        assert_eq!(
            refine_truth(ScalarFact::Float(ScalarFloatRange::any()), true),
            GuardRefinement::Undecided
        );
        assert_eq!(
            refine_truth(ScalarFact::NonNil, true),
            GuardRefinement::Undecided
        );
        assert_eq!(
            refine_truth(ScalarFact::MaybeNil, false),
            GuardRefinement::Undecided
        );

        assert_eq!(
            refine_nan(exact_integer(1), true),
            GuardRefinement::Infeasible,
            "an integer is never NaN"
        );
        assert_eq!(
            refine_nan(ScalarFact::Unknown, true),
            GuardRefinement::Undecided
        );
    }

    #[test]
    fn java_typed_locals_join_in_their_declared_domain() {
        // Untyped, the parameter's int interval and the literal's
        // mathematical integer have different domains and join to a
        // non-exact integer. Declared as `int`, both writes take the int
        // domain, so the join is the full int range and `x > MAX` is
        // infeasible.
        let source = "class C { boolean f(int p, boolean c) { int x; if (c) x = p; else x = 5; if (x > 2147483647) return true; return false; } }";
        let fixture = Fixture::java(source, "f");
        let semantics = fixture.procedure.semantics();
        let guard = semantics
            .guard_facts()
            .iter()
            .find(|guard| {
                matches!(
                    guard.predicate,
                    GuardPredicate::OrderedIntegerComparison { .. }
                )
            })
            .expect("ordered int comparison is normalized");
        let seeds = fixture.java_seeds(source);
        assert_eq!(
            seeds
                .entry_facts
                .iter()
                .map(|seed| seed.fact.label())
                .collect::<Vec<_>>(),
            ["integer_interval", "either_boolean"],
            "`p` starts in the int domain and `c` as either Boolean"
        );
        let typed = fixture.java_typed(source);
        assert!(typed.is_reachable(guard.point));
        assert!(!typed.edge_is_feasible(guard.true_edge.expect("true edge")));
        let operand = typed
            .guard_operand_fact(&fixture.procedure, guard)
            .expect("operand fact");
        assert!(guard_decides(semantics, guard.predicate, operand));

        let untyped = ScalarStateDerivation::derive_with_entry_facts(
            &fixture.procedure,
            ScalarCallEffects::default(),
            &seeds.entry_facts,
        );
        assert!(untyped.edge_is_feasible(guard.true_edge.expect("true edge")));
        let operand = untyped
            .guard_operand_fact(&fixture.procedure, guard)
            .expect("operand fact");
        assert_eq!(operand, ScalarFact::NonExactInteger);
        assert!(!guard_decides(semantics, guard.predicate, operand));
    }

    #[test]
    fn java_scalar_seeds_type_numeric_formals_and_locals_and_seed_only_primitives() {
        let source = "class C { void f(int a, double b, float c, Integer d, int[] e, long g[]) { byte h = 1; char i = 'i'; double j = 1; var k = 1; int l[] = null; String m = null; } }";
        let fixture = Fixture::java(source, "f");
        let semantics = fixture.procedure.semantics();
        let seeds = fixture.java_seeds(source);
        let entry = seeds
            .entry_facts
            .iter()
            .map(|seed| match seed.fact {
                ScalarFact::Integer(interval) => format!("{:?}", interval.domain()),
                fact => fact.label().to_string(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            entry,
            ["Signed { bits: 32 }", "float_range", "float_range"],
            "{:?}",
            seeds.entry_facts
        );
        let mut typed = seeds
            .typing
            .bindings
            .iter()
            .map(|(value, binding_type)| {
                let value = semantics.value(*value).expect("typed value resolves");
                let kind = match value.kind {
                    SemanticValueKind::Parameter { ordinal, .. } => format!("parameter {ordinal}"),
                    _ => "local".to_string(),
                };
                (kind, *binding_type)
            })
            .collect::<Vec<_>>();
        typed.sort_by(|left, right| format!("{left:?}").cmp(&format!("{right:?}")));
        let expected = [
            (
                "local",
                ScalarBindingType::MachineInteger(ScalarIntegerDomain::signed(8)),
            ),
            (
                "local",
                ScalarBindingType::MachineInteger(ScalarIntegerDomain::unsigned(16)),
            ),
            ("local", ScalarBindingType::Binary64),
            (
                "parameter 0",
                ScalarBindingType::MachineInteger(ScalarIntegerDomain::signed(32)),
            ),
            ("parameter 1", ScalarBindingType::Binary64),
            ("parameter 2", ScalarBindingType::Binary32),
            // A boxed formal takes its primitive type but no entry fact,
            // because it may be null.
            (
                "parameter 3",
                ScalarBindingType::MachineInteger(ScalarIntegerDomain::signed(32)),
            ),
        ]
        .map(|(kind, binding_type)| (kind.to_string(), binding_type));
        let mut expected = expected.to_vec();
        expected.sort_by(|left, right| format!("{left:?}").cmp(&format!("{right:?}")));
        assert_eq!(typed, expected);
    }

    #[test]
    fn java_integral_equality_and_ordered_guards_contradict_in_either_order() {
        for (source, inner_is_equality, inner_negated) in [
            (
                "class C { boolean f(int x) { if (x > 5) { if (x == 3) return true; } return false; } }",
                true,
                false,
            ),
            (
                "class C { boolean f(int x) { if (x == 3) { if (x > 5) return true; } return false; } }",
                false,
                false,
            ),
            (
                "class C { boolean f(int x) { if (x > 5) { if (x != 3) return true; } return false; } }",
                true,
                true,
            ),
        ] {
            let fixture = Fixture::java(source, "f");
            let semantics = fixture.procedure.semantics();
            let scalar = fixture.java_typed(source);
            let inner = semantics
                .guard_facts()
                .iter()
                .find(|guard| {
                    if inner_is_equality {
                        matches!(guard.predicate, GuardPredicate::ConstantEquality { negated, .. } if negated == inner_negated)
                    } else {
                        matches!(guard.predicate, GuardPredicate::OrderedIntegerComparison { .. })
                    }
                })
                .expect("inner integer guard is normalized");
            assert!(scalar.is_reachable(inner.point), "{source}");
            assert_eq!(
                scalar.edge_is_feasible(inner.true_edge.expect("inner true edge")),
                inner_negated,
                "{source}"
            );
            assert_eq!(
                scalar.edge_is_feasible(inner.false_edge.expect("inner false edge")),
                !inner_negated,
                "{source}"
            );
        }
    }

    #[test]
    fn java_direct_integral_writes_replace_prior_interval_with_exact_literal() {
        for source in [
            "class C { boolean f(int x) { if (x > 5) { x = 1; if (x < 3) return true; } return false; } }",
            "class C { boolean f() { int x = 1; if (x < 3) return true; return false; } }",
        ] {
            let fixture = Fixture::java(source, "f");
            let semantics = fixture.procedure.semantics();
            let scalar = fixture.java_typed(source);
            let inner = semantics
                .guard_facts()
                .iter()
                .find(|guard| {
                    matches!(
                        guard.predicate,
                        GuardPredicate::OrderedIntegerComparison {
                            relation: IntegerComparison::LessThan,
                            constant,
                        } if semantics.value(constant).is_some_and(|value| value.kind == SemanticValueKind::UnsignedInteger(3))
                    )
                })
                .expect("inner comparison is normalized");
            assert!(scalar.is_reachable(inner.point), "{source}");
            assert!(
                scalar.edge_is_feasible(inner.true_edge.expect("true edge")),
                "{source}"
            );
            assert!(
                !scalar.edge_is_feasible(inner.false_edge.expect("false edge")),
                "{source}"
            );
            assert!(
                semantics
                    .values()
                    .iter()
                    .any(|value| value.kind == SemanticValueKind::UnsignedInteger(1)),
                "assignment literal retains its exact value: {source}"
            );
        }
    }

    #[test]
    fn java_field_comparisons_remain_opaque() {
        let source = "class C { int x; boolean f() { if (x < 3) return true; return false; } }";
        let fixture = Fixture::java(source, "f");
        assert!(
            fixture
                .procedure
                .semantics()
                .guard_facts()
                .iter()
                .all(|guard| !matches!(
                    guard.predicate,
                    GuardPredicate::OrderedIntegerComparison { .. }
                )),
            "{source}"
        );
    }

    #[test]
    fn nested_null_identity_guards_prove_the_inner_true_arm_infeasible() {
        for (language, filename, source) in [
            (
                Language::Java,
                "C.java",
                "class C { boolean f(Object x) { if (x == null) { if (x != null) return true; } return false; } }",
            ),
            (
                Language::TypeScript,
                "main.ts",
                "function f(x: unknown) { if (x === null) { if (x !== null) return true; } return false; }",
            ),
            (
                Language::JavaScript,
                "main.js",
                "function f(x) { if (x === null) { if (x !== null) return true; } return false; }",
            ),
            (
                Language::Python,
                "main.py",
                "def f(x):\n    if x is None:\n        if x is not None:\n            return True\n    return False\n",
            ),
        ] {
            let fixture = Fixture::source(language, filename, source, "f");
            let semantics = fixture.procedure.semantics();
            let mut guards = semantics
                .guard_facts()
                .iter()
                .filter(|guard| matches!(guard.predicate, GuardPredicate::NullComparison { .. }))
                .collect::<Vec<_>>();
            guards.sort_by_key(|guard| {
                semantics
                    .source_mapping(guard.source)
                    .expect("guard has source")
                    .locator
                    .anchor()
                    .span()
                    .start_byte()
            });
            assert_eq!(guards.len(), 2, "{language:?}: {guards:?}");
            let inner = guards[1];
            let scalar = ScalarStateDerivation::derive(&fixture.procedure);
            assert!(scalar.is_reachable(inner.point), "{language:?}");
            assert!(
                !scalar.edge_is_feasible(inner.true_edge.expect("inner true arm")),
                "{language:?}"
            );
            assert!(
                scalar.edge_is_feasible(inner.false_edge.expect("inner false arm")),
                "{language:?}"
            );
        }
    }

    #[test]
    fn signed_magnitude_intervals_order_and_join_without_host_casts() {
        let domain = ScalarIntegerDomain::signed(8);
        let negative_two = ScalarIntegerValue::new(true, 2);
        let positive_three = ScalarIntegerValue::unsigned(3);
        let negative_seven = ScalarIntegerValue::new(true, 7);
        assert!(negative_seven < negative_two);
        assert!(negative_two < ScalarIntegerValue::unsigned(0));
        assert!(domain.contains(ScalarIntegerValue::new(true, 128)));
        assert!(!domain.contains(ScalarIntegerValue::new(true, 129)));
        assert!(domain.contains(ScalarIntegerValue::unsigned(127)));
        assert!(!domain.contains(ScalarIntegerValue::unsigned(128)));

        let left = ScalarIntegerInterval::new(negative_two, positive_three, domain);
        let right = ScalarIntegerInterval::new(
            ScalarIntegerValue::new(true, 7),
            ScalarIntegerValue::unsigned(1),
            domain,
        );
        assert_eq!(
            left.hull(right),
            Some(ScalarIntegerInterval::new(
                negative_seven,
                positive_three,
                domain
            ))
        );
        assert_eq!(
            ScalarFact::Integer(left).join(ScalarFact::Integer(right)),
            ScalarFact::Integer(ScalarIntegerInterval::new(
                negative_seven,
                positive_three,
                domain
            ))
        );
    }

    #[test]
    fn interval_arithmetic_distinguishes_domain_overflow_from_representation_limits() {
        let mathematical = ScalarIntegerDomain::Mathematical;
        let left = ScalarIntegerInterval::new(
            ScalarIntegerValue::new(true, 2),
            ScalarIntegerValue::unsigned(3),
            mathematical,
        );
        let right = ScalarIntegerInterval::new(
            ScalarIntegerValue::unsigned(4),
            ScalarIntegerValue::unsigned(5),
            mathematical,
        );
        assert_eq!(
            left.add_interval(right),
            ScalarIntegerArithmetic::Interval(ScalarIntegerInterval::new(
                ScalarIntegerValue::unsigned(2),
                ScalarIntegerValue::unsigned(8),
                mathematical,
            ))
        );
        assert_eq!(
            left.subtract_interval(right),
            ScalarIntegerArithmetic::Interval(ScalarIntegerInterval::new(
                ScalarIntegerValue::new(true, 7),
                ScalarIntegerValue::new(true, 1),
                mathematical,
            ))
        );

        let unsigned = ScalarIntegerDomain::unsigned(8);
        assert_eq!(
            ScalarIntegerInterval::exact(ScalarIntegerValue::unsigned(255), unsigned).add_interval(
                ScalarIntegerInterval::exact(ScalarIntegerValue::unsigned(1), unsigned,)
            ),
            ScalarIntegerArithmetic::Overflow
        );
        assert_eq!(
            ScalarIntegerInterval::exact(ScalarIntegerValue::unsigned(u128::MAX), mathematical)
                .add_interval(ScalarIntegerInterval::exact(
                    ScalarIntegerValue::unsigned(1),
                    mathematical
                )),
            ScalarIntegerArithmetic::MagnitudeExceeded
        );
        assert_eq!(
            ScalarIntegerInterval::exact(ScalarIntegerValue::unsigned(1), mathematical)
                .add_interval(ScalarIntegerInterval::exact(
                    ScalarIntegerValue::unsigned(1),
                    unsigned,
                )),
            ScalarIntegerArithmetic::UnknownDomain
        );
    }

    #[test]
    fn widening_is_finite_only_when_the_integer_domain_is_finite() {
        let signed = ScalarIntegerDomain::signed(8);
        let current = ScalarIntegerInterval::new(
            ScalarIntegerValue::new(true, 2),
            ScalarIntegerValue::unsigned(3),
            signed,
        );
        let growing = ScalarIntegerInterval::new(
            ScalarIntegerValue::new(true, 4),
            ScalarIntegerValue::unsigned(5),
            signed,
        );
        assert_eq!(
            current.widen(growing),
            ScalarIntegerWidening::Interval(ScalarIntegerInterval::new(
                ScalarIntegerValue::new(true, 128),
                ScalarIntegerValue::unsigned(127),
                signed,
            ))
        );

        let mathematical = ScalarIntegerDomain::Mathematical;
        let current = ScalarIntegerInterval::exact(ScalarIntegerValue::unsigned(1), mathematical);
        let growing = ScalarIntegerInterval::new(
            ScalarIntegerValue::unsigned(1),
            ScalarIntegerValue::unsigned(2),
            mathematical,
        );
        assert_eq!(current.widen(growing), ScalarIntegerWidening::Unbounded);
        assert_eq!(
            current.widen(ScalarIntegerInterval::exact(
                ScalarIntegerValue::unsigned(1),
                ScalarIntegerDomain::unsigned(8),
            )),
            ScalarIntegerWidening::UnknownDomain
        );
    }

    #[test]
    fn pointer_zero_and_address_join_to_maybe_nil() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func run(flag bool) int {
    var value *item
    if flag { value = &item{} }
    return value.field
}
"#,
            "run",
        );
        assert_eq!(fixture.field_base_facts(), vec![ScalarFact::MaybeNil]);
    }

    #[test]
    fn preserving_scalar_transfers_keep_the_source_fact() {
        let transfers = [
            ValueTransfer {
                kind: TransferKind::Copy,
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Move {
                    invalidation: MoveInvalidation::Invalidated,
                },
                operation: TransferOperation::CallSite(
                    CallSiteId::try_from_index(0).expect("zero is a valid call-site index"),
                ),
            },
            ValueTransfer {
                kind: TransferKind::Conversion {
                    preservation: ValuePreservation::Identity,
                },
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Conversion {
                    preservation: ValuePreservation::Preserving,
                },
                operation: TransferOperation::None,
            },
        ];
        for transfer in transfers {
            assert_eq!(
                transferred_scalar_fact(exact_integer(7), transfer),
                (
                    exact_integer(7),
                    matches!(transfer.kind, TransferKind::Move { .. })
                ),
                "{transfer:?}"
            );
        }
    }

    #[test]
    fn uncertain_and_non_scalar_preserving_transfers_stay_conservative() {
        let transfers = [
            ValueTransfer {
                kind: TransferKind::Copy,
                operation: TransferOperation::Unknown,
            },
            ValueTransfer {
                kind: TransferKind::AggregateCopy,
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Boxing,
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Unboxing,
                operation: TransferOperation::None,
            },
            ValueTransfer {
                kind: TransferKind::Conversion {
                    preservation: ValuePreservation::Changing,
                },
                operation: TransferOperation::None,
            },
        ];
        for transfer in transfers {
            assert_eq!(
                transferred_scalar_fact(exact_integer(7), transfer),
                (ScalarFact::Unknown, false),
                "{transfer:?}"
            );
        }
    }

    #[test]
    fn both_move_contracts_invalidate_the_source_scalar_fact() {
        for invalidation in [MoveInvalidation::Invalidated, MoveInvalidation::Unknown] {
            let transfer = ValueTransfer {
                kind: TransferKind::Move { invalidation },
                operation: TransferOperation::None,
            };
            assert_eq!(
                transferred_scalar_fact(ScalarFact::NonNil, transfer),
                (ScalarFact::NonNil, true),
                "{transfer:?}"
            );
        }
    }

    #[test]
    fn null_guard_refines_the_surviving_arm() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func run(value *item) int {
    if value == nil { return 0 }
    return value.field
}
"#,
            "run",
        );
        assert_eq!(
            fixture.field_base_facts(),
            vec![ScalarFact::NonNil],
            "{:#?}",
            fixture.procedure.semantics()
        );
    }

    #[test]
    fn exact_local_integer_reaches_an_index_operation() {
        let fixture = Fixture::go(
            r#"package sample
func run(values []int) int {
    start := 0x1
    return values[start]
}
"#,
            "run",
        );
        let derivation = ScalarStateDerivation::derive(&fixture.procedure);
        let semantics = fixture.procedure.semantics();
        let facts = semantics
            .points()
            .iter()
            .flat_map(|point| {
                point.events.iter().filter_map(|event| match event.effect {
                    SemanticEffect::MemoryLoad { location, .. } => {
                        let MemoryLocationKind::Index {
                            index: Some(index), ..
                        } = semantics.memory_location(location)?.kind
                        else {
                            return None;
                        };
                        Some(derivation.fact_at(point.id, index))
                    }
                    _ => None,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(facts, vec![exact_integer(1)], "{semantics:#?}");
    }

    #[test]
    fn seeded_countdown_prunes_ordered_arms_and_computes_the_next_argument() {
        let fixture = Fixture::go(
            r#"package sample
type cell struct{}
func run(ch chan *cell, value *cell, depth int) {
    if depth > 0 { run(ch, value, depth - 1); return }
    ch <- value
}
"#,
            "run",
        );
        let semantics = fixture.procedure.semantics();
        let depth = semantics
            .values()
            .iter()
            .find_map(|value| match &value.kind {
                SemanticValueKind::Parameter {
                    name: Some(name), ..
                } if name.as_ref() == "depth" => Some(value.id),
                _ => None,
            })
            .expect("depth formal");
        let [call] = semantics.call_sites() else {
            panic!("one recursive call: {semantics:#?}");
        };
        let call_point = semantics
            .points()
            .iter()
            .find(|point| {
                point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::Invoke { call_site } if call_site == call.id
                    )
                })
            })
            .map(|point| point.id)
            .expect("recursive call point");
        let send_point = semantics
            .points()
            .iter()
            .find(|point| {
                point
                    .events
                    .iter()
                    .any(|event| matches!(event.effect, SemanticEffect::Synchronization { .. }))
            })
            .map(|point| point.id)
            .expect("channel send point");
        let next_depth = call.arguments[2].value;

        let one = ScalarStateDerivation::derive_with_entry_facts(
            &fixture.procedure,
            ScalarCallEffects::default(),
            &[ScalarEntryFact {
                target: depth,
                fact: exact_integer(1),
            }],
        );
        assert!(one.is_reachable(call_point));
        assert!(!one.is_reachable(send_point));
        assert_eq!(one.fact_at(call_point, next_depth), exact_integer(0));

        let zero = ScalarStateDerivation::derive_with_entry_facts(
            &fixture.procedure,
            ScalarCallEffects::default(),
            &[ScalarEntryFact {
                target: depth,
                fact: exact_integer(0),
            }],
        );
        assert!(!zero.is_reachable(call_point));
        assert!(zero.is_reachable(send_point));

        let unknown = ScalarStateDerivation::derive(&fixture.procedure);
        assert!(unknown.is_reachable(call_point));
        assert!(unknown.is_reachable(send_point));
    }

    #[test]
    fn represented_integer_offset_overflow_stays_unknown() {
        let fixture = Fixture::go(
            r#"package sample
func run(value int) int { return value + 1 }
"#,
            "run",
        );
        let semantics = fixture.procedure.semantics();
        let parameter = semantics
            .values()
            .iter()
            .find_map(|value| {
                matches!(value.kind, SemanticValueKind::Parameter { .. }).then_some(value.id)
            })
            .expect("integer parameter");
        let (point, result) = semantics
            .points()
            .iter()
            .find_map(|point| {
                point.events.iter().find_map(|event| match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::IntegerOffset { .. },
                        target,
                        ..
                    } => Some((point.id, target)),
                    _ => None,
                })
            })
            .expect("integer offset flow");
        let derivation = ScalarStateDerivation::derive_with_entry_facts(
            &fixture.procedure,
            ScalarCallEffects::default(),
            &[ScalarEntryFact {
                target: parameter,
                fact: exact_integer(u128::MAX),
            }],
        );
        assert_eq!(derivation.fact_at(point, result), ScalarFact::Unknown);
    }

    #[test]
    fn opaque_call_result_kills_an_earlier_nil_binding() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func acquire() *item { return nil }
func run() int {
    var value *item
    value = acquire()
    return value.field
}
"#,
            "run",
        );
        assert_eq!(fixture.field_base_facts(), vec![ScalarFact::Unknown]);
    }

    #[test]
    fn mutable_closure_capture_kills_an_earlier_nil_binding() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func acquire() *item { return nil }
func run() int {
    var value *item
    func() { value = acquire() }()
    return value.field
}
"#,
            "run",
        );
        assert_eq!(fixture.field_base_facts(), vec![ScalarFact::Unknown]);
    }

    #[test]
    fn modeled_terminating_call_removes_its_normal_scalar_path() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func stop() {}
func run(value *item) int {
    if value == nil { stop() }
    return value.field
}
"#,
            "run",
        );
        let semantics = fixture.procedure.semantics();
        let call = semantics
            .call_sites()
            .iter()
            .find(|call| call.normal_continuation.target().is_some())
            .expect("run contains the stop invocation");
        let normal = call
            .normal_continuation
            .target()
            .expect("stop has a raw normal continuation");
        let infeasible = semantics
            .successor_edges(call.point)
            .filter_map(|(edge, control)| (control.target_point == normal).then_some(edge))
            .collect::<Vec<_>>();
        let [infeasible] = infeasible.as_slice() else {
            panic!("one raw edge reaches the call's normal continuation: {semantics:#?}");
        };
        let derivation = ScalarStateDerivation::derive_with_call_effects(
            &fixture.procedure,
            ScalarCallEffects {
                modeled_address_calls: &[],
                edge_writes: &[],
                infeasible_edges: &[*infeasible],
            },
        );
        let facts = semantics
            .points()
            .iter()
            .flat_map(|point| {
                point.events.iter().filter_map(|event| match event.effect {
                    SemanticEffect::MemoryLoad { location, .. } => {
                        let (MemoryLocationKind::Field { base, .. }
                        | MemoryLocationKind::Property { base, .. }) =
                            &semantics.memory_location(location)?.kind
                        else {
                            return None;
                        };
                        Some(derivation.fact_at(point.id, *base))
                    }
                    _ => None,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(facts, vec![ScalarFact::NonNil], "{semantics:#?}");
    }

    #[test]
    fn address_arguments_invalidate_unmodeled_bindings_but_complete_models_preserve_them() {
        let fixture = Fixture::go(
            r#"package sample
type item struct { field int }
func mutate(value **item) {}
func run() int {
    value := &item{}
    mutate(&value)
    return value.field
}
"#,
            "run",
        );
        assert_eq!(fixture.field_base_facts(), vec![ScalarFact::Unknown]);

        let call = fixture
            .procedure
            .semantics()
            .call_sites()
            .iter()
            .find(|call| !call.arguments.is_empty())
            .expect("run contains the mutate invocation");
        let modeled = ScalarStateDerivation::derive_with_call_effects(
            &fixture.procedure,
            ScalarCallEffects {
                modeled_address_calls: &[call.id],
                edge_writes: &[],
                infeasible_edges: &[],
            },
        );
        let semantics = fixture.procedure.semantics();
        let facts = semantics
            .points()
            .iter()
            .flat_map(|point| {
                point.events.iter().filter_map(|event| match event.effect {
                    SemanticEffect::MemoryLoad { location, .. } => {
                        let (MemoryLocationKind::Field { base, .. }
                        | MemoryLocationKind::Property { base, .. }) =
                            &semantics.memory_location(location)?.kind
                        else {
                            return None;
                        };
                        Some(modeled.fact_at(point.id, *base))
                    }
                    _ => None,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(facts, vec![ScalarFact::NonNil], "{semantics:#?}");
    }

    #[test]
    fn modeled_address_calls_do_not_close_published_or_indirectly_mutated_cells() {
        for body in [
            "mutate(&value); out <- &value",
            "mutate(&value); go func() { value = nil }()",
            "alias := &value; mutate(&value); *alias = nil",
            "alias := &value; mutate(&value); unknown(alias)",
        ] {
            let fixture = Fixture::go(
                &format!(
                    r#"package sample
type item struct {{ field int }}
func mutate(value **item) {{}}
func run(out chan **item) int {{
    value := &item{{}}
    {body}
    return value.field
}}
"#
                ),
                "run",
            );
            let semantics = fixture.procedure.semantics();
            let modeled_calls = semantics
                .call_sites()
                .iter()
                .filter(|call| {
                    call.arguments.iter().any(|argument| {
                        semantics
                            .value(argument.value)
                            .is_some_and(|value| value.kind == SemanticValueKind::Address)
                    })
                })
                .map(|call| call.id)
                .collect::<Vec<_>>();
            assert_eq!(modeled_calls.len(), 1, "{body}: {semantics:#?}");
            let derivation = ScalarStateDerivation::derive_with_call_effects(
                &fixture.procedure,
                ScalarCallEffects {
                    modeled_address_calls: &modeled_calls,
                    edge_writes: &[],
                    infeasible_edges: &[],
                },
            );
            assert_eq!(
                fixture.field_base_facts_from(&derivation),
                vec![ScalarFact::Unknown],
                "{body}: {semantics:#?}"
            );
        }
    }

    #[test]
    fn widening_gives_up_an_integer_bound_that_still_moves() {
        let domain = ScalarIntegerDomain::unsigned(8);
        let settled = ScalarFact::Integer(ScalarIntegerInterval::new(
            ScalarIntegerValue::unsigned(1),
            ScalarIntegerValue::unsigned(4),
            domain,
        ));
        // A join that stays inside the current bounds is not a growth signal.
        assert_eq!(
            settled.widen(ScalarFact::Integer(ScalarIntegerInterval::exact(
                ScalarIntegerValue::unsigned(2),
                domain
            ))),
            settled
        );
        // A finite domain has a bound to jump to.
        assert_eq!(
            settled.widen(ScalarFact::Integer(ScalarIntegerInterval::exact(
                ScalarIntegerValue::unsigned(5),
                domain
            ))),
            ScalarFact::Integer(ScalarIntegerInterval::new(
                ScalarIntegerValue::unsigned(1),
                ScalarIntegerValue::unsigned(255),
                domain
            ))
        );
        // The mathematical domain has none, so the value stops being exact.
        let unbounded = ScalarFact::Integer(ScalarIntegerInterval::exact(
            ScalarIntegerValue::unsigned(0),
            ScalarIntegerDomain::Mathematical,
        ));
        assert_eq!(
            unbounded.widen(exact_integer(1)),
            ScalarFact::NonExactInteger
        );
        // Everything else in the lattice is the ordinary join.
        assert_eq!(
            ScalarFact::Nil.widen(ScalarFact::NonNil),
            ScalarFact::MaybeNil
        );
        assert_eq!(
            ScalarFact::Unreachable.widen(exact_integer(3)),
            exact_integer(3)
        );
    }

    #[test]
    fn a_counted_loop_bounds_its_induction_variable() {
        let fixture = Fixture::go(
            r#"package sample
func take(value int) {}
func run() {
    for index := 0; index < 3; index++ {
        take(index)
    }
}
"#,
            "run",
        );
        assert_eq!(
            fixture.call_argument_facts(),
            vec![ScalarFact::Integer(ScalarIntegerInterval::new(
                ScalarIntegerValue::unsigned(0),
                ScalarIntegerValue::unsigned(2),
                ScalarIntegerDomain::Mathematical,
            ))],
            "an ordered guard and a structured step bound the induction variable"
        );
    }

    #[test]
    fn a_loop_longer_than_the_join_limit_widens_its_induction_variable() {
        let fixture = Fixture::go(
            &format!(
                r#"package sample
func take(value int) {{}}
func run() {{
    for index := 0; index < {limit}; index++ {{
        take(index)
    }}
}}
"#,
                limit = POINT_JOIN_WIDENING_LIMIT * 4,
            ),
            "run",
        );
        // Widening drops the bound, and the next step's offset over a value
        // with no interval is unknown. The contrast with the counted loop
        // above is what shows the limit, not the derivation, decided this.
        assert_eq!(
            fixture.call_argument_facts(),
            vec![ScalarFact::Unknown],
            "a loop past the join limit keeps no bound rather than iterating to one"
        );
    }

    #[test]
    fn an_unbounded_counting_loop_reaches_a_fixed_point() {
        let fixture = Fixture::go(
            r#"package sample
func take(value int) {}
func run() {
    index := 0
    for {
        index++
        take(index)
    }
}
"#,
            "run",
        );
        assert_eq!(
            fixture.call_argument_facts(),
            vec![ScalarFact::Unknown],
            "a loop with no bound must terminate the derivation instead of growing"
        );
    }
}
