use super::{
    ScalarFact, ScalarFloatBound, ScalarFloatRange, ScalarIntegerArithmetic, ScalarIntegerDomain,
    ScalarIntegerInterval, ScalarIntegerValue, ScalarIntegerWidening,
};
use crate::analyzer::semantic::IntegerComparison;
use proptest::prelude::*;

fn integer(n: i16) -> ScalarIntegerValue {
    ScalarIntegerValue::new(n < 0, u128::from(n.unsigned_abs()))
}

fn interval(lo: i16, hi: i16, domain: ScalarIntegerDomain) -> ScalarIntegerInterval {
    ScalarIntegerInterval::new(integer(lo), integer(hi), domain)
}

fn bounds(min: i16, max: i16) -> impl Strategy<Value = (i16, i16)> {
    (min..=max, min..=max).prop_map(|(a, b)| (a.min(b), a.max(b)))
}

fn contains(range: ScalarFloatRange, n: f64) -> bool {
    if n.is_nan() {
        return range.may_be_nan();
    }
    range.ordered().is_some_and(|(lo, hi)| {
        (n > lo.value() || (n == lo.value() && lo.inclusive()))
            && (n < hi.value() || (n == hi.value() && hi.inclusive()))
    })
}

fn ranges() -> Vec<ScalarFloatRange> {
    let mut ranges = vec![ScalarFloatRange::new(None, true).unwrap()];
    for lo in [f64::NEG_INFINITY, -1.0, 0.0, 1.0, f64::INFINITY] {
        for hi in [f64::NEG_INFINITY, -1.0, 0.0, 1.0, f64::INFINITY] {
            for lower_inclusive in [false, true] {
                for upper_inclusive in [false, true] {
                    for nan in [false, true] {
                        if let Some(range) = ScalarFloatRange::new(
                            Some((
                                ScalarFloatBound::new(lo, lower_inclusive),
                                ScalarFloatBound::new(hi, upper_inclusive),
                            )),
                            nan,
                        ) {
                            ranges.push(range);
                        }
                    }
                }
            }
        }
    }
    ranges
}

fn facts() -> Vec<ScalarFact> {
    let mut facts = vec![
        ScalarFact::Unreachable,
        ScalarFact::Nil,
        ScalarFact::NonNil,
        ScalarFact::MaybeNil,
        ScalarFact::True,
        ScalarFact::False,
        ScalarFact::EitherBoolean,
        ScalarFact::NonExactInteger,
        ScalarFact::Unconstrained,
        ScalarFact::Unknown,
    ];
    for domain in [
        ScalarIntegerDomain::Mathematical,
        ScalarIntegerDomain::signed(8),
        ScalarIntegerDomain::unsigned(8),
    ] {
        for lo in 0..=2 {
            for hi in lo..=2 {
                facts.push(ScalarFact::Integer(interval(lo, hi, domain)));
            }
        }
    }
    facts.extend(ranges().into_iter().map(ScalarFact::Float));
    facts
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn domain_conversion_preserves_all_values_or_refuses((lo, hi) in bounds(-9, 9)) {
        let original = interval(lo, hi, ScalarIntegerDomain::signed(8));
        for (domain, min, max) in [
            (ScalarIntegerDomain::signed(4), -8, 7),
            (ScalarIntegerDomain::unsigned(3), 0, 7),
        ] {
            let converted = original.in_domain(domain);
            prop_assert_eq!(converted.is_some(), (lo..=hi).all(|n| (min..=max).contains(&n)));
            if let Some(converted) = converted {
                prop_assert_eq!((converted.lower(), converted.upper(), converted.domain()),
                    (original.lower(), original.upper(), domain));
            }
        }
    }

    #[test]
    fn widening_preserves_the_stationary_bound_and_stabilizes(lower_moves in any::<bool>()) {
        let domain = ScalarIntegerDomain::signed(8);
        let sequence = if lower_moves { [(5, 10), (4, 10), (3, 10)] }
            else { [(3, 5), (3, 6), (3, 7)] };
        let mut current = interval(sequence[0].0, sequence[0].1, domain);
        let mut previous = None;
        for &(lo, hi) in &sequence[1..] {
            let ScalarIntegerWidening::Interval(next) = current.widen(interval(lo, hi, domain)) else {
                panic!("finite-domain widening must retain an interval");
            };
            for n in lo..=hi {
                prop_assert!(next.lower() <= integer(n) && integer(n) <= next.upper());
            }
            if lower_moves { prop_assert_eq!(next.upper(), integer(hi)); }
            else { prop_assert_eq!(next.lower(), integer(lo)); }
            if let Some(previous) = previous { prop_assert_eq!(next, previous); }
            previous = Some(next);
            current = next;
        }
    }

    #[test]
    fn unsigned_arithmetic_contains_every_modular_result(
        (lo, hi) in bounds(0, 7), (other_lo, other_hi) in bounds(0, 7)
    ) {
        let domain = ScalarIntegerDomain::unsigned(3);
        let a = interval(lo, hi, domain);
        let b = interval(other_lo, other_hi, domain);
        for (result, subtract) in [(a.add_interval(b), false), (a.subtract_interval(b), true)] {
            let ScalarIntegerArithmetic::Interval(result) = result else {
                panic!("modular arithmetic must return an interval: {result:?}");
            };
            for x in lo..=hi { for y in other_lo..=other_hi {
                let concrete = if subtract { (x-y).rem_euclid(8) } else { (x+y)%8 };
                prop_assert!(result.lower() <= integer(concrete) && integer(concrete) <= result.upper());
                if lo == hi && other_lo == other_hi { prop_assert_eq!(result.exact_value(), Some(integer(concrete))); }
            }}
        }
    }

    #[test]
    fn floating_hulls_and_refinements_agree_with_ieee_membership(
        a in proptest::sample::select(ranges()),
        b in proptest::sample::select(ranges()),
        c in proptest::sample::select(ranges()),
        constant in proptest::sample::select(vec![-1.0, 0.0, 1.0]),
        relation in proptest::sample::select(vec![IntegerComparison::LessThan,
            IntegerComparison::LessThanOrEqual, IntegerComparison::GreaterThan,
            IntegerComparison::GreaterThanOrEqual]), truth in any::<bool>()
    ) {
        prop_assert_eq!(a.hull(a), a);
        let exact = a.ordered().filter(|(lo, hi)| lo.value() == hi.value()
            && lo.inclusive() && hi.inclusive() && !a.may_be_nan()).map(|(lo, _)| lo.value());
        prop_assert_eq!(a.exact_value(), exact);
        prop_assert_eq!(a.hull(b), b.hull(a));
        prop_assert_eq!(a.hull(b).hull(c), a.hull(b.hull(c)));
        let refined = a.refine_order(relation, constant, truth);
        for n in [f64::NEG_INFINITY, -2.0, -1.0, -0.5, -0.0, 0.0, 0.5, 1.0, 2.0, f64::INFINITY, f64::NAN] {
            if contains(a, n) || contains(b, n) { prop_assert!(contains(a.hull(b), n)); }
            let comparison = match relation {
                IntegerComparison::LessThan => n < constant,
                IntegerComparison::LessThanOrEqual => n <= constant,
                IntegerComparison::GreaterThan => n > constant,
                IntegerComparison::GreaterThanOrEqual => n >= constant,
            };
            prop_assert_eq!(refined.is_some_and(|range| contains(range, n)), contains(a, n) && comparison == truth);
        }
    }

    #[test]
    fn mixed_numeric_joins_preserve_negative_integer_witnesses(
        (lo, hi) in bounds(-3, 3), n in proptest::sample::select(vec![-1.0, 0.0, 1.0])
    ) {
        let a = ScalarFact::Integer(interval(lo, hi, ScalarIntegerDomain::signed(8)));
        let b = ScalarFact::Float(ScalarFloatRange::exact(n));
        for joined in [a.join(b), b.join(a)] {
            let ScalarFact::Float(joined) = joined else { panic!("small integers convert exactly"); };
            prop_assert!(contains(joined, n));
            for integer in lo..=hi { prop_assert!(contains(joined, f64::from(integer))); }
        }
    }

    #[test]
    fn scalar_join_is_commutative_idempotent_and_an_upper_bound(
        a in proptest::sample::select(facts()), b in proptest::sample::select(facts())
    ) {
        prop_assert_eq!(a.join(a), a);
        let joined = a.join(b);
        prop_assert_eq!(joined, b.join(a));
        prop_assert_eq!(a.join(joined), joined);
        prop_assert_eq!(b.join(joined), joined);
    }
}

#[test]
fn unsigned_maximum_wraps_to_zero() {
    let domain = ScalarIntegerDomain::unsigned(128);
    let max = ScalarIntegerInterval::exact(ScalarIntegerValue::unsigned(u128::MAX), domain);
    let one = ScalarIntegerInterval::exact(ScalarIntegerValue::unsigned(1), domain);
    assert_eq!(
        max.add_interval(one),
        ScalarIntegerArithmetic::Interval(ScalarIntegerInterval::exact(
            ScalarIntegerValue::unsigned(0),
            domain
        ))
    );
}

#[test]
fn strict_refinement_excludes_an_existing_inclusive_boundary() {
    let nonnegative = ScalarFloatRange::any()
        .refine_order(IntegerComparison::GreaterThanOrEqual, 0.0, true)
        .unwrap();
    assert!(!contains(
        nonnegative
            .refine_order(IntegerComparison::GreaterThan, 0.0, true)
            .unwrap(),
        0.0
    ));
}

#[test]
fn nan_possible_singleton_does_not_claim_an_exact_value() {
    let zero = ScalarFloatBound::new(0.0, true);
    let possibly_nan = ScalarFloatRange::new(Some((zero, zero)), true).unwrap();
    assert_eq!(possibly_nan.exact_value(), None);
    assert_eq!(ScalarFloatRange::exact(0.0).exact_value(), Some(0.0));
}

#[test]
#[ignore = "finds real bug #7898: joining different integer domains before a float loses precision"]
fn scalar_join_is_associative_across_integer_domains_and_floats() {
    let a = ScalarFact::Integer(interval(0, 0, ScalarIntegerDomain::signed(8)));
    let b = ScalarFact::Integer(interval(0, 0, ScalarIntegerDomain::unsigned(8)));
    let c = ScalarFact::Float(ScalarFloatRange::exact(0.0));
    assert_eq!(a.join(b).join(c), a.join(b.join(c)), "{a:?}, {b:?}, {c:?}");
}

#[test]
#[ignore = "finds real bug #7898: ScalarFact join is not associative across fact domains"]
fn scalar_join_associativity_over_generated_facts() {
    let facts = facts();
    for &a in &facts {
        for &b in &facts {
            for &c in &facts {
                assert_eq!(a.join(b).join(c), a.join(b.join(c)), "{a:?}, {b:?}, {c:?}");
            }
        }
    }
}

#[test]
#[ignore = "finds real bug #7898: incompatible facts join inconsistently with Unconstrained"]
fn scalar_join_is_associative_with_unconstrained_and_incompatible_facts() {
    let a = ScalarFact::Nil;
    let b = ScalarFact::True;
    let c = ScalarFact::Unconstrained;
    assert_eq!(a.join(b).join(c), a.join(b.join(c)), "{a:?}, {b:?}, {c:?}");
}
