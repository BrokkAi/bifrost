use super::{ScalarFact, ScalarState, scalar_join_properties};
use proptest::prelude::*;

fn edited_snapshot(
    state: &ScalarState,
    dense: &[ScalarFact],
    edits: &[(usize, u8)],
    pool: &[ScalarFact],
) -> (ScalarState, Vec<ScalarFact>) {
    let mut incoming = state.clone();
    let mut other = dense.to_vec();
    for &(index, value) in edits {
        if !other.is_empty() {
            let index = index % other.len();
            let fact = pool[usize::from(value) % pool.len()];
            incoming.set(index, fact);
            other[index] = fact;
        }
    }
    (incoming, other)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn persistent_state_matches_dense_oracle(
        len in prop::sample::select(vec![0, 1, 15, 16, 17, 31, 32, 33, 511, 513]),
        operations in prop::collection::vec(
            (0_u8..6, any::<usize>(), any::<u8>(),
                prop::collection::vec((any::<usize>(), any::<u8>()), 0..5)),
            1..60,
        ),
    ) {
        let pool = scalar_join_properties::facts();
        let mut dense = vec![ScalarFact::Unreachable; len];
        let mut state = ScalarState::from_vec(dense.clone());
        for (op, index, value, edits) in operations {
            let idx = index % len.max(1);
            let fact = pool[usize::from(value) % pool.len()];
            match op {
                0 if len > 0 => { dense[idx] = fact; state.set(idx, fact); }
                1 if len > 0 => { prop_assert_eq!(state.get(idx), dense.get(idx).copied()); }
                2 => {
                    let clone = state.clone();
                    let before = dense.get(idx).copied();
                    prop_assert_eq!(&clone, &state);
                    if len > 0 { state.set(idx, fact); dense[idx] = fact; }
                    prop_assert_eq!(clone.get(idx), before);
                }
                3 | 4 => {
                    let (incoming, other) = edited_snapshot(&state, &dense, &edits, &pool);
                    let step: fn(ScalarFact, ScalarFact) -> ScalarFact =
                        if op == 3 { ScalarFact::join } else { ScalarFact::widen };
                    let changed = dense.iter().zip(&other).any(|(&a, &b)| step(a, b) != a);
                    for (a, &b) in dense.iter_mut().zip(&other) { *a = step(*a, b); }
                    prop_assert_eq!(state.merge(&incoming, step), changed);
                }
                _ => {
                    let (incoming, other) = edited_snapshot(&state, &dense, &edits, &pool);
                    prop_assert_eq!(state == incoming, dense == other);
                }
            }
            prop_assert_eq!((0..len).map(|i| state[i]).collect::<Vec<_>>(), dense.clone());
        }
    }
}
