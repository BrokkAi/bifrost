use crate::taint::{SourceClassId, TaintModelError, TaintUniverse};
use std::collections::BTreeSet;

fn label(name: &str) -> SourceClassId {
    SourceClassId::new(name).unwrap()
}

#[test]
fn stable_labels_validate_universe_membership_and_printable_ids() {
    assert_eq!(label("user supplied").as_str(), "user supplied");
    for invalid in [
        "",
        " alpha",
        "alpha ",
        "user\0supplied",
        "user\u{7f}supplied",
    ] {
        assert_eq!(
            SourceClassId::new(invalid),
            Err(TaintModelError::InvalidSourceClassId)
        );
    }
    assert_eq!(
        TaintUniverse::new(vec![label("alpha"), label("alpha")]),
        Err(TaintModelError::InvalidUniverse)
    );
    let universe = TaintUniverse::new(vec![label("beta"), label("alpha")]).unwrap();
    for labels in [
        vec![label("outside")],
        vec![label("alpha"), label("outside")],
    ] {
        assert_eq!(
            universe.class_set(&labels),
            Err(TaintModelError::UnknownSourceClass)
        );
    }
    let set = universe.class_set([&label("alpha")]).unwrap();
    assert!(universe.set_contains(&set, &label("alpha")).unwrap());
    assert!(!universe.set_contains(&set, &label("outside")).unwrap());
}

#[test]
fn universe_identity_preserves_the_v1_canonical_vector() {
    // SHA-256 of ASCII domain plus NUL, then (u64 little-endian byte length,
    // UTF-8 name) pairs: (5, alpha), (4, beta).
    for names in [["alpha", "beta"], ["beta", "alpha"]] {
        let universe = TaintUniverse::new(names.map(label).to_vec()).unwrap();
        assert_eq!(
            universe.hash().to_string(),
            "9cffe7490889b371e60f5e90d104a3c910192fdd46922506e64d51573cc6bfaa"
        );
        assert_eq!(
            universe
                .classes()
                .iter()
                .map(SourceClassId::as_str)
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }
}

#[test]
fn multiword_label_lattice_matches_scalar_sets() {
    let names = (0..130).rev().map(|i| label(&format!("c{i:03}"))).collect();
    let universe = TaintUniverse::new(names).unwrap();
    let subsets: &[&[usize]] = &[
        &[],
        &[0],
        &[64],
        &[129],
        &[64, 129],
        &[129, 0, 64],
        &[0, 129],
        &[0, 64],
    ];
    for left in subsets {
        for right in subsets {
            let scalar = |indices: &[usize]| {
                indices
                    .iter()
                    .map(|i| format!("c{i:03}"))
                    .collect::<BTreeSet<_>>()
            };
            let a = scalar(left);
            let b = scalar(right);
            let packed = |set: &BTreeSet<String>| {
                universe
                    .class_set(&set.iter().map(|s| label(s)).collect::<Vec<_>>())
                    .unwrap()
            };
            let render = |set| {
                universe
                    .stable_classes(&set)
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().to_owned())
                    .collect::<Vec<_>>()
            };
            let x = packed(&a);
            let y = packed(&b);
            assert_eq!(render(x.clone()), a.iter().cloned().collect::<Vec<_>>());
            assert_eq!(x.intersects(&y), !a.is_disjoint(&b));
            assert_eq!(
                render(x.union(&y)),
                a.union(&b).cloned().collect::<Vec<_>>()
            );
            assert_eq!(
                render(x.intersection(&y)),
                a.intersection(&b).cloned().collect::<Vec<_>>()
            );
            assert_eq!(
                render(x.subtract(&y)),
                a.difference(&b).cloned().collect::<Vec<_>>()
            );
        }
    }
}
