use super::super::{SourceClassId, TaintEdgeFunction, TaintUniverse};

#[test]
fn finite_relations_match_enumerated_union_and_two_hop_reachability() {
    let labels = ["alpha", "beta", "gamma"].map(|s| SourceClassId::new(s).unwrap());
    let universe = TaintUniverse::new(labels.to_vec()).unwrap();
    let set = |bits: u8| {
        universe
            .class_set(
                labels
                    .iter()
                    .enumerate()
                    .filter_map(|(i, label)| (bits & (1 << i) != 0).then_some(label)),
            )
            .unwrap()
    };
    // Each row independently lists the reachable targets of alpha, beta, gamma.
    let relations: [[u8; 3]; 8] = [
        [1, 2, 4],
        [1, 0, 4],
        [1, 2, 0],
        [0, 4, 0],
        [3, 4, 1],
        [0, 0, 0],
        [1, 2, 3],
        [4, 4, 4],
    ];
    let evaluate = |row: &[u8; 3], input: u8| {
        row.iter()
            .enumerate()
            .filter(|(i, _)| input & (1 << i) != 0)
            .fold(0, |output, (_, targets)| output | targets)
    };
    let mut functions = relations
        .iter()
        .map(|row| {
            TaintEdgeFunction::transform(
                &universe,
                labels
                    .iter()
                    .enumerate()
                    .map(|(i, label)| (label.clone(), set(row[i]))),
                false,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    // Exercise equivalent sparse identity/kill encodings as well as dense maps.
    functions[0] = TaintEdgeFunction::identity(&universe);
    functions[1] = TaintEdgeFunction::kill(&set(2));
    functions[2] = TaintEdgeFunction::kill(&set(4));
    for (i, left) in functions.iter().enumerate() {
        for (j, right) in functions.iter().enumerate() {
            for input in 0..8 {
                let l = evaluate(&relations[i], input);
                let r = evaluate(&relations[j], input);
                assert_eq!(
                    left.meet(right).apply(&set(input)),
                    set(l | r),
                    "union rows {i}, {j}, input {input}"
                );
                assert_eq!(
                    left.compose(right).apply(&set(input)),
                    set(evaluate(&relations[j], l)),
                    "path rows {i}, {j}, input {input}"
                );
            }
        }
    }
}
