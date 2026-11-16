//! Pure argument-position projection through Java supertype edges.

/// One hop of argument-position composition. `positions[i]` says which actual
/// argument the declaring owner's i-th type parameter holds; the result says
/// the same for the edge target's arguments. The declaring owner's parameters
/// must be known and as many as `positions`, and every argument of the edge
/// must be a bare one of them: a raw edge, a ground or compound argument or an
/// owner of another arity proves no position.
pub fn project_java_hop(
    positions: &[usize],
    owner_parameter_count: Option<usize>,
    edge_arguments: Option<&[Option<usize>]>,
) -> Option<Vec<usize>> {
    if owner_parameter_count? != positions.len() {
        return None;
    }
    edge_arguments?
        .iter()
        .map(|argument| positions.get((*argument)?).copied())
        .collect()
}

/// Compose where each of `actual_count` type arguments of a path's first owner
/// lands in its last owner, one [`project_java_hop`] per hop. Each hop is the
/// declaring owner's ordered type parameters (`None` when unknown) and the
/// edge target; the last owner's parameters must be known and as many as the
/// final positions.
pub fn compose_java_positions<'a>(
    actual_count: usize,
    hops: impl IntoIterator<Item = (Option<usize>, Option<&'a [Option<usize>]>)>,
    last_parameter_count: Option<usize>,
) -> Option<Vec<usize>> {
    let mut positions: Vec<usize> = (0..actual_count).collect();
    for (parameters, arguments) in hops {
        positions = project_java_hop(&positions, parameters, arguments)?;
    }
    (last_parameter_count? == positions.len()).then_some(positions)
}
