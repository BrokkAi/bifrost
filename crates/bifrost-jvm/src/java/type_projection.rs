//! Pure argument projection through Java supertype edges.

/// An argument expressed in the target interface's coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JavaArgument<T> {
    Position(usize),
    Closed(T),
    Open,
}

/// The argument representation supplied by a projection caller.
pub trait JavaProjectionValue: Clone {
    type Edge;
    fn project(positions: &[Self], argument: &Self::Edge) -> Option<Self>;
}

impl JavaProjectionValue for usize {
    type Edge = Option<usize>;
    fn project(positions: &[Self], argument: &Self::Edge) -> Option<Self> {
        positions.get((*argument)?).copied()
    }
}

impl<T: Clone> JavaProjectionValue for JavaArgument<T> {
    type Edge = Self;
    fn project(positions: &[Self], argument: &Self) -> Option<Self> {
        match argument {
            Self::Position(position) => positions.get(*position).cloned(),
            Self::Closed(_) | Self::Open => Some(argument.clone()),
        }
    }
}

/// EX starts with numbered positions; SAM starts with target-coordinate values.
pub trait JavaProjectionInput {
    type Value: JavaProjectionValue;
    fn positions(self) -> Vec<Self::Value>;
}
impl JavaProjectionInput for usize {
    type Value = usize;
    fn positions(self) -> Vec<usize> {
        (0..self).collect()
    }
}
impl<V: JavaProjectionValue> JavaProjectionInput for Vec<V> {
    type Value = V;
    fn positions(self) -> Vec<V> {
        self
    }
}

/// One hop of argument composition. Unknown owner arity, missing edge evidence
/// and an out-of-range position prove no projection. The usize representation
/// also rejects open arguments, preserving EX's positional-only contract.
pub fn project_java_hop<V: JavaProjectionValue>(
    positions: &[V],
    owner_parameter_count: Option<usize>,
    edge_arguments: Option<&[V::Edge]>,
) -> Option<Vec<V>> {
    if owner_parameter_count? != positions.len() {
        return None;
    }
    edge_arguments?
        .iter()
        .map(|argument| V::project(positions, argument))
        .collect()
}

/// Compose one path using the same hop operation for positional and closed
/// arguments. The last owner's recorded arity must match the projected values.
pub fn compose_java_positions<'a, I: JavaProjectionInput>(
    input: I,
    hops: impl IntoIterator<
        Item = (
            Option<usize>,
            Option<&'a [<I::Value as JavaProjectionValue>::Edge]>,
        ),
    >,
    last_parameter_count: Option<usize>,
) -> Option<Vec<I::Value>>
where
    I::Value: 'a,
    <I::Value as JavaProjectionValue>::Edge: 'a,
{
    let mut positions = input.positions();
    for (parameters, arguments) in hops {
        positions = project_java_hop(&positions, parameters, arguments)?;
    }
    (last_parameter_count? == positions.len()).then_some(positions)
}
