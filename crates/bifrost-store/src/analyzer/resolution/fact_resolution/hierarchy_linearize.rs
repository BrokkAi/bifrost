//! The shared C3 cursor over a caller-supplied supertype source. The driver
//! walks selected facts; this entry walks a source that already knows each
//! owner's ordered bases, such as the selected model authority, with the same
//! cursor and the same policy.
use super::*;

/// Why no order was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum LinearizationFailure {
    /// The source could not name some owner's bases.
    UnknownBases,
    Cyclic,
    Inconsistent,
    /// The step limit stopped the merge.
    Exhausted,
}

/// Ordered direct bases of an owner, or None when the source cannot say.
#[doc(hidden)]
pub trait SupertypeSource<T> {
    fn bases(&mut self, owner: &T) -> Option<Vec<T>>;
}

pub(crate) fn linearize<T: Clone + Eq + std::hash::Hash>(
    root: &T,
    source: &mut impl SupertypeSource<T>,
    policy: &'static dyn HierarchyLinearizationPolicy,
    step_limit: usize,
) -> Result<Vec<T>, LinearizationFailure> {
    let mut spent = 0usize;
    linearize_with_budget(root, source, policy, &mut || {
        spent += 1;
        spent <= step_limit
    })
}

pub(super) fn linearize_with_budget<T: Clone + Eq + std::hash::Hash>(
    root: &T,
    source: &mut impl SupertypeSource<T>,
    policy: &'static dyn HierarchyLinearizationPolicy,
    step: &mut dyn FnMut() -> bool,
) -> Result<Vec<T>, LinearizationFailure> {
    let mut arena = HierarchyOperationArena::default();
    // Owners are numbered in discovery order; the number is the identity the
    // cursor sees and the index into `owners`.
    let mut owners = Vec::<T>::new();
    let mut ids = HashMap::<T, usize>::default();
    let mut expressions = HashMap::<usize, HierarchyOrderExprId>::default();
    let id_of = |number: usize| SemanticId::operation_local(number as u64);
    // Iterative post-order: a node is built after every base it names.
    enum Work<T> {
        Enter(T),
        Exit(usize, Vec<usize>),
    }
    let mut stack = vec![Work::Enter(root.clone())];
    let mut visiting = HashSet::<usize>::default();
    // Discovery is charged against the same limit as the merge, so a wide
    // source stops after bounded work instead of being read whole.
    while let Some(work) = stack.pop() {
        if !step() {
            return Err(LinearizationFailure::Exhausted);
        }
        match work {
            Work::Enter(owner) => {
                let number = *ids.entry(owner.clone()).or_insert_with(|| {
                    owners.push(owner.clone());
                    owners.len() - 1
                });
                if expressions.contains_key(&number) {
                    continue;
                }
                if !visiting.insert(number) {
                    return Err(LinearizationFailure::Cyclic);
                }
                let bases = source
                    .bases(&owner)
                    .ok_or(LinearizationFailure::UnknownBases)?;
                for _ in &bases {
                    if !step() {
                        return Err(LinearizationFailure::Exhausted);
                    }
                }
                let base_numbers = bases
                    .iter()
                    .map(|base| {
                        *ids.entry(base.clone()).or_insert_with(|| {
                            owners.push(base.clone());
                            owners.len() - 1
                        })
                    })
                    .collect::<Vec<_>>();
                stack.push(Work::Exit(number, base_numbers.clone()));
                for (base, number) in bases.into_iter().zip(base_numbers).rev() {
                    if visiting.contains(&number) {
                        return Err(LinearizationFailure::Cyclic);
                    }
                    stack.push(Work::Enter(base));
                }
            }
            Work::Exit(number, base_numbers) => {
                let bases = base_numbers
                    .iter()
                    .enumerate()
                    .map(|(ordinal, &base)| HierarchyOrderedBase {
                        expression: expressions[&base],
                        reference: id_of(base),
                        kind: None,
                        ordinal: ordinal as u32,
                    })
                    .collect();
                let expression = arena.order.owner(
                    id_of(number),
                    bases,
                    HierarchyProvenanceId::default(),
                    false,
                );
                visiting.remove(&number);
                expressions.insert(number, expression);
            }
        }
    }
    let view = HierarchyProvenanceView::new(&arena);
    let mut state = HierarchyOrderState::new(
        HierarchyOrderRequest {
            policy,
            start_after: None,
        },
        view,
    );
    state.root(expressions[&0], id_of(0));
    let outcome = state
        .poll(&arena.order, view, id_of(0), usize::MAX, step, &mut || {
            false
        })
        .expect("an in-memory order has no store")
        .expect("an uncancellable order finishes");
    if outcome.complete && outcome.completion == ResolutionCompletion::Complete {
        Ok(outcome
            .owners
            .iter()
            .map(|entry| {
                let number = entry
                    .owner
                    .operation_local_number()
                    .expect("the cursor emits the owners it was given");
                owners[number as usize].clone()
            })
            .collect())
    } else if outcome.completion == ResolutionCompletion::Complete {
        Err(LinearizationFailure::Inconsistent)
    } else {
        Err(LinearizationFailure::Exhausted)
    }
}
