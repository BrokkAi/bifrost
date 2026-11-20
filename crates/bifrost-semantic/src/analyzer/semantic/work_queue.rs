//! Context captured at scheduling time, independent of language traversal.

use brokk_bifrost_core::allocation_size::allocation_size;
use brokk_bifrost_core::retention_budget::{AllocationCharge, RetentionBudget};

#[derive(Debug, Clone, Copy)]
pub struct ContextualWork<T, C = ()> {
    pub item: T,
    pub context: C,
}

/// One existing owner's incremental provenance allocation. Declare this before
/// its buffers so unwinding destroys the buffers before releasing the charge.
pub struct ProvenanceCharge {
    owner: RetentionBudget,
    bytes: usize,
    charge: Option<AllocationCharge>,
}

impl ProvenanceCharge {
    pub fn new(owner: &RetentionBudget) -> Self {
        Self {
            owner: owner.clone(),
            bytes: 0,
            charge: None,
        }
    }

    pub fn adjust(&mut self, previous: usize, next: usize) {
        let bytes = self
            .bytes
            .checked_sub(previous)
            .expect("provenance component is charged")
            .saturating_add(next);
        self.set_bytes(bytes);
    }

    pub fn set_bytes(&mut self, bytes: usize) {
        if self.bytes == bytes {
            return;
        }
        // Acquire before releasing: required storage stays charged throughout
        // replacement. Include the one new immutable charge control allocation.
        let charge = (bytes != 0)
            .then(|| AllocationCharge::acquire_required_with_control(&self.owner, bytes));
        self.charge = charge;
        self.bytes = bytes;
    }
}

pub trait WorkSink<T> {
    type Context: Copy;
    fn context(&self) -> Self::Context;
    fn push(&mut self, item: T);
    fn push_with_context(&mut self, item: T, context: Self::Context);
    fn is_empty(&self) -> bool;
}

impl<T> WorkSink<T> for Vec<T> {
    type Context = ();
    fn context(&self) {}
    fn push(&mut self, item: T) {
        Vec::push(self, item);
    }
    fn push_with_context(&mut self, item: T, (): ()) {
        Vec::push(self, item);
    }
    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }
}

impl<T, C: Copy> dyn WorkSink<T, Context = C> + '_ {
    pub fn extend(&mut self, items: impl IntoIterator<Item = T>) {
        for item in items {
            self.push(item);
        }
    }
}

/// A scoped facade. Ordinary children inherit the popped item's context;
/// foreign syntax must be scheduled with its explicitly admitted context.
pub struct WorkQueue<'queue, T, C: Copy = ()> {
    values: &'queue mut Vec<ContextualWork<T, C>>,
    context: C,
    charge: &'queue mut dyn FnMut(usize),
}

impl<'queue, T, C: Copy> WorkQueue<'queue, T, C> {
    #[doc(hidden)]
    pub fn new(
        values: &'queue mut Vec<ContextualWork<T, C>>,
        context: C,
        charge: &'queue mut dyn FnMut(usize),
    ) -> Self {
        let mut queue = Self {
            values,
            context,
            charge,
        };
        queue.reconcile(queue.values.capacity());
        queue
    }

    /// Allocation capacity, for admission observations without exposing storage.
    pub fn capacity(&self) -> usize {
        self.values.capacity()
    }

    fn reconcile(&mut self, capacity: usize) {
        (self.charge)(contextual_vec_bytes::<T, C>(capacity));
    }
}

impl<T, C: Copy> WorkSink<T> for WorkQueue<'_, T, C> {
    type Context = C;
    fn context(&self) -> C {
        self.context
    }
    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    fn push(&mut self, item: T) {
        self.push_with_context(item, self.context);
    }
    fn push_with_context(&mut self, item: T, context: C) {
        push_contextual_work(
            self.values,
            &mut |_, next| (self.charge)(next),
            ContextualWork { item, context },
        );
    }
}

/// Incremental allocation allowance for context carried in an existing Vec.
pub fn contextual_vec_bytes<T, C>(capacity: usize) -> usize {
    allocation_size(capacity.saturating_mul(std::mem::size_of::<ContextualWork<T, C>>()))
        .saturating_sub(allocation_size(
            capacity.saturating_mul(std::mem::size_of::<T>()),
        ))
}

/// Preserve Vec's geometric growth while admitting only the added context slots.
/// The callback may aggregate these slots with other file-owned provenance.
pub fn push_contextual_work<T, C>(
    values: &mut Vec<ContextualWork<T, C>>,
    observe: &mut dyn FnMut(usize, usize),
    item: ContextualWork<T, C>,
) {
    let mut previous = contextual_vec_bytes::<T, C>(values.capacity());
    push_with_capacity_observer(
        values,
        &mut |old, new| {
            let next =
                contextual_vec_bytes::<T, C>(old).saturating_add(contextual_vec_bytes::<T, C>(new));
            observe(previous, next);
            previous = next;
        },
        item,
    );
}

/// Observe both old and planned capacities before copying growth, then the
/// single retained allocation. A separate provenance column uses this same
/// growth policy without inventing another allocator or budget.
pub fn push_with_capacity_observer<T>(
    values: &mut Vec<T>,
    observe: &mut dyn FnMut(usize, usize),
    item: T,
) {
    if values.len() == values.capacity() {
        let capacity = values.capacity().saturating_mul(2).max(4);
        observe(values.capacity(), capacity);
        values.reserve_exact(capacity - values.len());
        observe(0, values.capacity());
    }
    values.push(item);
}
