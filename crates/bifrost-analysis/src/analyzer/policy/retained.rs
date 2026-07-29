//! Exact retained-storage accounting for bounded policy report values.

use std::mem::{size_of, size_of_val};

use crate::analyzer::semantic::WorkspaceRelativePath;

use super::definition::{
    EndpointId, FindingCombinationId, PolicyCategoryId, PolicyId, PolicySelectorPath, TaintEntryId,
    TaintImpact, TaintLabel, TaintTag, TypestateEventId, TypestateExpectationId, TypestateStateId,
};
use super::identity::PolicySemanticHash;
use super::resolved::PolicyDependencyPath;
use super::source::PolicySourceIdentity;

/// Total fixed and owned heap storage retained by a report value.
///
/// Implementations count the value's inline storage once, plus the exact
/// capacities of owned strings and vectors and the recursively owned storage
/// of populated vector elements. Allocator metadata is intentionally outside
/// the model because it is host-specific.
pub(crate) trait RetainedSize {
    fn retained_size(&self) -> usize;
}

pub(crate) fn retained_extra<T: RetainedSize>(value: &T) -> usize {
    value.retained_size().saturating_sub(size_of_val(value))
}

pub(crate) fn retained_vec_size_from_parts<T: RetainedSize>(
    values: &[T],
    capacity: usize,
) -> usize {
    let spare = capacity.saturating_sub(values.len());
    values.iter().fold(
        size_of::<Vec<T>>().saturating_add(spare.saturating_mul(size_of::<T>())),
        |bytes, value| bytes.saturating_add(value.retained_size()),
    )
}

impl RetainedSize for String {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(self.capacity())
    }
}

impl RetainedSize for Box<str> {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(self.len())
    }
}

impl<T: RetainedSize> RetainedSize for Vec<T> {
    fn retained_size(&self) -> usize {
        retained_vec_size_from_parts(self, self.capacity())
    }
}

impl<T: RetainedSize> RetainedSize for Option<T> {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(self.as_ref().map_or(0, |value| retained_extra(value)))
    }
}

impl RetainedSize for WorkspaceRelativePath {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(self.as_str().len())
    }
}

macro_rules! fixed_retained_size {
    ($($type:ty),+ $(,)?) => {
        $(
            impl RetainedSize for $type {
                fn retained_size(&self) -> usize {
                    size_of::<Self>()
                }
            }
        )+
    };
}

fixed_retained_size!(bool, u8, u16, u32, u64, usize);

macro_rules! string_newtype_retained_size {
    ($($type:ty),+ $(,)?) => {
        $(
            impl RetainedSize for $type {
                fn retained_size(&self) -> usize {
                    size_of::<Self>().saturating_add(self.as_str().len())
                }
            }
        )+
    };
}

string_newtype_retained_size!(
    PolicyId,
    EndpointId,
    PolicyCategoryId,
    TaintEntryId,
    FindingCombinationId,
    TaintLabel,
    TaintTag,
    TaintImpact,
    TypestateStateId,
    TypestateEventId,
    TypestateExpectationId,
    PolicySelectorPath,
    PolicyDependencyPath,
    PolicySourceIdentity,
);

impl RetainedSize for PolicySemanticHash {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_accounting_includes_spare_capacity_and_nested_owned_bytes() {
        let mut values = Vec::with_capacity(4);
        values.push(String::from("abc"));
        let expected = size_of::<Vec<String>>()
            + 3 * size_of::<String>()
            + size_of::<String>()
            + values[0].capacity();
        assert_eq!(values.retained_size(), expected);
    }
}
