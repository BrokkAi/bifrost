//! Exact retained-storage accounting for bounded policy report values.

use std::mem::{size_of, size_of_val};

use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;

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
    fn retained_size(&self) -> usize {
        size_of_val(self)
    }
}

pub(crate) fn ensure_truncation_consistency<E>(
    truncated: bool,
    omitted_lower_bound: u64,
    inconsistent: E,
) -> Result<(), E> {
    if truncated == (omitted_lower_bound > 0) {
        Ok(())
    } else {
        Err(inconsistent)
    }
}

pub(crate) fn retained_extra<T: RetainedSize>(value: &T) -> usize {
    value.retained_size().saturating_sub(size_of_val(value))
}

pub(crate) fn retained_size_with_extra<T: ?Sized>(value: &T, extra: usize) -> usize {
    size_of_val(value).saturating_add(extra)
}

pub(crate) fn retained_size_with_extras<T: ?Sized>(
    value: &T,
    extras: impl IntoIterator<Item = usize>,
) -> usize {
    extras
        .into_iter()
        .fold(size_of_val(value), usize::saturating_add)
}

pub(crate) fn retained_size_with_field_extra<T: ?Sized, F: RetainedSize>(
    value: &T,
    field: &F,
) -> usize {
    retained_size_with_extra(value, retained_extra(field))
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

/// Count JSON-owned scalar strings and container elements iteratively. Map
/// allocator bookkeeping is outside the model, as for other retained values.
impl RetainedSize for serde_json::Value {
    fn retained_size(&self) -> usize {
        let mut bytes = size_of::<Self>();
        let mut pending = vec![self];
        while let Some(value) = pending.pop() {
            match value {
                serde_json::Value::String(value) => bytes = bytes.saturating_add(value.capacity()),
                serde_json::Value::Array(values) => {
                    bytes =
                        bytes.saturating_add(values.capacity().saturating_mul(size_of::<Self>()));
                    pending.extend(values);
                }
                serde_json::Value::Object(values) => {
                    bytes = bytes.saturating_add(
                        values
                            .len()
                            .saturating_mul(size_of::<String>() + size_of::<Self>()),
                    );
                    for (key, value) in values {
                        bytes = bytes.saturating_add(key.capacity());
                        pending.push(value);
                    }
                }
                _ => {}
            }
        }
        bytes
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

    #[test]
    fn json_accounting_includes_nested_strings_and_spare_array_capacity() {
        let mut scalar = String::with_capacity(64);
        scalar.push_str("true");
        let string_bytes = scalar.capacity();
        let mut values = Vec::with_capacity(8);
        values.push(serde_json::Value::String(scalar));
        let array_bytes = values.capacity() * size_of::<serde_json::Value>();
        let key = String::from("contributors");
        let key_bytes = key.capacity();
        let mut object = serde_json::Map::new();
        object.insert(key, serde_json::Value::Array(values));
        let value = serde_json::Value::Object(object);
        let expected = size_of::<serde_json::Value>()
            + size_of::<String>()
            + size_of::<serde_json::Value>()
            + key_bytes
            + array_bytes
            + string_bytes;
        assert_eq!(value.retained_size(), expected);
        assert!(value.retained_size() > value.to_string().len());
    }
}
