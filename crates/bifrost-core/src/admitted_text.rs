//! Immutable text whose retained backing is admitted before it is copied.

use std::borrow::Cow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Serialize, Serializer};

use crate::allocation_size::allocation_size;
use crate::retention_budget::{ENTRY_OVERHEAD_BYTES, RetentionBudget, SharedBackingLease};

/// Text that keeps its allocation charged until its last owning handle drops.
///
/// Cloning shares the actual immutable payload; it never copies an owned string
/// or separates the payload from its admission. Serialization borrows the text.
#[derive(Clone)]
pub struct AdmittedText(TextBacking);

#[derive(Clone)]
enum TextBacking {
    Static(&'static str),
    Shared(Arc<AdmittedTextAllocation>),
}

struct AdmittedTextAllocation {
    text: Box<str>,
    // Keep the charge alive through the payload's drop, including extracted
    // handles that outlive the response or the analyzer that created them.
    _lease: SharedBackingLease,
}

impl AdmittedText {
    /// Empty text needs no dynamic allocation or owner admission.
    pub const fn empty() -> Self {
        Self::from_static("")
    }

    /// Borrow static text without allocating a dynamic payload or header.
    pub const fn from_static(text: &'static str) -> Self {
        Self(TextBacking::Static(text))
    }

    /// Admit the complete payload and control storage before allocating either.
    ///
    /// A refusal copies nothing. Empty text needs no admission. The returned
    /// handle offers borrowed access only; making a separate owned copy needs
    /// its own admission at the caller's allocation boundary.
    pub fn try_copy(owner: &RetentionBudget, text: &str) -> Option<Self> {
        if text.is_empty() {
            return Some(Self::empty());
        }
        let lease = Self::reserve(owner, text.len())?;
        Some(Self(TextBacking::Shared(Arc::new(
            AdmittedTextAllocation {
                text: Box::from(text),
                _lease: lease,
            },
        ))))
    }

    /// Count formatted UTF-8 bytes, admit storage, then write into that bound.
    ///
    /// Arguments are formatted twice and must produce stable output. Returns
    /// `None` only for size overflow or owner admission refusal.
    /// Formatters should stream borrowed data: allocations performed inside an
    /// argument's own `Display` implementation are outside this constructor.
    ///
    /// # Panics
    ///
    /// Panics if an argument formatter errors or changes its byte count between
    /// passes. Any admitted backing is released during unwinding.
    pub fn try_format(owner: &RetentionBudget, arguments: fmt::Arguments<'_>) -> Option<Self> {
        struct Length(Option<usize>);
        impl fmt::Write for Length {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                self.0 = self.0.and_then(|length| length.checked_add(text.len()));
                Ok(())
            }
        }
        let mut length = Length(Some(0));
        fmt::write(&mut length, arguments).expect("borrowed argument formatters must not fail");
        let length = length.0?;
        let lease = if length == 0 {
            None
        } else {
            Some(Self::reserve(owner, length)?)
        };
        struct Output<'a> {
            bytes: &'a mut [u8],
            written: usize,
        }
        impl fmt::Write for Output<'_> {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                let end = self
                    .written
                    .checked_add(text.len())
                    .expect("formatted byte count must remain within its measured bound");
                self.bytes
                    .get_mut(self.written..end)
                    .expect("formatted byte count must remain within its measured bound")
                    .copy_from_slice(text.as_bytes());
                self.written = end;
                Ok(())
            }
        }
        let mut bytes = vec![0; length].into_boxed_slice();
        let mut output = Output {
            bytes: &mut bytes,
            written: 0,
        };
        fmt::write(&mut output, arguments).expect("borrowed argument formatters must not fail");
        assert_eq!(
            output.written, length,
            "formatted byte count must match its measured bound"
        );
        let Some(lease) = lease else {
            return Some(Self::empty());
        };
        // The fixed slice received only complete UTF-8 strings. Its Vec has
        // exactly len capacity, so both ownership conversions keep the buffer.
        let text = String::from_utf8(bytes.into_vec())
            .expect("formatted text consists of complete UTF-8 writes")
            .into_boxed_str();
        Some(Self(TextBacking::Shared(Arc::new(
            AdmittedTextAllocation {
                text,
                _lease: lease,
            },
        ))))
    }

    fn reserve(owner: &RetentionBudget, length: usize) -> Option<SharedBackingLease> {
        let header = std::mem::size_of::<AdmittedTextAllocation>()
            .checked_add(2 * std::mem::size_of::<usize>())?;
        let bytes = allocation_size(length)
            .checked_add(allocation_size(header))?
            // The existing control-allocation allowance also covers the
            // accounting lease's control block; there is no separate pool.
            .checked_add(ENTRY_OVERHEAD_BYTES)?;
        owner.shared_backing(u64::try_from(bytes).ok()?)
    }
}

impl Default for AdmittedText {
    fn default() -> Self {
        Self::empty()
    }
}

impl Deref for AdmittedText {
    type Target = str;

    fn deref(&self) -> &str {
        match &self.0 {
            TextBacking::Static(text) => text,
            TextBacking::Shared(allocation) => &allocation.text,
        }
    }
}

impl AsRef<str> for AdmittedText {
    fn as_ref(&self) -> &str {
        self
    }
}

impl PartialEq for AdmittedText {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for AdmittedText {}

impl Hash for AdmittedText {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl fmt::Debug for AdmittedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(formatter)
    }
}

impl fmt::Display for AdmittedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_ref(), formatter)
    }
}

impl Serialize for AdmittedText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self)
    }
}

impl JsonSchema for AdmittedText {
    fn inline_schema() -> bool {
        String::inline_schema()
    }

    fn schema_name() -> Cow<'static, str> {
        String::schema_name()
    }

    fn schema_id() -> Cow<'static, str> {
        String::schema_id()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        String::json_schema(generator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#14068: extracted and cloned site text outlived its admission owner")]
    fn extracted_clones_keep_backing_charged_until_final_drop() {
        let owner = RetentionBudget::for_test_capacity(4096);
        let text = AdmittedText::try_copy(&owner, "selected source text").unwrap();
        let occupied = owner.accounted_bytes();
        assert!(occupied > text.len() as u64);
        let extracted = vec![text.clone()].pop().unwrap();
        assert_eq!(text.as_ptr(), extracted.as_ptr());
        assert_eq!(owner.accounted_bytes(), occupied);
        drop(text);
        owner.run_pending_tasks();
        assert_eq!(owner.accounted_bytes(), occupied);
        assert!(AdmittedText::try_copy(&owner, &"x".repeat(4096)).is_none());
        assert_eq!(owner.accounted_bytes(), occupied);
        let last = extracted.clone();
        drop(extracted);
        assert_eq!(owner.accounted_bytes(), occupied);
        drop(last);
        assert_eq!(owner.accounted_bytes(), 0);

        let outside_owner = AdmittedText::try_copy(&owner, "still valid").unwrap();
        drop(owner);
        assert_eq!(&*outside_owner, "still valid");
        drop(outside_owner);

        let refusing = RetentionBudget::retain_nothing();
        assert!(AdmittedText::try_copy(&refusing, "dynamic").is_none());
        assert_eq!(
            AdmittedText::try_copy(&refusing, "").unwrap(),
            AdmittedText::empty()
        );
        assert_eq!(&*AdmittedText::from_static("static"), "static");
        assert_eq!(refusing.accounted_bytes(), 0);
    }

    #[test]
    fn serde_and_schema_keep_the_string_contract() {
        let owner = RetentionBudget::for_test_capacity(4096);
        let admitted = AdmittedText::try_copy(&owner, "line\n\"quoted\"").unwrap();
        let static_text = AdmittedText::from_static("line\n\"quoted\"");
        assert_eq!(admitted, static_text);
        let mut admitted_hash = std::hash::DefaultHasher::new();
        let mut static_hash = std::hash::DefaultHasher::new();
        admitted.hash(&mut admitted_hash);
        static_text.hash(&mut static_hash);
        assert_eq!(admitted_hash.finish(), static_hash.finish());
        assert_eq!(format!("{admitted:?}"), format!("{:?}", admitted.as_ref()));
        assert_eq!(
            serde_json::to_string(&admitted).unwrap(),
            serde_json::to_string(admitted.as_ref()).unwrap()
        );
        assert_eq!(
            schemars::schema_for!(AdmittedText),
            schemars::schema_for!(String)
        );
    }

    #[test]
    #[hardwon("#14068: formatted site values copied dynamic payload before admission")]
    fn formatted_utf8_is_admitted_before_writing_and_never_grows_past_its_count() {
        use std::cell::Cell;

        let owner = RetentionBudget::for_test_capacity(4096);
        let text =
            AdmittedText::try_format(&owner, format_args!("{}:{}", "\u{e9}", i128::MIN)).unwrap();
        assert_eq!(&*text, "\u{e9}:-170141183460469231731687303715884105728");
        let clone = text.clone();
        assert_eq!(text.as_ptr(), clone.as_ptr());
        drop(text);
        assert!(owner.accounted_bytes() > 0);
        drop(clone);
        assert_eq!(owner.accounted_bytes(), 0);

        struct Changing<'a> {
            calls: Cell<usize>,
            output: [&'a str; 2],
        }
        impl fmt::Display for Changing<'_> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let index = self.calls.get();
                self.calls.set(index + 1);
                formatter.write_str(self.output[index])
            }
        }
        for output in [["a", "\u{e9}"], ["\u{e9}", "a"], ["", "a"], ["a", ""]] {
            let value = Changing {
                calls: Cell::new(0),
                output,
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                AdmittedText::try_format(&owner, format_args!("{value}"))
            }));
            assert!(result.is_err());
            assert_eq!(value.calls.get(), 2);
            assert_eq!(owner.accounted_bytes(), 0);
        }

        struct Erring {
            calls: Cell<usize>,
            failure_pass: usize,
        }
        impl fmt::Display for Erring {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let index = self.calls.get();
                self.calls.set(index + 1);
                if index == self.failure_pass {
                    return Err(fmt::Error);
                }
                formatter.write_str("x")
            }
        }
        for failure_pass in [0, 1] {
            let value = Erring {
                calls: Cell::new(0),
                failure_pass,
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                AdmittedText::try_format(&owner, format_args!("{value}"))
            }));
            assert!(result.is_err());
            assert_eq!(value.calls.get(), failure_pass + 1);
            assert_eq!(owner.accounted_bytes(), 0);
        }

        let refusing = RetentionBudget::retain_nothing();
        let value = Changing {
            calls: Cell::new(0),
            output: ["not admitted", "must not be written"],
        };
        assert!(AdmittedText::try_format(&refusing, format_args!("{value}")).is_none());
        assert_eq!(value.calls.get(), 1);
        assert_eq!(
            AdmittedText::try_format(&refusing, format_args!("")).unwrap(),
            AdmittedText::empty()
        );
    }
}
