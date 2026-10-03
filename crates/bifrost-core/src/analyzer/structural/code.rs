//! The integer code a vocabulary value is stored under (owner decision,
//! 2026-09-18: enumerations are integer codes in the database with a Rust-side
//! mapping and no label table).
//!
//! The code is the value's declaration ordinal in its vocabulary macro. That is
//! stable for the life of a store because a vocabulary change rotates the
//! producing epoch and this schema has no migrations: a store written under one
//! vocabulary is never read under another.
//!
//! `label()` and `from_label()` are a different representation and stay as they
//! are. They are what query JSON, RQL and rendered output use, and nothing about
//! the published wire format changes here.

/// A vocabulary whose values are stored as their declaration ordinal.
///
/// Every vocabulary declared through `normalized_kinds!`, `roles!`,
/// `occurrence_roles!`, `labelled_enum!` or `described_vocab!` implements this.
pub trait VocabularyCode: Copy + Sized {
    /// The declaration ordinal. Every vocabulary in this module fits in a `u8`.
    fn code(self) -> u8;

    /// The value a code names, or `None` when the code is outside the
    /// vocabulary. A reader that gets `None` has a row from another epoch,
    /// which the epoch rotation is supposed to have made unreachable.
    fn from_code(code: u8) -> Option<Self>;
}
