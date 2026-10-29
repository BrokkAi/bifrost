//! Bounded regex-value parsing and risk analysis over decoded characters.
//!
//! A producer supplies dialect rules through `RegexSyntax` and maps the returned
//! character offsets to source ranges. All retained state belongs to one pattern.

use super::kinds::NormalizedKind;
use std::collections::{HashMap, HashSet, VecDeque};

mod charset;
mod mapping;
pub use mapping::{MappedChar, facts_to_embedded};
mod nfa;
mod parser;
mod risks;

pub use charset::{CharacterSet, single_character};
use charset::{codeql_range_character_set, is_overly_broad_range};
pub use nfa::{NfaError, RegexNfa};
pub use parser::RegexParser;

pub const MAX_PATTERN_CHARS: usize = 8192;
pub const MAX_PATTERN_FACTS: usize = 4096;
const MAX_GROUP_DEPTH: usize = 128;
const MAX_NFA_STATES: usize = 512;
const MAX_NFA_PRODUCT_PAIRS: usize = 65_536;
const MAX_NFA_REPEAT: u32 = 32;
const MAX_REDOSE_GROUPS: usize = 16;
const MAX_REDOSE_ALTERNATIVES: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct RegexFlags {
    /// Uninterpreted, per-pattern dialect flag bits (not persisted).
    /// Java can keep u, d and U independent of the common flags.
    pub dialect_flags: u32,
    pub dotall: bool,
    pub multiline: bool,
    pub ignorecase: bool,
    /// Character classes are ASCII-only: Java's default, a Python toggle.
    pub ascii: bool,
    pub verbose: bool,
    pub complete: bool,
}

#[derive(Debug, Clone)]
pub struct Fact {
    pub kind: NormalizedKind,
    pub start: usize,
    pub end: usize,
    pub parent: Option<usize>,
    pub construct: Option<String>,
    pub first_set: Option<CharacterSet>,
    // Singleton escape value before case folding; retained only for this pattern.
    pub escaped_literal: Option<char>,
    pub quantifier: Option<Quantifier>,
    pub minimum_width: Option<u32>,
}

#[derive(Debug, Clone)]
struct BranchFrame {
    owner: usize,
    sequence: usize,
    group_start: Option<usize>,
    last_atom: Option<usize>,
    restore_flags: Option<RegexFlags>,
}

#[derive(Debug, Clone, Copy)]
pub struct Quantifier {
    pub minimum: u32,
    pub maximum: Option<u32>,
    pub possessive: bool,
}

#[derive(Debug)]
pub struct ClassAtom {
    pub start: usize,
    pub end: usize,
    pub value: Option<char>,
    pub set: Option<CharacterSet>,
    pub kind: NormalizedKind,
    pub construct: Option<String>,
    pub backspace: bool,
    pub incomplete: Option<&'static str>,
}

#[derive(Debug)]
pub struct EscapeValue {
    pub end: usize,
    pub anchor: bool,
    pub construct: Option<String>,
    pub first_set: Option<CharacterSet>,
    pub incomplete: Option<&'static str>,
    pub backspace: bool,
}

fn regex_sequence_branches(
    facts: &[Fact],
    children: impl IntoIterator<Item = usize>,
) -> Vec<Vec<usize>> {
    let mut branches = vec![Vec::new()];
    for child in children {
        if facts[child].kind == NormalizedKind::RegexAlternation {
            branches.push(Vec::new());
        } else {
            branches
                .last_mut()
                .expect("a regex sequence has a branch")
                .push(child);
        }
    }
    branches
}

fn polynomial_atoms_overlap(left: &Fact, right: &Fact) -> bool {
    match (&left.first_set, &right.first_set) {
        (Some(left), Some(right)) => left.intersects(right),
        _ => matches!(
            (left.construct.as_deref(), right.construct.as_deref()),
            (Some("category:d"), Some("category:d" | "category:w"))
                | (Some("category:w"), Some("category:d" | "category:w"))
                | (Some("category:s"), Some("category:s"))
        ),
    }
}

/// A dialect-selected special-group prefix. Offsets are decoded characters
/// relative to the `?` supplied to `group_prefix`, not source bytes.
#[derive(Debug, Clone, Copy)]
pub enum GroupPrefix {
    Noncapturing,
    Named { name_offset: usize },
    Comment,
    LookaheadPositive,
    LookaheadNegative,
    LookbehindPositive,
    LookbehindNegative,
    Flags,
    Unsupported,
}

/// Dialect semantics, implemented by language crates, never by the shared engine.
///
/// `escape` owns property names, quoted escapes, hex/octal/backreferences and
/// whitespace/grapheme escapes. `class_atom` owns nested union/intersection.
/// Unsupported constructs must return an incomplete reason (or `None`), rather
/// than silently treating their spelling as literals. Group syntax and flag
/// meanings are separate hooks: e.g. Java's `u` must not toggle Python ASCII mode.
/// New constructs that need new AST shapes must extend this interface and the
/// shared algorithm together; recognizing a token alone is not semantic support.
pub trait RegexSyntax {
    fn group_prefix(&self, chars: &[char], start: usize) -> GroupPrefix;
    fn incomplete_group_end(&self, chars: &[char], start: usize) -> Option<usize>;
    /// Returns the delimiter and updated flags, preserving `flags.complete`.
    /// `None` is the only incompleteness channel for inline flags.
    fn inline_flags(
        &self,
        chars: &[char],
        start: usize,
        flags: RegexFlags,
    ) -> Option<(usize, RegexFlags)>;
    fn escape(
        &self,
        chars: &[char],
        start: usize,
        in_class: bool,
        flags: RegexFlags,
    ) -> Option<EscapeValue>;
    fn class_atom(&self, chars: &[char], start: usize, flags: RegexFlags) -> Option<ClassAtom>;
    fn wildcard(&self, flags: RegexFlags) -> CharacterSet;
    fn fold_case(&self, set: CharacterSet, flags: RegexFlags) -> CharacterSet;
    fn case_folding_is_complete(&self, flags: RegexFlags) -> bool;
    fn verbose_whitespace(&self, character: char) -> bool;
    fn verbose_comment_terminator(&self, character: char) -> bool;
    fn supports_possessive_quantifiers(&self) -> bool;
    /// Producer-owned analysis run before ReDoS classifiers; may mark incomplete.
    fn analyze(&self, context: &mut RegexAnalysis<'_>);
}

pub type PendingRisk = (NormalizedKind, usize, usize, usize, String);

/// Per-pattern analysis view for producer-owned compatibility checks.
pub struct RegexAnalysis<'a> {
    pub value: &'a str,
    pub flags: RegexFlags,
    pub chars: &'a [char],
    pub facts: &'a [Fact],
    pub pending_risks: &'a mut Vec<PendingRisk>,
    pub incomplete: &'a mut Option<(usize, usize, String)>,
}

impl RegexAnalysis<'_> {
    pub fn mark_incomplete(&mut self, start: usize, end: usize, reason: &str) {
        if self.incomplete.is_none() {
            *self.incomplete = Some((start, end, reason.to_owned()));
        }
    }
}

#[cfg(test)]
mod tests;
