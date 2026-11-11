//! Known identifier misspellings for `js/misspelled-identifier`.
//!
//! The relation reports an identifier part only when an active typo table
//! lists it as a misspelling of another word, as CodeQL's
//! `MisspelledIdentifier.ql` does with its `typos` table. The table is pack
//! data: a rules pack ships it beside the policy and the host activates it for
//! the run (#10386). The engine owns only the format and its consumer.
//!
//! The document is UTF-8 text with one `wrong right` pair per line: two
//! lower-case ASCII words separated by spaces or tabs. Blank lines and lines
//! whose first non-blank character is `#` are ignored, so the attribution
//! header lives in the file. A wrong word may appear with several corrections.
//!
//! The bytes come from a pack root on disk. Parsing is bounded, and strict: a
//! malformed line refuses the whole document, because pack content is reviewed
//! and a silently skipped line would change what is reported.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};

/// The largest typo-table document read, in bytes.
pub const MAX_IDENTIFIER_TYPO_DOCUMENT_BYTES: usize = 256 * 1024;
/// The most distinct pairs one table holds, across every merged source.
pub const MAX_IDENTIFIER_TYPO_PAIRS: usize = 16_384;
/// The longest word either side of a pair, in bytes.
pub const MAX_IDENTIFIER_TYPO_WORD_BYTES: usize = 64;

const DIGEST_DOMAIN: &[u8] = b"bifrost-identifier-typos:v1\0";

/// A bounded set of known misspellings and their corrections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentifierTypoTable {
    /// Each misspelling with its corrections, all lower case.
    corrections: BTreeMap<String, BTreeSet<String>>,
    /// Every correction, for the segmentation guard in
    /// [`IdentifierTypoTable::known_misspelling`].
    correct_words: BTreeSet<String>,
    pairs: usize,
}

/// Why a typo-table document or merge was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifierTypoTableError {
    DocumentTooLarge {
        bytes: usize,
    },
    TooManyPairs {
        limit: usize,
    },
    InvalidLine {
        line: usize,
        reason: InvalidTypoLine,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidTypoLine {
    /// The line does not hold exactly two words.
    NotAPair,
    /// A word holds a character other than a lower-case ASCII letter.
    NotLowercaseLetters,
    /// A word is longer than [`MAX_IDENTIFIER_TYPO_WORD_BYTES`].
    WordTooLong,
    /// The misspelling equals its correction.
    SameWord,
}

impl fmt::Display for IdentifierTypoTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge { bytes } => write!(
                formatter,
                "identifier typo table is {bytes} bytes; the limit is {MAX_IDENTIFIER_TYPO_DOCUMENT_BYTES}"
            ),
            Self::TooManyPairs { limit } => write!(
                formatter,
                "identifier typo table holds more than {limit} distinct pairs"
            ),
            Self::InvalidLine { line, reason } => {
                write!(formatter, "identifier typo table line {line}: {reason}")
            }
        }
    }
}

impl fmt::Display for InvalidTypoLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotAPair => "expected `wrong right`, two words",
            Self::NotLowercaseLetters => "a word holds only lower-case ASCII letters",
            Self::WordTooLong => "a word is longer than the limit",
            Self::SameWord => "the misspelling equals its correction",
        })
    }
}

impl std::error::Error for IdentifierTypoTableError {}

impl IdentifierTypoTable {
    /// Parse one document. Any malformed line, or a document over the size or
    /// pair limit, refuses the whole document.
    pub fn parse(document: &str) -> Result<Self, IdentifierTypoTableError> {
        if document.len() > MAX_IDENTIFIER_TYPO_DOCUMENT_BYTES {
            return Err(IdentifierTypoTableError::DocumentTooLarge {
                bytes: document.len(),
            });
        }
        let mut table = Self::default();
        for (index, line) in document.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let invalid = |reason| IdentifierTypoTableError::InvalidLine {
                line: index + 1,
                reason,
            };
            let mut words = trimmed.split_ascii_whitespace();
            let (Some(wrong), Some(right), None) = (words.next(), words.next(), words.next())
            else {
                return Err(invalid(InvalidTypoLine::NotAPair));
            };
            for word in [wrong, right] {
                if !word.bytes().all(|byte| byte.is_ascii_lowercase()) {
                    return Err(invalid(InvalidTypoLine::NotLowercaseLetters));
                }
                if word.len() > MAX_IDENTIFIER_TYPO_WORD_BYTES {
                    return Err(invalid(InvalidTypoLine::WordTooLong));
                }
            }
            if wrong == right {
                return Err(invalid(InvalidTypoLine::SameWord));
            }
            table.insert(wrong, right)?;
        }
        Ok(table)
    }

    fn insert(&mut self, wrong: &str, right: &str) -> Result<(), IdentifierTypoTableError> {
        if self
            .corrections
            .entry(wrong.to_owned())
            .or_default()
            .insert(right.to_owned())
        {
            self.pairs += 1;
            if self.pairs > MAX_IDENTIFIER_TYPO_PAIRS {
                return Err(IdentifierTypoTableError::TooManyPairs {
                    limit: MAX_IDENTIFIER_TYPO_PAIRS,
                });
            }
            self.correct_words.insert(right.to_owned());
        }
        Ok(())
    }

    /// The union of two tables, refused when it exceeds the pair limit.
    pub fn merged(mut self, other: &Self) -> Result<Self, IdentifierTypoTableError> {
        for (wrong, rights) in &other.corrections {
            for right in rights {
                self.insert(wrong, right)?;
            }
        }
        Ok(self)
    }

    pub fn is_empty(&self) -> bool {
        self.pairs == 0
    }

    /// The number of distinct `wrong right` pairs.
    pub fn len(&self) -> usize {
        self.pairs
    }

    /// Whether the identifier part at `start..end` of `lowered_identifier`, a
    /// whole identifier lower-cased in ASCII, is a known misspelling.
    ///
    /// As upstream does, a listed part is not reported when the identifier
    /// read from the part's start spells a longer correct word that begins
    /// with the part, or read back from its end spells one that ends with it:
    /// the part splitter cut a real word there, not a typist.
    pub fn known_misspelling(&self, lowered_identifier: &str, start: usize, end: usize) -> bool {
        let part = &lowered_identifier[start..end];
        if !self.corrections.contains_key(part) {
            return false;
        }
        let from_start = &lowered_identifier[start..];
        let to_end = &lowered_identifier[..end];
        !self.correct_words.iter().any(|right| {
            right.len() > part.len()
                && ((right.starts_with(part) && from_start.starts_with(right.as_str()))
                    || (right.ends_with(part) && to_end.ends_with(right.as_str())))
        })
    }

    /// A digest of the pairs that ignores their order, comments, whitespace
    /// and duplicates. Pack manifests pin it, and policy units that consulted
    /// the table are keyed by it.
    pub fn content_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        for (wrong, rights) in &self.corrections {
            for right in rights {
                hasher.update(wrong.as_bytes());
                hasher.update(b"\0");
                hasher.update(right.as_bytes());
                hasher.update(b"\n");
            }
        }
        hasher.finalize().into()
    }

    /// [`Self::content_digest`] as lower-case hex, the form manifests record.
    pub fn content_hash_hex(&self) -> String {
        self.content_digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_ignores_order_comments_whitespace_and_duplicates() {
        let left = IdentifierTypoTable::parse("lenght length\nrecieve receive\n").unwrap();
        let right = IdentifierTypoTable::parse(
            "# From a list\n\nrecieve\treceive\n  lenght   length  \nlenght length\n",
        )
        .unwrap();
        assert_eq!(left, right);
        assert_eq!(left.len(), 2);
        assert_eq!(left.content_digest(), right.content_digest());
        let other = IdentifierTypoTable::parse("lenght length\n").unwrap();
        assert_ne!(left.content_digest(), other.content_digest());
        // A digest the packs repository can recompute without this crate.
        // sha256 of b"bifrost-identifier-typos:v1\0lenght\0length\nrecieve\0receive\n"
        assert_eq!(
            left.content_hash_hex(),
            "a393e44ed89f862de7c394042445a61aed12913a3ae12400a4b04e9fd4a173a1"
        );
    }

    #[test]
    fn a_malformed_line_refuses_the_whole_document() {
        for (document, reason) in [
            ("lenght\n", InvalidTypoLine::NotAPair),
            ("lenght length extra\n", InvalidTypoLine::NotAPair),
            ("Lenght length\n", InvalidTypoLine::NotLowercaseLetters),
            ("p0enis penis\n", InvalidTypoLine::NotLowercaseLetters),
            ("same same\n", InvalidTypoLine::SameWord),
        ] {
            assert_eq!(
                IdentifierTypoTable::parse(&format!("ok okay\n{document}")),
                Err(IdentifierTypoTableError::InvalidLine { line: 2, reason }),
                "{document:?}"
            );
        }
        let long = "a".repeat(MAX_IDENTIFIER_TYPO_WORD_BYTES + 1);
        assert_eq!(
            IdentifierTypoTable::parse(&format!("{long} b\n")),
            Err(IdentifierTypoTableError::InvalidLine {
                line: 1,
                reason: InvalidTypoLine::WordTooLong
            })
        );
    }

    #[test]
    fn size_and_pair_limits_refuse_rather_than_truncate() {
        let oversized = "#".repeat(MAX_IDENTIFIER_TYPO_DOCUMENT_BYTES + 1);
        assert_eq!(
            IdentifierTypoTable::parse(&oversized),
            Err(IdentifierTypoTableError::DocumentTooLarge {
                bytes: MAX_IDENTIFIER_TYPO_DOCUMENT_BYTES + 1
            })
        );
        // Distinct lower-case words: `index` in base 26, four letters.
        let word = |index: usize| {
            (0..4)
                .map(|place| char::from(b'a' + (index / 26usize.pow(place) % 26) as u8))
                .collect::<String>()
        };
        let pairs = |range: std::ops::Range<usize>| {
            range
                .map(|index| format!("{} x\n", word(index)))
                .collect::<String>()
        };
        let full = IdentifierTypoTable::parse(&pairs(0..MAX_IDENTIFIER_TYPO_PAIRS)).unwrap();
        assert_eq!(full.len(), MAX_IDENTIFIER_TYPO_PAIRS);
        let one_more = IdentifierTypoTable::parse("zzzzz yyyyy\n").unwrap();
        assert_eq!(
            full.merged(&one_more),
            Err(IdentifierTypoTableError::TooManyPairs {
                limit: MAX_IDENTIFIER_TYPO_PAIRS
            })
        );
    }

    #[test]
    fn segmentation_guard_follows_upstream() {
        // `ther` is listed, but at the start of `therefore` it begins the
        // correct word `there`, and at the end of `xother` it ends `other`.
        let table = IdentifierTypoTable::parse("ther there\nothr other\nlenght length\n").unwrap();
        assert!(table.known_misspelling("lenghtof", 0, 6));
        assert!(table.known_misspelling("therx", 0, 4));
        assert!(!table.known_misspelling("therefore", 0, 4));
        assert!(!table.known_misspelling("xother", 2, 6));
        assert!(!table.known_misspelling("length", 0, 6));
    }
}
