//! Accepted identifier words for relations that guess at misspellings.
//!
//! `js/misspelled-identifier` reports an identifier part one typing slip from
//! a more frequent part in the same file. A project or its host can name the
//! parts that are real words in its vocabulary, and the relation never reports
//! a part the dictionary accepts.
//!
//! The document is plain UTF-8 text with one word per line, so a repository
//! can append to a checked-in copy and merge appends from several branches
//! without conflicts. Blank lines and lines whose first non-blank character is
//! `#` are ignored. A word is one identifier part as the relation splits it:
//! ASCII letters, either all lower case, all upper case, or one capital
//! followed by lower case. Matching ignores case, as the relation does.
//!
//! The text is untrusted repository or tenant input. Parsing never allocates
//! more than the bounded document, and a line that is not a word is reported
//! and skipped rather than widening what the dictionary accepts.

use std::collections::BTreeSet;
use std::fmt;

use sha2::{Digest, Sha256};

/// The largest dictionary document read, in bytes.
pub const MAX_IDENTIFIER_DICTIONARY_DOCUMENT_BYTES: usize = 64 * 1024;
/// The most distinct words one dictionary holds, across every merged source.
pub const MAX_IDENTIFIER_DICTIONARY_WORDS: usize = 4_096;
/// The longest accepted word, in bytes.
pub const MAX_IDENTIFIER_DICTIONARY_WORD_BYTES: usize = 64;
/// The most rejected lines one parse reports; later ones are counted only.
pub const MAX_IDENTIFIER_DICTIONARY_REJECTIONS: usize = 32;

const DIGEST_DOMAIN: &[u8] = b"bifrost-identifier-dictionary:v1\0";

/// A bounded, case-insensitive set of accepted identifier parts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct IdentifierDictionary {
    words: BTreeSet<String>,
}

/// Why a whole dictionary document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifierDictionaryError {
    DocumentTooLarge { bytes: usize },
    TooManyWords { limit: usize },
}

impl fmt::Display for IdentifierDictionaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge { bytes } => write!(
                formatter,
                "identifier dictionary is {bytes} bytes; the limit is {MAX_IDENTIFIER_DICTIONARY_DOCUMENT_BYTES}"
            ),
            Self::TooManyWords { limit } => write!(
                formatter,
                "identifier dictionary holds more than {limit} distinct words"
            ),
        }
    }
}

impl std::error::Error for IdentifierDictionaryError {}

/// One line of a document that is neither a word, a comment nor blank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedDictionaryLine {
    /// One-based line number in the document.
    pub line: usize,
    pub reason: RejectedDictionaryLineReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectedDictionaryLineReason {
    /// The line holds a character other than an ASCII letter.
    NotLetters,
    /// The word is longer than [`MAX_IDENTIFIER_DICTIONARY_WORD_BYTES`].
    TooLong,
    /// The word spans several identifier parts, such as `fromLink`, which the
    /// relation never compares as a whole. Add each part instead.
    SeveralParts,
}

impl fmt::Display for RejectedDictionaryLineReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotLetters => "a word holds only ASCII letters",
            Self::TooLong => "the word is longer than the limit",
            Self::SeveralParts => "the word spans several identifier parts; add each part",
        })
    }
}

/// A parsed document and the lines it skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedIdentifierDictionary {
    pub dictionary: IdentifierDictionary,
    /// The first [`MAX_IDENTIFIER_DICTIONARY_REJECTIONS`] skipped lines.
    pub rejected: Vec<RejectedDictionaryLine>,
    /// Every skipped line, including those beyond the reported ones.
    pub rejected_count: usize,
}

impl IdentifierDictionary {
    /// The dictionary that accepts nothing.
    pub const EMPTY: Self = Self {
        words: BTreeSet::new(),
    };

    /// Parse one document. A document over the size or word limit is refused
    /// as a whole, because accepting a prefix would make which words count
    /// depend on their order in the file.
    pub fn parse(document: &str) -> Result<ParsedIdentifierDictionary, IdentifierDictionaryError> {
        if document.len() > MAX_IDENTIFIER_DICTIONARY_DOCUMENT_BYTES {
            return Err(IdentifierDictionaryError::DocumentTooLarge {
                bytes: document.len(),
            });
        }
        let mut parsed = ParsedIdentifierDictionary::default();
        for (index, line) in document.lines().enumerate() {
            let word = line.trim();
            if word.is_empty() || word.starts_with('#') {
                continue;
            }
            match normalized_word(word) {
                Ok(normalized) => {
                    parsed.dictionary.words.insert(normalized);
                    if parsed.dictionary.words.len() > MAX_IDENTIFIER_DICTIONARY_WORDS {
                        return Err(IdentifierDictionaryError::TooManyWords {
                            limit: MAX_IDENTIFIER_DICTIONARY_WORDS,
                        });
                    }
                }
                Err(reason) => {
                    parsed.rejected_count += 1;
                    if parsed.rejected.len() < MAX_IDENTIFIER_DICTIONARY_REJECTIONS {
                        parsed.rejected.push(RejectedDictionaryLine {
                            line: index + 1,
                            reason,
                        });
                    }
                }
            }
        }
        Ok(parsed)
    }

    /// The union of two dictionaries, refused when it exceeds the word limit.
    pub fn merged(mut self, other: &Self) -> Result<Self, IdentifierDictionaryError> {
        self.words.extend(other.words.iter().cloned());
        if self.words.len() > MAX_IDENTIFIER_DICTIONARY_WORDS {
            return Err(IdentifierDictionaryError::TooManyWords {
                limit: MAX_IDENTIFIER_DICTIONARY_WORDS,
            });
        }
        Ok(self)
    }

    /// Whether the dictionary accepts `part`, compared without case.
    pub fn accepts(&self, part: &str) -> bool {
        !self.words.is_empty() && self.words.contains(&part.to_ascii_lowercase())
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// The accepted words, lower case and sorted.
    pub fn words(&self) -> impl Iterator<Item = &str> {
        self.words.iter().map(String::as_str)
    }

    /// A digest of the accepted words that ignores their order, case, comments
    /// and duplicates, for keying results that consulted the dictionary.
    pub fn content_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        for word in &self.words {
            hasher.update(word.as_bytes());
            hasher.update(b"\n");
        }
        hasher.finalize().into()
    }
}

fn normalized_word(word: &str) -> Result<String, RejectedDictionaryLineReason> {
    if !word.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(RejectedDictionaryLineReason::NotLetters);
    }
    if word.len() > MAX_IDENTIFIER_DICTIONARY_WORD_BYTES {
        return Err(RejectedDictionaryLineReason::TooLong);
    }
    let rest = &word.as_bytes()[1..];
    let one_part = rest.iter().all(u8::is_ascii_lowercase)
        || word.bytes().all(|byte| byte.is_ascii_uppercase());
    if !one_part {
        return Err(RejectedDictionaryLineReason::SeveralParts);
    }
    Ok(word.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_comments_and_blank_lines() {
        let parsed = IdentifierDictionary::parse(
            "# project words\nfrom\n\n  Href  \nHTTP\nhref\n\t# indented comment\n",
        )
        .unwrap();
        assert_eq!(parsed.rejected_count, 0);
        assert_eq!(
            parsed.dictionary.words().collect::<Vec<_>>(),
            ["from", "href", "http"]
        );
        assert!(parsed.dictionary.accepts("From"));
        assert!(parsed.dictionary.accepts("HREF"));
        assert!(!parsed.dictionary.accepts("form"));
    }

    #[test]
    fn rejected_lines_are_reported_and_skipped() {
        let parsed =
            IdentifierDictionary::parse("fromLink\nsnake_case\nwörd\ngood\nxHTTP\n").unwrap();
        assert_eq!(parsed.dictionary.words().collect::<Vec<_>>(), ["good"]);
        assert_eq!(
            parsed.rejected,
            [
                RejectedDictionaryLine {
                    line: 1,
                    reason: RejectedDictionaryLineReason::SeveralParts
                },
                RejectedDictionaryLine {
                    line: 2,
                    reason: RejectedDictionaryLineReason::NotLetters
                },
                RejectedDictionaryLine {
                    line: 3,
                    reason: RejectedDictionaryLineReason::NotLetters
                },
                RejectedDictionaryLine {
                    line: 5,
                    reason: RejectedDictionaryLineReason::SeveralParts
                },
            ]
        );
    }

    #[test]
    fn limits_refuse_the_whole_document() {
        let too_long_word = "a".repeat(MAX_IDENTIFIER_DICTIONARY_WORD_BYTES + 1);
        let parsed = IdentifierDictionary::parse(&too_long_word).unwrap();
        assert_eq!(
            parsed.rejected[0].reason,
            RejectedDictionaryLineReason::TooLong
        );

        let oversized = "#".repeat(MAX_IDENTIFIER_DICTIONARY_DOCUMENT_BYTES + 1);
        assert_eq!(
            IdentifierDictionary::parse(&oversized),
            Err(IdentifierDictionaryError::DocumentTooLarge {
                bytes: MAX_IDENTIFIER_DICTIONARY_DOCUMENT_BYTES + 1
            })
        );

        let mut rejections = String::new();
        for _ in 0..MAX_IDENTIFIER_DICTIONARY_REJECTIONS + 5 {
            rejections.push_str("not-a-word\n");
        }
        let parsed = IdentifierDictionary::parse(&rejections).unwrap();
        assert_eq!(parsed.rejected.len(), MAX_IDENTIFIER_DICTIONARY_REJECTIONS);
        assert_eq!(
            parsed.rejected_count,
            MAX_IDENTIFIER_DICTIONARY_REJECTIONS + 5
        );
    }

    #[test]
    fn word_limit_applies_to_documents_and_merges() {
        let words = |range: std::ops::Range<usize>| {
            range
                .map(|index| {
                    // Spell each index in letters so it is a valid word.
                    let mut word = String::from("w");
                    let mut rest = index;
                    loop {
                        word.push(char::from(b'a' + (rest % 26) as u8));
                        rest /= 26;
                        if rest == 0 {
                            break word;
                        }
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        let full = IdentifierDictionary::parse(&words(0..MAX_IDENTIFIER_DICTIONARY_WORDS))
            .unwrap()
            .dictionary;
        assert_eq!(full.len(), MAX_IDENTIFIER_DICTIONARY_WORDS);
        assert_eq!(
            IdentifierDictionary::parse(&words(0..MAX_IDENTIFIER_DICTIONARY_WORDS + 1)),
            Err(IdentifierDictionaryError::TooManyWords {
                limit: MAX_IDENTIFIER_DICTIONARY_WORDS
            })
        );
        let same = full.clone().merged(&full).unwrap();
        assert_eq!(same, full);
        let one_more = IdentifierDictionary::parse("zzzz").unwrap().dictionary;
        assert!(full.merged(&one_more).is_err());
    }

    #[test]
    fn digest_ignores_order_case_and_duplicates() {
        let left = IdentifierDictionary::parse("from\nHref\n")
            .unwrap()
            .dictionary;
        let right = IdentifierDictionary::parse("# reordered\nhref\nFROM\nfrom\n")
            .unwrap()
            .dictionary;
        assert_eq!(left.content_digest(), right.content_digest());
        let other = IdentifierDictionary::parse("from\n").unwrap().dictionary;
        assert_ne!(left.content_digest(), other.content_digest());
        assert_ne!(
            IdentifierDictionary::default().content_digest(),
            other.content_digest()
        );
    }
}
