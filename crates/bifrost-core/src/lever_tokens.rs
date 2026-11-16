//! Cache-identity levers kept as files of unique change names (#11570).
//!
//! A lever file lists one change name per line, in the form
//! `<issue>-<slug>`, for example `11570-lever-token-files`. Lines that start
//! with `#` are comments, and blank lines are ignored; neither is hashed. The
//! first non-comment line may instead be `checkpoint <64 lowercase hex>`,
//! which stands for every line a compaction replaced.
//!
//! The file's state is a digest chained over its lines in order, starting
//! from a fixed value. A checkpoint line is that state at the point where it
//! was cut, so compacting a file never changes any identity derived from it.
//! Each lever's identity is the state hashed with the lever's name, so one
//! file can carry several levers that always move together.
//!
//! Two changes add two different lines, so two heads with different token
//! sets have different identities by construction, whatever their number of
//! lines; a cache written by a binary built from one head is never read as
//! another head's. The rules for adding a token are in
//! `.agents/docs/cache-identity-levers.md`.

use std::fmt;

use sha2::{Digest, Sha256};

const STATE_DOMAIN: &[u8] = b"bifrost-lever-tokens\0";
const IDENTITY_DOMAIN: &[u8] = b"bifrost-lever\0";
const CHECKPOINT_PREFIX: &str = "checkpoint ";

/// The chained state of a lever file at one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeverState([u8; 32]);

impl LeverState {
    /// The state of a file with no token line.
    pub fn initial() -> Self {
        Self(Sha256::digest(STATE_DOMAIN).into())
    }

    /// The state after one more token line.
    pub fn after(self, token: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(token.as_bytes());
        Self(hasher.finalize().into())
    }

    /// The identity of the lever `name` at this state.
    pub fn identity(self, name: &str) -> LeverIdentity {
        let mut hasher = Sha256::new();
        hasher.update(IDENTITY_DOMAIN);
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(self.0);
        LeverIdentity(hasher.finalize().into())
    }

    fn parse_hex(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut bytes = [0; 32];
        for (index, pair) in text.as_bytes().chunks(2).enumerate() {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            bytes[index] = digit(pair[0])? << 4 | digit(pair[1])?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for LeverState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|byte| write!(formatter, "{byte:02x}"))
    }
}

/// One lever's identity: the value a cache key carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeverIdentity([u8; 32]);

impl fmt::Display for LeverIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|byte| write!(formatter, "{byte:02x}"))
    }
}

/// A parsed lever file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeverTokens<'a> {
    checkpoint: Option<LeverState>,
    tokens: Vec<&'a str>,
}

/// Why a lever file is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeverTokensError {
    /// A token is not `<issue>-<slug>`: digits, then lowercase letters,
    /// digits and single hyphens.
    MalformedToken { line: usize, text: String },
    /// A token appears twice, as a union merge of two branches that added
    /// the same line would leave it.
    DuplicateToken { line: usize, token: String },
    /// A checkpoint line is not the first non-comment line, or its digest is
    /// not 64 lowercase hex digits.
    MisplacedCheckpoint { line: usize },
}

impl fmt::Display for LeverTokensError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedToken { line, text } => {
                write!(
                    formatter,
                    "line {line}: `{text}` is not an <issue>-<slug> token"
                )
            }
            Self::DuplicateToken { line, token } => {
                write!(formatter, "line {line}: token `{token}` appears twice")
            }
            Self::MisplacedCheckpoint { line } => write!(
                formatter,
                "line {line}: a checkpoint must be the first non-comment line and hold 64 lowercase hex digits"
            ),
        }
    }
}

impl std::error::Error for LeverTokensError {}

impl<'a> LeverTokens<'a> {
    pub fn parse(text: &'a str) -> Result<Self, LeverTokensError> {
        let mut checkpoint = None;
        let mut tokens = Vec::<&str>::new();
        let mut first = true;
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(hex) = line.strip_prefix(CHECKPOINT_PREFIX) {
                if !first {
                    return Err(LeverTokensError::MisplacedCheckpoint { line: line_number });
                }
                checkpoint = Some(
                    LeverState::parse_hex(hex)
                        .ok_or(LeverTokensError::MisplacedCheckpoint { line: line_number })?,
                );
            } else if !is_well_formed_token(line) {
                return Err(LeverTokensError::MalformedToken {
                    line: line_number,
                    text: line.to_owned(),
                });
            } else if tokens.contains(&line) {
                return Err(LeverTokensError::DuplicateToken {
                    line: line_number,
                    token: line.to_owned(),
                });
            } else {
                tokens.push(line);
            }
            first = false;
        }
        Ok(Self { checkpoint, tokens })
    }

    /// The token lines after any checkpoint, in file order.
    pub fn tokens(&self) -> &[&'a str] {
        &self.tokens
    }

    /// The chained state after every line.
    pub fn state(&self) -> LeverState {
        Self::state_of(self.checkpoint, &self.tokens)
    }

    /// The identity of the lever `name` this file carries.
    pub fn identity(&self, name: &str) -> LeverIdentity {
        self.state().identity(name)
    }

    /// The identity `name` had before the file's last token was added: what a
    /// head one change older keyed its caches by. Used to show that a new
    /// token invalidates them. A lever file always keeps at least one token
    /// line, and compaction keeps the last one.
    pub fn identity_before_last_token(&self, name: &str) -> LeverIdentity {
        let (_, older) = self
            .tokens
            .split_last()
            .expect("a lever file keeps at least one token line");
        Self::state_of(self.checkpoint, older).identity(name)
    }

    /// The file text with the first `cut` token lines replaced by one
    /// checkpoint line. The comment lines before the first token line are
    /// kept; the identity of every lever the file carries is unchanged.
    pub fn compact(&self, text: &str, cut: usize) -> String {
        assert!(
            cut <= self.tokens.len(),
            "cut {cut} is past the file's tokens"
        );
        let checkpoint = Self::state_of(self.checkpoint, &self.tokens[..cut]);
        let mut compacted = text
            .lines()
            .take_while(|line| {
                let line = line.trim();
                line.is_empty() || line.starts_with('#')
            })
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        compacted.push_str(&format!("{CHECKPOINT_PREFIX}{checkpoint}\n"));
        for token in &self.tokens[cut..] {
            compacted.push_str(token);
            compacted.push('\n');
        }
        compacted
    }

    fn state_of(checkpoint: Option<LeverState>, tokens: &[&str]) -> LeverState {
        tokens.iter().fold(
            checkpoint.unwrap_or_else(LeverState::initial),
            |state, token| state.after(token),
        )
    }
}

/// The text of the lever file `levers/<file>` in the invoking crate, embedded
/// at compile time so the published package carries it.
#[macro_export]
macro_rules! lever_file {
    ($file:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/levers/", $file))
    };
}

/// The identity of the lever `name` as `<name>/<64 hex digits>`, for a cache
/// key that keeps a recognizable prefix. Parses the file text, so call it
/// through [`lever_label!`] to compute it once.
pub fn lever_label(name: &str, file_text: &str) -> String {
    let tokens = LeverTokens::parse(file_text)
        .unwrap_or_else(|error| panic!("lever file for `{name}` is malformed: {error}"));
    format!("{name}/{}", tokens.identity(name))
}

/// The raw 32-byte identity of a lever, for scalar BLOB columns and hash fields.
/// This is the domain-separated identity, never the token-chain state or label.
pub fn lever_identity(name: &str, file_text: &str) -> [u8; 32] {
    let tokens = LeverTokens::parse(file_text)
        .unwrap_or_else(|error| panic!("lever file for `{name}` is malformed: {error}"));
    tokens.identity(name).0
}

/// The raw identity a head one token older used, for invalidation tests.
pub fn lever_identity_before_last_token(name: &str, file_text: &str) -> [u8; 32] {
    let tokens = LeverTokens::parse(file_text)
        .unwrap_or_else(|error| panic!("lever file for `{name}` is malformed: {error}"));
    tokens.identity_before_last_token(name).0
}

/// The label a head one change older had: [`lever_label`] without the last
/// token line. Tests use it to show that a new token moves the label.
pub fn lever_label_before_last_token(name: &str, file_text: &str) -> String {
    let tokens = LeverTokens::parse(file_text)
        .unwrap_or_else(|error| panic!("lever file for `{name}` is malformed: {error}"));
    format!("{name}/{}", tokens.identity_before_last_token(name))
}

/// The label of the lever `$name` kept in `levers/$file` of the invoking
/// crate, as a `&'static str`. The label is computed on first use and then
/// kept.
#[macro_export]
macro_rules! lever_label {
    ($name:literal, $file:literal) => {{
        static LABEL: ::std::sync::LazyLock<::std::string::String> =
            ::std::sync::LazyLock::new(|| {
                $crate::lever_tokens::lever_label($name, $crate::lever_file!($file))
            });
        LABEL.as_str()
    }};
}

/// `<issue>-<slug>`: one or more digits, a hyphen, then lowercase letters
/// and digits in hyphen-separated words.
fn is_well_formed_token(token: &str) -> bool {
    let Some((issue, slug)) = token.split_once('-') else {
        return false;
    };
    !issue.is_empty()
        && issue.bytes().all(|byte| byte.is_ascii_digit())
        && !slug.is_empty()
        && slug.split('-').all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# A test lever.\n# Second comment line.\n\n11570-first\n11571-second-change\n11572-third\n";

    #[test]
    fn compacting_any_prefix_keeps_every_identity() {
        let tokens = LeverTokens::parse(FILE).unwrap();
        for cut in 0..=tokens.tokens().len() {
            let compacted = tokens.compact(FILE, cut);
            let reparsed = LeverTokens::parse(&compacted).unwrap();
            assert_eq!(reparsed.state(), tokens.state(), "cut {cut}:\n{compacted}");
            assert_eq!(reparsed.tokens(), &tokens.tokens()[cut..]);
            assert!(
                compacted.starts_with("# A test lever.\n# Second comment line.\n\ncheckpoint ")
            );
            // Compacting a compacted file again keeps it too.
            for again in 0..=reparsed.tokens().len() {
                let twice_text = reparsed.compact(&compacted, again);
                let twice = LeverTokens::parse(&twice_text).unwrap();
                assert_eq!(twice.state(), tokens.state(), "cut {cut} then {again}");
            }
        }
    }

    #[test]
    fn different_token_sets_have_different_identities() {
        let identity = |text: &str| LeverTokens::parse(text).unwrap().identity("test.lever");
        // As many tokens, one different: two heads that each added a change.
        assert_ne!(identity("1-a\n2-b\n3-c\n"), identity("1-a\n2-b\n4-d\n"));
        // The same tokens in another order.
        assert_ne!(identity("1-a\n2-b\n"), identity("2-b\n1-a\n"));
        // A file carries one identity per lever name.
        let tokens = LeverTokens::parse("1-a\n").unwrap();
        assert_ne!(tokens.identity("first"), tokens.identity("second"));
        // A new token moves the identity away from the one before it.
        let two = LeverTokens::parse("1-a\n2-b\n").unwrap();
        assert_eq!(
            two.identity_before_last_token("first"),
            tokens.identity("first")
        );
        assert_ne!(two.identity("first"), tokens.identity("first"));
    }

    #[test]
    fn malformed_files_are_refused() {
        let error = |text: &str| LeverTokens::parse(text).unwrap_err();
        assert_eq!(
            error("1-a\n2-b\n1-a\n"),
            LeverTokensError::DuplicateToken {
                line: 3,
                token: "1-a".to_owned()
            }
        );
        assert!(matches!(
            error("1-a\ncheckpoint 00\n"),
            LeverTokensError::MisplacedCheckpoint { line: 2 }
        ));
        assert!(matches!(
            error(&format!("1-a\ncheckpoint {}\n", "0".repeat(64))),
            LeverTokensError::MisplacedCheckpoint { line: 2 }
        ));
        assert!(matches!(
            error(&format!("checkpoint {}\n", "A".repeat(64))),
            LeverTokensError::MisplacedCheckpoint { line: 1 }
        ));
        for token in [
            "v849",
            "11570",
            "11570-",
            "11570-Upper",
            "11570--double",
            "x-11570",
            "11570 slug",
        ] {
            assert!(
                matches!(
                    error(token),
                    LeverTokensError::MalformedToken { line: 1, .. }
                ),
                "{token}"
            );
        }
    }

    #[test]
    fn every_lever_file_in_the_workspace_is_well_formed() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&crates).unwrap() {
            let levers = entry.unwrap().path().join("levers");
            let Ok(entries) = std::fs::read_dir(&levers) else {
                continue;
            };
            for file in entries {
                let path = file.unwrap().path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "tokens")
                {
                    files.push(path);
                }
            }
        }
        assert!(
            !files.is_empty(),
            "no lever files under {}",
            crates.display()
        );
        for path in &files {
            let text = std::fs::read_to_string(path).unwrap();
            let tokens = LeverTokens::parse(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert!(
                !tokens.tokens().is_empty(),
                "{}: a lever file keeps at least one token line; compact with --keep 1 or more",
                path.display()
            );
        }
    }
}
