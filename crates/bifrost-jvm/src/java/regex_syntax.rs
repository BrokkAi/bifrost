//! Java Pattern value grammar. Unrepresented languages explicitly abstain.
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::analyzer::structural::regex::{
    CharacterSet, ClassAtom, EscapeValue, GroupPrefix, RegexAnalysis, RegexFlags, RegexSyntax,
    single_character,
};

#[derive(Default)]
pub(super) struct JavaRegexSyntax {
    pub refusal: std::cell::Cell<Option<&'static str>>,
    named_groups: std::cell::RefCell<std::collections::HashSet<Vec<char>>>,
}
const UNIX_LINES: u32 = 1;
const UNICODE_CASE: u32 = 2;
const UNICODE_CLASSES: u32 = 4;

fn ascii_category(code: char) -> Option<CharacterSet> {
    let set = match code.to_ascii_lowercase() {
        'd' => CharacterSet {
            ranges: vec![(48, 57)],
        },
        's' => CharacterSet {
            ranges: vec![(9, 13), (32, 32)],
        },
        'w' => CharacterSet {
            ranges: vec![(48, 57), (65, 90), (95, 95), (97, 122)],
        },
        _ => return None,
    };
    Some(if code.is_ascii_uppercase() {
        set.complement()
    } else {
        set
    })
}
fn property(name: &str) -> Option<CharacterSet> {
    Some(CharacterSet {
        ranges: match name {
            "Lower" => vec![(97, 122)],
            "Upper" => vec![(65, 90)],
            "ASCII" => vec![(0, 127)],
            "Alpha" => vec![(65, 90), (97, 122)],
            "Digit" => vec![(48, 57)],
            "Alnum" => vec![(48, 57), (65, 90), (97, 122)],
            "Punct" => vec![(33, 47), (58, 64), (91, 96), (123, 126)],
            "Graph" => vec![(33, 126)],
            "Print" => vec![(32, 126)],
            "Blank" => vec![(9, 9), (32, 32)],
            "Cntrl" => vec![(0, 31), (127, 127)],
            "XDigit" => vec![(48, 57), (65, 70), (97, 102)],
            "Space" => vec![(9, 13), (32, 32)],
            // javaLowerCase, IsAlphabetic, InGreek, block and script tables must
            // match the selected JDK Unicode version; Rust Unicode tables do not.
            _ => return None,
        },
    })
}
impl RegexSyntax for JavaRegexSyntax {
    fn group_prefix(&self, chars: &[char], start: usize) -> GroupPrefix {
        let prefix = match (chars.get(start + 1), chars.get(start + 2)) {
            (Some(':'), _) => GroupPrefix::Noncapturing,
            (Some('='), _) => GroupPrefix::LookaheadPositive,
            (Some('!'), _) => GroupPrefix::LookaheadNegative,
            (Some('<'), Some('=')) => GroupPrefix::LookbehindPositive,
            (Some('<'), Some('!')) => GroupPrefix::LookbehindNegative,
            (Some('<'), _) => {
                let name: Vec<_> = chars[start + 2..]
                    .iter()
                    .copied()
                    .take_while(|c| *c != '>')
                    .collect();
                if !name.first().is_some_and(char::is_ascii_alphabetic)
                    || !name.iter().all(char::is_ascii_alphanumeric)
                {
                    self.refusal.set(Some("java-invalid-group-name"));
                }
                if !self.named_groups.borrow_mut().insert(name) {
                    self.refusal.set(Some("java-duplicate-group-name"));
                }
                GroupPrefix::Named { name_offset: 2 }
            }
            (Some('i' | 'm' | 's' | 'x' | 'u' | 'd' | 'U' | '-'), _) => GroupPrefix::Flags,
            // Atomic groups require backtracking semantics absent in the NFA.
            _ => GroupPrefix::Unsupported,
        };
        if matches!(prefix, GroupPrefix::Unsupported) {
            self.refusal.set(Some("java-special-group-not-modeled"));
        }
        prefix
    }
    fn incomplete_group_end(&self, chars: &[char], start: usize) -> Option<usize> {
        if chars.get(start) != Some(&'<') {
            return None;
        }
        let mut close = start + 1;
        while chars.get(close).is_some_and(|c| c.is_ascii_alphanumeric()) {
            close += 1;
        }
        (chars.get(start + 1).is_some_and(char::is_ascii_alphabetic)
            && chars.get(close) == Some(&'>'))
        .then_some(close + 1)
    }
    fn inline_flags(
        &self,
        chars: &[char],
        start: usize,
        mut flags: RegexFlags,
    ) -> Option<(usize, RegexFlags)> {
        let mut enabled = true;
        let mut i = start;
        while let Some(&code) = chars.get(i) {
            match code {
                ':' | ')' => {
                    // Java restores flag-only groups at the enclosing group's
                    // end; the shared parser currently restores scoped groups
                    // only. Admit flag-only syntax solely at pattern offset 0.
                    if code == ')' && start != 2 {
                        self.refusal
                            .set(Some("java-flag-only-group-position-not-modeled"));
                        return None;
                    }
                    if flags.verbose && flags.dialect_flags & UNIX_LINES != 0 {
                        self.refusal
                            .set(Some("java-comments-unix-lines-not-modeled"));
                        return None;
                    }
                    flags.ascii = flags.dialect_flags & UNICODE_CLASSES == 0;
                    if !self.case_folding_is_complete(flags) {
                        self.refusal
                            .set(Some("java-unicode-case-folding-not-modeled"));
                        return None;
                    }
                    return (i > start).then_some((i, flags));
                }
                '-' if enabled => enabled = false,
                'i' => flags.ignorecase = enabled,
                'm' => {
                    flags.multiline = enabled;
                    if enabled {
                        self.refusal.set(Some("java-multiline-anchors-not-modeled"));
                        return None;
                    }
                }
                's' => flags.dotall = enabled,
                'x' => flags.verbose = enabled,
                'd' | 'u' | 'U' => {
                    let bit = match code {
                        'd' => UNIX_LINES,
                        'u' => UNICODE_CASE,
                        _ => UNICODE_CASE | UNICODE_CLASSES,
                    };
                    if enabled {
                        flags.dialect_flags |= bit;
                    } else {
                        flags.dialect_flags &= !bit;
                    }
                }
                _ => return None,
            }
            i += 1;
        }
        None
    }
    fn escape(
        &self,
        chars: &[char],
        start: usize,
        in_class: bool,
        flags: RegexFlags,
    ) -> Option<EscapeValue> {
        let result = self.parse_escape(chars, start, in_class, flags);
        if let Some(reason) = result.as_ref().and_then(|value| value.incomplete) {
            self.refusal.set(Some(reason));
        } else if result.is_none() {
            self.refusal.set(Some("java-unsupported-regex-escape"));
        }
        result
    }
    fn class_atom(&self, chars: &[char], start: usize, flags: RegexFlags) -> Option<ClassAtom> {
        let value = *chars.get(start)?;
        if value == '[' || (value == '&' && chars.get(start + 1) == Some(&'&')) {
            self.refusal
                .set(Some("java-class-set-operation-not-modeled"));
            return Some(ClassAtom {
                start,
                end: start + 1,
                value: None,
                set: None,
                kind: NormalizedKind::RegexLiteral,
                construct: None,
                backspace: false,
                incomplete: Some("java-class-set-operation-not-modeled"),
            });
        }
        if value == '\\' {
            let escape = self.escape(chars, start, true, flags)?;
            return Some(ClassAtom {
                start,
                end: escape.end,
                value: escape.first_set.as_ref().and_then(single_character),
                set: escape.first_set,
                kind: NormalizedKind::RegexEscape,
                construct: escape.construct,
                backspace: false,
                incomplete: escape.incomplete,
            });
        }
        // Java COMMENTS applies inside classes; the shared class parser does
        // not skip whitespace/comments there, so refuse rather than differ.
        let incomplete = (flags.verbose && (self.verbose_whitespace(value) || value == '#'))
            .then_some("java-comments-in-class-not-modeled");
        if let Some(reason) = incomplete {
            self.refusal.set(Some(reason));
        }
        Some(ClassAtom {
            start,
            end: start + 1,
            value: Some(value),
            set: Some(CharacterSet::one(value)),
            kind: NormalizedKind::RegexLiteral,
            construct: Some(value.to_string()),
            backspace: false,
            incomplete,
        })
    }
    fn wildcard(&self, flags: RegexFlags) -> CharacterSet {
        if flags.dotall {
            CharacterSet {
                ranges: vec![(0, 0x10ffff)],
            }
        } else if flags.dialect_flags & UNIX_LINES != 0 {
            CharacterSet::any_except_newline()
        } else {
            CharacterSet {
                ranges: vec![(10, 10), (13, 13), (0x85, 0x85), (0x2028, 0x2029)],
            }
            .complement()
        }
    }
    fn fold_case(&self, set: CharacterSet, flags: RegexFlags) -> CharacterSet {
        if flags.ignorecase && flags.dialect_flags & UNICODE_CASE != 0 {
            self.refusal
                .set(Some("java-unicode-case-folding-not-modeled"));
        }
        if flags.ignorecase {
            set.with_ascii_case_variants()
        } else {
            set
        }
    }
    fn case_folding_is_complete(&self, flags: RegexFlags) -> bool {
        !flags.ignorecase || flags.dialect_flags & UNICODE_CASE == 0
    }
    fn verbose_whitespace(&self, character: char) -> bool {
        matches!(character, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
    }
    fn verbose_comment_terminator(&self, character: char) -> bool {
        matches!(character, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
    }
    fn supports_possessive_quantifiers(&self) -> bool {
        false
    }
    fn analyze(&self, context: &mut RegexAnalysis<'_>) {
        for fact in context.facts {
            if fact
                .quantifier
                .is_some_and(|quantifier| quantifier.possessive)
            {
                self.refusal
                    .set(Some("java-possessive-quantifier-not-modeled"));
            }
            if fact.quantifier.is_some_and(|quantifier| {
                quantifier.minimum > i32::MAX as u32
                    || quantifier
                        .maximum
                        .is_some_and(|maximum| maximum > i32::MAX as u32)
            }) {
                self.refusal
                    .set(Some("java-counted-repetition-not-modeled"));
            }
            // These are AST-selected regex-value literal atoms, not Java
            // source searches. Java rejects a literal opening brace outside
            // classes; the shared parser uses literal braces for malformed or
            // COMMENTS-whitespace counted repetitions with Python semantics.
            if fact.kind == NormalizedKind::RegexLiteral
                && fact.construct.as_deref() == Some("{")
                && !fact.parent.is_some_and(|parent| {
                    context.facts[parent].kind == NormalizedKind::RegexCharacterClass
                })
            {
                self.refusal
                    .set(Some("java-counted-repetition-not-modeled"));
            }
        }
        // The common risk algorithms model LF-only assertions and ASCII word
        // boundaries. Java's Unicode boundaries/multi-terminator anchors need
        // dedicated semantics before they can contribute exact risk facts.
        if context.facts.iter().any(|f| {
            f.kind == NormalizedKind::RegexAnchor
                && (matches!(
                    f.construct.as_deref(),
                    Some("boundary:b" | "boundary:B" | "boundary:Z")
                ) || (context.flags.dialect_flags & UNIX_LINES == 0 && context.flags.multiline))
        }) {
            self.refusal
                .set(Some("java-boundary-semantics-not-modeled"));
        }
        if let Some(reason) = self.refusal.get() {
            context.mark_incomplete(0, context.chars.len(), reason);
        }
    }
}

impl JavaRegexSyntax {
    fn parse_escape(
        &self,
        chars: &[char],
        start: usize,
        in_class: bool,
        flags: RegexFlags,
    ) -> Option<EscapeValue> {
        let escaped = *chars.get(start + 1)?;
        let mut end = start + 2;
        let mut set = None;
        let mut anchor = false;
        let mut incomplete = None;
        let construct = match escaped {
            'A' | 'Z' | 'z' | 'b' | 'B' | 'G' if !in_class => {
                anchor = true;
                if escaped == 'G' {
                    incomplete = Some("java-previous-match-boundary");
                }
                Some(format!("boundary:{escaped}"))
            }
            'd' | 'D' | 'w' | 'W' | 's' | 'S' => {
                if flags.dialect_flags & UNICODE_CLASSES != 0 {
                    incomplete = Some("java-unicode-category-not-modeled");
                } else {
                    set = ascii_category(escaped);
                }
                Some(format!("category:{escaped}"))
            }
            'p' | 'P' => {
                if chars.get(end) != Some(&'{') {
                    return None;
                }
                let begin = end + 1;
                end = begin;
                while chars.get(end).is_some_and(|c| *c != '}') {
                    end += 1;
                }
                if chars.get(end) != Some(&'}') {
                    return None;
                }
                let name: String = chars[begin..end].iter().collect();
                end += 1;
                set = property(&name);
                if flags.dialect_flags & UNICODE_CLASSES != 0 || set.is_none() {
                    incomplete = Some("java-unicode-property-not-modeled");
                }
                if escaped == 'P' {
                    if flags.ignorecase {
                        incomplete = Some("java-negated-property-casefold-not-modeled");
                        set = None;
                    } else {
                        set = set.map(CharacterSet::complement);
                    }
                }
                Some(format!("property:{escaped}:{name}"))
            }
            'h' | 'H' => {
                let horizontal = CharacterSet {
                    ranges: vec![
                        (9, 9),
                        (32, 32),
                        (160, 160),
                        (0x1680, 0x1680),
                        (0x180e, 0x180e),
                        (0x2000, 0x200a),
                        (0x202f, 0x202f),
                        (0x205f, 0x205f),
                        (0x3000, 0x3000),
                    ],
                };
                set = Some(if escaped == 'H' {
                    horizontal.complement()
                } else {
                    horizontal
                });
                Some(format!("category:{escaped}"))
            }
            'v' | 'V' => {
                let vertical = CharacterSet {
                    ranges: vec![(10, 13), (0x85, 0x85), (0x2028, 0x2029)],
                };
                set = Some(if escaped == 'V' {
                    vertical.complement()
                } else {
                    vertical
                });
                Some(format!("category:{escaped}"))
            }
            'R' | 'X' => {
                incomplete = Some("java-variable-width-escape-not-modeled");
                Some(format!("escape:{escaped}"))
            }
            'Q' | 'E' => {
                incomplete = Some("java-quoted-sequence-not-modeled");
                Some("java-quoting".to_owned())
            }
            'k' | '1'..='9' => {
                incomplete = Some("java-backreference-not-modeled");
                Some("backreference".to_owned())
            }
            'x' | 'u' => {
                let braced = escaped == 'x' && chars.get(end) == Some(&'{');
                let mut scalar = 0u32;
                let digits = if braced {
                    end += 1;
                    6
                } else if escaped == 'u' {
                    4
                } else {
                    2
                };
                let mut count = 0;
                while count < digits && chars.get(end).is_some_and(|c| c.is_ascii_hexdigit()) {
                    scalar = scalar * 16 + chars[end].to_digit(16)?;
                    end += 1;
                    count += 1;
                }
                if braced {
                    if count == 0 || chars.get(end) != Some(&'}') {
                        return None;
                    }
                    end += 1;
                } else if count != digits {
                    return None;
                }
                set = Some(CharacterSet::one(char::from_u32(scalar)?));
                Some(format!("U+{scalar:04X}"))
            }
            '0' => {
                let mut scalar = 0u32;
                let first = *chars.get(end)?;
                if !matches!(first, '0'..='7') {
                    return None;
                }
                let digits = if first <= '3' { 3 } else { 2 };
                for _ in 0..digits {
                    let Some(digit @ '0'..='7') = chars.get(end) else {
                        break;
                    };
                    scalar = scalar * 8 + digit.to_digit(8)?;
                    end += 1;
                }
                set = Some(CharacterSet::one(char::from_u32(scalar)?));
                Some(format!("U+{scalar:04X}"))
            }
            't' | 'n' | 'r' | 'f' | 'a' | 'e' => {
                let ch = match escaped {
                    't' => '\t',
                    'n' => '\n',
                    'r' => '\r',
                    'f' => '\x0c',
                    'a' => '\x07',
                    _ => '\x1b',
                };
                set = Some(CharacterSet::one(ch));
                Some(format!("U+{:04X}", ch as u32))
            }
            other if other.is_ascii_alphabetic() => {
                incomplete = Some("java-unsupported-regex-escape");
                Some(format!("unknown:{other}"))
            }
            other => {
                set = Some(CharacterSet::one(other));
                Some(other.to_string())
            }
        };
        Some(EscapeValue {
            end,
            anchor,
            construct,
            first_set: set,
            incomplete,
            backspace: false,
        })
    }
}
