//! Parsers for decoded Python string-format values.
//!
//! Tree-sitter selects the string node; this module parses only its decoded
//! value. It does not search Python source text for calls, operands, or names.

use std::collections::HashSet;

const MAX_FORMAT_CHARS: usize = 8192;
const MAX_FORMAT_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraceField {
    pub selector: BraceSelector,
    pub source_char: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BraceSelector {
    Automatic(usize),
    Positional(usize),
    Named(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BraceFormat {
    pub fields: Vec<BraceField>,
    pub named_fields: HashSet<String>,
    pub max_positional_count: usize,
    pub has_automatic_fields: bool,
    pub has_explicit_fields: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PercentItem {
    pub conversion: char,
    pub mapping_key: Option<String>,
    pub width_stars: usize,
    pub precision_stars: usize,
    pub source_char: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PercentFormat {
    pub items: Vec<PercentItem>,
    pub named_fields: HashSet<String>,
    pub positional_slots: usize,
    pub has_named_items: bool,
    pub has_positional_items: bool,
    pub unsupported_conversions: Vec<(char, usize)>,
    pub complete: bool,
}

pub fn parse_brace_format(value: &str) -> BraceFormat {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() > MAX_FORMAT_CHARS {
        return BraceFormat::incomplete();
    }
    let mut parser = BraceParser {
        chars: &chars,
        fields: Vec::new(),
        named_fields: HashSet::new(),
        next_automatic: 0,
        max_positional_count: 0,
        has_automatic_fields: false,
        has_explicit_fields: false,
        complete: true,
    };
    parser.scan(0, chars.len(), 0);
    BraceFormat {
        fields: parser.fields,
        named_fields: parser.named_fields,
        max_positional_count: parser.max_positional_count,
        has_automatic_fields: parser.has_automatic_fields,
        has_explicit_fields: parser.has_explicit_fields,
        complete: parser.complete,
    }
}

impl BraceFormat {
    fn incomplete() -> Self {
        Self {
            fields: Vec::new(),
            named_fields: HashSet::new(),
            max_positional_count: 0,
            has_automatic_fields: false,
            has_explicit_fields: false,
            complete: false,
        }
    }

    pub fn mixes_numbering(&self) -> bool {
        self.has_automatic_fields && self.has_explicit_fields
    }
}

struct BraceParser<'a> {
    chars: &'a [char],
    fields: Vec<BraceField>,
    named_fields: HashSet<String>,
    next_automatic: usize,
    max_positional_count: usize,
    has_automatic_fields: bool,
    has_explicit_fields: bool,
    complete: bool,
}

impl BraceParser<'_> {
    fn scan(&mut self, start: usize, end: usize, depth: usize) {
        if depth > MAX_FORMAT_DEPTH {
            self.complete = false;
            return;
        }
        let mut cursor = start;
        while cursor < end {
            match self.chars[cursor] {
                '{' if self.chars.get(cursor + 1) == Some(&'{') => cursor += 2,
                '}' if self.chars.get(cursor + 1) == Some(&'}') => cursor += 2,
                '{' => {
                    let Some(close) = self.field_close(cursor, end) else {
                        self.complete = false;
                        return;
                    };
                    let (header_end, spec_start) = self.field_header(cursor + 1, close);
                    self.field_selector(cursor + 1, header_end, cursor);
                    if let Some(spec_start) = spec_start {
                        self.scan(spec_start, close, depth + 1);
                    }
                    cursor = close + 1;
                }
                '}' => {
                    self.complete = false;
                    return;
                }
                _ => cursor += 1,
            }
        }
    }

    fn field_close(&self, open: usize, end: usize) -> Option<usize> {
        let mut depth = 1usize;
        let mut cursor = open + 1;
        while cursor < end {
            match self.chars[cursor] {
                '{' if self.chars.get(cursor + 1) == Some(&'{') => cursor += 2,
                '{' => {
                    depth = depth.checked_add(1)?;
                    cursor += 1;
                }
                '}' if depth == 1 => return Some(cursor),
                '}' => {
                    depth -= 1;
                    cursor += 1;
                }
                _ => cursor += 1,
            }
        }
        None
    }

    fn field_header(&mut self, start: usize, close: usize) -> (usize, Option<usize>) {
        let mut cursor = start;
        let mut bracket_depth = 0usize;
        while cursor < close {
            match self.chars[cursor] {
                '[' => bracket_depth += 1,
                ']' => {
                    if bracket_depth == 0 {
                        self.complete = false;
                    } else {
                        bracket_depth -= 1;
                    }
                }
                '!' if bracket_depth == 0 => {
                    let conversion = self.chars.get(cursor + 1).copied();
                    if !matches!(conversion, Some('s' | 'r' | 'a'))
                        || !matches!(self.chars.get(cursor + 2), Some(':' | '}'))
                    {
                        self.complete = false;
                        return (close, None);
                    }
                    if self.chars.get(cursor + 2) == Some(&':') {
                        return (cursor, Some(cursor + 3));
                    }
                    return (cursor, None);
                }
                ':' if bracket_depth == 0 => return (cursor, Some(cursor + 1)),
                _ => {}
            }
            cursor += 1;
        }
        if bracket_depth != 0 {
            self.complete = false;
        }
        (close, None)
    }

    fn field_selector(&mut self, start: usize, header_end: usize, source_char: usize) {
        let mut cursor = start;
        while cursor < header_end && !matches!(self.chars[cursor], '.' | '[') {
            cursor += 1;
        }
        let root = self.chars[start..cursor].iter().collect::<String>();
        if root.is_empty() {
            let index = self.next_automatic;
            let Some(next) = index.checked_add(1) else {
                self.complete = false;
                return;
            };
            self.next_automatic = next;
            self.max_positional_count = self.max_positional_count.max(next);
            self.has_automatic_fields = true;
            self.fields.push(BraceField {
                selector: BraceSelector::Automatic(index),
                source_char,
            });
        } else if root.bytes().all(|byte| byte.is_ascii_digit()) {
            let Ok(index) = root.parse::<usize>() else {
                self.complete = false;
                return;
            };
            let Some(count) = index.checked_add(1) else {
                self.complete = false;
                return;
            };
            self.max_positional_count = self.max_positional_count.max(count);
            self.has_explicit_fields = true;
            self.fields.push(BraceField {
                selector: BraceSelector::Positional(index),
                source_char,
            });
        } else {
            self.named_fields.insert(root.clone());
            self.fields.push(BraceField {
                selector: BraceSelector::Named(root),
                source_char,
            });
        }
    }
}

pub fn parse_percent_format(value: &str) -> PercentFormat {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() > MAX_FORMAT_CHARS {
        return PercentFormat::incomplete();
    }
    let mut result = PercentFormat {
        items: Vec::new(),
        named_fields: HashSet::new(),
        positional_slots: 0,
        has_named_items: false,
        has_positional_items: false,
        unsupported_conversions: Vec::new(),
        complete: true,
    };
    let mut cursor = 0usize;
    while cursor < chars.len() {
        if chars[cursor] != '%' {
            cursor += 1;
            continue;
        }
        let source_char = cursor;
        cursor += 1;
        if cursor == chars.len() {
            result.complete = false;
            break;
        }
        if chars[cursor] == '%' {
            cursor += 1;
            continue;
        }

        let mapping_key = if chars[cursor] == '(' {
            cursor += 1;
            let start = cursor;
            while cursor < chars.len() && chars[cursor] != ')' {
                cursor += 1;
            }
            if cursor == chars.len() || cursor == start {
                result.complete = false;
                break;
            }
            let key = chars[start..cursor].iter().collect::<String>();
            cursor += 1;
            result.named_fields.insert(key.clone());
            result.has_named_items = true;
            Some(key)
        } else {
            result.has_positional_items = true;
            None
        };

        while cursor < chars.len() && matches!(chars[cursor], '#' | '0' | '-' | ' ' | '+') {
            cursor += 1;
        }

        let mut width_stars = 0usize;
        if cursor < chars.len() && chars[cursor] == '*' {
            width_stars = 1;
            cursor += 1;
        } else {
            while cursor < chars.len() && chars[cursor].is_ascii_digit() {
                cursor += 1;
            }
        }

        let mut precision_stars = 0usize;
        if cursor < chars.len() && chars[cursor] == '.' {
            cursor += 1;
            if cursor < chars.len() && chars[cursor] == '*' {
                precision_stars = 1;
                cursor += 1;
            } else {
                while cursor < chars.len() && chars[cursor].is_ascii_digit() {
                    cursor += 1;
                }
            }
        }

        if cursor < chars.len() && matches!(chars[cursor], 'h' | 'l' | 'L') {
            cursor += 1;
        }
        let Some(&conversion) = chars.get(cursor) else {
            result.complete = false;
            break;
        };
        cursor += 1;
        if !matches!(
            conversion,
            'b' | 'd'
                | 'i'
                | 'o'
                | 'u'
                | 'x'
                | 'X'
                | 'e'
                | 'E'
                | 'f'
                | 'F'
                | 'g'
                | 'G'
                | 'c'
                | 'r'
                | 's'
                | 'a'
        ) {
            result
                .unsupported_conversions
                .push((conversion, cursor - 1));
        }
        if mapping_key.is_some() && (width_stars != 0 || precision_stars != 0) {
            result.complete = false;
        }
        result.positional_slots = result
            .positional_slots
            .saturating_add(width_stars)
            .saturating_add(precision_stars)
            .saturating_add(usize::from(mapping_key.is_none()));
        result.items.push(PercentItem {
            conversion,
            mapping_key,
            width_stars,
            precision_stars,
            source_char,
        });
    }
    result
}

impl PercentFormat {
    fn incomplete() -> Self {
        Self {
            items: Vec::new(),
            named_fields: HashSet::new(),
            positional_slots: 0,
            has_named_items: false,
            has_positional_items: false,
            unsupported_conversions: Vec::new(),
            complete: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brace_fields_decode_numbering_names_and_escapes() {
        let parsed = parse_brace_format("{{literal}} {} {2[name]} {user.name!r:>{width}}");

        assert!(parsed.complete);
        assert_eq!(parsed.max_positional_count, 3);
        assert!(parsed.mixes_numbering());
        assert_eq!(
            parsed.named_fields,
            HashSet::from(["user".to_owned(), "width".to_owned()])
        );
        assert_eq!(parsed.fields.len(), 4);
        assert_eq!(parsed.fields[0].selector, BraceSelector::Automatic(0));
        assert_eq!(parsed.fields[1].selector, BraceSelector::Positional(2));
        assert_eq!(
            parsed.fields[2].selector,
            BraceSelector::Named("user".to_owned())
        );
        assert_eq!(
            parsed.fields[3].selector,
            BraceSelector::Named("width".to_owned())
        );
    }

    #[test]
    fn brace_argument_count_does_not_count_duplicate_explicit_fields() {
        let parsed = parse_brace_format("{0} {0}");

        assert!(parsed.complete);
        assert_eq!(parsed.max_positional_count, 1);
        assert!(!parsed.mixes_numbering());
    }

    #[test]
    fn malformed_brace_values_are_incomplete() {
        for value in ["{", "}", "{name!q}", "{name[broken}"] {
            assert!(
                !parse_brace_format(value).complete,
                "{value:?} must be incomplete"
            );
        }
    }

    #[test]
    fn percent_parser_counts_conversion_and_star_slots() {
        let parsed = parse_percent_format("%% %(name)08.2f %*.*s %Z");

        assert!(parsed.complete);
        assert!(parsed.has_named_items);
        assert!(parsed.has_positional_items);
        assert_eq!(parsed.named_fields, HashSet::from(["name".to_owned()]));
        assert_eq!(parsed.positional_slots, 4);
        assert_eq!(parsed.unsupported_conversions, vec![('Z', 23)]);
        assert_eq!(parsed.items.len(), 3);
        assert_eq!(parsed.items[1].width_stars, 1);
        assert_eq!(parsed.items[1].precision_stars, 1);
    }

    #[test]
    fn percent_parser_skips_escaped_percent_and_marks_dangling_percent_incomplete() {
        let parsed = parse_percent_format("100%% complete");
        assert!(parsed.complete);
        assert!(parsed.items.is_empty());
        assert_eq!(parsed.positional_slots, 0);

        assert!(!parse_percent_format("value %").complete);
    }

    #[test]
    fn percent_parser_keeps_conversion_source_positions() {
        let parsed = parse_percent_format("%s %Z");
        assert_eq!(parsed.items[0].source_char, 0);
        assert_eq!(parsed.items[1].source_char, 3);
        assert_eq!(parsed.unsupported_conversions, vec![('Z', 4)]);
    }
}
