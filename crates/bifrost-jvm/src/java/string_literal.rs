//! Java string values: JLS 3.3 translation precedes JLS 3.10.7 escapes.
use brokk_bifrost_core::analyzer::structural::regex::{MAX_PATTERN_CHARS, MappedChar};

fn java_string_literal_has_interpolation(node: tree_sitter::Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "string_interpolation")
}

/// Decode an AST-selected ordinary Java string; unsupported or recovered syntax has no value.
pub fn decoded_string_literal_value(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string_literal"
        || node.has_error()
        || java_string_literal_has_interpolation(node)
    {
        return None;
    }
    let text = node.utf8_text(source.as_bytes()).ok()?;
    decode(text, node.start_byte())
        .ok()
        .map(|literal| literal.value)
}

#[derive(Debug)]
pub(super) struct DecodedLiteral {
    pub value: String,
    pub source_start: usize,
    pub chars: Vec<MappedChar>,
}

/// Decode one AST-selected ordinary string literal, retaining original bytes.
/// Text blocks deliberately abstain until indentation and continuation semantics
/// are implemented together. The structural adapter already excludes them through
/// `string_literal_value_may_be_absent`; this guard serves the regex producer,
/// which calls `decode` directly and reports the returned reason.
pub(super) fn decode(text: &str, offset: usize) -> Result<DecodedLiteral, &'static str> {
    if text.starts_with("\"\"\"") {
        return Err("java-text-block-not-supported");
    }
    let raw: Vec<_> = text.char_indices().collect();
    let mut translated = Vec::<(u16, usize, usize)>::new();
    let mut i = 0;
    let mut slashes = 0;
    let mut unicode_last = false;
    while i < raw.len() {
        let (begin, ch) = raw[i];
        let eligible = slashes % 2 == 0 || unicode_last;
        let mut end = begin + ch.len_utf8();
        let mut units = [0u16; 2];
        let mut was_unicode = false;
        let decoded = if ch == '\\' && eligible && raw.get(i + 1).is_some_and(|(_, c)| *c == 'u') {
            i += 1;
            while raw.get(i).is_some_and(|(_, c)| *c == 'u') {
                i += 1;
            }
            let mut unit = 0u16;
            for _ in 0..4 {
                let &(pos, digit) = raw.get(i).ok_or("java-invalid-unicode-escape")?;
                unit = unit * 16 + digit.to_digit(16).ok_or("java-invalid-unicode-escape")? as u16;
                end = pos + digit.len_utf8();
                i += 1;
            }
            units[0] = unit;
            was_unicode = true;
            &units[..1]
        } else {
            i += 1;
            ch.encode_utf16(&mut units)
        };
        for &unit in decoded.iter() {
            translated.push((unit, offset + begin, offset + end));
        }
        let is_slash = decoded == [b'\\' as u16];
        slashes = if is_slash { slashes + 1 } else { 0 };
        unicode_last = was_unicode;
        if translated.len() > MAX_PATTERN_CHARS * 8 {
            return Err("java-pattern-budget");
        }
    }
    if translated.first().map(|t| t.0) != Some(34) || translated.last().map(|t| t.0) != Some(34) {
        return Err("java-invalid-string-delimiters");
    }
    let mut cooked = Vec::new();
    i = 1;
    while i + 1 < translated.len() {
        let (mut unit, begin, mut end) = translated[i];
        i += 1;
        if unit == 92 {
            let &(escape, _, escape_end) =
                translated.get(i).ok_or("java-trailing-string-escape")?;
            i += 1;
            end = escape_end;
            unit = match escape {
                98 => 8,
                116 => 9,
                110 => 10,
                102 => 12,
                114 => 13,
                115 => 32,
                34 | 39 | 92 => escape,
                48..=55 => {
                    let max_digits = if escape <= 51 { 3 } else { 2 };
                    let mut value = escape - 48;
                    for _ in 1..max_digits {
                        if let Some(&(digit @ 48..=55, _, digit_end)) = translated.get(i) {
                            value = value * 8 + digit - 48;
                            end = digit_end;
                            i += 1;
                        } else {
                            break;
                        }
                    }
                    value
                }
                _ => return Err("java-invalid-string-escape"),
            };
            if i >= translated.len() {
                return Err("java-escaped-closing-delimiter");
            }
        } else if matches!(unit, 10 | 13 | 34) {
            return Err("java-invalid-string-character");
        }
        cooked.push((unit, begin, end));
    }
    let mut value = String::new();
    let mut chars = Vec::new();
    i = 0;
    while i < cooked.len() {
        let (unit, source_start, mut source_end) = cooked[i];
        i += 1;
        let scalar = if (0xd800..=0xdbff).contains(&unit) {
            let &(low, _, end) = cooked.get(i).ok_or("java-unpaired-surrogate")?;
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err("java-unpaired-surrogate");
            }
            source_end = end;
            i += 1;
            0x10000 + ((u32::from(unit) - 0xd800) << 10) + u32::from(low) - 0xdc00
        } else {
            u32::from(unit)
        };
        value.push(char::from_u32(scalar).ok_or("java-unpaired-surrogate")?);
        chars.push(MappedChar {
            source_start,
            source_end,
        });
    }
    Ok(DecodedLiteral {
        value,
        chars,
        source_start: offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_translation_precedes_string_escapes_and_maps_original_bytes() {
        let text = r#""\uu005cn\\u0061\uD83D\uDE00""#;
        let decoded = decode(text, 10).unwrap();
        assert_eq!(decoded.value, "\n\\u0061\u{1f600}");
        assert_eq!(
            (decoded.chars[0].source_start, decoded.chars[0].source_end),
            (11, 19)
        );
        assert_eq!(
            decoded.chars.last().unwrap().source_end,
            10 + text.len() - 1
        );
        assert_eq!(decode(r#""\u005c\u005c\u006e""#, 0).unwrap().value, "\\n");
        assert_eq!(decode(r#""\\\u0061""#, 0).unwrap().value, "\\a");
        assert!(decode(r#""\u005cu0061""#, 0).is_err());
        assert!(decode(r#""\u000a""#, 0).is_err());
        assert!(decode(r#""\uD800""#, 0).is_err());
    }
    #[test]
    fn octal_digit_limit_depends_on_first_digit() {
        let decoded = decode(r#""\377\400\77\0\s""#, 0).unwrap();
        assert_eq!(decoded.value, "\u{ff} 0?\0 ");
        assert_eq!(decoded.chars[0].source_end, 5);
        assert!(decode("\"\"\"\n a\n\"\"\"", 0).is_err());
    }
}
