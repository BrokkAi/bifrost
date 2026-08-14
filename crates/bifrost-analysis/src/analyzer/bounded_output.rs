//! Shared transactional output for balanced, bounded IR renderers.

use std::fmt;
use std::fmt::Write as _;

const QUOTED_CHUNK_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy)]
pub(crate) enum TruncationStyle {
    Positional,
    ReasonAttribute,
}

/// A line-oriented formatter that preserves balanced forms under truncation.
///
/// Each line is written transactionally. If formatting would exceed the byte
/// limit, the partial line is rolled back and [`Self::finish`] emits a bounded
/// truncation marker followed by every required closing parenthesis.
pub(crate) struct BalancedWriter {
    output: String,
    max_output_bytes: usize,
    truncation_reserve: usize,
    truncation_style: TruncationStyle,
    open_forms: usize,
    truncated: Option<&'static str>,
}

/// A transactional formatter over one output row.
struct CapacityWriter<'a> {
    output: &'a mut String,
    max_len: usize,
    rejected: bool,
}

impl fmt::Write for CapacityWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.output.len().saturating_add(value.len()) > self.max_len {
            self.rejected = true;
            return Err(fmt::Error);
        }
        self.output.push_str(value);
        Ok(())
    }
}

impl BalancedWriter {
    pub(crate) fn new(
        max_output_bytes: usize,
        truncation_reserve: usize,
        truncation_style: TruncationStyle,
    ) -> Self {
        Self {
            output: String::new(),
            max_output_bytes,
            truncation_reserve,
            truncation_style,
            open_forms: 0,
            truncated: None,
        }
    }

    pub(crate) fn is_truncated(&self) -> bool {
        self.truncated.is_some()
    }

    pub(crate) fn open(&mut self, depth: usize, line: &str) -> bool {
        self.open_with(depth, |writer| writer.write_str(line))
    }

    pub(crate) fn open_with(
        &mut self,
        depth: usize,
        render: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
    ) -> bool {
        if !self.write_line(depth, self.open_forms.saturating_add(1), render) {
            return false;
        }
        self.open_forms += 1;
        true
    }

    pub(crate) fn line(&mut self, depth: usize, line: &str) -> bool {
        self.line_with(depth, |writer| writer.write_str(line))
    }

    pub(crate) fn line_with(
        &mut self,
        depth: usize,
        render: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
    ) -> bool {
        self.write_line(depth, self.open_forms, render)
    }

    pub(crate) fn close(&mut self, depth: usize) -> bool {
        let remaining = self.open_forms.saturating_sub(1);
        if !self.write_line(depth, remaining, |writer| writer.write_char(')')) {
            return false;
        }
        self.open_forms = remaining;
        true
    }

    pub(crate) fn truncate(&mut self, reason: &'static str) {
        self.truncated.get_or_insert(reason);
    }

    fn write_line(
        &mut self,
        depth: usize,
        prospective_open_forms: usize,
        render: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
    ) -> bool {
        if self.is_truncated() {
            return false;
        }
        let checkpoint = self.output.len();
        let indent = depth.saturating_mul(2);
        let reserve = self
            .truncation_reserve
            .saturating_add(prospective_open_forms);
        let max_line_end = self
            .max_output_bytes
            .saturating_sub(reserve)
            .saturating_sub(1);
        if checkpoint.saturating_add(indent) > max_line_end {
            self.truncate("output byte limit reached");
            return false;
        }
        self.output.extend(std::iter::repeat_n(' ', indent));

        let (result, rejected) = {
            let mut writer = CapacityWriter {
                output: &mut self.output,
                max_len: max_line_end,
                rejected: false,
            };
            let result = render(&mut writer);
            (result, writer.rejected)
        };
        if result.is_err() || rejected {
            self.output.truncate(checkpoint);
            self.truncate("output byte limit reached");
            return false;
        }
        self.output.push('\n');
        true
    }

    pub(crate) fn finish(mut self) -> (String, bool) {
        let truncated = self.is_truncated();
        if let Some(reason) = self.truncated {
            let marker_start = self.output.len();
            match self.truncation_style {
                TruncationStyle::Positional => {
                    writeln!(self.output, "(truncated {})", quoted(reason))
                }
                TruncationStyle::ReasonAttribute => {
                    writeln!(self.output, "(truncated :reason {})", quoted(reason))
                }
            }
            .expect("writing to a string cannot fail");
            self.output
                .extend(std::iter::repeat_n(')', self.open_forms));
            if self.open_forms > 0 {
                self.output.push('\n');
            }
            self.open_forms = 0;
            debug_assert!(
                self.output.len() <= self.max_output_bytes,
                "truncation marker exceeded its {}-byte reserve by {} bytes",
                self.truncation_reserve,
                self.output.len().saturating_sub(marker_start)
            );
        }
        debug_assert!(truncated || self.open_forms == 0);
        (self.output, truncated)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Quoted<'a>(&'a str);

pub(crate) const fn quoted(value: &str) -> Quoted<'_> {
    Quoted(value)
}

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_char('"')?;
        let mut plain_start = 0;
        for (offset, character) in self.0.char_indices() {
            let escaped = match character {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\u{08}' => "\\b",
                '\u{0c}' => "\\f",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                character if character <= '\u{1f}' => {
                    formatter.write_str(&self.0[plain_start..offset])?;
                    write!(formatter, "\\u{:04x}", u32::from(character))?;
                    plain_start = offset + character.len_utf8();
                    continue;
                }
                _ => {
                    if offset.saturating_sub(plain_start) >= QUOTED_CHUNK_BYTES {
                        formatter.write_str(&self.0[plain_start..offset])?;
                        plain_start = offset;
                    }
                    continue;
                }
            };
            formatter.write_str(&self.0[plain_start..offset])?;
            formatter.write_str(escaped)?;
            plain_start = offset + character.len_utf8();
        }
        formatter.write_str(&self.0[plain_start..])?;
        formatter.write_char('"')
    }
}
