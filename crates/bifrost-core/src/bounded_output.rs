//! Shared transactional output for balanced, bounded IR renderers.

use std::fmt;
use std::fmt::Write as _;

const QUOTED_CHUNK_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy)]
pub enum TruncationStyle {
    Positional,
    ReasonAttribute,
}

/// A line-oriented formatter that preserves balanced forms under truncation.
///
/// Each line is written transactionally. If formatting would exceed the byte
/// limit, the partial line is rolled back and [`Self::finish`] emits a bounded
/// truncation marker followed by every required closing parenthesis.
pub struct BalancedWriter {
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
    pub fn new(
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

    pub fn is_truncated(&self) -> bool {
        self.truncated.is_some()
    }

    pub fn open(&mut self, depth: usize, line: &str) -> bool {
        self.open_with(depth, |writer| writer.write_str(line))
    }

    pub fn open_with(
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

    pub fn line(&mut self, depth: usize, line: &str) -> bool {
        self.line_with(depth, |writer| writer.write_str(line))
    }

    pub fn line_with(
        &mut self,
        depth: usize,
        render: impl FnOnce(&mut dyn fmt::Write) -> fmt::Result,
    ) -> bool {
        self.write_line(depth, self.open_forms, render)
    }

    pub fn close(&mut self, depth: usize) -> bool {
        let remaining = self.open_forms.saturating_sub(1);
        if !self.write_line(depth, remaining, |writer| writer.write_char(')')) {
            return false;
        }
        self.open_forms = remaining;
        true
    }

    pub fn truncate(&mut self, reason: &'static str) {
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

    pub fn finish(mut self) -> (String, bool) {
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
pub struct Quoted<'a>(&'a str);

pub const fn quoted(value: &str) -> Quoted<'_> {
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

/// Properties of the transactional writer and the JSON-style quoting.
///
/// `BalancedWriter` is checked against a model written from its documented
/// contract, not from its code: a line is accepted only while the output, the
/// truncation reserve, and one closing parenthesis per open form still fit in
/// the byte limit; a rejected line leaves no trace; every open form is closed
/// by `finish`. `quoted` is checked against `serde_json`, which implements the
/// JSON string escaping the renderers promise.
#[cfg(test)]
mod bounded_output_properties {
    use super::{BalancedWriter, TruncationStyle, quoted};
    use proptest::prelude::*;

    /// Large enough for the longest marker plus its trailing newlines.
    const RESERVE: usize = 60;
    const LIMIT_REASON: &str = "output byte limit reached";

    #[derive(Debug, Clone)]
    enum Op {
        Open(usize, Vec<String>),
        Line(usize, Vec<String>),
        Close(usize),
        Truncate(&'static str),
    }

    /// Text pieces without parentheses, so the output's parenthesis balance
    /// depends only on the writer. Several pieces exercise a render closure
    /// that fails after part of a line is already written.
    fn pieces() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec("[a-z ]{0,8}", 0..4)
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => (0usize..8, pieces()).prop_map(|(d, p)| Op::Open(d, p)),
            4 => (0usize..8, pieces()).prop_map(|(d, p)| Op::Line(d, p)),
            3 => (0usize..8).prop_map(Op::Close),
            1 => prop_oneof![Just("first"), Just("second")].prop_map(Op::Truncate),
        ]
    }

    fn style() -> impl Strategy<Value = TruncationStyle> {
        prop_oneof![
            Just(TruncationStyle::Positional),
            Just(TruncationStyle::ReasonAttribute)
        ]
    }

    fn write_pieces(writer: &mut dyn std::fmt::Write, pieces: &[String]) -> std::fmt::Result {
        for piece in pieces {
            writer.write_str(piece)?;
        }
        Ok(())
    }

    /// Reference model: the line a successful operation appends.
    fn reference_line(depth: usize, body: &str) -> String {
        format!("{}{body}\n", " ".repeat(depth * 2))
    }

    fn marker(style: TruncationStyle, reason: &str) -> String {
        match style {
            TruncationStyle::Positional => format!("(truncated {})\n", quoted(reason)),
            TruncationStyle::ReasonAttribute => {
                format!("(truncated :reason {})\n", quoted(reason))
            }
        }
    }

    struct Model {
        expected: String,
        open_forms: usize,
        reason: Option<&'static str>,
    }

    impl Model {
        fn new() -> Self {
            Self {
                expected: String::new(),
                open_forms: 0,
                reason: None,
            }
        }

        /// Accepts the line only when the output, the reserve, and one `)` per
        /// open form (counting this operation's effect) still fit.
        fn offer(&mut self, max: usize, line: String, forms_after: usize) -> bool {
            if self.reason.is_none()
                && self.expected.len() + line.len() + RESERVE + forms_after <= max
            {
                self.expected.push_str(&line);
                self.open_forms = forms_after;
                return true;
            }
            self.reason.get_or_insert(LIMIT_REASON);
            false
        }

        fn finish(mut self, style: TruncationStyle) -> (String, bool) {
            if let Some(reason) = self.reason {
                self.expected.push_str(&marker(style, reason));
                self.expected.push_str(&")".repeat(self.open_forms));
                if self.open_forms > 0 {
                    self.expected.push('\n');
                }
            }
            (self.expected, self.reason.is_some())
        }
    }

    /// Applies `ops` to a real writer and to the model, asserting that every
    /// operation reports the same acceptance as the model.
    fn run(max: usize, style: TruncationStyle, ops: &[Op]) -> ((String, bool), (String, bool)) {
        let mut writer = BalancedWriter::new(max, RESERVE, style);
        let mut model = Model::new();
        for op in ops {
            match op {
                Op::Open(depth, parts) => {
                    let line = reference_line(*depth, &format!("(f {}", parts.concat()));
                    let expected = model.offer(max, line, model.open_forms + 1);
                    let actual = writer.open_with(*depth, |w| {
                        w.write_str("(f ")?;
                        write_pieces(w, parts)
                    });
                    assert_eq!(actual, expected, "open {op:?}");
                }
                Op::Line(depth, parts) => {
                    let line = reference_line(*depth, &parts.concat());
                    let expected = model.offer(max, line, model.open_forms);
                    let actual = writer.line_with(*depth, |w| write_pieces(w, parts));
                    assert_eq!(actual, expected, "line {op:?}");
                }
                Op::Close(depth) => {
                    if model.open_forms == 0 {
                        continue;
                    }
                    let line = reference_line(*depth, ")");
                    let expected = model.offer(max, line, model.open_forms - 1);
                    let actual = writer.close(*depth);
                    assert_eq!(actual, expected, "close {op:?}");
                }
                Op::Truncate(reason) => {
                    writer.truncate(reason);
                    model.reason.get_or_insert(reason);
                }
            }
            assert_eq!(
                writer.is_truncated(),
                model.reason.is_some(),
                "after {op:?}"
            );
        }
        // `finish` requires an untruncated writer to have no open forms.
        if !writer.is_truncated() {
            while model.open_forms > 0 && model.reason.is_none() {
                let line = reference_line(0, ")");
                let expected = model.offer(max, line, model.open_forms - 1);
                assert_eq!(writer.close(0), expected, "closing trailer");
            }
        }
        (writer.finish(), model.finish(style))
    }

    fn count(text: &str, needle: char) -> usize {
        text.chars().filter(|c| *c == needle).count()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Any operation sequence under any limit: the output equals the
        /// model's (so rejected lines leave no partial text), stays within the
        /// limit, and has balanced parentheses. The truncation flag is true
        /// exactly when content was dropped or `truncate` was called.
        #[test]
        fn bounded_writer_matches_model_and_stays_balanced(
            max in (RESERVE + 1)..(RESERVE + 400),
            style in style(),
            ops in prop::collection::vec(op(), 0..40),
        ) {
            let ((output, truncated), (expected, expected_truncated)) = run(max, style, &ops);
            prop_assert_eq!(&output, &expected);
            prop_assert_eq!(truncated, expected_truncated);
            prop_assert!(output.len() <= max, "{} > {}", output.len(), max);
            prop_assert_eq!(count(&output, '('), count(&output, ')'));
        }

        /// With a limit far above the content, the output is the unbounded
        /// rendering of the same operations and nothing is truncated.
        #[test]
        fn huge_limit_equals_unbounded_rendering(
            style in style(),
            ops in prop::collection::vec(op(), 0..40),
        ) {
            let mut ops: Vec<Op> = ops
                .into_iter()
                .filter(|op| !matches!(op, Op::Truncate(_)))
                .collect();
            // Close every open form so an untruncated writer ends balanced.
            let mut open = 0usize;
            for op in &ops {
                match op {
                    Op::Open(..) => open += 1,
                    Op::Close(_) if open > 0 => open -= 1,
                    _ => {}
                }
            }
            ops.extend((0..open).map(|_| Op::Close(0)));

            let ((output, truncated), _) = run(1 << 20, style, &ops);
            let mut reference = String::new();
            let mut open = 0usize;
            for op in &ops {
                match op {
                    Op::Open(d, p) => {
                        open += 1;
                        reference.push_str(&reference_line(*d, &format!("(f {}", p.concat())));
                    }
                    Op::Line(d, p) => reference.push_str(&reference_line(*d, &p.concat())),
                    Op::Close(d) if open > 0 => {
                        open -= 1;
                        reference.push_str(&reference_line(*d, ")"));
                    }
                    _ => {}
                }
            }
            prop_assert!(!truncated);
            prop_assert_eq!(output, reference);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// `quoted` is JSON string escaping, including control characters and
        /// inputs longer than its internal chunk size.
        #[test]
        fn quoted_matches_json_string_encoding(
            text in prop::collection::vec(
                prop_oneof![
                    4 => any::<char>(),
                    2 => (0u8..0x20).prop_map(char::from),
                    1 => Just('"'),
                    1 => Just('\\'),
                    1 => Just('\u{e9}'),
                    1 => Just('\u{1f600}'),
                ],
                0..3000,
            ).prop_map(|chars| chars.into_iter().collect::<String>()),
        ) {
            let rendered = quoted(&text).to_string();
            prop_assert_eq!(&rendered, &serde_json::to_string(&text).unwrap());
            prop_assert_eq!(serde_json::from_str::<String>(&rendered).unwrap(), text);
        }
    }

    /// A render closure that fails after writing part of a line, and one that
    /// writes more than fits, both roll the line back.
    #[test]
    fn failed_or_oversized_render_rolls_back_the_line() {
        let mut writer = BalancedWriter::new(200, RESERVE, TruncationStyle::Positional);
        assert!(writer.line(0, "kept"));
        assert!(!writer.line_with(1, |w| {
            w.write_str("partial")?;
            Err(std::fmt::Error)
        }));
        assert!(writer.is_truncated());
        let (output, truncated) = writer.finish();
        assert!(truncated);
        assert_eq!(output, "kept\n(truncated \"output byte limit reached\")\n");

        let mut writer = BalancedWriter::new(100, RESERVE, TruncationStyle::ReasonAttribute);
        assert!(writer.open(0, "(f"));
        assert!(!writer.line_with(1, |w| write!(w, "{}", "x".repeat(80))));
        let (output, truncated) = writer.finish();
        assert!(truncated);
        assert_eq!(
            output,
            "(f\n(truncated :reason \"output byte limit reached\")\n)\n"
        );
    }
}
