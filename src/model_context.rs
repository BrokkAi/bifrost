use std::cmp::{max, min};

pub const MAX_CHARS_PER_LINE: usize = 2048;
pub const SAMPLE_MAX_LINES: usize = 50;
pub const SAMPLE_TOP_SHOWN: usize = 25;
pub const SAMPLE_BOTTOM_SHOWN: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadTail {
    pub text: String,
    pub truncated: bool,
    pub total_lines: usize,
    pub head_shown: usize,
    pub tail_shown: usize,
}

pub fn count_lines(content: &str) -> usize {
    logical_lines(content).len()
}

pub fn truncate_line(line: &str) -> String {
    truncate_line_range(line, 0, line.len())
}

pub fn truncate_line_range(content: &str, start_inclusive: usize, end_exclusive: usize) -> String {
    let len = end_exclusive.saturating_sub(start_inclusive);
    if len <= MAX_CHARS_PER_LINE {
        return content[start_inclusive..end_exclusive].to_string();
    }
    // MAX_CHARS_PER_LINE is applied as a byte budget; snap the cut down to the
    // nearest UTF-8 char boundary so multibyte content (CJK/Cyrillic) straddling
    // the offset doesn't panic the slice.
    let mut cut = start_inclusive + MAX_CHARS_PER_LINE;
    while cut > start_inclusive && !content.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{} [TRUNCATED at {} chars]",
        &content[start_inclusive..cut],
        MAX_CHARS_PER_LINE
    )
}

pub fn cap_lines(content: &str) -> String {
    if content.is_empty() {
        return String::new();
    }

    let mut out = Vec::new();
    for line in logical_lines(content) {
        out.push(truncate_line(line));
    }
    let mut text = out.join("\n");
    if content.ends_with('\n') || content.ends_with('\r') {
        text.push('\n');
    }
    text
}

pub fn sample(content: &str) -> HeadTail {
    cap(
        content,
        SAMPLE_MAX_LINES,
        SAMPLE_TOP_SHOWN,
        SAMPLE_BOTTOM_SHOWN,
    )
}

pub fn cap(content: &str, max_lines: usize, top_shown: usize, bottom_shown: usize) -> HeadTail {
    if content.is_empty() {
        return HeadTail {
            text: String::new(),
            truncated: false,
            total_lines: 0,
            head_shown: 0,
            tail_shown: 0,
        };
    }

    let length = content.len();
    let mut head_starts = vec![0usize; top_shown];
    let mut head_ends = vec![0usize; top_shown];
    let mut head_count = 0usize;

    let mut tail_starts = vec![0usize; bottom_shown];
    let mut tail_ends = vec![0usize; bottom_shown];
    let mut tail_size = 0usize;
    let mut tail_pos = 0usize;

    let mut total_lines = 0usize;
    let mut line_start = 0usize;
    let mut iter = content.char_indices().peekable();
    while let Some((index, ch)) = iter.next() {
        if ch == '\n' || ch == '\r' {
            let line_end = index;
            total_lines += 1;
            if head_count < top_shown {
                head_starts[head_count] = line_start;
                head_ends[head_count] = line_end;
                head_count += 1;
            }
            if bottom_shown > 0 {
                if tail_size < bottom_shown {
                    tail_starts[tail_size] = line_start;
                    tail_ends[tail_size] = line_end;
                    tail_size += 1;
                } else {
                    tail_starts[tail_pos] = line_start;
                    tail_ends[tail_pos] = line_end;
                    tail_pos = (tail_pos + 1) % bottom_shown;
                }
            }

            if ch == '\r' && matches!(iter.peek(), Some((_, '\n'))) {
                let (_, _) = iter.next().unwrap();
            }
            line_start = iter.peek().map(|(next, _)| *next).unwrap_or(length);
        }
    }

    if line_start < length || total_lines == 0 {
        total_lines += 1;
        if head_count < top_shown {
            head_starts[head_count] = line_start;
            head_ends[head_count] = length;
        }
        if bottom_shown > 0 {
            if tail_size < bottom_shown {
                tail_starts[tail_size] = line_start;
                tail_ends[tail_size] = length;
                tail_size += 1;
            } else {
                tail_starts[tail_pos] = line_start;
                tail_ends[tail_pos] = length;
            }
        }
    }

    if total_lines <= max_lines {
        return HeadTail {
            text: cap_lines(content),
            truncated: false,
            total_lines,
            head_shown: total_lines,
            tail_shown: 0,
        };
    }

    let top = min(top_shown, total_lines);
    let bottom = min(bottom_shown, max(0, total_lines.saturating_sub(top)));
    let omitted = max(0, total_lines.saturating_sub(top).saturating_sub(bottom));

    let head = join_lines(content, &head_starts, &head_ends, 0, top);
    let tail = if bottom == 0 {
        String::new()
    } else {
        let ordered_size = tail_size;
        let ordered_start = if tail_size < bottom_shown {
            0
        } else {
            tail_pos
        };
        let skip = max(0, ordered_size.saturating_sub(bottom));
        let mut tail_lines = Vec::with_capacity(bottom);
        for n in skip..ordered_size {
            let ring_index = (ordered_start + n) % ordered_size;
            tail_lines.push(truncate_line_range(
                content,
                tail_starts[ring_index],
                tail_ends[ring_index],
            ));
        }
        tail_lines.join("\n")
    };

    let delimiter = format!("----- OMITTED {omitted} LINES -----");
    let mut parts = Vec::with_capacity(3);
    if !head.is_empty() {
        parts.push(head);
    }
    parts.push(delimiter);
    if !tail.is_empty() {
        parts.push(tail);
    }

    HeadTail {
        text: parts.join("\n\n"),
        truncated: true,
        total_lines,
        head_shown: top,
        tail_shown: bottom,
    }
}

pub fn logical_lines(content: &str) -> Vec<&str> {
    if content.is_empty() {
        return Vec::new();
    }

    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut iter = content.char_indices().peekable();
    while let Some((index, ch)) = iter.next() {
        if ch == '\n' || ch == '\r' {
            lines.push(&content[start..index]);
            if ch == '\r' && matches!(iter.peek(), Some((_, '\n'))) {
                let (next_index, _) = iter.next().unwrap();
                start = next_index + 1;
            } else {
                start = index + 1;
            }
        }
    }
    if start < content.len() {
        lines.push(&content[start..]);
    }
    lines
}

fn join_lines(
    content: &str,
    starts: &[usize],
    ends: &[usize],
    start_index: usize,
    count: usize,
) -> String {
    if count == 0 {
        return String::new();
    }
    let mut lines = Vec::with_capacity(count);
    for idx in start_index..start_index + count {
        lines.push(truncate_line_range(content, starts[idx], ends[idx]));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::{HeadTail, cap_lines, count_lines, logical_lines, sample, truncate_line};

    #[test]
    fn count_lines_handles_mixed_endings() {
        assert_eq!(0, count_lines(""));
        assert_eq!(3, count_lines("a\nb\nc"));
        assert_eq!(3, count_lines("a\r\nb\r\nc"));
        assert_eq!(3, count_lines("a\rb\rc"));
        assert_eq!(1, count_lines("a\r\n"));
    }

    #[test]
    fn logical_lines_match_searchtools_behavior() {
        assert_eq!(vec!["a", "b", "c"], logical_lines("a\r\nb\r\nc"));
        assert_eq!(vec!["a", "b", "c"], logical_lines("a\nb\nc"));
        assert_eq!(vec!["a", "b", "c"], logical_lines("a\rb\rc"));
        assert_eq!(vec!["a"], logical_lines("a\r\n"));
        assert_eq!(Vec::<&str>::new(), logical_lines(""));
    }

    #[test]
    fn truncate_line_caps_long_lines() {
        let long = "x".repeat(2050);
        let truncated = truncate_line(&long);
        assert!(truncated.len() > 2048);
        assert!(truncated.ends_with(" [TRUNCATED at 2048 chars]"));
    }

    #[test]
    fn cap_lines_truncates_each_line() {
        let text = format!("{}\nshort", "x".repeat(2050));
        let capped = cap_lines(&text);
        assert!(capped.contains("[TRUNCATED at 2048 chars]"));
        assert!(capped.ends_with("\nshort"));
    }

    #[test]
    fn sample_keeps_small_content_full() {
        let text = "a\nb\nc\n";
        assert_eq!(
            HeadTail {
                text: "a\nb\nc\n".to_string(),
                truncated: false,
                total_lines: 3,
                head_shown: 3,
                tail_shown: 0
            },
            sample(text)
        );
    }

    #[test]
    fn sample_uses_head_tail_for_large_content() {
        let text = (1..=60)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let sampled = sample(&text);
        assert!(sampled.truncated);
        assert_eq!(60, sampled.total_lines);
        assert_eq!(25, sampled.head_shown);
        assert_eq!(25, sampled.tail_shown);
        assert!(sampled.text.contains("line 1"));
        assert!(sampled.text.contains("line 25"));
        assert!(sampled.text.contains("----- OMITTED 10 LINES -----"));
        assert!(sampled.text.contains("line 36"));
        assert!(sampled.text.contains("line 60"));
        assert!(!sampled.text.contains("line 30"));
    }
}
