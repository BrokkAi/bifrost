// Pure text utilities used by the git tools: XML escaping helpers and an
// in-crate ISO 8601 date formatter. Lives here so the rest of git_tools
// stays focused on git plumbing and presentation.

pub(super) fn escape_xml_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\n' | '\r' | '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

// Escape text destined for element content (not attribute values). Keeps
// newlines verbatim — multi-line commit messages should render as
// multi-line text inside `<message>`. Only `&`, `<`, `>` need escaping;
// quotes are legal in PCDATA. Filenames and message bodies can otherwise
// contain `</message>`, `</edited_files>`, etc. as literal substrings
// and would break the wrapping envelope when consumed by a downstream
// XML-aware parser (or a less-cautious LLM).
pub(super) fn escape_xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

// Format a Unix timestamp as ISO 8601 UTC. Implemented in-crate to avoid
// pulling chrono just for date formatting. Uses Howard Hinnant's
// `civil_from_days` algorithm (proleptic Gregorian). Defined for the full
// i64 range; assumes the input represents seconds since the Unix epoch.
pub(super) fn format_iso_date(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{sec:02}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64; // 0..=146096
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // 0..=399
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // 0..=11
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // 1..=31
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 }; // 1..=12
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}
