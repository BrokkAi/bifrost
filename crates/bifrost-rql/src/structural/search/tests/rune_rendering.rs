use crate::analyzer::Language;
use crate::structural::rune_ir::*;

#[test]
fn rune_rendering_preserves_selections_and_budget_boundaries() {
    let source = "fn first() { alpha(long_name); beta(); }\nfn second_long() { gamma(); }";
    let mut output = String::new();
    let defaults = RuneIrLimits::default();
    let call_start = source.find("alpha").unwrap();
    let call_end = source.find(";").unwrap();
    let cursor = source.find("long_name").unwrap() + 2;
    let cases = [
        ("whole", RuneIrSelection::WholeSource, defaults),
        (
            "siblings",
            RuneIrSelection::ByteRange(0..source.len()),
            defaults,
        ),
        (
            "call",
            RuneIrSelection::ByteRange(call_start..call_end),
            defaults,
        ),
        (
            "cursor",
            RuneIrSelection::ByteRange(cursor..cursor),
            defaults,
        ),
        // RuneIrError documents an inclusive input byte bound.
        (
            "exact input",
            RuneIrSelection::WholeSource,
            RuneIrLimits {
                max_input_bytes: source.len(),
                ..defaults
            },
        ),
        (
            "over input",
            RuneIrSelection::WholeSource,
            RuneIrLimits {
                max_input_bytes: source.len() - 1,
                ..defaults
            },
        ),
        (
            "one node",
            RuneIrSelection::WholeSource,
            RuneIrLimits {
                max_nodes: 1,
                ..defaults
            },
        ),
        (
            "two nodes",
            RuneIrSelection::WholeSource,
            RuneIrLimits {
                max_nodes: 2,
                ..defaults
            },
        ),
        (
            "one depth",
            RuneIrSelection::WholeSource,
            RuneIrLimits {
                max_depth: 1,
                ..defaults
            },
        ),
        (
            "two depth",
            RuneIrSelection::WholeSource,
            RuneIrLimits {
                max_depth: 2,
                ..defaults
            },
        ),
        (
            "source copies",
            RuneIrSelection::WholeSource,
            RuneIrLimits {
                max_source_bytes: 24,
                ..defaults
            },
        ),
    ];
    for (label, selection, limits) in cases {
        use std::fmt::Write;
        let result = render_source_rune_ir(Language::Rust, source, selection.clone(), limits);
        if let Ok(value) = &result {
            let full = render_source_rune_ir(Language::Rust, source, selection, defaults).unwrap();
            let reduced_limits = limits.max_nodes < defaults.max_nodes
                || limits.max_depth < defaults.max_depth
                || limits.max_source_bytes < defaults.max_source_bytes;
            if reduced_limits || value.truncated {
                assert!(value.truncated, "{label}: expected a reported cut");
                assert_eq!(value.source_range, full.source_range, "{label}");
                let mut nodes = 0;
                let mut copied_bytes = 0;
                // The API exposes text only. Node/role headers carry ranges and
                // indentation carries depth; copied values use JSON quoting.
                // Decode each string with serde_json so escaped quotes and Unicode
                // count as source bytes, rather than encoded output bytes.
                for line in value.rune_ir.lines() {
                    let header = line.split_once('"').map_or(line, |(header, _)| header);
                    let is_node = header.contains(" :range (");
                    if !is_node && !header.contains(" :span (") {
                        continue;
                    }
                    if is_node {
                        nodes += 1;
                        let depth = (line.len() - line.trim_start().len()) / 2 + 1;
                        assert!(depth <= limits.max_depth, "{label}: depth bound");
                    }
                    assert!(
                        full.rune_ir
                            .lines()
                            .any(|full_line| full_line.trim() == line.trim()),
                        "{label}: rendered line absent from full result: {line}"
                    );
                    let mut rest = line;
                    while let Some(start) = rest.find('"') {
                        let mut strings = serde_json::Deserializer::from_str(&rest[start..])
                            .into_iter::<String>();
                        let text = strings.next().unwrap().unwrap();
                        copied_bytes += text.len();
                        rest = &rest[start + strings.byte_offset()..];
                    }
                }
                assert!(nodes > 0, "{label}: must render at least one node");
                assert!(nodes <= limits.max_nodes, "{label}: node bound");
                assert!(
                    copied_bytes <= limits.max_source_bytes,
                    "{label}: copied source byte bound"
                );
                continue;
            }
        }
        writeln!(output, "== {label} ==").unwrap();
        match result {
            Ok(value) => {
                writeln!(
                    output,
                    "range={:?} truncated={}\n{}",
                    value.source_range, value.truncated, value.rune_ir
                )
                .unwrap();
            }
            Err(error) => {
                writeln!(output, "{error}").unwrap();
            }
        }
    }
    let expected = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/structural/search/tests/rune_rendering.expected.txt");
    if std::env::var_os("BIFROST_BLESS").is_some() {
        std::fs::write(&expected, &output).unwrap();
    }
    assert_eq!(std::fs::read_to_string(expected).unwrap(), output);
}
