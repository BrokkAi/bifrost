use lsp_types::Uri;
use serde_json::{Value, json};

use crate::analyzer::{CodeUnit, IAnalyzer, Project, Range};
use crate::lsp::handlers::util::project_file_for_uri;

pub(super) fn cursor_byte_range(content: &str, offset: usize) -> Range {
    let start = offset.min(content.len());
    let end = if start < content.len() {
        start
            + content[start..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(0)
    } else {
        start
    };
    Range {
        start_byte: start,
        end_byte: end,
        start_line: 0,
        end_line: 0,
    }
}

pub(super) fn hierarchy_item_data(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    uri: &Uri,
) -> Value {
    let range = code_unit_range(analyzer, code_unit);
    json!({
        "fqName": code_unit.fq_name(),
        "uri": uri.as_str(),
        "kind": code_unit.kind(),
        "signature": code_unit.signature(),
        "range": {
            "startByte": range.map(|range| range.start_byte),
            "endByte": range.map(|range| range.end_byte),
        },
    })
}

pub(super) fn resolve_hierarchy_item_code_unit(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    data: Option<&Value>,
    item_uri: &Uri,
    predicate: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let data = data?;
    let fq_name = data.get("fqName")?.as_str()?;
    let signature = data.get("signature").and_then(|value| value.as_str());
    let start_byte = data
        .pointer("/range/startByte")
        .and_then(|value| value.as_u64());
    let end_byte = data
        .pointer("/range/endByte")
        .and_then(|value| value.as_u64());
    let uri = data
        .get("uri")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| item_uri.as_str());
    let uri: Uri = uri.parse().ok()?;
    let file = project_file_for_uri(project, &uri)?;

    analyzer
        .declarations(&file)
        .into_iter()
        .find(|candidate| {
            candidate.fq_name() == fq_name
                && predicate(candidate)
                && item_identity_matches(analyzer, candidate, signature, start_byte, end_byte)
        })
        .or_else(|| {
            analyzer.definitions(fq_name).find(|candidate| {
                candidate.source() == &file
                    && predicate(candidate)
                    && item_identity_matches(analyzer, candidate, signature, start_byte, end_byte)
            })
        })
}

fn item_identity_matches(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    signature: Option<&str>,
    start_byte: Option<u64>,
    end_byte: Option<u64>,
) -> bool {
    if candidate.signature() != signature {
        return false;
    }
    match (start_byte, end_byte, code_unit_range(analyzer, candidate)) {
        (Some(start), Some(end), Some(range)) => {
            range.start_byte as u64 == start && range.end_byte as u64 == end
        }
        _ => true,
    }
}

fn code_unit_range(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<Range> {
    analyzer.ranges(code_unit).iter().min().copied()
}
