#![allow(dead_code)]

use crate::common::lsp_client::{LspServer, uri_for};
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Marker {
    pub file: String,
    pub line: u64,
    pub character: u64,
}

#[derive(Debug)]
pub struct ClickFixture {
    name: String,
    files: Vec<(String, String)>,
}

impl ClickFixture {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            files: Vec::new(),
        }
    }

    pub fn file(mut self, path: impl Into<String>, source: impl Into<String>) -> Self {
        let path = path.into();
        validate_fixture_path(&path).unwrap_or_else(|message| panic!("{message}"));
        self.files.push((path, source.into()));
        self
    }

    pub fn build(&self) -> BuiltClickFixture {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical temp root");
        let mut markers = HashMap::new();

        for (relative_path, marked_source) in &self.files {
            let (clean_source, file_markers) = strip_markers(relative_path, marked_source);
            let path = root.join(relative_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .unwrap_or_else(|err| panic!("failed to create {}: {err}", parent.display()));
            }
            fs::write(&path, clean_source)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
            for (name, marker) in file_markers {
                assert!(
                    markers.insert(name.clone(), marker).is_none(),
                    "duplicate marker {name} in fixture {}",
                    self.name
                );
            }
        }

        BuiltClickFixture {
            name: self.name.clone(),
            temp,
            root,
            markers,
        }
    }
}

#[derive(Debug)]
pub struct BuiltClickFixture {
    name: String,
    temp: TempDir,
    root: PathBuf,
    markers: HashMap<String, Marker>,
}

impl BuiltClickFixture {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn marker(&self, name: &str) -> &Marker {
        self.markers
            .get(name)
            .unwrap_or_else(|| panic!("missing marker {name} in fixture {}", self.name))
    }

    fn marker_uri(&self, name: &str) -> String {
        uri_for(&self.root.join(&self.marker(name).file))
    }

    fn marker_position(&self, name: &str) -> (String, u64, u64) {
        let marker = self.marker(name);
        (
            uri_for(&self.root.join(&marker.file)),
            marker.line,
            marker.character,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ClickOperation {
    Definition,
    References { include_declaration: bool },
    Implementation,
    TypeDefinition,
    PrepareTypeHierarchy,
    TypeHierarchySupertypes,
    TypeHierarchySubtypes,
    Hover,
}

#[derive(Debug)]
pub enum ClickExpectation<'a> {
    Locations(&'a [&'a str]),
    LocationsAllowing(&'a [&'a str], &'a [&'a str]),
    Empty,
    HoverContains(&'a str),
}

#[derive(Debug)]
pub struct ClickCase<'a> {
    pub name: &'a str,
    pub marker: &'a str,
    pub operation: ClickOperation,
    pub expect: ClickExpectation<'a>,
}

impl<'a> ClickCase<'a> {
    pub fn new(
        name: &'a str,
        marker: &'a str,
        operation: ClickOperation,
        expect: ClickExpectation<'a>,
    ) -> Self {
        Self {
            name,
            marker,
            operation,
            expect,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClickTiming {
    pub case_name: String,
    pub marker: String,
    pub operation: &'static str,
    pub elapsed: Duration,
}

pub fn assert_click_cases(fixture: ClickFixture, cases: &[ClickCase<'_>]) -> Vec<ClickTiming> {
    let built = fixture.build();
    let mut server = LspServer::start(built.root());
    let mut timings = Vec::new();
    let mut failure = None;

    for case in cases {
        let started = Instant::now();
        let response = request_case(&mut server, &built, case);
        let elapsed = started.elapsed();
        let timing = ClickTiming {
            case_name: case.name.to_string(),
            marker: case.marker.to_string(),
            operation: operation_name(case.operation),
            elapsed,
        };
        let result = response.and_then(|response| check_response(&built, case, &response, &timing));
        if let Err(message) = result {
            failure = Some(message);
            timings.push(timing);
            break;
        }
        timings.push(timing);
    }

    server.shutdown();
    if let Some(message) = failure {
        panic!("{message}");
    }
    timings
}

fn request_case(
    server: &mut LspServer,
    fixture: &BuiltClickFixture,
    case: &ClickCase<'_>,
) -> Result<Value, String> {
    let (uri, line, character) = fixture.marker_position(case.marker);
    let response = match case.operation {
        ClickOperation::Definition => {
            server.text_document_position_response("textDocument/definition", &uri, line, character)
        }
        ClickOperation::References {
            include_declaration,
        } => server.references_response(&uri, line, character, include_declaration),
        ClickOperation::Implementation => server.implementation_response(&uri, line, character),
        ClickOperation::TypeDefinition => server.type_definition_response(&uri, line, character),
        ClickOperation::PrepareTypeHierarchy => server.request(
            "textDocument/prepareTypeHierarchy",
            json!({
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character}
            }),
        ),
        ClickOperation::TypeHierarchySupertypes | ClickOperation::TypeHierarchySubtypes => {
            let prepare = server.request(
                "textDocument/prepareTypeHierarchy",
                json!({
                    "textDocument": {"uri": uri},
                    "position": {"line": line, "character": character}
                }),
            );
            let Some(items) = prepare["result"].as_array() else {
                return match case.expect {
                    ClickExpectation::Empty => Ok(prepare),
                    _ => Err(format!(
                        "fixture {} case {} expected one hierarchy prepare item, got {prepare}",
                        fixture.name, case.name
                    )),
                };
            };
            if items.len() != 1 {
                return match case.expect {
                    ClickExpectation::Empty if items.is_empty() => Ok(prepare),
                    _ => Err(format!(
                        "fixture {} case {} expected one hierarchy prepare item, got {prepare}",
                        fixture.name, case.name
                    )),
                };
            }
            let item = items[0].clone();
            let method = match case.operation {
                ClickOperation::TypeHierarchySupertypes => "typeHierarchy/supertypes",
                ClickOperation::TypeHierarchySubtypes => "typeHierarchy/subtypes",
                _ => unreachable!(),
            };
            server.request(method, json!({"item": item}))
        }
        ClickOperation::Hover => server.hover_response(&uri, line, character),
    };
    Ok(response)
}

fn check_response(
    fixture: &BuiltClickFixture,
    case: &ClickCase<'_>,
    response: &Value,
    timing: &ClickTiming,
) -> Result<(), String> {
    if !response["error"].is_null() {
        return Err(format!(
            "fixture {} case {} at marker {} returned error after {} ms: {response}",
            fixture.name,
            case.name,
            case.marker,
            timing.elapsed.as_millis()
        ));
    }

    match &case.expect {
        ClickExpectation::Locations(expected_markers) => {
            let actual = location_starts(&response["result"]);
            let mut expected = expected_markers
                .iter()
                .map(|marker| {
                    let expected_marker = fixture.marker(marker);
                    (
                        fixture.marker_uri(marker),
                        expected_marker.line,
                        expected_marker.character,
                    )
                })
                .collect::<Vec<_>>();
            expected.sort();
            if actual != expected {
                return Err(format!(
                    "fixture {} case {} expected exact locations {:?}, got {:?} after {} ms; response: {response}",
                    fixture.name,
                    case.name,
                    expected,
                    actual,
                    timing.elapsed.as_millis()
                ));
            }
        }
        ClickExpectation::LocationsAllowing(required_markers, optional_markers) => {
            let actual = location_starts(&response["result"]);
            let required = required_markers
                .iter()
                .map(|marker| {
                    let expected_marker = fixture.marker(marker);
                    (
                        fixture.marker_uri(marker),
                        expected_marker.line,
                        expected_marker.character,
                    )
                })
                .collect::<Vec<_>>();
            let optional = optional_markers
                .iter()
                .map(|marker| {
                    let expected_marker = fixture.marker(marker);
                    (
                        fixture.marker_uri(marker),
                        expected_marker.line,
                        expected_marker.character,
                    )
                })
                .collect::<Vec<_>>();
            let mut allowed = required.clone();
            allowed.extend(optional);
            allowed.sort();
            let mut missing = required
                .iter()
                .filter(|expected| !actual.contains(expected))
                .cloned()
                .collect::<Vec<_>>();
            missing.sort();
            let mut unexpected = actual
                .iter()
                .filter(|location| !allowed.contains(location))
                .cloned()
                .collect::<Vec<_>>();
            unexpected.sort();
            if !missing.is_empty() || !unexpected.is_empty() {
                return Err(format!(
                    "fixture {} case {} expected required locations {:?} with optional locations {:?}, missing {:?}, unexpected {:?}, got {:?} after {} ms; response: {response}",
                    fixture.name,
                    case.name,
                    required_markers,
                    optional_markers,
                    missing,
                    unexpected,
                    actual,
                    timing.elapsed.as_millis()
                ));
            }
        }
        ClickExpectation::Empty => {
            if !response_result_is_empty(&response["result"]) {
                return Err(format!(
                    "fixture {} case {} expected empty result after {} ms, got {response}",
                    fixture.name,
                    case.name,
                    timing.elapsed.as_millis()
                ));
            }
        }
        ClickExpectation::HoverContains(expected) => {
            let rendered = response["result"].to_string();
            if !rendered.contains(expected) {
                return Err(format!(
                    "fixture {} case {} expected hover to contain {expected:?} after {} ms, got {response}",
                    fixture.name,
                    case.name,
                    timing.elapsed.as_millis()
                ));
            }
        }
    }
    Ok(())
}

fn response_result_is_empty(result: &Value) -> bool {
    result.is_null() || result.as_array().is_some_and(|array| array.is_empty())
}

fn location_starts(result: &Value) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    collect_location_starts(result, &mut out);
    out.sort();
    out
}

fn collect_location_starts(value: &Value, out: &mut Vec<(String, u64, u64)>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_location_starts(item, out);
            }
        }
        Value::Object(object) => {
            if let (Some(uri), Some(range)) = (object.get("uri"), object.get("range"))
                && let (Some(uri), Some(line), Some(character)) = (
                    uri.as_str(),
                    range["start"]["line"].as_u64(),
                    range["start"]["character"].as_u64(),
                )
            {
                out.push((uri.to_string(), line, character));
            }
        }
        _ => {}
    }
}

fn operation_name(operation: ClickOperation) -> &'static str {
    match operation {
        ClickOperation::Definition => "definition",
        ClickOperation::References { .. } => "references",
        ClickOperation::Implementation => "implementation",
        ClickOperation::TypeDefinition => "typeDefinition",
        ClickOperation::PrepareTypeHierarchy => "prepareTypeHierarchy",
        ClickOperation::TypeHierarchySupertypes => "typeHierarchy/supertypes",
        ClickOperation::TypeHierarchySubtypes => "typeHierarchy/subtypes",
        ClickOperation::Hover => "hover",
    }
}

fn strip_markers(relative_path: &str, source: &str) -> (String, HashMap<String, Marker>) {
    let mut cleaned = String::with_capacity(source.len());
    let mut markers = HashMap::new();
    let mut current_line = 0_u64;
    let mut current_character = 0_u64;
    let mut line_start_clean_len = 0_usize;
    let mut index = 0_usize;
    let bytes = source.as_bytes();

    while index < bytes.len() {
        if bytes[index] == b'<'
            && let Some(end) = marker_end(source, index)
        {
            let name = source[index + 1..end].to_string();
            insert_marker(
                &mut markers,
                name,
                relative_path,
                current_line,
                current_character,
            );
            index = end + 1;
            continue;
        }

        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let line_end = source[index..]
                .find('\n')
                .map(|offset| index + offset)
                .unwrap_or(source.len());
            let comment = &source[index..line_end];
            if let Some(caret_offset) = comment.find('^') {
                let name_start = index + caret_offset + 1;
                let name_end = source[name_start..line_end]
                    .find(|ch: char| !is_marker_name_char(ch))
                    .map(|offset| name_start + offset)
                    .unwrap_or(line_end);
                if name_end > name_start && cleaned[line_start_clean_len..].trim().is_empty() {
                    let marker_column = marker_comment_column(comment, caret_offset);
                    let name = source[name_start..name_end].to_string();
                    insert_marker(
                        &mut markers,
                        name,
                        relative_path,
                        current_line.saturating_sub(1),
                        marker_column,
                    );
                    cleaned.truncate(line_start_clean_len);
                    if line_end < source.len() {
                        index = line_end + 1;
                        current_character = 0;
                    } else {
                        index = line_end;
                    }
                    continue;
                }
            }
        }

        let ch = source[index..].chars().next().expect("valid char boundary");
        cleaned.push(ch);
        index += ch.len_utf8();
        if ch == '\n' {
            current_line += 1;
            current_character = 0;
            line_start_clean_len = cleaned.len();
        } else {
            current_character += ch.len_utf16() as u64;
        }
    }

    (cleaned, markers)
}

fn marker_end(source: &str, start: usize) -> Option<usize> {
    let end = source[start..].find('>').map(|offset| start + offset)?;
    let name = &source[start + 1..end];
    (!name.is_empty() && name.contains('_') && name.chars().all(is_marker_name_char)).then_some(end)
}

fn is_marker_name_char(ch: char) -> bool {
    ch == '_' || ch == '-' || ch.is_ascii_alphanumeric()
}

fn marker_comment_column(comment: &str, caret_offset: usize) -> u64 {
    let before_caret = &comment[..caret_offset];
    let after_slashes = before_caret
        .strip_prefix("//")
        .expect("marker comment starts with slashes");
    let aligned = after_slashes.strip_prefix(' ').unwrap_or(after_slashes);
    utf16_len(aligned)
}

fn insert_marker(
    markers: &mut HashMap<String, Marker>,
    name: String,
    relative_path: &str,
    line: u64,
    character: u64,
) {
    assert!(
        markers
            .insert(
                name.clone(),
                Marker {
                    file: relative_path.to_string(),
                    line,
                    character,
                },
            )
            .is_none(),
        "duplicate marker {name} in {relative_path}"
    );
}

fn validate_fixture_path(path: &str) -> Result<(), String> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() {
        return Err("fixture path must not be empty".to_string());
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(format!(
                    "fixture path must stay relative to the temporary root: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn utf16_len(input: &str) -> u64 {
    input.encode_utf16().count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn milestone_0_marker_parser_preserves_generic_syntax() {
        let source =
            "class Box {\n    List<String> values;\n    void <call_target>target() {}\n}\n";
        let (cleaned, markers) = strip_markers("Box.java", source);

        assert!(
            cleaned.contains("List<String>"),
            "generic syntax should not be stripped as a marker: {cleaned}"
        );
        assert!(
            !markers.contains_key("String"),
            "generic argument should not become a marker"
        );
        assert!(markers.contains_key("call_target"));
    }

    #[test]
    fn milestone_0_marker_parser_strips_caret_marker_line_without_deleting_target() {
        let source = "class Smoke {\n    target();\n    //     ^call_target\n    next();\n}\n";
        let (cleaned, markers) = strip_markers("Smoke.java", source);

        assert!(
            cleaned.contains("    target();\n    next();"),
            "caret marker line should be removed without deleting surrounding source: {cleaned}"
        );
        assert!(
            !cleaned.contains("^call_target"),
            "caret marker annotation should be stripped: {cleaned}"
        );
        let marker = markers.get("call_target").expect("call marker");
        assert_eq!(marker.line, 1);
        assert_eq!(marker.character, 4);
    }

    #[test]
    fn milestone_0_marker_parser_counts_utf16_columns() {
        let source = "let value = \"😀\"; 😀<emoji_target>target();\n";
        let (_cleaned, markers) = strip_markers("unicode.js", source);

        let marker = markers.get("emoji_target").expect("emoji marker");
        assert_eq!(
            marker.character, 20,
            "marker character should count supplementary emoji as two UTF-16 code units"
        );
    }

    #[test]
    fn milestone_0_fixture_rejects_paths_outside_temp_root() {
        let result = validate_fixture_path("../Escape.java");

        assert!(
            result.is_err(),
            "parent-directory fixture path should be rejected"
        );
    }
}
