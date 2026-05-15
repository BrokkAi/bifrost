//! Structured-data MCP tools: jq for JSON, xml_skim and xml_select for XML.
//!
//! HTML is intentionally not supported in this revision — `sxd-document` is
//! strict XML and rejects most real-world HTML. A follow-up issue should add
//! HTML support via a lenient parser (scraper / kuchikiki) with either an
//! HTML-to-XML normalization step or a CSS-selector-based variant.

use crate::analyzer::{IAnalyzer, ProjectFile};
use glob::{MatchOptions, Pattern};
use serde::{Deserialize, Serialize};

const STRICT_SEPARATOR: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

const DEFAULT_MAX_FILES: usize = 25;
const DEFAULT_MATCHES_PER_FILE: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JqParams {
    pub filepath: String,
    pub filter: String,
    #[serde(default = "default_max_files")]
    pub max_files: usize,
    #[serde(default = "default_matches_per_file")]
    pub matches_per_file: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlSkimParams {
    pub filepath: String,
    #[serde(default = "default_max_files")]
    pub max_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum XmlSelectOutput {
    #[default]
    Text,
    Attribute,
    OuterXml,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmlSelectParams {
    pub filepath: String,
    pub xpath: String,
    #[serde(default)]
    pub output: XmlSelectOutput,
    #[serde(default)]
    pub attr_name: Option<String>,
    #[serde(default = "default_max_files")]
    pub max_files: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct JqResult {
    pub files: Vec<JqFileResult>,
    pub truncated_files: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JqFileResult {
    pub path: String,
    pub matches: Vec<String>,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct XmlSkimResult {
    pub files: Vec<XmlSkimFile>,
    pub truncated_files: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct XmlSkimFile {
    pub path: String,
    pub elements: Vec<XmlSkimElement>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct XmlSkimElement {
    pub tag: String,
    pub depth: usize,
    pub attribute_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct XmlSelectResult {
    pub files: Vec<XmlSelectFile>,
    pub truncated_files: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct XmlSelectFile {
    pub path: String,
    pub matches: Vec<String>,
    pub error: Option<String>,
}

pub fn jq(analyzer: &dyn IAnalyzer, params: JqParams) -> JqResult {
    let project = analyzer.project();
    let files = match resolve_files(project, &params.filepath, params.max_files) {
        Ok(out) => out,
        Err(err) => {
            return JqResult {
                files: Vec::new(),
                truncated_files: false,
                error: Some(err),
            };
        }
    };

    let matches_per_file = params.matches_per_file.max(1);
    let mut file_results = Vec::new();

    for file in files.files {
        let path = rel_path_string(&file);
        match file.read_to_string() {
            Ok(content) => match run_jq_filter(&content, &params.filter, matches_per_file) {
                Ok((matches, truncated)) => file_results.push(JqFileResult {
                    path,
                    matches,
                    truncated,
                    error: None,
                }),
                Err(err) => file_results.push(JqFileResult {
                    path,
                    matches: Vec::new(),
                    truncated: false,
                    error: Some(err),
                }),
            },
            Err(err) => file_results.push(JqFileResult {
                path,
                matches: Vec::new(),
                truncated: false,
                error: Some(format!("read failed: {err}")),
            }),
        }
    }

    JqResult {
        files: file_results,
        truncated_files: files.truncated,
        error: None,
    }
}

pub fn xml_skim(analyzer: &dyn IAnalyzer, params: XmlSkimParams) -> XmlSkimResult {
    let project = analyzer.project();
    let files = match resolve_files(project, &params.filepath, params.max_files) {
        Ok(out) => out,
        Err(_) => {
            return XmlSkimResult {
                files: Vec::new(),
                truncated_files: false,
            };
        }
    };

    let mut file_results = Vec::new();
    for file in files.files {
        let path = rel_path_string(&file);
        match file.read_to_string() {
            Ok(content) => match skim_xml_string(&content) {
                Ok(elements) => file_results.push(XmlSkimFile {
                    path,
                    elements,
                    error: None,
                }),
                Err(err) => file_results.push(XmlSkimFile {
                    path,
                    elements: Vec::new(),
                    error: Some(err),
                }),
            },
            Err(err) => file_results.push(XmlSkimFile {
                path,
                elements: Vec::new(),
                error: Some(format!("read failed: {err}")),
            }),
        }
    }

    XmlSkimResult {
        files: file_results,
        truncated_files: files.truncated,
    }
}

pub fn xml_select(analyzer: &dyn IAnalyzer, params: XmlSelectParams) -> XmlSelectResult {
    if matches!(params.output, XmlSelectOutput::Attribute) && params.attr_name.is_none() {
        return XmlSelectResult {
            files: Vec::new(),
            truncated_files: false,
            error: Some(
                "attr_name is required when output is \"attribute\"".to_string(),
            ),
        };
    }

    let project = analyzer.project();
    let files = match resolve_files(project, &params.filepath, params.max_files) {
        Ok(out) => out,
        Err(err) => {
            return XmlSelectResult {
                files: Vec::new(),
                truncated_files: false,
                error: Some(err),
            };
        }
    };

    let mut file_results = Vec::new();
    for file in files.files {
        let path = rel_path_string(&file);
        match file.read_to_string() {
            Ok(content) => match run_xpath(
                &content,
                &params.xpath,
                &params.output,
                params.attr_name.as_deref(),
            ) {
                Ok(matches) => file_results.push(XmlSelectFile {
                    path,
                    matches,
                    error: None,
                }),
                Err(err) => file_results.push(XmlSelectFile {
                    path,
                    matches: Vec::new(),
                    error: Some(err),
                }),
            },
            Err(err) => file_results.push(XmlSelectFile {
                path,
                matches: Vec::new(),
                error: Some(format!("read failed: {err}")),
            }),
        }
    }

    XmlSelectResult {
        files: file_results,
        truncated_files: files.truncated,
        error: None,
    }
}

struct ResolvedFiles {
    files: Vec<ProjectFile>,
    truncated: bool,
}

fn resolve_files(
    project: &dyn crate::analyzer::Project,
    raw_pattern: &str,
    max_files: usize,
) -> Result<ResolvedFiles, String> {
    let max = max_files.max(1);
    let pattern_norm = normalize_pattern(raw_pattern.trim());
    if pattern_norm.is_empty() {
        return Err("filepath must not be empty".to_string());
    }

    if !is_glob_pattern(&pattern_norm) {
        let rel = std::path::Path::new(&pattern_norm);
        return match project.file_by_rel_path(rel) {
            Some(file) => Ok(ResolvedFiles {
                files: vec![file],
                truncated: false,
            }),
            None => Ok(ResolvedFiles {
                files: Vec::new(),
                truncated: false,
            }),
        };
    }

    let glob = Pattern::new(&pattern_norm).map_err(|err| format!("invalid glob: {err}"))?;
    let all_files = project
        .all_files()
        .map_err(|err| format!("workspace walk failed: {err}"))?;
    let mut matched: Vec<ProjectFile> = all_files
        .into_iter()
        .filter(|file| {
            let rel = rel_path_string(file);
            glob.matches_with(&rel, STRICT_SEPARATOR)
        })
        .collect();
    matched.sort();
    let truncated = matched.len() > max;
    matched.truncate(max);
    Ok(ResolvedFiles {
        files: matched,
        truncated,
    })
}

fn run_jq_filter(
    json_text: &str,
    filter: &str,
    matches_limit: usize,
) -> Result<(Vec<String>, bool), String> {
    use jaq_core::data::JustLut;
    use jaq_core::load::{Arena, File, Loader};
    use jaq_core::{Compiler, Ctx, Vars};
    use jaq_json::{Val, read};

    let input = read::parse_single(json_text.as_bytes())
        .map_err(|err| format!("invalid JSON: {err:?}"))?;

    let program = File {
        code: filter,
        path: (),
    };
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs::<JustLut<Val>>()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());

    let loader = Loader::new(defs);
    let arena = Arena::default();
    let modules = loader
        .load(&arena, program)
        .map_err(|err| format!("jq parse error: {err:?}"))?;
    let compiled = Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|err| format!("jq compile error: {err:?}"))?;

    let ctx = Ctx::<JustLut<Val>>::new(&compiled.lut, Vars::new([]));
    let mut out = Vec::new();
    let mut truncated = false;

    for result in compiled.id.run((ctx, input)) {
        if out.len() >= matches_limit {
            truncated = true;
            break;
        }
        match result {
            Ok(val) => out.push(val.to_string()),
            Err(err) => return Err(format!("jq runtime error: {err:?}")),
        }
    }

    Ok((out, truncated))
}

fn skim_xml_string(content: &str) -> Result<Vec<XmlSkimElement>, String> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut elements = Vec::new();
    let mut depth: usize = 0;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(start)) => {
                let tag = std::str::from_utf8(start.name().as_ref())
                    .map_err(|err| format!("invalid utf-8 in tag: {err}"))?
                    .to_string();
                let attribute_count = start.attributes().filter_map(Result::ok).count();
                elements.push(XmlSkimElement {
                    tag,
                    depth,
                    attribute_count,
                });
                depth += 1;
            }
            Ok(Event::Empty(start)) => {
                let tag = std::str::from_utf8(start.name().as_ref())
                    .map_err(|err| format!("invalid utf-8 in tag: {err}"))?
                    .to_string();
                let attribute_count = start.attributes().filter_map(Result::ok).count();
                elements.push(XmlSkimElement {
                    tag,
                    depth,
                    attribute_count,
                });
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(format!("xml parse error at {}: {err}", reader.buffer_position()));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(elements)
}

fn run_xpath(
    content: &str,
    xpath: &str,
    output: &XmlSelectOutput,
    attr_name: Option<&str>,
) -> Result<Vec<String>, String> {
    use sxd_document::parser;
    use sxd_xpath::{Context, Factory, Value};

    let package = parser::parse(content).map_err(|err| format!("xml parse error: {err}"))?;
    let document = package.as_document();

    let factory = Factory::new();
    let compiled = factory
        .build(xpath)
        .map_err(|err| format!("xpath compile error: {err}"))?
        .ok_or_else(|| "xpath compilation returned no expression".to_string())?;
    let ctx = Context::new();

    let value = compiled
        .evaluate(&ctx, document.root())
        .map_err(|err| format!("xpath evaluation error: {err}"))?;

    let matches = match value {
        Value::Nodeset(nodes) => nodes
            .document_order()
            .into_iter()
            .map(|node| format_node(node, output, attr_name))
            .collect(),
        Value::Boolean(b) => vec![b.to_string()],
        Value::Number(n) => vec![n.to_string()],
        Value::String(s) => vec![s],
    };

    Ok(matches)
}

fn format_node(
    node: sxd_xpath::nodeset::Node<'_>,
    output: &XmlSelectOutput,
    attr_name: Option<&str>,
) -> String {
    use sxd_xpath::nodeset::Node;
    match output {
        XmlSelectOutput::Text => node.string_value(),
        XmlSelectOutput::Attribute => {
            let Some(name) = attr_name else {
                return String::new();
            };
            match node {
                Node::Element(el) => el
                    .attribute(name)
                    .map(|a| a.value().to_string())
                    .unwrap_or_default(),
                Node::Attribute(a) => a.value().to_string(),
                _ => String::new(),
            }
        }
        XmlSelectOutput::OuterXml => match node {
            Node::Element(el) => format_element_outer(el),
            Node::Text(t) => t.text().to_string(),
            Node::Attribute(a) => format!("{}=\"{}\"", a.name().local_part(), a.value()),
            _ => String::new(),
        },
    }
}

fn format_element_outer(element: sxd_document::dom::Element<'_>) -> String {
    let mut out = String::new();
    let name = element.name().local_part();
    out.push('<');
    out.push_str(name);
    for attr in element.attributes() {
        out.push(' ');
        out.push_str(attr.name().local_part());
        out.push_str("=\"");
        out.push_str(attr.value());
        out.push('"');
    }
    out.push('>');
    for child in element.children() {
        match child {
            sxd_document::dom::ChildOfElement::Element(child_el) => {
                out.push_str(&format_element_outer(child_el));
            }
            sxd_document::dom::ChildOfElement::Text(t) => {
                out.push_str(t.text());
            }
            _ => {}
        }
    }
    out.push_str("</");
    out.push_str(name);
    out.push('>');
    out
}

fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/")
}

fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

fn rel_path_string(file: &ProjectFile) -> String {
    file.rel_path().to_string_lossy().replace('\\', "/")
}

fn default_max_files() -> usize {
    DEFAULT_MAX_FILES
}

fn default_matches_per_file() -> usize {
    DEFAULT_MATCHES_PER_FILE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: WorkspaceAnalyzer,
    }

    impl Fixture {
        fn new(files: &[(&str, &str)]) -> Self {
            let temp = TempDir::new().expect("tempdir");
            for (rel, content) in files {
                let abs = temp.path().join(rel);
                if let Some(parent) = abs.parent() {
                    fs::create_dir_all(parent).expect("mkdir");
                }
                fs::write(&abs, content).expect("write");
            }
            let project: Arc<dyn Project> = Arc::new(
                FilesystemProject::new(temp.path().to_path_buf()).expect("project"),
            );
            let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
            Self {
                _temp: temp,
                analyzer,
            }
        }
    }

    #[test]
    fn jq_runs_simple_filter() {
        let fix = Fixture::new(&[(
            "pkg.json",
            "{\"name\":\"bifrost\",\"version\":\"0.2.0\"}",
        )]);
        let result = jq(
            fix.analyzer.analyzer(),
            JqParams {
                filepath: "pkg.json".to_string(),
                filter: ".name".to_string(),
                max_files: 10,
                matches_per_file: 10,
            },
        );
        assert!(result.error.is_none(), "error: {:?}", result.error);
        assert_eq!(result.files.len(), 1);
        let file = &result.files[0];
        assert!(file.error.is_none(), "file error: {:?}", file.error);
        assert_eq!(file.matches, vec!["\"bifrost\"".to_string()]);
    }

    #[test]
    fn jq_returns_per_file_error_for_invalid_json() {
        let fix = Fixture::new(&[("bad.json", "{not json")]);
        let result = jq(
            fix.analyzer.analyzer(),
            JqParams {
                filepath: "bad.json".to_string(),
                filter: ".".to_string(),
                max_files: 10,
                matches_per_file: 10,
            },
        );
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].error.is_some());
    }

    #[test]
    fn jq_supports_glob_filepath() {
        let fix = Fixture::new(&[
            ("a.json", "{\"n\":1}"),
            ("b.json", "{\"n\":2}"),
            ("c.txt", "ignored"),
        ]);
        let result = jq(
            fix.analyzer.analyzer(),
            JqParams {
                filepath: "*.json".to_string(),
                filter: ".n".to_string(),
                max_files: 10,
                matches_per_file: 10,
            },
        );
        let paths: Vec<_> = result.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["a.json", "b.json"]);
    }

    #[test]
    fn xml_skim_emits_outline() {
        let fix = Fixture::new(&[(
            "pom.xml",
            "<project><groupId>org.example</groupId><dependencies><dep id=\"a\"/></dependencies></project>",
        )]);
        let result = xml_skim(
            fix.analyzer.analyzer(),
            XmlSkimParams {
                filepath: "pom.xml".to_string(),
                max_files: 10,
            },
        );
        assert_eq!(result.files.len(), 1);
        let file = &result.files[0];
        assert!(file.error.is_none(), "error: {:?}", file.error);
        let tags: Vec<_> = file.elements.iter().map(|e| e.tag.as_str()).collect();
        assert_eq!(tags, vec!["project", "groupId", "dependencies", "dep"]);
        assert_eq!(file.elements[3].attribute_count, 1);
    }

    #[test]
    fn xml_skim_reports_invalid_xml_per_file() {
        let fix = Fixture::new(&[("bad.xml", "<a><b></a>")]);
        let result = xml_skim(
            fix.analyzer.analyzer(),
            XmlSkimParams {
                filepath: "bad.xml".to_string(),
                max_files: 10,
            },
        );
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].error.is_some());
    }

    #[test]
    fn xml_select_returns_text_matches() {
        let fix = Fixture::new(&[(
            "data.xml",
            "<root><item>alpha</item><item>beta</item></root>",
        )]);
        let result = xml_select(
            fix.analyzer.analyzer(),
            XmlSelectParams {
                filepath: "data.xml".to_string(),
                xpath: "//item".to_string(),
                output: XmlSelectOutput::Text,
                attr_name: None,
                max_files: 10,
            },
        );
        assert!(result.error.is_none(), "error: {:?}", result.error);
        let file = &result.files[0];
        assert!(file.error.is_none(), "file error: {:?}", file.error);
        assert_eq!(file.matches, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn xml_select_returns_attribute_when_requested() {
        let fix = Fixture::new(&[(
            "data.xml",
            "<root><item id=\"1\"/><item id=\"2\"/></root>",
        )]);
        let result = xml_select(
            fix.analyzer.analyzer(),
            XmlSelectParams {
                filepath: "data.xml".to_string(),
                xpath: "//item".to_string(),
                output: XmlSelectOutput::Attribute,
                attr_name: Some("id".to_string()),
                max_files: 10,
            },
        );
        let file = &result.files[0];
        assert_eq!(file.matches, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn xml_select_requires_attr_name_for_attribute_output() {
        let fix = Fixture::new(&[("data.xml", "<root/>")]);
        let result = xml_select(
            fix.analyzer.analyzer(),
            XmlSelectParams {
                filepath: "data.xml".to_string(),
                xpath: "//root".to_string(),
                output: XmlSelectOutput::Attribute,
                attr_name: None,
                max_files: 10,
            },
        );
        assert!(result.error.is_some());
    }
}
