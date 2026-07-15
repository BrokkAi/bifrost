//! Rune IR rendering for query-by-example workflows.
//!
//! Rune IR is Bifrost's normalized, language-neutral source representation:
//! the [`FileFacts`] arena consumed by the structural matcher. This module is
//! deliberately independent of workspace analyzers so callers can inspect
//! unsaved or pasted source without indexing a project.

use super::CodeQuery;
use super::extract::extract_file_facts;
use super::facts::FileFacts;
use crate::analyzer::Language;
use crate::analyzer::common::is_unparseable_source;
use crate::analyzer::{ParserFlavor, parser_flavor_for_path, parser_language_for_flavor};
use std::fmt;
use std::ops::Range;
use std::path::Path;

const TRUNCATION_RESERVE: usize = 96;
const MIN_OUTPUT_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuneIrLimits {
    pub max_input_bytes: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_source_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for RuneIrLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 256 * 1024,
            max_nodes: 10_000,
            max_depth: 128,
            max_source_bytes: 64 * 1024,
            max_output_bytes: 256 * 1024,
        }
    }
}

/// The parser flavor used to extract Rune IR from a source snippet.
///
/// Most languages have one grammar. TypeScript is the exception because `.ts`
/// and `.tsx` files use distinct tree-sitter grammars while sharing the same
/// normalized structural adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuneIrLanguage {
    Standard(Language),
    TypeScriptTsx,
}

impl RuneIrLanguage {
    pub fn from_config_label(label: &str) -> Option<Self> {
        let normalized = label
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .replace(['_', '-'], "");
        if matches!(normalized.as_str(), "tsx" | "typescriptreact") {
            return Some(Self::TypeScriptTsx);
        }
        Language::from_config_label(label).map(Self::Standard)
    }

    pub fn for_path(language: Language, path: &Path) -> Self {
        if parser_flavor_for_path(language, path) == ParserFlavor::TypeScriptTsx {
            Self::TypeScriptTsx
        } else {
            Self::Standard(language)
        }
    }

    pub fn language(self) -> Language {
        match self {
            Self::Standard(language) => language,
            Self::TypeScriptTsx => Language::TypeScript,
        }
    }

    pub fn config_label(self) -> &'static str {
        match self {
            Self::Standard(language) => language.config_label(),
            Self::TypeScriptTsx => "tsx",
        }
    }

    pub fn config_labels() -> impl Iterator<Item = &'static str> {
        Language::ANALYZABLE
            .iter()
            .map(|language| language.config_label())
            .chain(std::iter::once("tsx"))
    }

    fn parser_language(self) -> Option<tree_sitter::Language> {
        let flavor = match self {
            Self::Standard(_) => ParserFlavor::Default,
            Self::TypeScriptTsx => ParserFlavor::TypeScriptTsx,
        };
        parser_language_for_flavor(self.language(), flavor)
    }
}

impl From<Language> for RuneIrLanguage {
    fn from(language: Language) -> Self {
        Self::Standard(language)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuneIrSelection {
    WholeSource,
    ByteRange(Range<usize>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedRuneIr {
    pub rune_ir: String,
    pub starter_rql: String,
    pub source_range: Range<usize>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuneIrError {
    UnsupportedLanguage(String),
    EmptySource,
    InvalidSelection(Range<usize>),
    SourceTooLarge { actual: usize, limit: usize },
    UnsafeSource,
    NoStructuralFacts,
    InvalidLimits,
    StarterQuery(String),
}

impl fmt::Display for RuneIrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedLanguage(language) => write!(
                f,
                "language `{language}` does not have a Rune IR structural adapter"
            ),
            Self::EmptySource => f.write_str("source is empty; provide source code to inspect"),
            Self::InvalidSelection(range) => write!(
                f,
                "source selection {}..{} is outside the supplied source",
                range.start, range.end
            ),
            Self::SourceTooLarge { actual, limit } => write!(
                f,
                "source is {actual} bytes; Rune IR accepts at most {limit} bytes per request"
            ),
            Self::UnsafeSource => f.write_str(
                "source is unsafe to parse because it contains a NUL byte or a line longer than Bifrost's configured parser-safety limit; provide ordinary text source with shorter lines",
            ),
            Self::NoStructuralFacts => f.write_str(
                "the structural adapter produced no Rune IR facts for the supplied source",
            ),
            Self::InvalidLimits => write!(
                f,
                "Rune IR input, node, depth, and source-copy limits must be greater than zero, and the output limit must be at least {MIN_OUTPUT_BYTES} bytes"
            ),
            Self::StarterQuery(error) => {
                write!(f, "generated starter RQL did not parse: {error}")
            }
        }
    }
}

impl std::error::Error for RuneIrError {}

pub fn render_source_rune_ir(
    language: impl Into<RuneIrLanguage>,
    source: &str,
    selection: RuneIrSelection,
    limits: RuneIrLimits,
) -> Result<RenderedRuneIr, RuneIrError> {
    if source.is_empty() {
        return Err(RuneIrError::EmptySource);
    }
    if limits.max_input_bytes == 0
        || limits.max_nodes == 0
        || limits.max_depth == 0
        || limits.max_source_bytes == 0
        || limits.max_output_bytes < MIN_OUTPUT_BYTES
    {
        return Err(RuneIrError::InvalidLimits);
    }
    if source.len() > limits.max_input_bytes {
        return Err(RuneIrError::SourceTooLarge {
            actual: source.len(),
            limit: limits.max_input_bytes,
        });
    }
    if is_unparseable_source(source) {
        return Err(RuneIrError::UnsafeSource);
    }
    let selected = match selection {
        RuneIrSelection::WholeSource => None,
        RuneIrSelection::ByteRange(range) => {
            if range.start > range.end
                || range.end > source.len()
                || !source.is_char_boundary(range.start)
                || !source.is_char_boundary(range.end)
            {
                return Err(RuneIrError::InvalidSelection(range));
            }
            Some(range)
        }
    };
    let language = language.into();
    let analyzer_language = language.language();
    let spec = crate::analyzer::structural_spec_for(analyzer_language).ok_or_else(|| {
        RuneIrError::UnsupportedLanguage(analyzer_language.config_label().to_string())
    })?;
    let grammar = language.parser_language().ok_or_else(|| {
        RuneIrError::UnsupportedLanguage(analyzer_language.config_label().to_string())
    })?;
    let facts = extract_file_facts(spec, &grammar, source).ok_or(RuneIrError::NoStructuralFacts)?;
    let roots = selected_roots(&facts, selected.as_ref());
    if roots.is_empty() {
        return Err(RuneIrError::NoStructuralFacts);
    }
    let source_range = roots_source_range(&facts, &roots);
    let starter_rql = starter_rql(&facts, roots[0])?;
    let (rune_ir, truncated) = Renderer::new(&facts, limits).render(&roots);
    Ok(RenderedRuneIr {
        rune_ir,
        starter_rql,
        source_range,
        truncated,
    })
}

fn selected_roots(facts: &FileFacts, selection: Option<&Range<usize>>) -> Vec<u32> {
    let Some(selection) = selection else {
        return facts
            .nodes()
            .iter()
            .enumerate()
            .filter_map(|(id, node)| node.parent.is_none().then_some(id as u32))
            .collect();
    };

    let exact = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            node.range.start_byte == selection.start && node.range.end_byte == selection.end
        })
        .map(|(id, _)| id as u32)
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        return exact;
    }

    let contained = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            selection.start <= node.range.start_byte && node.range.end_byte <= selection.end
        })
        .filter(|(_, node)| {
            node.parent.is_none_or(|parent| {
                let parent = facts.node(parent);
                !(selection.start <= parent.range.start_byte
                    && parent.range.end_byte <= selection.end)
            })
        })
        .map(|(id, _)| id as u32)
        .collect::<Vec<_>>();
    if !contained.is_empty() {
        return contained;
    }

    facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            node.range.start_byte <= selection.start && selection.end <= node.range.end_byte
        })
        .min_by_key(|(_, node)| node.range.end_byte - node.range.start_byte)
        .map(|(id, _)| vec![id as u32])
        .unwrap_or_default()
}

fn roots_source_range(facts: &FileFacts, roots: &[u32]) -> Range<usize> {
    let first = facts.node(roots[0]);
    roots
        .iter()
        .skip(1)
        .fold(first.range.start_byte..first.range.end_byte, |range, id| {
            let node = facts.node(*id);
            range.start.min(node.range.start_byte)..range.end.max(node.range.end_byte)
        })
}

fn starter_rql(facts: &FileFacts, root: u32) -> Result<String, RuneIrError> {
    let node = facts.node(root);
    let rql = match node.name {
        Some(name) if !name.text(facts.source()).is_empty() => format!(
            "({} :name {})",
            node.kind.label(),
            quoted(name.text(facts.source()))
        ),
        _ => format!("({})", node.kind.label()),
    };
    CodeQuery::from_source(&rql).map_err(RuneIrError::StarterQuery)?;
    Ok(rql)
}

#[derive(Debug, Clone, Copy)]
enum Event {
    Open(u32, usize),
    Close(usize),
}

struct Renderer<'a> {
    facts: &'a FileFacts,
    limits: RuneIrLimits,
    output: String,
    rendered_nodes: usize,
    copied_source_bytes: usize,
    truncated: Option<&'static str>,
    open_nodes: usize,
    children: Vec<Vec<u32>>,
}

impl<'a> Renderer<'a> {
    fn new(facts: &'a FileFacts, limits: RuneIrLimits) -> Self {
        let mut children = vec![Vec::new(); facts.nodes().len()];
        for (id, node) in facts.nodes().iter().enumerate() {
            if let Some(parent) = node.parent {
                children[parent as usize].push(id as u32);
            }
        }
        Self {
            facts,
            limits,
            output: String::new(),
            rendered_nodes: 0,
            copied_source_bytes: 0,
            truncated: None,
            open_nodes: 0,
            children,
        }
    }

    fn render(mut self, roots: &[u32]) -> (String, bool) {
        let mut stack = roots
            .iter()
            .rev()
            .map(|root| Event::Open(*root, 0))
            .collect::<Vec<_>>();
        while let Some(event) = stack.pop() {
            if self.truncated.is_some() {
                break;
            }
            match event {
                Event::Open(id, depth) => self.open_node(id, depth, &mut stack),
                Event::Close(depth) => {
                    if self.push_line(depth, ")") {
                        self.open_nodes -= 1;
                    }
                }
            }
        }
        if let Some(reason) = self.truncated {
            self.append_truncation(reason);
        }
        let truncated = self.truncated.is_some();
        (self.output, truncated)
    }

    fn open_node(&mut self, id: u32, depth: usize, stack: &mut Vec<Event>) {
        if self.rendered_nodes >= self.limits.max_nodes {
            self.truncated = Some("node limit reached");
            return;
        }
        if depth >= self.limits.max_depth {
            self.truncated = Some("depth limit reached");
            return;
        }
        self.rendered_nodes += 1;
        let node = self.facts.node(id);
        let mut line = format!(
            "({} :range ({} {})",
            node.kind.label(),
            node.range.start_byte,
            node.range.end_byte
        );
        if let Some(name) = node.name {
            let Some(value) = self.source_value(name.text(self.facts.source())) else {
                return;
            };
            line.push_str(" :name ");
            line.push_str(&value);
        }
        if !self.push_line(depth, &line) {
            return;
        }
        self.open_nodes += 1;
        for role in self.facts.roles(id) {
            let mut role_line = format!(
                "({} :span ({} {})",
                role.role.label(),
                role.span.start_byte,
                role.span.end_byte
            );
            if let Some(keyword) = role.keyword {
                let Some(value) = self.source_value(keyword.text(self.facts.source())) else {
                    return;
                };
                role_line.push_str(" :keyword ");
                role_line.push_str(&value);
            }
            if let Some(name) = role.name {
                let Some(value) = self.source_value(name.text(self.facts.source())) else {
                    return;
                };
                role_line.push_str(" :name ");
                role_line.push_str(&value);
            }
            let Some(value) = self.source_value(role.span.text(self.facts.source())) else {
                return;
            };
            role_line.push_str(" :text ");
            role_line.push_str(&value);
            role_line.push(')');
            if !self.push_line(depth + 1, &role_line) {
                return;
            }
        }
        stack.push(Event::Close(depth));
        for child in self.children[id as usize].iter().rev() {
            stack.push(Event::Open(*child, depth + 1));
        }
    }

    fn source_value(&mut self, value: &str) -> Option<String> {
        if self.copied_source_bytes.saturating_add(value.len()) > self.limits.max_source_bytes {
            self.truncated = Some("source byte limit reached");
            return None;
        }
        self.copied_source_bytes += value.len();
        Some(quoted(value))
    }

    fn push_line(&mut self, depth: usize, line: &str) -> bool {
        let needed = depth.saturating_mul(2) + line.len() + 1;
        // Preserve enough space for a truncation form and compact closing
        // parentheses for every node that would remain open after this line.
        let opens_node = line.starts_with('(') && !line.ends_with(')');
        let prospective_open_nodes = self.open_nodes + usize::from(opens_node);
        let reserve = TRUNCATION_RESERVE.saturating_add(prospective_open_nodes);
        if self
            .output
            .len()
            .saturating_add(needed)
            .saturating_add(reserve)
            > self.limits.max_output_bytes
        {
            self.truncated = Some("output byte limit reached");
            return false;
        }
        self.output.extend(std::iter::repeat_n(' ', depth * 2));
        self.output.push_str(line);
        self.output.push('\n');
        true
    }

    fn append_truncation(&mut self, reason: &str) {
        let marker = format!("(truncated {})\n", quoted(reason));
        debug_assert!(
            self.output.len() + marker.len() + self.open_nodes < self.limits.max_output_bytes
        );
        self.output.push_str(&marker);
        self.output
            .extend(std::iter::repeat_n(')', self.open_nodes));
        if self.open_nodes > 0 {
            self.output.push('\n');
        }
        self.open_nodes = 0;
    }
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_rune_ir_uses_canonical_facts_and_parseable_starter() {
        let source = "fn greet(name: &str) { println!(\"{name}\"); }";
        let rendered = render_source_rune_ir(
            Language::Rust,
            source,
            RuneIrSelection::WholeSource,
            RuneIrLimits::default(),
        )
        .unwrap();

        assert!(rendered.rune_ir.contains("(function"));
        assert!(rendered.rune_ir.contains(":name \"greet\""));
        assert!(!rendered.rune_ir.contains("function_item"));
        assert!(!rendered.truncated);
        CodeQuery::from_source(&rendered.starter_rql).unwrap();
    }

    #[test]
    fn python_rune_ir_renders_roles_and_escaped_source() {
        let source = "@trace\ndef greet(name):\n    client.send(name, label=\"a\\\"b\")\n";
        let rendered = render_source_rune_ir(
            Language::Python,
            source,
            RuneIrSelection::WholeSource,
            RuneIrLimits::default(),
        )
        .unwrap();

        assert!(rendered.rune_ir.contains("(decorator"));
        assert!(rendered.rune_ir.contains("(callee"));
        assert!(rendered.rune_ir.contains("(kwargs"));
        assert!(rendered.rune_ir.contains(":keyword \"label\""));
        assert!(rendered.rune_ir.contains("a\\\\\\\"b"));
        assert!(!rendered.rune_ir.contains("function_definition"));
    }

    #[test]
    fn python_rune_ir_covers_import_and_assignment_roles() {
        let source = "import os\nvalue = \"ready\"\n";
        let rendered = render_source_rune_ir(
            Language::Python,
            source,
            RuneIrSelection::WholeSource,
            RuneIrLimits::default(),
        )
        .unwrap();

        assert!(rendered.rune_ir.contains("(import"), "{rendered:?}");
        assert!(rendered.rune_ir.contains("(module"), "{rendered:?}");
        assert!(rendered.rune_ir.contains(":text \"os\""), "{rendered:?}");
        assert!(rendered.rune_ir.contains("(assignment"), "{rendered:?}");
        assert!(rendered.rune_ir.contains("(left"), "{rendered:?}");
        assert!(rendered.rune_ir.contains("(right"), "{rendered:?}");
        assert!(
            !rendered.rune_ir.contains("import_statement"),
            "{rendered:?}"
        );
    }

    #[test]
    fn typescript_selection_uses_top_level_contained_facts() {
        let source = "const prefix = 1;\nclass Greeter {\n  greet() { return service.name; }\n}\n";
        let start = source.find("class").unwrap();
        let end = source.len() - 1;
        let rendered = render_source_rune_ir(
            Language::TypeScript,
            source,
            RuneIrSelection::ByteRange(start..end),
            RuneIrLimits::default(),
        )
        .unwrap();

        assert!(rendered.rune_ir.starts_with("(class"));
        assert!(rendered.rune_ir.contains("(method"));
        assert!(rendered.rune_ir.contains("(field_access"));
        assert!(!rendered.rune_ir.contains("lexical_declaration"));
    }

    #[test]
    fn tsx_uses_the_file_specific_parser_grammar() {
        let source = "function View() { return <div>{value}</div>; }";
        let rendered = render_source_rune_ir(
            RuneIrLanguage::TypeScriptTsx,
            source,
            RuneIrSelection::WholeSource,
            RuneIrLimits::default(),
        )
        .unwrap();

        assert!(rendered.rune_ir.starts_with("(function"), "{rendered:?}");
        assert!(rendered.rune_ir.contains(":name \"View\""));
        assert_eq!(rendered.starter_rql, "(function :name \"View\")");
    }

    #[test]
    fn renderer_marks_each_bounded_dimension() {
        let source = "fn outer() { if true { loop { return; } } }";
        let cases = [
            RuneIrLimits {
                max_nodes: 1,
                ..RuneIrLimits::default()
            },
            RuneIrLimits {
                max_depth: 1,
                ..RuneIrLimits::default()
            },
            RuneIrLimits {
                max_source_bytes: 1,
                ..RuneIrLimits::default()
            },
            RuneIrLimits {
                max_output_bytes: 80,
                ..RuneIrLimits::default()
            },
        ];
        for limits in cases {
            let rendered =
                render_source_rune_ir(Language::Rust, source, RuneIrSelection::WholeSource, limits)
                    .unwrap();
            assert!(rendered.truncated, "limits: {limits:?}");
            assert!(rendered.rune_ir.contains("truncated"), "limits: {limits:?}");
            assert!(rendered.rune_ir.len() <= limits.max_output_bytes);
            assert_balanced_sexpr(&rendered.rune_ir);
        }
    }

    fn assert_balanced_sexpr(value: &str) {
        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        for byte in value.bytes() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
                continue;
            }
            match byte {
                b'"' => quoted = true,
                b'(' => depth += 1,
                b')' => {
                    depth = depth
                        .checked_sub(1)
                        .expect("unexpected closing parenthesis")
                }
                _ => {}
            }
        }
        assert!(!quoted, "unterminated string in {value:?}");
        assert_eq!(depth, 0, "unclosed form in {value:?}");
    }

    #[test]
    fn invalid_and_empty_inputs_are_actionable() {
        assert_eq!(
            render_source_rune_ir(
                Language::Rust,
                "",
                RuneIrSelection::WholeSource,
                RuneIrLimits::default()
            ),
            Err(RuneIrError::EmptySource)
        );
        assert!(matches!(
            render_source_rune_ir(
                Language::None,
                "text",
                RuneIrSelection::WholeSource,
                RuneIrLimits::default()
            ),
            Err(RuneIrError::UnsupportedLanguage(_))
        ));
        assert!(matches!(
            render_source_rune_ir(
                Language::Rust,
                "fn oversized() {}",
                RuneIrSelection::WholeSource,
                RuneIrLimits {
                    max_input_bytes: 4,
                    ..RuneIrLimits::default()
                }
            ),
            Err(RuneIrError::SourceTooLarge { limit: 4, .. })
        ));
        assert_eq!(
            render_source_rune_ir(
                Language::Rust,
                "fn main() {\0}",
                RuneIrSelection::WholeSource,
                RuneIrLimits::default()
            ),
            Err(RuneIrError::UnsafeSource)
        );
        let long_line = "x".repeat(crate::analyzer::common::DEFAULT_MAX_LINE_LENGTH + 1);
        assert_eq!(
            render_source_rune_ir(
                Language::Rust,
                &long_line,
                RuneIrSelection::WholeSource,
                RuneIrLimits::default()
            ),
            Err(RuneIrError::UnsafeSource)
        );
    }

    #[test]
    fn role_edges_do_not_expose_internal_arena_ids() {
        let rendered = render_source_rune_ir(
            Language::Rust,
            "fn f() { g(x); }",
            RuneIrSelection::WholeSource,
            RuneIrLimits::default(),
        )
        .unwrap();

        assert!(rendered.rune_ir.contains("(callee"));
        assert!(rendered.rune_ir.contains("(args"));
        assert!(!rendered.rune_ir.contains(":node"));
    }
}
