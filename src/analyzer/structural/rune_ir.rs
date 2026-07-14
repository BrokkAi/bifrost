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
use std::fmt;
use std::ops::Range;

const TRUNCATION_RESERVE: usize = 96;
const MIN_OUTPUT_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuneIrLimits {
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_source_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for RuneIrLimits {
    fn default() -> Self {
        Self {
            max_nodes: 10_000,
            max_depth: 128,
            max_source_bytes: 64 * 1024,
            max_output_bytes: 256 * 1024,
        }
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
            Self::NoStructuralFacts => f.write_str(
                "the structural adapter produced no Rune IR facts for the supplied source",
            ),
            Self::InvalidLimits => write!(
                f,
                "Rune IR node, depth, and source limits must be greater than zero, and the output limit must be at least {MIN_OUTPUT_BYTES} bytes"
            ),
            Self::StarterQuery(error) => {
                write!(f, "generated starter RQL did not parse: {error}")
            }
        }
    }
}

impl std::error::Error for RuneIrError {}

pub fn render_source_rune_ir(
    language: Language,
    source: &str,
    selection: RuneIrSelection,
    limits: RuneIrLimits,
) -> Result<RenderedRuneIr, RuneIrError> {
    if source.is_empty() {
        return Err(RuneIrError::EmptySource);
    }
    if limits.max_nodes == 0
        || limits.max_depth == 0
        || limits.max_source_bytes == 0
        || limits.max_output_bytes < MIN_OUTPUT_BYTES
    {
        return Err(RuneIrError::InvalidLimits);
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
    let (spec, grammar) = crate::analyzer::structural_language(language)
        .ok_or_else(|| RuneIrError::UnsupportedLanguage(language.config_label().to_string()))?;
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
                    self.push_line(depth, ")");
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
        for role in &node.roles {
            let mut role_line = format!(
                "({} :span ({} {})",
                role.role.label(),
                role.span.start_byte,
                role.span.end_byte
            );
            if let Some(target) = role.node {
                role_line.push_str(&format!(" :node {target}"));
            }
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
        if self
            .output
            .len()
            .saturating_add(needed)
            .saturating_add(TRUNCATION_RESERVE)
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
        debug_assert!(marker.len() <= self.limits.max_output_bytes);
        let available = self.limits.max_output_bytes - marker.len();
        if self.output.len() > available {
            let end = floor_char_boundary(&self.output, available);
            self.output.truncate(end);
        }
        self.output.push_str(&marker);
    }
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while !value.is_char_boundary(index) {
        index -= 1;
    }
    index
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
        }
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
    }
}
