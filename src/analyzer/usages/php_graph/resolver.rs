use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, PhpAnalyzer, PhpUseAliases,
    ProjectFile, Range, parse_php_use_aliases_from_source, php_namespace_to_fq,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::find_line_index_for_offset;
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::Node;

pub(super) enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
    Constant,
    Function,
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner_fq_name: Option<String>,
    pub(super) target_fq_name: String,
    pub(super) member_name: String,
}

impl TargetSpec {
    pub(super) fn from_target(php: &PhpAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner_fq_name: None,
                target_fq_name: target.fq_name(),
                member_name: target.identifier().to_string(),
            });
        }

        let parent = php.parent_of(target);
        let kind = if target.is_function() {
            if parent.is_some() && target.identifier() == "__construct" {
                TargetKind::Constructor
            } else if parent.is_some() {
                TargetKind::Method
            } else {
                TargetKind::Function
            }
        } else if target.is_field() {
            if parent.is_some() {
                TargetKind::Field
            } else {
                TargetKind::Constant
            }
        } else {
            return None;
        };

        Some(Self {
            target: target.clone(),
            kind,
            owner_fq_name: parent.map(|owner| owner.fq_name()),
            target_fq_name: target.fq_name(),
            member_name: target.identifier().to_string(),
        })
    }
}

pub(super) fn resolve_php_analyzer(analyzer: &dyn IAnalyzer) -> Option<&PhpAnalyzer> {
    if let Some(php) = (analyzer as &dyn std::any::Any).downcast_ref::<PhpAnalyzer>() {
        return Some(php);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Php) {
        Some(AnalyzerDelegate::Php(php)) => Some(php),
        _ => None,
    }
}

pub(super) struct FileContext {
    pub(super) namespace: String,
    pub(super) aliases: PhpUseAliases,
}

#[derive(Default)]
pub(super) struct PhpHierarchyIndex {
    ancestors: HashMap<String, HashSet<String>>,
    interfaces: HashSet<String>,
}

impl PhpHierarchyIndex {
    pub(super) fn build(php: &PhpAnalyzer, files: &HashSet<ProjectFile>) -> Self {
        let mut hierarchy = Self::default();
        for file in files {
            if language_for_file(file) != Language::Php {
                continue;
            }
            let Ok(source) = file.read_to_string() else {
                continue;
            };
            let ctx = FileContext {
                namespace: php.namespace_of_file(file),
                aliases: parse_php_use_aliases_from_source(&source),
            };
            hierarchy.extend_file(&source, &ctx);
        }
        hierarchy
    }

    fn extend_file(&mut self, source: &str, ctx: &FileContext) {
        for captures in TYPE_DECLARATION_RE.captures_iter(source) {
            let Some(kind) = captures.name("kind") else {
                continue;
            };
            let Some(name) = captures.name("name") else {
                continue;
            };
            let Some(type_name) = resolve_php_type(name.as_str(), ctx) else {
                continue;
            };
            if kind.as_str() == "interface" {
                self.interfaces.insert(type_name.clone());
            }
            let parents = self.ancestors.entry(type_name).or_default();
            if let Some(extends) = captures.name("extends") {
                parents.extend(resolve_type_list(extends.as_str(), ctx));
            }
            if let Some(implements) = captures.name("implements") {
                parents.extend(resolve_type_list(implements.as_str(), ctx));
            }
        }
    }

    fn is_subtype(&self, receiver_fq_name: &str, owner: &str) -> bool {
        let mut stack: Vec<&str> = self
            .ancestors
            .get(receiver_fq_name)
            .map(|ancestors| ancestors.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let mut visited: HashSet<&str> = HashSet::default();
        while let Some(candidate) = stack.pop() {
            if candidate == owner {
                return true;
            }
            if !visited.insert(candidate) {
                continue;
            }
            if let Some(ancestors) = self.ancestors.get(candidate) {
                stack.extend(ancestors.iter().map(String::as_str));
            }
        }
        false
    }
}

static TYPE_DECLARATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?P<kind>class|interface|trait)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s+extends\s+(?P<extends>[^ {]+(?:\s*,\s*[^ {]+)*))?(?:\s+implements\s+(?P<implements>[^ {]+(?:\s*,\s*[^ {]+)*))?",
    )
    .expect("valid PHP type declaration regex")
});

fn resolve_type_list(raw: &str, ctx: &FileContext) -> Vec<String> {
    raw.split(',')
        .filter_map(|name| resolve_php_type(name.trim(), ctx))
        .collect()
}

pub(super) fn receiver_type_matches(
    receiver_fq_name: &str,
    owner: &str,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    if receiver_fq_name == owner {
        return !hierarchy.interfaces.contains(owner);
    }
    hierarchy.is_subtype(receiver_fq_name, owner)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn static_receiver_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
    receiver: &str,
    owner: &str,
    ctx: &FileContext,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    match receiver {
        "self" | "static" => {
            receiver_is_enclosing_subtype(analyzer, file, start, end, line_starts, owner, hierarchy)
        }
        "parent" => enclosing_owner_at(analyzer, file, start, end, line_starts)
            .is_some_and(|enclosing_owner| hierarchy.is_subtype(&enclosing_owner, owner)),
        _ => resolve_php_type(receiver, ctx)
            .is_some_and(|fq| receiver_type_matches(&fq, owner, hierarchy)),
    }
}

fn public_php_fq_name(fq_name: &str) -> String {
    fq_name.replace("._module_.", ".")
}

pub(super) fn receiver_is_enclosing_subtype(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
    owner: &str,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    enclosing_owner_at(analyzer, file, start, end, line_starts)
        .is_some_and(|receiver| receiver_type_matches(&receiver, owner, hierarchy))
}

fn enclosing_owner_at(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
) -> Option<String> {
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(line_starts, start),
        end_line: find_line_index_for_offset(line_starts, end),
    };
    analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|enclosing| analyzer.parent_of(&enclosing).or(Some(enclosing)))
        .map(|enclosing_owner| enclosing_owner.fq_name())
}

pub(super) fn qualified_candidate_text(node: Node<'_>, source: &str) -> String {
    let mut candidate = node;
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        let text = node_text(ancestor, source).trim();
        if is_php_qualified_name_text(text) {
            candidate = ancestor;
            parent = ancestor.parent();
        } else {
            break;
        }
    }
    let start = candidate.start_byte();
    let text = node_text(candidate, source).trim().to_string();
    if source.get(..start).unwrap_or_default().ends_with('\\') {
        format!("\\{text}")
    } else {
        text
    }
}

fn is_php_qualified_name_text(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '\\'))
}

pub(super) fn resolve_php_type(raw: &str, ctx: &FileContext) -> Option<String> {
    let first = raw.split('|').next().unwrap_or(raw).trim();
    if first.is_empty() || matches!(first, "self" | "static" | "parent") {
        return None;
    }
    if first.starts_with('\\') {
        return Some(php_namespace_to_fq(first));
    }
    let normalized = php_namespace_to_fq(first);
    let local = normalized.split('.').next().unwrap_or(normalized.as_str());
    if let Some(imported) = ctx.aliases.type_aliases.get(local) {
        if normalized == local {
            return Some(imported.clone());
        }
        let suffix = normalized
            .strip_prefix(local)
            .unwrap_or("")
            .trim_start_matches('.');
        return Some(if suffix.is_empty() {
            imported.clone()
        } else {
            format!("{imported}.{suffix}")
        });
    }
    Some(join_namespace(&ctx.namespace, &normalized))
}

pub(super) fn resolve_php_function(raw: &str, ctx: &FileContext) -> Option<String> {
    if raw.starts_with('\\') {
        return Some(php_namespace_to_fq(raw));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.function_aliases.get(&normalized) {
        return Some(imported.clone());
    }
    Some(join_namespace(&ctx.namespace, &normalized))
}

pub(super) fn resolve_php_constant(raw: &str, ctx: &FileContext) -> Option<String> {
    if raw.starts_with('\\') {
        return Some(module_constant_fq(&php_namespace_to_fq(raw)));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.const_aliases.get(&normalized) {
        return Some(module_constant_fq(imported));
    }
    Some(join_namespace(
        &ctx.namespace,
        &format!("_module_.{normalized}"),
    ))
}

fn module_constant_fq(fq_name: &str) -> String {
    if fq_name.contains("._module_.") {
        return fq_name.to_string();
    }
    let public = public_php_fq_name(fq_name);
    if let Some((namespace, name)) = public.rsplit_once('.') {
        format!("{namespace}._module_.{name}")
    } else {
        format!("_module_.{public}")
    }
}

fn join_namespace(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        namespace.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

pub(super) fn has_token_before(start: usize, source: &str, token: &str) -> bool {
    source
        .get(..start)
        .unwrap_or_default()
        .trim_end()
        .ends_with(token)
}

pub(super) fn has_operator_before(start: usize, source: &str, op: &str) -> bool {
    source
        .get(..start)
        .unwrap_or_default()
        .trim_end()
        .ends_with(op)
}

pub(super) fn has_open_paren_after(end: usize, source: &str) -> bool {
    source
        .get(end..)
        .unwrap_or_default()
        .trim_start()
        .starts_with('(')
}

pub(super) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}
