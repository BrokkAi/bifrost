//! The language half of PHP's resolution logic: namespace identity, `use`
//! alias visibility, declaration-kind classification and supertype resolution,
//! written as free functions over a source trait instead of as methods on
//! `PhpAnalyzer`.
//!
//! `PhpAnalyzer` owns the one lazy cell PHP has (a moka cache of direct
//! ancestors) and implements [`PhpAnalysisSource`] out of its own accessors, so
//! the functions below reach back for the memoized products they need without
//! naming the analyzer type.

use super::aliases::{
    PhpFileContext, PhpUseAliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, resolve_php_type,
};
use crate::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile, TypeHierarchyProvider};
use crate::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser};

/// The analyzer-resident products PHP's language logic resolves through: the
/// core declaration index plus the memoized type hierarchy. `PhpAnalyzer` is the
/// only implementor that matters and every method it answers comes from one of
/// its own accessors, so the ancestor cache stays where it is and no free
/// function below can reach past this surface.
pub trait PhpAnalysisSource: CodeUnitIndex + TypeHierarchyProvider {}

impl<T: CodeUnitIndex + TypeHierarchyProvider + ?Sized> PhpAnalysisSource for T {}

pub fn php_is_constructor(method: &CodeUnit, class_unit: &CodeUnit, _package_name: &str) -> bool {
    method.is_function()
        && class_unit.is_class()
        && method.identifier() == "__construct"
        && method.fq_name() == format!("{}.__construct", class_unit.fq_name())
}

pub fn php_namespace_of_file(php: &dyn PhpAnalysisSource, file: &ProjectFile) -> String {
    php.top_level_declarations(file)
        .into_iter()
        .next()
        .map(|unit| unit.package_name().to_string())
        .unwrap_or_default()
}

pub fn php_use_aliases_of(
    php: &dyn PhpAnalysisSource,
    file: &ProjectFile,
) -> HashMap<String, String> {
    php_use_aliases_by_kind_of(php, file).type_aliases
}

pub fn php_use_aliases_by_kind_of(
    php: &dyn PhpAnalysisSource,
    file: &ProjectFile,
) -> PhpUseAliases {
    let Ok(source) = php.project().read_source(file) else {
        return PhpUseAliases::default();
    };
    php_use_aliases_by_kind_from_source(&source)
}

pub fn php_use_aliases_by_kind_from_source(source: &str) -> PhpUseAliases {
    parse_php_use_aliases_from_source(source)
}

pub fn php_file_context_from_source(
    php: &dyn PhpAnalysisSource,
    file: &ProjectFile,
    source: &str,
) -> PhpFileContext {
    PhpFileContext {
        namespace: php_namespace_of_file(php, file),
        aliases: php_use_aliases_by_kind_from_source(source),
    }
}

fn php_declaration_context(php: &dyn PhpAnalysisSource, code_unit: &CodeUnit) -> PhpFileContext {
    let namespace = code_unit.package_name().to_string();
    let aliases = php_declaration_start(php, code_unit)
        .and_then(|start| php_aliases_visible_before_declaration(php, code_unit.source(), start))
        .unwrap_or_else(|| php_use_aliases_by_kind_of(php, code_unit.source()));
    PhpFileContext { namespace, aliases }
}

fn php_declaration_start(php: &dyn PhpAnalysisSource, code_unit: &CodeUnit) -> Option<usize> {
    php.ranges(code_unit)
        .iter()
        .map(|range| range.start_byte)
        .min()
}

fn php_aliases_visible_before_declaration(
    php: &dyn PhpAnalysisSource,
    file: &ProjectFile,
    declaration_start: usize,
) -> Option<PhpUseAliases> {
    let source = php.project().read_source(file).ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    Some(php_aliases_visible_before(
        tree.root_node(),
        &source,
        declaration_start,
    ))
}

pub fn php_is_interface(php: &dyn PhpAnalysisSource, code_unit: &CodeUnit) -> bool {
    if !code_unit.is_class() {
        return false;
    }
    if let Some(kind) = php_declaration_kind(php, code_unit) {
        return kind == "interface_declaration";
    }
    php.signatures(code_unit).iter().any(|signature| {
        signature
            .split_whitespace()
            .any(|token| token == "interface")
    })
}

pub fn php_is_trait(php: &dyn PhpAnalysisSource, code_unit: &CodeUnit) -> bool {
    code_unit.is_class()
        && php_declaration_kind(php, code_unit).is_some_and(|kind| kind == "trait_declaration")
}

pub fn php_resolve_declared_supertype(
    php: &dyn PhpAnalysisSource,
    code_unit: &CodeUnit,
    raw: &str,
) -> Option<CodeUnit> {
    let ctx = php_declaration_context(php, code_unit);
    let fq_name = resolve_php_type(raw, &ctx)?;
    php.definitions(&fq_name)
        .find(|candidate| candidate.is_class())
}

pub fn php_direct_declared_class_parent(
    php: &dyn PhpAnalysisSource,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    php.get_direct_ancestors(code_unit)
        .into_iter()
        .find(|ancestor| !php_is_interface(php, ancestor) && !php_is_trait(php, ancestor))
}

fn php_declaration_kind(php: &dyn PhpAnalysisSource, code_unit: &CodeUnit) -> Option<&'static str> {
    let source = php.project().read_source(code_unit.source()).ok()?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let ranges = php.ranges(code_unit);
    let start = ranges.iter().map(|range| range.start_byte).min()?;
    let end = ranges.iter().map(|range| range.end_byte).max()?;
    php_declaration_kind_for_range(tree.root_node(), start, end)
}

fn php_declaration_kind_for_range(
    root: Node<'_>,
    start: usize,
    end: usize,
) -> Option<&'static str> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "class_declaration" | "interface_declaration" | "trait_declaration"
        ) && node.start_byte() >= start
            && node.end_byte() <= end
        {
            return Some(node.kind());
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index)
                && child.end_byte() >= start
                && child.start_byte() <= end
            {
                stack.push(child);
            }
        }
    }
    None
}

fn php_aliases_visible_before(
    root: Node<'_>,
    source: &str,
    declaration_start: usize,
) -> PhpUseAliases {
    let namespace_scope = php_namespace_scope(root, declaration_start);
    let mut aliases = PhpUseAliases::default();
    let mut stack = vec![namespace_scope.unwrap_or(root)];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= declaration_start {
            continue;
        }
        if node.kind() == "namespace_use_declaration" {
            aliases.extend(parse_php_use_aliases_by_kind(
                &source[node.start_byte()..node.end_byte()],
            ));
            continue;
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    aliases
}

fn php_namespace_scope(root: Node<'_>, declaration_start: usize) -> Option<Node<'_>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "namespace_definition"
            && node.start_byte() <= declaration_start
            && declaration_start <= node.end_byte()
        {
            best = Some(node);
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    best
}

/// Files declaring the target's owning type or a descendant of it, plus every PHP file
/// whose `use` aliases name one of those types.
///
/// `analyzed_php_files` is a thunk rather than a slice: the whole-language file set is
/// only read once the target has a relevant owning type, and the caller's own composer
/// arm decides separately whether to pay for it.
pub fn php_import_alias_candidates(
    target: &CodeUnit,
    index: &dyn CodeUnitIndex,
    hierarchy: Option<&dyn TypeHierarchyProvider>,
    php: &dyn PhpAnalysisSource,
    analyzed_php_files: &dyn Fn() -> Vec<ProjectFile>,
) -> HashSet<ProjectFile> {
    let mut candidates = HashSet::default();
    let relevant_types = php_relevant_candidate_types(target, hierarchy, php);
    if relevant_types.is_empty() {
        return candidates;
    }
    for fq_name in &relevant_types {
        candidates.extend(
            index
                .definitions(fq_name)
                .filter(|unit| unit.is_class())
                .map(|unit| unit.source().clone()),
        );
    }
    for file in analyzed_php_files() {
        let aliases = php_use_aliases_by_kind_of(php, &file);
        if aliases
            .type_aliases
            .values()
            .any(|fq_name| relevant_types.contains(fq_name))
        {
            candidates.insert(file);
        }
    }
    candidates
}

fn php_relevant_candidate_types(
    target: &CodeUnit,
    hierarchy: Option<&dyn TypeHierarchyProvider>,
    php: &dyn PhpAnalysisSource,
) -> HashSet<String> {
    let mut types = HashSet::default();
    let owner = if target.is_class() {
        Some(target.clone())
    } else {
        php.parent_of(target)
    };
    let Some(owner) = owner else {
        return types;
    };
    types.insert(owner.fq_name());
    if let Some(provider) = hierarchy {
        types.extend(
            provider
                .get_descendants(&owner)
                .into_iter()
                .map(|unit| unit.fq_name()),
        );
    }
    types
}
