//! The language half of PHP's resolution logic: namespace identity, `use`
//! alias visibility, declaration-kind classification and supertype resolution,
//! written as free functions over a source trait instead of as methods on
//! `PhpAnalyzer`.
//!
//! `PhpAnalyzer` owns the one lazy cell PHP has (a moka cache of direct
//! ancestors) and implements [`PhpSource`] out of its own accessors, so
//! the functions below reach back for the memoized products they need without
//! naming the analyzer type.

use super::aliases::{PhpFileContext, PhpUseAliases, resolve_php_type};
use crate::source_facts::PhpSourceFactProvider;
use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
use brokk_bifrost_core::analyzer::php_facts::{PhpAliasKind, PhpDeclarationKind};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};

pub trait PhpSource: CodeUnitIndex + TypeHierarchyProvider + PhpSourceFactProvider {}

impl<T: CodeUnitIndex + TypeHierarchyProvider + PhpSourceFactProvider + ?Sized> PhpSource for T {}

pub fn php_is_constructor(method: &CodeUnit, class_unit: &CodeUnit, _package_name: &str) -> bool {
    method.is_function()
        && class_unit.is_class()
        && method.identifier() == "__construct"
        && method.fq_name() == format!("{}.__construct", class_unit.fq_name())
}

pub fn php_namespace_of_file(php: &dyn PhpSource, file: &ProjectFile) -> String {
    php.top_level_declarations(file)
        .into_iter()
        .next()
        .map(|unit| unit.package_name().to_string())
        .unwrap_or_default()
}

pub fn php_use_aliases_of(php: &dyn PhpSource, file: &ProjectFile) -> HashMap<String, String> {
    php_use_aliases_by_kind_of(php, file).type_aliases
}

pub fn php_use_aliases_by_kind_of(php: &dyn PhpSource, file: &ProjectFile) -> PhpUseAliases {
    let Some(source) = php.php_source_facts(file) else {
        return PhpUseAliases::default();
    };
    let mut aliases = PhpUseAliases::default();
    for alias in &source.facts.aliases {
        let map = match alias.kind {
            PhpAliasKind::Type => &mut aliases.type_aliases,
            PhpAliasKind::Function => &mut aliases.function_aliases,
            PhpAliasKind::Constant => &mut aliases.const_aliases,
        };
        let (local, target) = alias.binding(&source.imports);
        map.insert(local.to_owned(), target);
    }
    aliases
}

pub fn php_file_context_from_source(
    php: &dyn PhpSource,
    file: &ProjectFile,
    _source: &str,
) -> PhpFileContext {
    PhpFileContext {
        namespace: php_namespace_of_file(php, file),
        aliases: php_use_aliases_by_kind_of(php, file),
    }
}

fn php_declaration_context(php: &dyn PhpSource, code_unit: &CodeUnit) -> Option<PhpFileContext> {
    let source = php.php_source_facts(code_unit.source())?;
    let mut declarations = source.declarations_for(code_unit);
    let first = declarations.next()?;
    let context = &source.facts.contexts[first.context.index()];
    if declarations
        .any(|declaration| &source.facts.contexts[declaration.context.index()] != context)
    {
        return None;
    }
    let mut aliases = PhpUseAliases::default();
    for id in &context.aliases {
        let alias = &source.facts.aliases[*id as usize];
        let map = match alias.kind {
            PhpAliasKind::Type => &mut aliases.type_aliases,
            PhpAliasKind::Function => &mut aliases.function_aliases,
            PhpAliasKind::Constant => &mut aliases.const_aliases,
        };
        let (local, target) = alias.binding(&source.imports);
        map.insert(local.to_owned(), target);
    }
    Some(PhpFileContext {
        namespace: context.namespace.clone(),
        aliases,
    })
}

pub fn php_is_interface(php: &dyn PhpSource, code_unit: &CodeUnit) -> bool {
    php_declaration_kind(php, code_unit) == Some(PhpDeclarationKind::Interface)
}

pub fn php_is_trait(php: &dyn PhpSource, code_unit: &CodeUnit) -> bool {
    php_declaration_kind(php, code_unit) == Some(PhpDeclarationKind::Trait)
}

pub fn php_resolve_declared_supertype(
    php: &dyn PhpSource,
    code_unit: &CodeUnit,
    raw: &str,
) -> Option<CodeUnit> {
    let ctx = php_declaration_context(php, code_unit)?;
    let fq_name = resolve_php_type(raw, &ctx)?;
    php.definitions(&fq_name)
        .find(|candidate| candidate.is_class())
}

pub fn php_direct_declared_class_parent(
    php: &dyn PhpSource,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    php.get_direct_ancestors(code_unit)
        .into_iter()
        .find(|ancestor| !php_is_interface(php, ancestor) && !php_is_trait(php, ancestor))
}

fn php_declaration_kind(php: &dyn PhpSource, unit: &CodeUnit) -> Option<PhpDeclarationKind> {
    if !unit.is_class() {
        return None;
    }
    let source = php.php_source_facts(unit.source())?;
    let mut declarations = source.declarations_for(unit);
    let kind = declarations.next()?.kind;
    declarations
        .all(|declaration| declaration.kind == kind)
        .then_some(kind)
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
    php: &dyn PhpSource,
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
    php: &dyn PhpSource,
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
