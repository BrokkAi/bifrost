use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::cpp_call_match::{
    CppArgType, cpp_signature_param_types, cpp_split_top_level_commas, normalize_cpp_type_name,
};
use crate::analyzer::usages::cpp_graph::extractor::ScanCtx;
use crate::analyzer::usages::local_inference::LocalInferenceEngine;
use crate::analyzer::{
    CallableArity, CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, IncludeTargetIndex, ProjectFile,
    cpp_include_paths, cpp_node_text as node_text, normalize_cpp_whitespace,
    recovered_exported_class_has_body, resolve_analyzer, resolve_include_targets_with_index,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::hash::Hash;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tree_sitter::{Node, Parser};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::analyzer::usages) enum TargetKind {
    Type,
    Constructor,
    FreeFunction,
    Method,
    GlobalField,
    MemberField,
}

pub(super) enum LexicalTypeResolution {
    Resolved {
        unit: CodeUnit,
        components: Vec<String>,
        candidates: Vec<CodeUnit>,
    },
    Ambiguous,
    Missing,
}

pub(super) enum LexicalCallableValueResolution {
    Type(CodeUnit),
    FreeFunction(CodeUnit),
    Ambiguous,
    Missing,
}

pub(super) enum UsingEnumMemberResolution {
    Resolved { owner: CodeUnit, member: CodeUnit },
    Ambiguous,
    Missing,
}

pub(super) enum NamespaceValueResolution {
    Resolved,
    Ambiguous,
    Missing,
}

pub(super) fn resolve_namespace_value(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    namespace: &str,
    name: &str,
    before_byte: usize,
) -> NamespaceValueResolution {
    let mut matches = Vec::new();
    for candidate in visibility.visible_identifier_candidates(file, name) {
        if type_owner_of(analyzer, candidate).is_some()
            || candidate.package_name() != namespace
            || (candidate.source() == file
                && !analyzer
                    .ranges(candidate)
                    .iter()
                    .any(|range| range.start_byte < before_byte))
            || matches
                .iter()
                .any(|existing| same_visible_symbol(existing, candidate))
        {
            continue;
        }
        matches.push(candidate.clone());
        if matches.len() > 1 {
            return NamespaceValueResolution::Ambiguous;
        }
    }
    matches
        .pop()
        .map(|_| NamespaceValueResolution::Resolved)
        .unwrap_or(NamespaceValueResolution::Missing)
}

pub(super) struct ScopedUsingEnumOwners {
    scopes: Vec<Vec<CodeUnit>>,
}

/// Same-file class and namespace imports collected by the targeted scanner's AST prepass.
/// Cross-file and inherited class imports are deliberately not inferred without persisted
/// evidence; a missing imported enumerator therefore remains unproven rather than being
/// misresolved.
pub(super) struct SemanticUsingEnumOwners {
    class_imports: HashMap<CodeUnit, Vec<CodeUnit>>,
    namespace_imports: HashMap<Vec<String>, Vec<(usize, CodeUnit)>>,
}

pub(super) enum SemanticUsingEnumMemberResolution {
    Class(UsingEnumMemberResolution),
    Namespace(UsingEnumMemberResolution),
    Missing,
}

impl SemanticUsingEnumOwners {
    pub(super) fn new() -> Self {
        Self {
            class_imports: HashMap::default(),
            namespace_imports: HashMap::default(),
        }
    }

    pub(super) fn import_class(&mut self, class: CodeUnit, enum_owner: CodeUnit) {
        let imports = self.class_imports.entry(class).or_default();
        if !imports
            .iter()
            .any(|existing| same_visible_symbol(existing, &enum_owner))
        {
            imports.push(enum_owner);
        }
    }

    pub(super) fn import_namespace(
        &mut self,
        namespace: Vec<String>,
        declaration_byte: usize,
        enum_owner: CodeUnit,
    ) {
        let imports = self.namespace_imports.entry(namespace).or_default();
        if !imports
            .iter()
            .any(|(_, existing)| same_visible_symbol(existing, &enum_owner))
        {
            imports.push((declaration_byte, enum_owner));
        }
    }

    pub(super) fn resolve_member(
        &self,
        visibility: &VisibilityIndex,
        file: &ProjectFile,
        class: Option<&CodeUnit>,
        namespace: &[String],
        before_byte: usize,
        name: &str,
    ) -> SemanticUsingEnumMemberResolution {
        if let Some(class) = class
            && let Some((_, imports)) = self
                .class_imports
                .iter()
                .find(|(owner, _)| same_visible_symbol(owner, class))
        {
            let resolution =
                resolve_using_enum_member_for_owners(visibility, file, imports.iter(), name);
            if !matches!(resolution, UsingEnumMemberResolution::Missing) {
                return SemanticUsingEnumMemberResolution::Class(resolution);
            }
        }
        for prefix_len in (0..=namespace.len()).rev() {
            let Some(imports) = self.namespace_imports.get(&namespace[..prefix_len]) else {
                continue;
            };
            let owners = imports
                .iter()
                .filter(|(declaration_byte, _)| *declaration_byte < before_byte)
                .map(|(_, owner)| owner);
            let resolution = resolve_using_enum_member_for_owners(visibility, file, owners, name);
            if !matches!(resolution, UsingEnumMemberResolution::Missing) {
                return SemanticUsingEnumMemberResolution::Namespace(resolution);
            }
        }
        SemanticUsingEnumMemberResolution::Missing
    }
}

fn resolve_using_enum_member_for_owners<'a>(
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    owners: impl IntoIterator<Item = &'a CodeUnit>,
    name: &str,
) -> UsingEnumMemberResolution {
    let mut matches: Vec<(CodeUnit, CodeUnit)> = Vec::new();
    for owner in owners {
        for member in visibility.visible_members_for_owner_name(file, owner, name) {
            if !member.is_field()
                || matches.iter().any(|(existing_owner, existing_member)| {
                    same_visible_symbol(existing_owner, owner)
                        && same_visible_symbol(existing_member, member)
                })
            {
                continue;
            }
            matches.push((owner.clone(), member.clone()));
        }
    }
    match matches.len() {
        0 => UsingEnumMemberResolution::Missing,
        1 => {
            let (owner, member) = matches.pop().expect("one using-enum match");
            UsingEnumMemberResolution::Resolved { owner, member }
        }
        _ => UsingEnumMemberResolution::Ambiguous,
    }
}

impl ScopedUsingEnumOwners {
    pub(super) fn new() -> Self {
        Self {
            scopes: vec![Vec::new()],
        }
    }

    pub(super) fn enter_scope(&mut self) {
        self.scopes.push(Vec::new());
    }

    pub(super) fn exit_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    pub(super) fn import(&mut self, owner: CodeUnit) {
        let scope = self
            .scopes
            .last_mut()
            .expect("using-enum scope stack is never empty");
        if !scope
            .iter()
            .any(|existing| same_visible_symbol(existing, &owner))
        {
            scope.push(owner);
        }
    }

    pub(super) fn resolve_member(
        &self,
        visibility: &VisibilityIndex,
        file: &ProjectFile,
        name: &str,
    ) -> UsingEnumMemberResolution {
        for scope in self.scopes.iter().rev() {
            let resolution =
                resolve_using_enum_member_for_owners(visibility, file, scope.iter(), name);
            if !matches!(resolution, UsingEnumMemberResolution::Missing) {
                return resolution;
            }
        }
        UsingEnumMemberResolution::Missing
    }
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner: Option<CodeUnit>,
    pub(super) member_name: String,
    pub(super) callable_arity: Option<CallableArity>,
    pub(super) param_types: Option<Vec<String>>,
    pub(super) enum_owner_kind: EnumOwnerKind,
    pub(super) owner_is_forward_declaration: bool,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct TypeScanKey {
    target: LogicalSymbolKey,
    member_name: String,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct LogicalSymbolKey {
    kind: CodeUnitType,
    fq_name: String,
    signature: Option<String>,
}

struct ResolvedTypeOwner {
    unit: CodeUnit,
    is_forward_declaration: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum EnumOwnerKind {
    Scoped,
    Unscoped,
    NonEnum,
}

impl TargetSpec {
    pub(super) fn type_scan_key(&self) -> Option<TypeScanKey> {
        (self.kind == TargetKind::Type).then(|| TypeScanKey {
            target: logical_symbol_key(&self.target),
            member_name: self.member_name.clone(),
        })
    }

    pub(super) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self::new(
                target.clone(),
                TargetKind::Type,
                Some(target.clone()),
                target.identifier().to_string(),
                None,
                None,
            ));
        }

        if target.is_field() {
            // A namespace (module) is not a receiver: a namespace-scoped constant such as
            // `example::DefaultPrefix` is referenced unqualified from inside the namespace and
            // qualified from outside, exactly like a global. Treating a module owner as a
            // member-field owner makes the receiver/owner-context match reject every valid
            // reference, so resolve it as a global field instead.
            let owner = type_owner_of(analyzer, target);
            let kind = if owner.is_some() {
                TargetKind::MemberField
            } else {
                TargetKind::GlobalField
            };
            let enum_owner_kind = owner
                .as_ref()
                .map(|owner| classify_enum_owner(analyzer, owner))
                .unwrap_or(EnumOwnerKind::NonEnum);
            let mut spec = Self::new(
                target.clone(),
                kind,
                owner,
                target.identifier().to_string(),
                None,
                None,
            );
            spec.enum_owner_kind = enum_owner_kind;
            return Some(spec);
        }

        if target.is_function() {
            // Free functions declared inside a namespace have a module owner; that namespace is
            // not a call receiver, so resolve them as free functions rather than methods.
            let owner_resolution = type_owner_resolution(analyzer, target);
            let owner_is_forward_declaration = owner_resolution
                .as_ref()
                .is_some_and(|owner| owner.is_forward_declaration);
            let owner = owner_resolution.map(|owner| owner.unit);
            let kind = if owner
                .as_ref()
                .is_some_and(|owner| target.identifier() == owner.identifier())
            {
                TargetKind::Constructor
            } else if owner.is_some() {
                TargetKind::Method
            } else {
                TargetKind::FreeFunction
            };
            let mut spec = Self::new(
                target.clone(),
                kind,
                owner,
                target.identifier().to_string(),
                Some(cpp_callable_arity(analyzer, target)),
                target.signature().and_then(cpp_signature_param_types),
            );
            spec.owner_is_forward_declaration = owner_is_forward_declaration;
            return Some(spec);
        }

        None
    }

    pub(super) fn new(
        target: CodeUnit,
        kind: TargetKind,
        owner: Option<CodeUnit>,
        member_name: String,
        callable_arity: Option<CallableArity>,
        param_types: Option<Vec<String>>,
    ) -> Self {
        Self {
            target,
            kind,
            owner,
            member_name,
            callable_arity,
            param_types,
            enum_owner_kind: EnumOwnerKind::NonEnum,
            owner_is_forward_declaration: false,
        }
    }
}

fn logical_symbol_key(unit: &CodeUnit) -> LogicalSymbolKey {
    LogicalSymbolKey {
        kind: unit.kind(),
        fq_name: unit.fq_name(),
        signature: unit.signature().map(str::to_string),
    }
}

fn classify_enum_owner(analyzer: &dyn IAnalyzer, owner: &CodeUnit) -> EnumOwnerKind {
    let classify = |source: &str| {
        let source = source.trim_start();
        if source.starts_with("enum class ") || source.starts_with("enum struct ") {
            Some(EnumOwnerKind::Scoped)
        } else if source.starts_with("enum ") {
            Some(EnumOwnerKind::Unscoped)
        } else {
            None
        }
    };
    owner
        .signature()
        .and_then(classify)
        .or_else(|| {
            analyzer
                .get_source(owner, false)
                .as_deref()
                .and_then(classify)
        })
        .unwrap_or(EnumOwnerKind::NonEnum)
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct CppScanBinding {
    pub(super) unit: Option<CodeUnit>,
    pub(super) type_name: Option<String>,
    pub(super) indirection: i32,
}

impl CppScanBinding {
    pub(super) fn from_unit(unit: CodeUnit, indirection: i32) -> Self {
        Self {
            type_name: Some(cpp_name_for(&unit)),
            unit: Some(unit),
            indirection,
        }
    }

    pub(super) fn from_type_name(
        type_name: String,
        unit: Option<CodeUnit>,
        indirection: i32,
    ) -> Self {
        Self {
            type_name: Some(type_name),
            unit,
            indirection,
        }
    }

    pub(super) fn as_arg_type(&self) -> Option<CppArgType> {
        let name = self
            .type_name
            .clone()
            .or_else(|| self.unit.as_ref().map(cpp_name_for))?;
        Some(CppArgType {
            name,
            unit: self.unit.clone(),
            indirection: self.indirection,
        })
    }
}

type AliasCell = Arc<OnceLock<Box<[CppAlias]>>>;

pub(in crate::analyzer::usages) struct VisibilityIndex {
    pub(super) visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    visible_by_identifier: HashMap<ProjectFile, HashMap<String, Vec<CodeUnit>>>,
    visible_source_files_by_root: HashMap<ProjectFile, HashSet<ProjectFile>>,
    alias_cells: Mutex<HashMap<ProjectFile, AliasCell>>,
    #[cfg(test)]
    alias_source_parse_counts: Mutex<HashMap<ProjectFile, usize>>,
    field_type_facts: Mutex<HashMap<CodeUnit, Option<DeclaredFieldTypeFact>>>,
    structured_alias_targets: Mutex<HashMap<CodeUnit, Option<StructuredAliasTarget>>>,
    #[cfg(test)]
    qualified_candidate_inspections: AtomicUsize,
}

#[derive(Clone)]
struct DeclaredFieldTypeFact {
    type_text: String,
    indirection: i32,
}

#[derive(Clone)]
enum StructuredAliasTarget {
    Builtin,
    Named {
        components: Vec<String>,
        global: bool,
    },
}

struct CppAlias {
    name: String,
    target: String,
    namespace: Option<String>,
}

type ReceiverResolver<'a> = dyn for<'tree> Fn(Node<'tree>, &str) -> Vec<CodeUnit> + 'a;

impl VisibilityIndex {
    pub(in crate::analyzer::usages) fn build(
        cpp: &CppAnalyzer,
        analyzer: &dyn IAnalyzer,
        roots: &HashSet<ProjectFile>,
    ) -> Self {
        Self::build_with_cancellation(cpp, analyzer, roots, None)
    }

    pub(in crate::analyzer::usages) fn build_with_cancellation(
        cpp: &CppAnalyzer,
        analyzer: &dyn IAnalyzer,
        roots: &HashSet<ProjectFile>,
        cancellation: Option<&CancellationToken>,
    ) -> Self {
        let include_targets = cpp.include_target_index();
        let VisibilityData {
            visible_by_file,
            visible_source_files_by_root,
        } = build_visibility_data(
            roots,
            cancellation,
            |file| {
                let imports = analyzer.import_statements(file);
                cpp_include_paths(&imports)
                    .into_iter()
                    .flat_map(|include| {
                        resolve_include_targets_with_index(file, &include, include_targets)
                    })
                    .collect()
            },
            |file| analyzer.declarations(file),
        );
        let visible_by_identifier = build_visible_identifier_index(&visible_by_file);
        Self {
            visible_by_file,
            visible_by_identifier,
            visible_source_files_by_root,
            alias_cells: Mutex::new(HashMap::default()),
            #[cfg(test)]
            alias_source_parse_counts: Mutex::new(HashMap::default()),
            field_type_facts: Mutex::new(HashMap::default()),
            structured_alias_targets: Mutex::new(HashMap::default()),
            #[cfg(test)]
            qualified_candidate_inspections: AtomicUsize::new(0),
        }
    }

    pub(in crate::analyzer::usages) fn is_visible(
        &self,
        file: &ProjectFile,
        target: &CodeUnit,
    ) -> bool {
        file == target.source()
            || self
                .visible_by_file
                .get(file)
                .is_some_and(|visible| visible.iter().any(|unit| same_visible_symbol(unit, target)))
    }

    pub(super) fn is_physically_visible(&self, file: &ProjectFile, target: &CodeUnit) -> bool {
        file == target.source()
            || self
                .visible_by_file
                .get(file)
                .is_some_and(|visible| visible.contains(target))
    }

    pub(in crate::analyzer::usages) fn resolve_type(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        self.type_candidates(file, &normalized)
            .into_iter()
            .next()
            .cloned()
    }

    pub(super) fn resolve_type_components_lexically(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
    ) -> LexicalTypeResolution {
        if components.is_empty() {
            return LexicalTypeResolution::Missing;
        }
        for qualified in lexical_component_tiers(components, global, lexical_scope) {
            let qualified_name = qualified.join("::");
            let candidates = self
                .type_candidates(file, &qualified_name)
                .into_iter()
                .filter(|candidate| cpp_name_for(candidate) == qualified_name)
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                continue;
            }
            let Some(unit) = self.unique_canonical_type_candidate(analyzer, file, &candidates)
            else {
                return LexicalTypeResolution::Ambiguous;
            };
            return LexicalTypeResolution::Resolved {
                unit,
                components: qualified,
                candidates: candidates.into_iter().cloned().collect(),
            };
        }
        LexicalTypeResolution::Missing
    }

    pub(super) fn resolve_callable_value_components_lexically(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        owner_components: &[String],
        member_name: &str,
        global: bool,
        lexical_scope: &[String],
    ) -> LexicalCallableValueResolution {
        if owner_components.is_empty() || member_name.is_empty() {
            return LexicalCallableValueResolution::Missing;
        }
        for qualified_owner in lexical_component_tiers(owner_components, global, lexical_scope) {
            let owner_name = qualified_owner.join("::");
            let type_candidates = self
                .type_candidates(file, &owner_name)
                .into_iter()
                .filter(|candidate| cpp_name_for(candidate) == owner_name)
                .collect::<Vec<_>>();
            let resolved_type = if type_candidates.is_empty() {
                None
            } else {
                let Some(unit) =
                    self.unique_canonical_type_candidate(analyzer, file, &type_candidates)
                else {
                    return LexicalCallableValueResolution::Ambiguous;
                };
                Some(unit)
            };

            let mut qualified_callable = qualified_owner;
            qualified_callable.push(member_name.to_string());
            let callable_name = qualified_callable.join("::");
            let free_function = self
                .named_candidates_for_normalized(file, &callable_name, TargetKind::FreeFunction)
                .into_iter()
                .find(|candidate| {
                    cpp_name_for(candidate) == callable_name
                        && type_owner_of(analyzer, candidate).is_none()
                })
                .cloned();

            match (resolved_type, free_function) {
                (Some(_), Some(_)) => return LexicalCallableValueResolution::Ambiguous,
                (Some(owner), None) => return LexicalCallableValueResolution::Type(owner),
                (None, Some(function)) => {
                    return LexicalCallableValueResolution::FreeFunction(function);
                }
                (None, None) => {}
            }
        }
        LexicalCallableValueResolution::Missing
    }

    fn resolve_type_for_declaration(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        if !normalized.contains("::")
            && let Some(namespace) = cpp_namespace_for(declaration)
        {
            for prefix in namespace_prefixes(&namespace) {
                let qualified = format!("{prefix}::{normalized}");
                if let Some(unit) = self
                    .type_candidates(visible_from, &qualified)
                    .into_iter()
                    .next()
                {
                    return Some(unit.clone());
                }
            }
        }
        self.resolve_type(visible_from, raw_name)
    }

    fn resolve_unique_canonical_type_for_declaration(
        &self,
        analyzer: &dyn IAnalyzer,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        let mut current =
            self.resolve_unique_type_for_declaration(visible_from, declaration, raw_name)?;
        let mut seen_aliases = HashSet::default();
        loop {
            let Some(target) = self.structured_alias_target(analyzer, &current) else {
                return current.is_class().then_some(current);
            };
            if matches!(target, StructuredAliasTarget::Builtin) {
                return current.is_class().then_some(current);
            }
            if !seen_aliases.insert(current.clone()) {
                return None;
            }
            current = self.resolve_structured_alias_target(visible_from, &current, &target)?;
        }
    }

    pub(super) fn canonical_type_unit(
        &self,
        analyzer: &dyn IAnalyzer,
        visible_from: &ProjectFile,
        unit: &CodeUnit,
    ) -> Option<CodeUnit> {
        let mut current = unit.clone();
        let mut seen_aliases = HashSet::default();
        loop {
            let Some(target) = self.structured_alias_target(analyzer, &current) else {
                return current.is_class().then_some(current);
            };
            if matches!(target, StructuredAliasTarget::Builtin) {
                return current.is_class().then_some(current);
            }
            if !seen_aliases.insert(current.clone()) {
                return None;
            }
            current = self.resolve_structured_alias_target(visible_from, &current, &target)?;
        }
    }

    fn resolve_structured_alias_target(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        target: &StructuredAliasTarget,
    ) -> Option<CodeUnit> {
        let StructuredAliasTarget::Named { components, global } = target else {
            return None;
        };
        let qualified = components.join("::");
        if *global {
            return unique_logical_type_candidate(self.type_candidates(visible_from, &qualified));
        }
        self.resolve_unique_type_for_declaration(visible_from, declaration, &qualified)
    }

    fn unique_canonical_type_candidate(
        &self,
        analyzer: &dyn IAnalyzer,
        visible_from: &ProjectFile,
        candidates: &[&CodeUnit],
    ) -> Option<CodeUnit> {
        let mut canonical = Vec::new();
        for candidate in candidates {
            let resolved = self.canonical_type_unit(analyzer, visible_from, candidate)?;
            if canonical
                .iter()
                .any(|existing| same_visible_symbol(existing, &resolved))
            {
                continue;
            }
            canonical.push(resolved);
            if canonical.len() > 1 {
                return None;
            }
        }
        canonical.pop()
    }

    fn resolve_unique_type_for_declaration(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        if !normalized.contains("::")
            && let Some(namespace) = cpp_namespace_for(declaration)
        {
            for prefix in namespace_prefixes(&namespace) {
                let qualified = format!("{prefix}::{normalized}");
                let candidates = self.type_candidates(visible_from, &qualified);
                if !candidates.is_empty() {
                    return unique_logical_type_candidate(candidates);
                }
            }
        }
        unique_logical_type_candidate(self.type_candidates(visible_from, &normalized))
    }

    pub(super) fn resolves_to_type(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        raw_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return false;
        };
        let candidates = self.type_candidates(file, &normalized);
        if candidates.is_empty() {
            return self.parser_alias_resolves_to_type(analyzer, file, raw_name, target);
        }
        let mut canonical_candidates = Vec::new();
        for candidate in candidates {
            let resolved = if same_visible_symbol(candidate, target) {
                candidate.clone()
            } else {
                let Some(canonical) = self.canonical_type_unit(analyzer, file, candidate) else {
                    return false;
                };
                canonical
            };
            if !canonical_candidates
                .iter()
                .any(|existing| same_visible_symbol(existing, &resolved))
            {
                canonical_candidates.push(resolved);
                if canonical_candidates.len() > 1 {
                    return false;
                }
            }
        }
        let Some(canonical) = canonical_candidates.pop() else {
            return false;
        };
        same_symbol(&canonical, target) || same_visible_symbol(&canonical, target)
    }

    pub(super) fn alias_target(&self, alias: &CodeUnit) -> Option<CodeUnit> {
        let raw_target = type_alias_target_text(alias)?;
        let resolved = self.resolve_type_for_declaration(alias.source(), alias, raw_target)?;
        match resolved.kind() {
            CodeUnitType::Class => Some(resolved),
            _ if is_type_alias(&resolved) => self.alias_target(&resolved),
            _ => None,
        }
    }

    pub(super) fn canonical_type_for_reference(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        let resolved = self.resolve_type(file, raw_name)?;
        self.alias_target(&resolved).or(Some(resolved))
    }

    pub(super) fn parser_alias_resolves_to_type(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        raw_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let Some(alias_name) = normalize_reference_name(raw_name) else {
            return false;
        };
        let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
            return false;
        };
        let matches_file = |source_file: &ProjectFile| {
            self.file_alias_matches(cpp, source_file, &alias_name, target)
        };
        self.visible_source_files_by_root.get(file).map_or_else(
            || matches_file(file),
            |files| files.iter().any(matches_file),
        )
    }

    fn file_alias_matches(
        &self,
        cpp: &CppAnalyzer,
        file: &ProjectFile,
        alias_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let cell = {
            let mut cells = self.alias_cells.lock().expect("alias cell map lock");
            Arc::clone(
                cells
                    .entry(file.clone())
                    .or_insert_with(|| Arc::new(OnceLock::new())),
            )
        };
        cell.get_or_init(|| {
            #[cfg(test)]
            {
                *self
                    .alias_source_parse_counts
                    .lock()
                    .expect("alias source parse count lock")
                    .entry(file.clone())
                    .or_default() += 1;
            }
            aliases_from_prepared_source(cpp, file).into_boxed_slice()
        })
        .iter()
        .any(|alias| alias.name == alias_name && alias_target_matches_target(alias, target))
    }

    #[cfg(test)]
    pub(super) fn visible_source_files_for_test(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        self.visible_source_files_by_root
            .get(file)
            .cloned()
            .unwrap_or_else(|| HashSet::from_iter([file.clone()]))
    }

    #[cfg(test)]
    pub(super) fn alias_source_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.alias_source_parse_counts
            .lock()
            .expect("alias source parse count lock")
            .get(file)
            .copied()
            .unwrap_or(0)
    }

    pub(in crate::analyzer::usages) fn resolve_named(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        self.named_candidates_for_normalized(file, &normalized, kind)
            .into_iter()
            .next()
            .cloned()
    }

    pub(super) fn contains_named_symbol(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
        target: &CodeUnit,
    ) -> bool {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return false;
        };
        self.named_candidates_for_normalized(file, &normalized, kind)
            .into_iter()
            .any(|unit| {
                matches_kind_for_lookup(unit, kind)
                    && reference_matches_unit(&normalized, unit)
                    && same_visible_symbol(unit, target)
            })
    }

    pub(super) fn named_candidates(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
    ) -> Vec<CodeUnit> {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return Vec::new();
        };
        self.named_candidates_for_normalized(file, &normalized, kind)
            .into_iter()
            .cloned()
            .collect()
    }

    pub(super) fn resolve_known_non_target(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
        target: &CodeUnit,
    ) -> bool {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return false;
        };
        normalized.contains("::")
            && self
                .named_candidates_for_normalized(file, &normalized, kind)
                .into_iter()
                .any(|unit| {
                    matches_kind_for_lookup(unit, kind)
                        && reference_matches_unit(&normalized, unit)
                        && !same_visible_symbol(unit, target)
                })
    }

    pub(super) fn resolve_call_return_binding(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        raw_name: &str,
        arity: usize,
        lexical_namespace: Option<&str>,
    ) -> Option<CppScanBinding> {
        let normalized = normalize_reference_name(raw_name)?;
        let mut candidates = Vec::new();
        for function in
            self.named_candidates_for_normalized(file, &normalized, TargetKind::FreeFunction)
        {
            if cpp_callable_arity(analyzer, function).accepts(arity) {
                candidates.push(function.clone());
            }
        }
        if !normalized.contains("::")
            && let Some(namespace) = lexical_namespace
        {
            let scoped: Vec<_> = candidates
                .iter()
                .filter(|function| cpp_namespace_for(function).as_deref() == Some(namespace))
                .cloned()
                .collect();
            if !scoped.is_empty() {
                candidates = scoped;
            }
        }
        unanimous_return_binding(analyzer, self, file, &candidates)
    }

    pub(in crate::analyzer::usages) fn visible_identifier_candidates<'b>(
        &'b self,
        file: &ProjectFile,
        identifier: &str,
    ) -> impl Iterator<Item = &'b CodeUnit> + 'b {
        self.visible_by_identifier
            .get(file)
            .and_then(|by_name| by_name.get(identifier))
            .into_iter()
            .flatten()
    }

    pub(in crate::analyzer::usages) fn type_name_candidates<'b>(
        &'b self,
        file: &ProjectFile,
        normalized: &str,
    ) -> Vec<&'b CodeUnit> {
        self.candidate_units(file, normalized, TargetKind::Type)
    }

    pub(super) fn visible_members_for_owner_name<'b>(
        &'b self,
        file: &ProjectFile,
        owner: &CodeUnit,
        name: &str,
    ) -> Vec<&'b CodeUnit> {
        self.visible_identifier_candidates(file, name)
            .filter(|unit| {
                unit.fq_name()
                    .rsplit_once('.')
                    .is_some_and(|(parent, _)| parent == owner.fq_name())
            })
            .collect()
    }

    pub(super) fn visible_member_for_owner_name(
        &self,
        file: &ProjectFile,
        owner: &CodeUnit,
        name: &str,
    ) -> VisibleMemberResolution {
        let candidates = self.visible_members_for_owner_name(file, owner, name);
        let mut callables = Vec::new();
        let mut non_callable = None;
        for candidate in candidates {
            if candidate.is_function() {
                callables.push(candidate.clone());
            } else if non_callable.is_none() {
                non_callable = Some(candidate.clone());
            }
        }
        match (callables.is_empty(), non_callable) {
            (false, None) => VisibleMemberResolution::Callable(callables),
            (true, Some(_)) => VisibleMemberResolution::NonCallable,
            (false, Some(_)) => VisibleMemberResolution::AmbiguousKind,
            (true, None) => VisibleMemberResolution::Missing,
        }
    }

    fn field_declared_type_fact(
        &self,
        analyzer: &dyn IAnalyzer,
        field: &CodeUnit,
    ) -> Option<DeclaredFieldTypeFact> {
        if let Some(cached) = self
            .field_type_facts
            .lock()
            .expect("C++ field type fact cache poisoned")
            .get(field)
            .cloned()
        {
            return cached;
        }
        let decoded = decode_field_declared_type_fact(analyzer, field);
        self.field_type_facts
            .lock()
            .expect("C++ field type fact cache poisoned")
            .insert(field.clone(), decoded.clone());
        decoded
    }

    fn structured_alias_target(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<StructuredAliasTarget> {
        if let Some(cached) = self
            .structured_alias_targets
            .lock()
            .expect("C++ structured alias target cache poisoned")
            .get(unit)
            .cloned()
        {
            return cached;
        }
        let decoded = decode_structured_alias_target(analyzer, unit);
        self.structured_alias_targets
            .lock()
            .expect("C++ structured alias target cache poisoned")
            .insert(unit.clone(), decoded.clone());
        decoded
    }

    fn type_candidates<'b>(&'b self, file: &ProjectFile, normalized: &str) -> Vec<&'b CodeUnit> {
        let mut candidates = self
            .candidate_units(file, normalized, TargetKind::Type)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class || is_type_alias(unit))
            .collect::<Vec<_>>();
        dedup_unit_refs(&mut candidates);
        candidates
    }

    fn named_candidates_for_normalized<'b>(
        &'b self,
        file: &ProjectFile,
        normalized: &str,
        kind: TargetKind,
    ) -> Vec<&'b CodeUnit> {
        let mut candidates = self
            .candidate_units(file, normalized, kind)
            .into_iter()
            .filter(|unit| {
                matches_kind_for_lookup(unit, kind) && reference_matches_unit(normalized, unit)
            })
            .collect::<Vec<_>>();
        dedup_unit_refs(&mut candidates);
        candidates
    }

    fn candidate_units<'b>(
        &'b self,
        file: &ProjectFile,
        normalized: &str,
        kind: TargetKind,
    ) -> Vec<&'b CodeUnit> {
        if normalized.contains("::") {
            let Some(identifier) = normalized
                .rsplit("::")
                .find(|component| !component.is_empty())
            else {
                return Vec::new();
            };
            let fqns = cpp_reference_fqn_candidates(normalized, kind);
            return self
                .visible_identifier_candidates(file, identifier)
                .filter(|unit| {
                    #[cfg(test)]
                    self.qualified_candidate_inspections
                        .fetch_add(1, Ordering::Relaxed);
                    fqns.iter().any(|fqn| unit.fq_name() == *fqn)
                })
                .collect();
        }
        self.visible_identifier_candidates(file, normalized)
            .collect()
    }

    #[cfg(test)]
    fn reset_qualified_candidate_inspections(&self) {
        self.qualified_candidate_inspections
            .store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn qualified_candidate_inspections(&self) -> usize {
        self.qualified_candidate_inspections.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct IncludeGraph {
    targets_by_file: HashMap<ProjectFile, Vec<ProjectFile>>,
}

impl IncludeGraph {
    fn extend_with<F>(
        &mut self,
        root: &ProjectFile,
        cancellation: Option<&CancellationToken>,
        targets_for: &mut F,
    ) where
        F: FnMut(&ProjectFile) -> Vec<ProjectFile>,
    {
        let mut stack = vec![root.clone()];
        while let Some(file) = stack.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                break;
            }
            if self.targets_by_file.contains_key(&file) {
                continue;
            }
            let targets = targets_for(&file);
            stack.extend(targets.iter().cloned());
            self.targets_by_file.insert(file, targets);
        }
    }

    fn files(&self) -> impl Iterator<Item = &ProjectFile> {
        self.targets_by_file.keys()
    }

    fn targets(&self, file: &ProjectFile) -> &[ProjectFile] {
        self.targets_by_file
            .get(file)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

struct VisibilityData {
    visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    visible_source_files_by_root: HashMap<ProjectFile, HashSet<ProjectFile>>,
}

fn build_visibility_data<F, D>(
    roots: &HashSet<ProjectFile>,
    cancellation: Option<&CancellationToken>,
    mut targets_for: F,
    mut declarations_for: D,
) -> VisibilityData
where
    F: FnMut(&ProjectFile) -> Vec<ProjectFile>,
    D: FnMut(&ProjectFile) -> BTreeSet<CodeUnit>,
{
    let mut include_graph = IncludeGraph::default();
    for file in roots {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        include_graph.extend_with(file, cancellation, &mut targets_for);
    }
    let declarations_by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>> = include_graph
        .files()
        .take_while(|_| !cancellation.is_some_and(CancellationToken::is_cancelled))
        .map(|file| (file.clone(), declarations_for(file)))
        .collect();
    let mut visible_by_file = HashMap::default();
    let mut visible_source_files_by_root = HashMap::default();
    for file in roots {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        let mut visited = HashSet::default();
        let mut visible = HashSet::default();
        collect_visible_declarations(
            &include_graph,
            &declarations_by_file,
            file,
            &mut visited,
            &mut visible,
            cancellation,
        );
        visible_by_file.insert(file.clone(), visible);
        visible_source_files_by_root.insert(file.clone(), visited);
    }
    VisibilityData {
        visible_by_file,
        visible_source_files_by_root,
    }
}

pub(super) enum VisibleMemberResolution {
    Callable(Vec<CodeUnit>),
    NonCallable,
    AmbiguousKind,
    Missing,
}

#[derive(Clone)]
pub(super) enum EnclosingMemberOwnerResolution {
    Owner(CodeUnit),
    Ambiguous,
    Missing,
}

pub(super) fn resolve_enclosing_member_owner(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    enclosing_owner: &CodeUnit,
    member_name: &str,
) -> EnclosingMemberOwnerResolution {
    let Some(hierarchy) = analyzer.type_hierarchy_provider() else {
        return EnclosingMemberOwnerResolution::Missing;
    };
    let resolve_level = |frontier: &[CodeUnit]| {
        let mut member_owners = Vec::new();
        for owner in frontier {
            for member in visibility.visible_members_for_owner_name(file, owner, member_name) {
                let Some(member_owner) = type_owner_of(analyzer, member) else {
                    return EnclosingMemberOwnerResolution::Ambiguous;
                };
                if !member_owners
                    .iter()
                    .any(|existing| same_visible_symbol(existing, &member_owner))
                {
                    member_owners.push(member_owner);
                }
            }
        }
        match member_owners.len() {
            0 => EnclosingMemberOwnerResolution::Missing,
            1 => EnclosingMemberOwnerResolution::Owner(member_owners.pop().unwrap()),
            _ => EnclosingMemberOwnerResolution::Ambiguous,
        }
    };
    let direct = resolve_level(std::slice::from_ref(enclosing_owner));
    if !matches!(direct, EnclosingMemberOwnerResolution::Missing) {
        return direct;
    }
    let mut stack = hierarchy.get_direct_ancestors(enclosing_owner);
    let mut propagated_counts: HashMap<CodeUnit, u8> = HashMap::default();
    let mut path_matches = Vec::new();
    while let Some(owner) = stack.pop() {
        // Persisted hierarchy edges do not encode virtual-base or base-subobject paths.
        // Propagate at most two occurrences of each owner: that preserves the distinction
        // between one and multiple resolving base paths without exponential diamond walks.
        let propagated = propagated_counts.entry(owner.clone()).or_default();
        if *propagated == 2 {
            continue;
        }
        *propagated += 1;
        match resolve_level(std::slice::from_ref(&owner)) {
            EnclosingMemberOwnerResolution::Owner(owner) => {
                path_matches.push(owner);
                if path_matches.len() == 2 {
                    return EnclosingMemberOwnerResolution::Ambiguous;
                }
            }
            EnclosingMemberOwnerResolution::Ambiguous => {
                return EnclosingMemberOwnerResolution::Ambiguous;
            }
            EnclosingMemberOwnerResolution::Missing => {
                stack.extend(hierarchy.get_direct_ancestors(&owner));
            }
        }
    }
    match path_matches.len() {
        0 => EnclosingMemberOwnerResolution::Missing,
        1 => EnclosingMemberOwnerResolution::Owner(path_matches.pop().unwrap()),
        _ => unreachable!("base-path matches are capped at one before returning"),
    }
}

fn lexical_component_tiers<'a>(
    components: &'a [String],
    global: bool,
    lexical_scope: &'a [String],
) -> impl Iterator<Item = Vec<String>> + 'a {
    let first_prefix_len = if global { 0 } else { lexical_scope.len() };
    (0..=first_prefix_len).rev().map(move |prefix_len| {
        let mut qualified = Vec::with_capacity(prefix_len + components.len());
        qualified.extend_from_slice(&lexical_scope[..prefix_len]);
        qualified.extend_from_slice(components);
        qualified
    })
}

fn build_visible_identifier_index(
    visible_by_file: &HashMap<ProjectFile, HashSet<CodeUnit>>,
) -> HashMap<ProjectFile, HashMap<String, Vec<CodeUnit>>> {
    let mut out = HashMap::default();
    for (file, visible) in visible_by_file {
        let mut by_identifier: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for unit in visible {
            by_identifier
                .entry(unit.identifier().to_string())
                .or_default()
                .push(unit.clone());
        }
        for units in by_identifier.values_mut() {
            sort_lookup_units(units);
            units.dedup();
        }
        out.insert(file.clone(), by_identifier);
    }
    out
}

fn sort_lookup_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        left.fq_name()
            .cmp(&right.fq_name())
            .then_with(|| left.signature().cmp(&right.signature()))
            .then_with(|| left.source().cmp(right.source()))
    });
}

fn dedup_unit_refs(units: &mut Vec<&CodeUnit>) {
    let mut deduped = Vec::with_capacity(units.len());
    for unit in units.drain(..) {
        if !deduped.contains(&unit) {
            deduped.push(unit);
        }
    }
    *units = deduped;
}

pub(in crate::analyzer::usages) fn cpp_reference_fqn_candidates(
    reference: &str,
    kind: TargetKind,
) -> Vec<String> {
    let parts = reference
        .split("::")
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    for package_len in 0..parts.len() {
        let package = parts[..package_len].join("::");
        let rest = &parts[package_len..];
        if rest.is_empty() {
            continue;
        }
        match kind {
            TargetKind::Type | TargetKind::Constructor => {
                push_cpp_fqn_candidate(&mut candidates, &package, &rest.join("$"));
                push_cpp_fqn_candidate(&mut candidates, &package, &rest.join("."));
            }
            TargetKind::FreeFunction
            | TargetKind::Method
            | TargetKind::GlobalField
            | TargetKind::MemberField => {
                push_cpp_fqn_candidate(&mut candidates, &package, &rest.join("."));
                if rest.len() > 1 {
                    let owner = rest[..rest.len() - 1].join("$");
                    let short = format!("{}.{}", owner, rest[rest.len() - 1]);
                    push_cpp_fqn_candidate(&mut candidates, &package, &short);
                }
            }
        }
    }
    candidates
}

fn push_cpp_fqn_candidate(out: &mut Vec<String>, package: &str, short: &str) {
    let fqn = if package.is_empty() {
        short.to_string()
    } else {
        format!("{package}.{short}")
    };
    if !out.contains(&fqn) {
        out.push(fqn);
    }
}

pub(in crate::analyzer::usages) fn infer_cpp_initializer_type(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    infer_cpp_initializer_binding(analyzer, visibility, file, source, node, None)
        .and_then(|binding| binding.unit)
}

pub(super) fn infer_cpp_initializer_binding(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    receiver_resolver: Option<&ReceiverResolver<'_>>,
) -> Option<CppScanBinding> {
    match node.kind() {
        "new_expression" => {
            let text = normalize_cpp_whitespace(node_text(node, source));
            let rest = text.strip_prefix("new ").unwrap_or(text.as_str());
            let type_text = rest.split(['(', '{']).next().unwrap_or(rest);
            let name = normalize_cpp_type_name(type_text);
            Some(CppScanBinding::from_type_name(
                name.clone(),
                visibility.resolve_type(file, &name),
                1,
            ))
        }
        "call_expression" => node.child_by_field_name("function").and_then(|function| {
            let function_text = node_text(function, source);
            resolve_static_method_call_return_binding(
                analyzer,
                visibility,
                file,
                source,
                function,
                call_arity(node),
            )
            .or_else(|| {
                visibility
                    .resolve_type(file, function_text)
                    .map(|unit| CppScanBinding::from_unit(unit, 0))
            })
            .or_else(|| {
                visibility.resolve_call_return_binding(
                    analyzer,
                    file,
                    function_text,
                    call_arity(node),
                    enclosing_namespace_context(node, source).as_deref(),
                )
            })
            .or_else(|| {
                resolve_field_method_call_return_binding(
                    analyzer,
                    visibility,
                    file,
                    source,
                    function,
                    call_arity(node),
                    receiver_resolver,
                )
            })
        }),
        _ => None,
    }
}

fn resolve_static_method_call_return_binding(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    arity: usize,
) -> Option<CppScanBinding> {
    if function.kind() != "qualified_identifier" {
        return None;
    }
    let qualified = normalize_cpp_reference_text(node_text(function, source));
    let (owner_text, member_name) = qualified.rsplit_once("::").or_else(|| {
        let scope = function.child_by_field_name("scope")?;
        let name = function.child_by_field_name("name")?;
        Some((node_text(scope, source), node_text(name, source)))
    })?;
    let owner = visibility.resolve_type(file, owner_text)?;
    let candidates = visibility
        .visible_members_for_owner_name(file, &owner, member_name)
        .into_iter()
        .filter(|unit| unit.is_function() && cpp_callable_arity(analyzer, unit).accepts(arity))
        .cloned()
        .collect::<Vec<_>>();
    unanimous_return_binding(analyzer, visibility, file, &candidates)
}

fn resolve_field_method_call_return_binding(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    arity: usize,
    receiver_resolver: Option<&ReceiverResolver<'_>>,
) -> Option<CppScanBinding> {
    if function.kind() != "field_expression" {
        return None;
    }
    let receiver_resolver = receiver_resolver?;
    let field = function.child_by_field_name("field")?;
    let member_name = node_text(field, source);
    let receiver = function
        .child_by_field_name("argument")
        .or_else(|| function.named_child(0))?;
    let owners = receiver_resolver(receiver, source);
    let mut candidates = Vec::new();
    for owner in owners {
        candidates.extend(
            visibility
                .visible_members_for_owner_name(file, &owner, member_name)
                .into_iter()
                .filter(|unit| {
                    unit.is_function() && cpp_callable_arity(analyzer, unit).accepts(arity)
                })
                .cloned(),
        );
    }
    unanimous_return_binding(analyzer, visibility, file, &candidates)
}

fn unanimous_return_binding(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    candidates: &[CodeUnit],
) -> Option<CppScanBinding> {
    let mut resolved_return: Option<CppScanBinding> = None;
    for function in candidates {
        let metadata = analyzer.signature_metadata(function);
        let return_types = if metadata.is_empty() {
            vec![cpp_function_return_type_text(analyzer, function)?]
        } else {
            metadata
                .iter()
                .map(|metadata| metadata.return_type_text().map(str::to_string))
                .collect::<Option<Vec<_>>>()?
        };
        for return_text in return_types {
            let indirection =
                crate::analyzer::usages::cpp_call_match::cpp_type_text_pointer_depth(&return_text);
            let name = normalize_cpp_type_name(&return_text);
            let binding = CppScanBinding::from_type_name(
                name.clone(),
                visibility
                    .resolve_unique_canonical_type_for_declaration(analyzer, file, function, &name),
                indirection,
            );
            if let Some(existing) = resolved_return.as_ref()
                && (existing.indirection != binding.indirection
                    || match (&existing.unit, &binding.unit) {
                        (Some(left), Some(right)) => !same_visible_symbol(left, right),
                        (None, None) => existing.type_name != binding.type_name,
                        (Some(_), None) | (None, Some(_)) => true,
                    })
            {
                return None;
            }
            resolved_return = Some(binding);
        }
    }
    resolved_return
}

fn aliases_from_prepared_source(cpp: &CppAnalyzer, file: &ProjectFile) -> Vec<CppAlias> {
    let Some(prepared) = cpp.prepared_syntax(file) else {
        return Vec::new();
    };
    let mut aliases = Vec::new();
    collect_cpp_aliases(prepared.tree().root_node(), prepared.source(), &mut aliases);
    aliases
}

fn collect_cpp_aliases(root: Node<'_>, source: &str, out: &mut Vec<CppAlias>) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "alias_declaration" if alias_has_visible_file_scope(node) => {
                if let Some(alias) = cpp_alias_from_alias_declaration(node, source) {
                    out.push(alias);
                }
            }
            "type_definition" if alias_has_visible_file_scope(node) => {
                collect_typedef_aliases(node, source, out)
            }
            _ => {}
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn alias_has_visible_file_scope(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "translation_unit"
            | "namespace_definition"
            | "declaration_list"
            | "linkage_specification" => current = parent.parent(),
            "template_declaration" => current = parent.parent(),
            _ => return false,
        }
    }
    true
}

fn cpp_alias_from_alias_declaration(node: Node<'_>, source: &str) -> Option<CppAlias> {
    let name = node
        .child_by_field_name("name")
        .and_then(|node| normalize_reference_name(node_text(node, source)))?;
    let target = node
        .child_by_field_name("type")
        .and_then(|node| normalize_reference_name(node_text(node, source)))?;
    Some(CppAlias {
        name,
        target,
        namespace: enclosing_namespace_context(node, source),
    })
}

fn collect_typedef_aliases(node: Node<'_>, source: &str, out: &mut Vec<CppAlias>) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(target) = normalize_reference_name(node_text(type_node, source)) else {
        return;
    };

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if same_node(child, type_node) {
            continue;
        }
        if let Some(name) = extract_typedef_declarator_name(child, source) {
            out.push(CppAlias {
                name,
                target: target.clone(),
                namespace: enclosing_namespace_context(node, source),
            });
        }
    }
}

fn extract_typedef_declarator_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "qualified_identifier" => {
            normalize_reference_name(node_text(node, source))
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(|child| extract_typedef_declarator_name(child, source)),
    }
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

pub(super) fn collect_include_closure(
    analyzer: &dyn IAnalyzer,
    include_targets: &IncludeTargetIndex,
    file: &ProjectFile,
    out: &mut HashSet<ProjectFile>,
    cancellation: Option<&CancellationToken>,
) {
    let mut stack = vec![file.clone()];
    while let Some(file) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        if !out.insert(file.clone()) {
            continue;
        }
        let imports = analyzer.import_statements(&file);
        for include in cpp_include_paths(&imports) {
            for target in resolve_include_targets_with_index(&file, &include, include_targets) {
                stack.push(target);
            }
        }
    }
}

fn collect_visible_declarations(
    include_graph: &IncludeGraph,
    declarations_by_file: &HashMap<ProjectFile, BTreeSet<CodeUnit>>,
    file: &ProjectFile,
    visited: &mut HashSet<ProjectFile>,
    out: &mut HashSet<CodeUnit>,
    cancellation: Option<&CancellationToken>,
) {
    let mut stack = vec![file.clone()];
    while let Some(file) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        if !visited.insert(file.clone()) {
            continue;
        }
        if let Some(declarations) = declarations_by_file.get(&file) {
            out.extend(declarations.iter().cloned());
        }
        stack.extend(include_graph.targets(&file).iter().cloned());
    }
}

pub(in crate::analyzer::usages) fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .find('(')
        .and_then(|open| {
            signature[open + 1..]
                .find(')')
                .map(|close| &signature[open + 1..open + 1 + close])
        })
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() || inner == "void" {
        return 0;
    }
    cpp_split_top_level_commas(inner).count()
}

pub(super) fn cpp_callable_arity(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> CallableArity {
    analyzer
        .signature_metadata(unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| CallableArity::exact(signature_arity(unit.signature())))
}

pub(in crate::analyzer::usages) fn call_arity(node: Node<'_>) -> usize {
    node.child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("parameters"))
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| first_named_child_of_kind(node, "argument_list"))
        .or_else(|| first_named_child_of_kind(node, "initializer_list"))
        .map(|args| args.named_child_count())
        .unwrap_or(0)
}

pub(in crate::analyzer::usages) fn constructor_type_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "new_expression" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0)),
        "compound_literal_expression" => node.child_by_field_name("type"),
        "call_expression" => node.child_by_field_name("function"),
        _ => None,
    }
}

pub(super) fn field_initializer_constructs_target(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(name) = node
        .child_by_field_name("name")
        .or_else(|| first_named_child_of_kind(node, "field_identifier"))
        .or_else(|| first_named_child_of_kind(node, "qualified_identifier"))
    else {
        return false;
    };
    let field_name = node_text(name, ctx.source);
    ctx.visibility
        .visible_identifier_candidates(ctx.file, field_name)
        .filter(|unit| unit.is_field() && unit.identifier() == field_name)
        .any(|unit| field_declares_type(unit, ctx, owner))
}

fn field_declares_type(unit: &CodeUnit, ctx: &ScanCtx<'_>, owner: &CodeUnit) -> bool {
    unit.signature()
        .is_some_and(|declaration| field_declaration_type_matches(declaration, unit, ctx, owner))
        || ctx
            .analyzer
            .get_source(unit, false)
            .is_some_and(|declaration| {
                field_declaration_type_matches(&declaration, unit, ctx, owner)
            })
}

pub(super) fn field_declared_binding(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    visible_from: &ProjectFile,
    field: &CodeUnit,
) -> Option<CppScanBinding> {
    let fact = visibility.field_declared_type_fact(analyzer, field)?;
    let normalized = normalize_field_type_text(&fact.type_text);
    let resolved = visibility.resolve_unique_canonical_type_for_declaration(
        analyzer,
        visible_from,
        field,
        &normalized,
    );
    Some(CppScanBinding::from_type_name(
        normalized,
        resolved,
        fact.indirection,
    ))
}

fn type_alias_target_text(alias: &CodeUnit) -> Option<&str> {
    alias
        .signature()?
        .strip_prefix("using ")
        .and_then(|rest| rest.split_once('=').map(|(_, rhs)| rhs))
        .or_else(|| {
            alias
                .signature()?
                .strip_prefix("typedef ")
                .and_then(|rest| rest.rsplit_once(' ').map(|(lhs, _)| lhs))
        })
        .map(str::trim)
        .map(|target| target.trim_end_matches(';').trim())
}

fn unique_logical_type_candidate(candidates: Vec<&CodeUnit>) -> Option<CodeUnit> {
    let first = candidates.first()?;
    candidates
        .iter()
        .all(|candidate| candidate.kind() == first.kind() && candidate.fq_name() == first.fq_name())
        .then(|| (*first).clone())
}

pub(in crate::analyzer::usages) fn field_declared_type_text(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    field: &CodeUnit,
) -> Option<(String, i32)> {
    let fact = visibility.field_declared_type_fact(analyzer, field)?;
    Some((fact.type_text, fact.indirection))
}

fn decode_field_declared_type_fact(
    analyzer: &dyn IAnalyzer,
    field: &CodeUnit,
) -> Option<DeclaredFieldTypeFact> {
    let declaration = analyzer.get_source(field, false)?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(&declaration, None)?;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "declaration" | "field_declaration")
            && let Some(type_node) = node
                .child_by_field_name("type")
                .or_else(|| first_type_child(node))
            && let Some(indirection) =
                declared_name_indirection(node, type_node, field.identifier(), &declaration)
        {
            return Some(DeclaredFieldTypeFact {
                type_text: node_text(type_node, &declaration).to_string(),
                indirection,
            });
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

fn decode_structured_alias_target(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<StructuredAliasTarget> {
    let declaration = analyzer.get_source(unit, false)?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(&declaration, None)?;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let type_node = match node.kind() {
            "type_definition" => {
                if node
                    .parent()
                    .is_none_or(|parent| parent.kind() != "translation_unit")
                {
                    let mut cursor = node.walk();
                    stack.extend(node.named_children(&mut cursor));
                    continue;
                }
                let mut declarator_cursor = node.walk();
                let declares_unit = node
                    .children_by_field_name("declarator", &mut declarator_cursor)
                    .any(|declarator| {
                        extract_typedef_declarator_name(declarator, &declaration)
                            .is_some_and(|name| name == unit.identifier())
                    });
                declares_unit.then(|| node.child_by_field_name("type"))??
            }
            "alias_declaration" => {
                if node
                    .parent()
                    .is_none_or(|parent| parent.kind() != "translation_unit")
                {
                    let mut cursor = node.walk();
                    stack.extend(node.named_children(&mut cursor));
                    continue;
                }
                let name = node.child_by_field_name("name")?;
                (node_text(name, &declaration) == unit.identifier())
                    .then(|| node.child_by_field_name("type"))??
            }
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
                continue;
            }
        };
        return structured_alias_type_target(type_node, &declaration);
    }
    None
}

fn structured_alias_type_target(
    mut type_node: Node<'_>,
    source: &str,
) -> Option<StructuredAliasTarget> {
    while type_node.kind() == "type_descriptor" {
        type_node = type_node.child_by_field_name("type")?;
    }
    if type_node.kind() == "primitive_type" {
        return Some(StructuredAliasTarget::Builtin);
    }
    if matches!(
        type_node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
    ) {
        type_node = type_node.child_by_field_name("name")?;
    }
    let global = type_node.child_by_field_name("scope").is_none()
        && type_node.child(0).is_some_and(|child| child.kind() == "::");
    let mut components = Vec::new();
    append_structured_type_components(type_node, source, &mut components)?;
    (!components.is_empty()).then_some(StructuredAliasTarget::Named { components, global })
}

fn append_structured_type_components(
    node: Node<'_>,
    source: &str,
    out: &mut Vec<String>,
) -> Option<()> {
    match node.kind() {
        "identifier" | "namespace_identifier" | "type_identifier" => {
            out.push(node_text(node, source).to_string());
            Some(())
        }
        "template_type" => {
            append_structured_type_components(node.child_by_field_name("name")?, source, out)
        }
        "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
            if let Some(scope) = node.child_by_field_name("scope") {
                append_structured_type_components(scope, source, out)?;
            }
            append_structured_type_components(node.child_by_field_name("name")?, source, out)
        }
        _ => None,
    }
}

fn declared_name_indirection(
    declaration: Node<'_>,
    type_node: Node<'_>,
    field_name: &str,
    source: &str,
) -> Option<i32> {
    let mut stack = Vec::new();
    let mut cursor = declaration.walk();
    stack.extend(
        declaration
            .named_children(&mut cursor)
            .filter(|child| !same_node(*child, type_node)),
    );
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "identifier" | "field_identifier")
            && node_text(node, source) == field_name
        {
            let mut indirection = 0;
            let mut current = node.parent();
            while let Some(parent) = current {
                if same_node(parent, declaration) {
                    return Some(indirection);
                }
                if parent.kind() == "pointer_declarator" {
                    indirection += 1;
                }
                current = parent.parent();
            }
            return None;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

fn field_declaration_type_matches(
    declaration: &str,
    unit: &CodeUnit,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    ctx.visibility
        .resolves_to_type(ctx.analyzer, ctx.file, declaration, owner)
        || field_type_prefix(declaration, unit.identifier()).is_some_and(|type_text| {
            let normalized = normalize_field_type_text(type_text);
            ctx.visibility
                .resolves_to_type(ctx.analyzer, ctx.file, type_text, owner)
                || ctx.visibility.resolves_to_type(
                    ctx.analyzer,
                    ctx.file,
                    normalized.as_str(),
                    owner,
                )
        })
}

fn field_type_prefix<'a>(declaration: &'a str, field_name: &str) -> Option<&'a str> {
    let declaration = declaration
        .split(['=', ';'])
        .next()
        .unwrap_or(declaration)
        .trim();
    let index = declaration.rfind(field_name)?;
    let before = &declaration[..index];
    let after = &declaration[index + field_name.len()..];
    if before.chars().next_back().is_some_and(is_identifier_char)
        || after.chars().next().is_some_and(is_identifier_char)
    {
        return None;
    }
    Some(before.trim())
}

fn normalize_field_type_text(type_text: &str) -> String {
    const FIELD_SPECIFIERS: [&str; 8] = [
        "extern ",
        "static ",
        "mutable ",
        "constexpr ",
        "constinit ",
        "inline ",
        "volatile ",
        "const ",
    ];

    let mut normalized = normalize_type_text(type_text);
    loop {
        let Some(stripped) = FIELD_SPECIFIERS
            .iter()
            .find_map(|specifier| normalized.strip_prefix(specifier))
        else {
            return normalized;
        };
        normalized = normalize_type_text(stripped);
    }
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

pub(super) fn declaration_mentions_type(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(type_node) = node.child_by_field_name("type") else {
        return false;
    };
    ctx.visibility.resolves_to_type(
        ctx.analyzer,
        ctx.file,
        node_text(type_node, ctx.source),
        owner,
    )
}

pub(super) fn declaration_is_object_construction_candidate(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> bool {
    !ctx.analyzer
        .declarations(ctx.file)
        .into_iter()
        .filter(|unit| unit.is_function())
        .any(|unit| {
            ctx.analyzer.ranges(&unit).iter().any(|range| {
                node.start_byte() <= range.start_byte && range.end_byte <= node.end_byte()
            })
        })
}

pub(super) fn declaration_constructor_arity(node: Node<'_>, _ctx: &ScanCtx<'_>) -> usize {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "init_declarator" {
            return child
                .child_by_field_name("value")
                .or_else(|| first_named_child_of_kind(child, "initializer_list"))
                .or_else(|| first_named_child_of_kind(child, "compound_literal_expression"))
                .map(declaration_init_value_arity)
                .unwrap_or(0);
        }
        if is_declarator_node(child) {
            return declaration_declarator_arity(child);
        }
    }
    0
}

fn declaration_init_value_arity(value: Node<'_>) -> usize {
    match value.kind() {
        "argument_list" | "initializer_list" => count_non_comment_named_children(value),
        "compound_literal_expression" => call_arity(value),
        _ => 1,
    }
}

fn declaration_declarator_arity(node: Node<'_>) -> usize {
    if let Some(parameters) = node.child_by_field_name("parameters") {
        return count_non_comment_named_children(parameters);
    }
    node.child_by_field_name("declarator")
        .map(declaration_declarator_arity)
        .unwrap_or(0)
}

fn count_non_comment_named_children(node: Node<'_>) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .count()
}

fn first_named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

pub(in crate::analyzer::usages) fn extract_variable_name(
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" => {
            let name = node_text(node, source).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))
            .and_then(|child| extract_variable_name(child, source)),
    }
}

pub(in crate::analyzer::usages) fn is_declarator_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier"
            | "field_identifier"
            | "pointer_declarator"
            | "reference_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "function_declarator"
    )
}

/// Aggregate-owner proof for a structurally recognized designated initializer.
pub(in crate::analyzer::usages) enum DesignatedInitializerOwner {
    Resolved(CodeUnit),
    Unresolved,
}

/// Recognize a designated-initializer field and, when possible, resolve its
/// aggregate owner.
///
/// Covers both the grammar's ordinary `field_designator` shape and the exact
/// recovery used for `.field = value` after a preprocessor-split array
/// initializer. Nested aggregate levels are deliberately left unresolved unless
/// the single outer level is the containing array initializer: resolving those
/// would require following the enclosing field's declared type. `None` means the
/// node is not a designator at all; an unresolved designator remains classified so
/// callers cannot fall through to unrelated global/member heuristics.
pub(in crate::analyzer::usages) fn designated_initializer_owner(
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<DesignatedInitializerOwner> {
    if let Some(designator) = node
        .parent()
        .filter(|parent| parent.kind() == "field_designator")
    {
        let pair = designator.parent()?;
        if pair.kind() != "initializer_pair"
            || pair.child_by_field_name("designator") != Some(designator)
        {
            return None;
        }
        let initializer = pair.parent()?;
        if initializer.kind() != "initializer_list" {
            return None;
        }
        return Some(classified_designated_owner(initializer_list_owner(
            visibility,
            file,
            source,
            initializer,
        )));
    }

    let init_declarator = node.parent()?;
    if init_declarator.child_by_field_name("declarator") != Some(node)
        || !crate::analyzer::cpp::structural::is_recovered_designator_init_declarator(
            init_declarator,
        )
    {
        return None;
    }
    Some(classified_designated_owner(declaration_owner(
        visibility,
        file,
        source,
        init_declarator.parent()?,
    )))
}

fn classified_designated_owner(owner: Option<CodeUnit>) -> DesignatedInitializerOwner {
    owner.map_or(
        DesignatedInitializerOwner::Unresolved,
        DesignatedInitializerOwner::Resolved,
    )
}

fn initializer_list_owner(
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    initializer: Node<'_>,
) -> Option<CodeUnit> {
    let mut current = initializer;
    let mut outer_initializer_lists = 0usize;
    loop {
        let parent = current.parent()?;
        match parent.kind() {
            "initializer_pair" => return None,
            "initializer_list" => {
                outer_initializer_lists += 1;
                if outer_initializer_lists > 1 {
                    return None;
                }
                current = parent;
            }
            "init_declarator" if parent.child_by_field_name("value") == Some(current) => {
                let declaration = parent.parent()?;
                if outer_initializer_lists == 1
                    && !parent
                        .child_by_field_name("declarator")
                        .is_some_and(contains_array_declarator)
                {
                    return None;
                }
                return declaration_owner(visibility, file, source, declaration);
            }
            "compound_literal_expression"
                if parent.child_by_field_name("value") == Some(current)
                    && outer_initializer_lists == 0 =>
            {
                let type_node = parent.child_by_field_name("type")?;
                return resolve_designated_owner_type(visibility, file, source, type_node);
            }
            "ERROR" => current = parent,
            _ => return None,
        }
    }
}

fn declaration_owner(
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    declaration: Node<'_>,
) -> Option<CodeUnit> {
    if !matches!(declaration.kind(), "declaration" | "field_declaration") {
        return None;
    }
    let type_node = declaration
        .child_by_field_name("type")
        .or_else(|| first_type_child(declaration))?;
    resolve_designated_owner_type(visibility, file, source, type_node)
}

fn resolve_designated_owner_type(
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<CodeUnit> {
    let type_name = normalize_type_text(node_text(type_node, source));
    visibility
        .resolve_type(file, &type_name)
        .filter(CodeUnit::is_class)
}

fn contains_array_declarator(declarator: Node<'_>) -> bool {
    let mut stack = vec![declarator];
    while let Some(node) = stack.pop() {
        if node.kind() == "array_declarator" {
            return true;
        }
        if matches!(node.kind(), "initializer_list" | "compound_statement") {
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

pub(super) fn recovered_macro_function_return_type(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "namespace_identifier" {
        return None;
    }
    let qualified = node.parent()?;
    if qualified.kind() != "qualified_identifier"
        || qualified.child_by_field_name("scope") != Some(node)
    {
        return None;
    }
    let mut cursor = qualified.walk();
    if !qualified
        .children(&mut cursor)
        .any(|child| child.kind() == "::" && child.is_missing())
    {
        return None;
    }
    let function = qualified.parent()?;
    if function.kind() != "function_definition"
        || function.child_by_field_name("declarator") != Some(qualified)
    {
        return None;
    }

    let mut declarator = qualified.child_by_field_name("name")?;
    loop {
        match declarator.kind() {
            "function_declarator" => return Some(node),
            "pointer_declarator" | "pointer_type_declarator" | "reference_declarator" => {
                declarator = declarator.child_by_field_name("declarator")?;
            }
            _ => return None,
        }
    }
}

pub(in crate::analyzer::usages) fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "type_identifier"
                | "primitive_type"
                | "qualified_identifier"
                | "scoped_type_identifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
        )
    })
}

pub(in crate::analyzer::usages) fn constructor_style_local_declaration<T: Clone + Eq + Hash>(
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    declarator: Node<'_>,
    type_text: Option<&str>,
    bindings: &LocalInferenceEngine<T>,
) -> bool {
    if !has_ancestor_kind(declarator, "compound_statement") {
        return false;
    }
    if declarator
        .child_by_field_name("declarator")
        .is_none_or(|declarator| declarator.kind() != "identifier")
    {
        return false;
    }
    if !type_text
        .and_then(|text| visibility.resolve_type(file, text))
        .is_some_and(|unit| unit.is_class())
    {
        return false;
    }
    declarator
        .child_by_field_name("parameters")
        .is_some_and(|parameters| {
            constructor_parameters_look_like_expressions(parameters, source, bindings)
        })
}

fn constructor_parameters_look_like_expressions<T: Clone + Eq + Hash>(
    parameters: Node<'_>,
    source: &str,
    bindings: &LocalInferenceEngine<T>,
) -> bool {
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        !matches!(
            parameter.kind(),
            "parameter_declaration" | "optional_parameter_declaration"
        ) || parameter_declaration_is_local_expression(parameter, source, bindings)
    })
}

fn parameter_declaration_is_local_expression<T: Clone + Eq + Hash>(
    parameter: Node<'_>,
    source: &str,
    bindings: &LocalInferenceEngine<T>,
) -> bool {
    let text = node_text(parameter, source).trim();
    text.chars()
        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !bindings.resolve_symbol(text).is_unknown()
}

pub(in crate::analyzer::usages) fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if matches!(
        parent.kind(),
        "class_specifier"
            | "struct_specifier"
            | "union_specifier"
            | "enum_specifier"
            | "namespace_definition"
            | "namespace_alias_definition"
            | "alias_declaration"
            | "enumerator"
    ) && parent
        .child_by_field_name("name")
        .is_some_and(|name| same_node(name, node))
    {
        return true;
    }

    let mut current = Some(parent);
    while let Some(ancestor) = current {
        let type_definition = ancestor.kind() == "type_definition";
        if ancestor
            .child_by_field_name("declarator")
            .is_some_and(|declarator| {
                declarator_name_path_contains(declarator, node, type_definition)
            })
        {
            return true;
        }
        if matches!(
            ancestor.kind(),
            "declaration"
                | "field_declaration"
                | "parameter_declaration"
                | "optional_parameter_declaration"
                | "function_definition"
                | "type_definition"
                | "alias_declaration"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
        ) {
            return false;
        }
        current = ancestor.parent();
    }
    false
}

pub(super) fn declarator_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier"
        | "field_identifier"
        | "qualified_identifier"
        | "scoped_identifier"
        | "operator_name"
        | "destructor_name"
        | "literal_operator_name" => Some(node),
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("field"))
            .and_then(declarator_name_node),
    }
}

fn declarator_name_path_contains(
    declarator: Node<'_>,
    candidate: Node<'_>,
    allow_type_identifier: bool,
) -> bool {
    let Some(name) = declarator_name_leaf(declarator, allow_type_identifier) else {
        return false;
    };
    let mut current = Some(declarator);
    while let Some(node) = current {
        if same_node(node, candidate) {
            return true;
        }
        if same_node(node, name) {
            return false;
        }
        current = node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("field"));
    }
    false
}

fn declarator_name_leaf(node: Node<'_>, allow_type_identifier: bool) -> Option<Node<'_>> {
    match node.kind() {
        "identifier"
        | "field_identifier"
        | "operator_name"
        | "destructor_name"
        | "literal_operator_name" => Some(node),
        "type_identifier" if allow_type_identifier => Some(node),
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("field"))
            .and_then(|child| declarator_name_leaf(child, allow_type_identifier)),
    }
}

/// True when `node` is a component of a larger structured type node whose outer
/// range is the single reference surfaced to callers.
pub(super) fn is_nested_type_node(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "qualified_identifier" | "scoped_type_identifier" | "template_type"
        )
    })
}

pub(super) struct OutOfLineMemberDefinitionOwners<'tree> {
    pub(super) owners: Vec<(Node<'tree>, CodeUnit)>,
    innermost: Option<(Node<'tree>, CodeUnit)>,
}

impl OutOfLineMemberDefinitionOwners<'_> {
    pub(super) fn innermost(&self) -> Option<(Node<'_>, &CodeUnit)> {
        self.innermost.as_ref().map(|(node, owner)| (*node, owner))
    }
}

pub(super) fn out_of_line_member_definition_owner<'tree>(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'tree>,
) -> Option<OutOfLineMemberDefinitionOwners<'tree>> {
    if !matches!(node.kind(), "qualified_identifier" | "scoped_identifier")
        || !has_ancestor_kind(node, "function_definition")
        || !is_function_declarator_name_root(node)
    {
        return None;
    }
    let mut component_nodes = cpp_name_component_nodes(node)?;
    component_nodes.pop()?;
    if component_nodes.is_empty() {
        return None;
    }
    let components = component_nodes
        .iter()
        .map(|component| node_text(*component, source).to_string())
        .collect::<Vec<_>>();
    let global = is_globally_qualified_cpp_name(node);
    let lexical_scope = enclosing_namespace_components(node, source)?;
    let mut owners = Vec::new();
    let mut innermost = None;
    for component_count in 1..=components.len() {
        if let LexicalTypeResolution::Resolved { unit, .. } = visibility
            .resolve_type_components_lexically(
                analyzer,
                file,
                &components[..component_count],
                global,
                &lexical_scope,
            )
            && !owners
                .iter()
                .any(|(_, existing)| same_visible_symbol(existing, &unit))
        {
            if component_count == components.len() {
                innermost = Some((component_nodes[component_count - 1], unit.clone()));
            }
            owners.push((component_nodes[component_count - 1], unit));
        }
    }
    (!owners.is_empty()).then_some(OutOfLineMemberDefinitionOwners { owners, innermost })
}

fn is_function_declarator_name_root(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_declarator" {
            return parent.child_by_field_name("declarator") == Some(current);
        }
        if matches!(
            parent.kind(),
            "pointer_declarator" | "reference_declarator" | "parenthesized_declarator"
        ) && parent.child_by_field_name("declarator") == Some(current)
        {
            current = parent;
            continue;
        }
        return false;
    }
    false
}

pub(super) fn append_cpp_name_components(
    node: Node<'_>,
    source: &str,
    out: &mut Vec<String>,
) -> Option<()> {
    out.extend(
        cpp_name_component_nodes(node)?
            .into_iter()
            .map(|component| node_text(component, source).to_string()),
    );
    Some(())
}

fn cpp_name_component_nodes(node: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut components = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "operator_name"
            | "destructor_name" => components.push(current),
            "template_type" | "template_function" => {
                stack.push(current.child_by_field_name("name")?);
            }
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
                stack.push(current.child_by_field_name("name")?);
                if let Some(scope) = current.child_by_field_name("scope") {
                    stack.push(scope);
                }
            }
            "nested_namespace_specifier" => {
                for index in (0..current.named_child_count()).rev() {
                    stack.push(current.named_child(index)?);
                }
            }
            _ => return None,
        }
    }
    Some(components)
}

pub(super) fn is_globally_qualified_cpp_name(node: Node<'_>) -> bool {
    node.child_by_field_name("scope").is_none()
        && node.child(0).is_some_and(|child| child.kind() == "::")
}

fn enclosing_namespace_components(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut namespaces = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_definition"
            && let Some(name) = parent.child_by_field_name("name")
        {
            let mut components = Vec::new();
            append_cpp_name_components(name, source, &mut components)?;
            namespaces.push(components);
        }
        current = parent.parent();
    }
    namespaces.reverse();
    Some(namespaces.into_iter().flatten().collect())
}

pub(super) fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub(super) fn function_terminal_node(mut node: Node<'_>) -> Node<'_> {
    loop {
        let next = match node.kind() {
            "qualified_identifier" | "scoped_identifier" | "template_function" => {
                node.child_by_field_name("name")
            }
            "field_expression" => node.child_by_field_name("field"),
            _ => None,
        };
        let Some(next) = next else {
            return node;
        };
        node = next;
    }
}

pub(in crate::analyzer::usages) fn normalize_type_text(value: &str) -> String {
    strip_tag_type_prefix(
        normalize_cpp_whitespace(value)
            .trim_start_matches("const ")
            .trim_end_matches('*')
            .trim_end_matches('&')
            .trim(),
    )
    .to_string()
}

fn strip_tag_type_prefix(value: &str) -> &str {
    let value = value.trim_start_matches("const ");
    value
        .strip_prefix("struct ")
        .or_else(|| value.strip_prefix("class "))
        .or_else(|| value.strip_prefix("enum "))
        .unwrap_or(value)
        .trim()
}

pub(super) fn normalize_reference_name(value: &str) -> Option<String> {
    let normalized = normalize_cpp_reference_text(value);
    (!normalized.is_empty()).then_some(normalized)
}

pub(super) fn normalize_cpp_reference_text(value: &str) -> String {
    let mut text = normalize_cpp_whitespace(value)
        .trim_start_matches("new ")
        .trim()
        .to_string();
    if let Some(index) = text.find(['(', '{']) {
        text.truncate(index);
    }
    if let Some(index) = text.find('<') {
        text.truncate(index);
    }
    let normalized = text
        .trim()
        .trim_start_matches("const ")
        .trim_end_matches(|ch: char| ch == '*' || ch == '&' || ch.is_whitespace())
        .trim_matches(':')
        .trim();
    strip_tag_type_prefix(normalized).to_string()
}

pub(in crate::analyzer::usages) fn cpp_name_for(unit: &CodeUnit) -> String {
    let short = unit.short_name().replace(['.', '$'], "::");
    if unit.package_name().is_empty() {
        short
    } else {
        format!("{}::{}", unit.package_name(), short)
    }
}

pub(super) fn terminal_name(value: &str) -> &str {
    value
        .rsplit("::")
        .next()
        .unwrap_or(value)
        .rsplit(['.', '-', '>'])
        .next()
        .unwrap_or(value)
        .trim()
}

pub(super) fn name_matches_terminal(value: &str, expected: &str) -> bool {
    terminal_name(&normalize_cpp_reference_text(value)) == expected
}

pub(super) fn name_matches_callable(value: &str, expected: &str) -> bool {
    name_matches_terminal(value, expected)
        || expected.starts_with("operator")
            && terminal_name(&normalize_cpp_reference_text(value)) == "operator"
}

pub(super) fn name_mentions(value: &str, expected: &str) -> bool {
    normalize_cpp_reference_text(value)
        .split("::")
        .any(|part| part == expected)
}

pub(super) fn reference_matches_unit(reference: &str, unit: &CodeUnit) -> bool {
    let cpp_name = cpp_name_for(unit);
    if reference.contains("::") {
        return reference == cpp_name;
    }
    reference == cpp_name
        || terminal_name(reference) == unit.identifier()
            && (unit.package_name().is_empty() || reference == unit.identifier())
}

pub(super) fn matches_kind_for_lookup(unit: &CodeUnit, kind: TargetKind) -> bool {
    match kind {
        TargetKind::Type
        | TargetKind::Constructor
        | TargetKind::Method
        | TargetKind::MemberField => true,
        TargetKind::FreeFunction => unit.is_function(),
        TargetKind::GlobalField => unit.is_field(),
    }
}

pub(super) fn is_type_alias(unit: &CodeUnit) -> bool {
    unit.kind() == CodeUnitType::Field
        && unit.signature().is_some_and(|signature| {
            signature.starts_with("typedef ") || signature.starts_with("using ")
        })
}

fn alias_target_matches_target(alias: &CppAlias, target: &CodeUnit) -> bool {
    let normalized = normalize_cpp_reference_text(alias.target.trim().trim_end_matches(';'));
    let target_name = cpp_name_for(target);
    if normalized.contains("::") {
        return normalized == target_name;
    }
    if let Some(namespace) = alias.namespace.as_deref() {
        return namespace_prefixes(namespace)
            .into_iter()
            .any(|prefix| format!("{prefix}::{normalized}") == target_name);
    }
    target.package_name().is_empty() && normalized == target.identifier()
}

/// The declared return type text of a C++ function unit, with leading declaration specifiers
/// stripped, e.g. `T*` for `T* operator->()`.
pub(in crate::analyzer::usages) fn cpp_function_return_type_text(
    analyzer: &dyn IAnalyzer,
    function: &CodeUnit,
) -> Option<String> {
    let metadata = analyzer.signature_metadata(function);
    if !metadata.is_empty() {
        let first = metadata.first()?.return_type_text()?;
        return metadata
            .iter()
            .all(|metadata| metadata.return_type_text() == Some(first))
            .then(|| first.to_string());
    }
    let signature = cpp_function_signature_text(analyzer, function)?;
    cpp_function_return_type_text_from_signature(&signature)
}

fn cpp_function_signature_text(analyzer: &dyn IAnalyzer, function: &CodeUnit) -> Option<String> {
    function
        .signature()
        .filter(|signature| signature.contains(function.identifier()))
        .map(str::to_string)
        .or_else(|| analyzer.signatures(function).first().cloned())
        .or_else(|| analyzer.get_source(function, false))
}

fn cpp_function_return_type_text_from_signature(signature: &str) -> Option<String> {
    let open = signature.find('(')?;
    let name_at = cpp_function_name_start(signature, open)?;
    if let Some(return_type) = cpp_trailing_return_type(&signature[name_at..]) {
        return Some(return_type);
    }
    let type_text = cpp_strip_leading_template_clause(&signature[..name_at])
        .split_whitespace()
        .filter(|token| {
            !matches!(
                *token,
                "static" | "virtual" | "inline" | "constexpr" | "explicit" | "friend"
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let type_text = type_text.trim();
    (!type_text.is_empty()).then(|| type_text.to_string())
}

fn cpp_function_name_start(signature: &str, open: usize) -> Option<usize> {
    let before_parameters = &signature[..open];
    if let Some(operator_at) = before_parameters.rfind("operator") {
        let boundary = operator_at == 0
            || before_parameters[..operator_at]
                .chars()
                .next_back()
                .is_some_and(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()));
        if boundary {
            return Some(operator_at);
        }
    }
    before_parameters
        .rfind(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .map(|index| index + 1)
}

fn cpp_trailing_return_type(signature_from_name: &str) -> Option<String> {
    let open = signature_from_name.find('(')?;
    let mut depth = 0i32;
    for (offset, ch) in signature_from_name[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let rest = signature_from_name[open + offset + ch.len_utf8()..].trim_start();
                    let arrow = rest.find("->")?;
                    let return_type = rest[arrow + 2..].trim_start();
                    let return_type = return_type
                        .split(['{', ';'])
                        .next()
                        .unwrap_or(return_type)
                        .trim();
                    return (!return_type.is_empty()).then(|| return_type.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Strip a leading `template <...>` parameter clause, leaving the declaration that follows.
/// Returns the input unchanged when there is no such clause.
fn cpp_strip_leading_template_clause(text: &str) -> &str {
    let trimmed = text.trim_start();
    let Some(rest) = trimmed.strip_prefix("template") else {
        return text;
    };
    let rest = rest.trim_start();
    if !rest.starts_with('<') {
        return text;
    }
    let mut depth = 0i32;
    for (offset, ch) in rest.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return rest[offset + ch.len_utf8()..].trim_start();
                }
            }
            _ => {}
        }
    }
    text
}

pub(super) fn cpp_namespace_for(unit: &CodeUnit) -> Option<String> {
    cpp_name_for(unit).rsplit_once("::").map(|(namespace, _)| {
        namespace
            .strip_prefix("anonymous_namespace::")
            .unwrap_or(namespace)
            .to_string()
    })
}

fn namespace_prefixes(namespace: &str) -> Vec<&str> {
    let mut prefixes = Vec::new();
    let mut current = Some(namespace);
    while let Some(prefix) = current {
        prefixes.push(prefix);
        current = prefix.rsplit_once("::").map(|(parent, _)| parent);
    }
    prefixes
}

pub(in crate::analyzer::usages) fn enclosing_namespace_context(
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let mut namespaces = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_definition"
            && let Some(name) = parent.child_by_field_name("name")
        {
            let namespace = normalize_cpp_reference_text(node_text(name, source));
            if !namespace.is_empty() {
                namespaces.push(namespace);
            }
        }
        current = parent.parent();
    }
    if namespaces.is_empty() {
        None
    } else {
        namespaces.reverse();
        Some(namespaces.join("::"))
    }
}

/// Like [`precise_parent_of`], but drops module (namespace) parents. A namespace is a scope, not a
/// type or receiver, so namespace-scoped functions and constants resolve as free functions and
/// globals rather than members.
pub(super) fn type_owner_of(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<CodeUnit> {
    type_owner_resolution(analyzer, code_unit).map(|owner| owner.unit)
}

fn type_owner_resolution(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<ResolvedTypeOwner> {
    precise_parent_resolution(analyzer, code_unit).filter(|owner| !owner.unit.is_module())
}

pub(super) fn precise_parent_of(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    precise_parent_resolution(analyzer, code_unit).map(|owner| owner.unit)
}

fn precise_parent_resolution(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<ResolvedTypeOwner> {
    #[cfg(test)]
    if let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) {
        cpp.record_cpp_parent_resolution_for_test();
    }
    if let Some(unit) = exact_structural_type_parent(analyzer, code_unit) {
        return Some(ResolvedTypeOwner {
            unit,
            is_forward_declaration: false,
        });
    }
    let fallback = analyzer.parent_of(code_unit);
    let Some(owner_name) = code_unit
        .short_name()
        .rsplit_once('.')
        .map(|(owner, _)| owner)
    else {
        return fallback.map(|unit| ResolvedTypeOwner {
            unit,
            is_forward_declaration: false,
        });
    };
    let owner_fqn = if code_unit.package_name().is_empty() {
        owner_name.to_string()
    } else {
        format!("{}.{}", code_unit.package_name(), owner_name)
    };
    match same_source_owner(analyzer, code_unit, &owner_fqn, owner_name) {
        DirectOwnerResolution::UniqueFull(owner) => {
            return Some(ResolvedTypeOwner {
                unit: owner,
                is_forward_declaration: false,
            });
        }
        DirectOwnerResolution::Ambiguous => return None,
        DirectOwnerResolution::ForwardsOnly(_) | DirectOwnerResolution::None => {}
    }
    match directly_included_owner(analyzer, code_unit, &owner_fqn, owner_name) {
        DirectOwnerResolution::UniqueFull(owner) => Some(ResolvedTypeOwner {
            unit: owner,
            is_forward_declaration: false,
        }),
        DirectOwnerResolution::Ambiguous => None,
        DirectOwnerResolution::ForwardsOnly(forwards) => {
            match visible_full_cpp_owner(analyzer, code_unit, &owner_fqn, owner_name) {
                FullOwnerResolution::Unique(owner) => Some(ResolvedTypeOwner {
                    unit: owner,
                    is_forward_declaration: false,
                }),
                FullOwnerResolution::None if forwards.len() == 1 => {
                    forwards.into_iter().next().map(|unit| ResolvedTypeOwner {
                        unit,
                        is_forward_declaration: true,
                    })
                }
                FullOwnerResolution::None | FullOwnerResolution::Ambiguous => None,
            }
        }
        DirectOwnerResolution::None => {
            match visible_full_cpp_owner(analyzer, code_unit, &owner_fqn, owner_name) {
                FullOwnerResolution::Unique(owner) => Some(ResolvedTypeOwner {
                    unit: owner,
                    is_forward_declaration: false,
                }),
                FullOwnerResolution::Ambiguous => None,
                FullOwnerResolution::None => fallback
                    .filter(|parent| {
                        parent.source() == code_unit.source()
                            && parent.short_name() == owner_name
                            && parent.package_name() == code_unit.package_name()
                            && (!parent.is_class()
                                || cpp_class_declaration_strength(analyzer, parent)
                                    == CppClassDeclarationStrength::Full)
                    })
                    .map(|unit| ResolvedTypeOwner {
                        unit,
                        is_forward_declaration: false,
                    }),
            }
        }
    }
}

fn exact_structural_type_parent(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    if !code_unit.is_function() && !code_unit.is_field() {
        return None;
    }
    let encoded_owner = code_unit.short_name().rsplit_once('.')?.0;
    let cpp = resolve_analyzer::<CppAnalyzer>(analyzer)?;
    let parent = cpp.structural_parent_of(code_unit)?;
    (!parent.is_module()
        && parent.source() == code_unit.source()
        && parent.package_name() == code_unit.package_name()
        && parent.short_name() == encoded_owner)
        .then_some(parent)
}

fn same_source_owner(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    owner_fqn: &str,
    owner_name: &str,
) -> DirectOwnerResolution {
    let candidates = analyzer
        .global_usage_definition_index()
        .by_fqn(owner_fqn)
        .iter()
        .filter(|candidate| {
            candidate.is_class()
                && candidate.source() == code_unit.source()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
        });
    classify_direct_owner_candidates(analyzer, candidates)
}

fn visible_full_cpp_owner(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    owner_fqn: &str,
    owner_name: &str,
) -> FullOwnerResolution {
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return FullOwnerResolution::None;
    };
    let mut visible_files = HashSet::default();
    collect_include_closure(
        analyzer,
        cpp.include_target_index(),
        code_unit.source(),
        &mut visible_files,
        None,
    );
    let candidates = analyzer
        .global_usage_definition_index()
        .by_fqn(owner_fqn)
        .iter()
        .filter(|candidate| {
            candidate.is_class()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
                && visible_files.contains(candidate.source())
        });
    let mut full_definition = None;
    for candidate in candidates {
        match cpp_class_declaration_strength(analyzer, candidate) {
            CppClassDeclarationStrength::Full if full_definition.is_some() => {
                return FullOwnerResolution::Ambiguous;
            }
            CppClassDeclarationStrength::Full => full_definition = Some(candidate.clone()),
            CppClassDeclarationStrength::Forward => {}
            CppClassDeclarationStrength::Unknown => return FullOwnerResolution::Ambiguous,
        }
    }
    full_definition.map_or(FullOwnerResolution::None, FullOwnerResolution::Unique)
}

enum DirectOwnerResolution {
    None,
    ForwardsOnly(Vec<CodeUnit>),
    UniqueFull(CodeUnit),
    Ambiguous,
}

enum FullOwnerResolution {
    None,
    Unique(CodeUnit),
    Ambiguous,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CppClassDeclarationStrength {
    Full,
    Forward,
    Unknown,
}

fn directly_included_owner(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    owner_fqn: &str,
    owner_name: &str,
) -> DirectOwnerResolution {
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return DirectOwnerResolution::None;
    };
    let imports = analyzer.import_statements(code_unit.source());
    let direct_includes: HashSet<ProjectFile> = cpp_include_paths(&imports)
        .into_iter()
        .flat_map(|include| {
            resolve_include_targets_with_index(
                code_unit.source(),
                &include,
                cpp.include_target_index(),
            )
        })
        .collect();
    let candidates = analyzer
        .global_usage_definition_index()
        .by_fqn(owner_fqn)
        .iter()
        .filter(|candidate| {
            candidate.is_class()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
                && direct_includes.contains(candidate.source())
        });
    classify_direct_owner_candidates(analyzer, candidates)
}

fn classify_direct_owner_candidates<'a>(
    analyzer: &dyn IAnalyzer,
    candidates: impl Iterator<Item = &'a CodeUnit>,
) -> DirectOwnerResolution {
    collapse_owner_candidates(candidates.map(|candidate| {
        (
            candidate.clone(),
            cpp_class_declaration_strength(analyzer, candidate),
        )
    }))
}

fn collapse_owner_candidates(
    candidates: impl Iterator<Item = (CodeUnit, CppClassDeclarationStrength)>,
) -> DirectOwnerResolution {
    let mut full_definition = None;
    let mut forwards = Vec::new();
    for (candidate, strength) in candidates {
        match strength {
            CppClassDeclarationStrength::Full if full_definition.is_some() => {
                return DirectOwnerResolution::Ambiguous;
            }
            CppClassDeclarationStrength::Full => full_definition = Some(candidate),
            CppClassDeclarationStrength::Forward => forwards.push(candidate),
            CppClassDeclarationStrength::Unknown => return DirectOwnerResolution::Ambiguous,
        }
    }
    if let Some(owner) = full_definition {
        DirectOwnerResolution::UniqueFull(owner)
    } else if !forwards.is_empty() {
        DirectOwnerResolution::ForwardsOnly(forwards)
    } else {
        DirectOwnerResolution::None
    }
}

fn cpp_class_declaration_strength(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
) -> CppClassDeclarationStrength {
    let Some(source) = analyzer.indexed_source(candidate.source()) else {
        return CppClassDeclarationStrength::Unknown;
    };
    #[cfg(test)]
    if let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) {
        cpp.record_cpp_class_strength_parse_for_test();
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return CppClassDeclarationStrength::Unknown;
    }
    let Some(tree) = parser.parse(&source, None) else {
        return CppClassDeclarationStrength::Unknown;
    };
    let ranges = analyzer.ranges(candidate);
    let mut saw_forward = false;
    for range in ranges {
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
                continue;
            }
            if node.start_byte() == range.start_byte && node.end_byte() == range.end_byte {
                if matches!(
                    node.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
                ) {
                    if cpp_class_node_has_body(node) {
                        return CppClassDeclarationStrength::Full;
                    }
                    saw_forward = true;
                } else if let Some(has_body) =
                    recovered_exported_class_has_body(node, &source, candidate.identifier())
                {
                    if has_body {
                        return CppClassDeclarationStrength::Full;
                    }
                    saw_forward = true;
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }
    if saw_forward {
        CppClassDeclarationStrength::Forward
    } else {
        CppClassDeclarationStrength::Unknown
    }
}

fn cpp_class_node_has_body(node: Node<'_>) -> bool {
    node.child_by_field_name("body").is_some() || {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).any(|child| {
            matches!(
                child.kind(),
                "declaration_list" | "field_declaration_list" | "enumerator_list"
            )
        })
    }
}

pub(super) fn visible_owner_from_member_name(
    ctx: &ScanCtx<'_>,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    let owner_name = code_unit
        .short_name()
        .rsplit_once('.')
        .map(|(owner, _)| owner)?;
    let owner_fqn = if code_unit.package_name().is_empty() {
        owner_name.to_string()
    } else {
        format!("{}.{}", code_unit.package_name(), owner_name)
    };
    ctx.analyzer
        .global_usage_definition_index()
        .by_fqn(&owner_fqn)
        .iter()
        .find(|candidate| {
            candidate.is_class()
                && ctx.visibility.is_visible(ctx.file, candidate)
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
        })
        .cloned()
}

pub(super) fn same_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
        && left.source() == right.source()
}

pub(super) fn same_visible_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    same_symbol(left, right) || same_logical_symbol(left, right)
}

pub(super) fn same_logical_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_target_spec_scan_keys_collapse_logical_redeclarations() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let logical_type = |path: &str| {
            CodeUnit::with_signature(
                ProjectFile::new(root.clone(), path),
                CodeUnitType::Class,
                "gfx",
                "Size",
                Some("class Size".to_string()),
                false,
            )
        };
        let first_type = logical_type("first.h");
        let duplicate_type = logical_type("duplicate.h");
        let first_type_spec = TargetSpec::new(
            first_type.clone(),
            TargetKind::Type,
            Some(first_type),
            "Size".to_string(),
            None,
            None,
        );
        let duplicate_type_spec = TargetSpec::new(
            duplicate_type.clone(),
            TargetKind::Type,
            Some(duplicate_type),
            "Size".to_string(),
            None,
            None,
        );
        assert_eq!(
            first_type_spec.type_scan_key(),
            duplicate_type_spec.type_scan_key()
        );

        let other_namespace = CodeUnit::with_signature(
            ProjectFile::new(root, "other_namespace.h"),
            CodeUnitType::Class,
            "other",
            "Size",
            Some("class Size".to_string()),
            false,
        );
        let other_namespace_spec = TargetSpec::new(
            other_namespace.clone(),
            TargetKind::Type,
            Some(other_namespace),
            "Size".to_string(),
            None,
            None,
        );
        assert_ne!(
            first_type_spec.type_scan_key(),
            other_namespace_spec.type_scan_key(),
            "same-short-name Types with distinct FQNs must retain separate scans"
        );
    }

    #[test]
    fn visibility_build_hydrates_overlapping_closures_once_and_preserves_root_visibility() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let left = ProjectFile::new(root.clone(), "left.cpp");
        let right = ProjectFile::new(root.clone(), "right.cpp");
        let shared = ProjectFile::new(root.clone(), "shared.h");
        let leaf = ProjectFile::new(root.clone(), "leaf.h");
        let right_only = ProjectFile::new(root, "right_only.h");

        let adjacency = HashMap::from_iter([
            (left.clone(), vec![shared.clone()]),
            (right.clone(), vec![shared.clone(), right_only.clone()]),
            (shared.clone(), vec![leaf.clone()]),
            (leaf.clone(), Vec::new()),
            (right_only.clone(), Vec::new()),
        ]);
        let declarations_by_file: HashMap<_, _> = [
            (left.clone(), "Left"),
            (right.clone(), "Right"),
            (shared.clone(), "Shared"),
            (leaf.clone(), "Leaf"),
            (right_only.clone(), "RightOnly"),
        ]
        .into_iter()
        .map(|(file, name)| {
            let declaration = CodeUnit::new(file.clone(), CodeUnitType::Class, "", name);
            (file, BTreeSet::from([declaration]))
        })
        .collect();

        let roots = HashSet::from_iter([left.clone(), right.clone()]);
        let mut include_discovery_counts = HashMap::<ProjectFile, usize>::default();
        let VisibilityData {
            visible_by_file, ..
        } = build_visibility_data(
            &roots,
            None,
            |file| {
                *include_discovery_counts.entry(file.clone()).or_default() += 1;
                adjacency.get(file).cloned().unwrap_or_default()
            },
            |file| declarations_by_file.get(file).cloned().unwrap_or_default(),
        );

        assert_eq!(include_discovery_counts.len(), adjacency.len());
        assert!(
            include_discovery_counts.values().all(|count| *count == 1),
            "the complete visibility build must discover each union-closure file exactly once: \
             {include_discovery_counts:#?}"
        );
        assert_eq!(include_discovery_counts.get(&shared), Some(&1));
        assert_eq!(include_discovery_counts.get(&leaf), Some(&1));

        let visible_names = |root: &ProjectFile| {
            visible_by_file
                .get(root)
                .into_iter()
                .flatten()
                .map(|unit| unit.identifier().to_string())
                .collect::<HashSet<_>>()
        };

        assert_eq!(
            visible_names(&left),
            HashSet::from_iter(["Left", "Shared", "Leaf"].map(str::to_string))
        );
        assert_eq!(
            visible_names(&right),
            HashSet::from_iter(["Right", "Shared", "Leaf", "RightOnly"].map(str::to_string))
        );
    }

    #[test]
    fn union_visibility_keeps_colliding_declarations_root_local() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let left = ProjectFile::new(root.clone(), "left.cpp");
        let right = ProjectFile::new(root.clone(), "right.cpp");
        let left_header = ProjectFile::new(root.clone(), "left/collision.h");
        let right_header = ProjectFile::new(root, "right/collision.h");
        let left_collision =
            CodeUnit::new(left_header.clone(), CodeUnitType::Class, "", "Collision");
        let right_collision =
            CodeUnit::new(right_header.clone(), CodeUnitType::Class, "", "Collision");
        let adjacency = HashMap::from_iter([
            (left.clone(), vec![left_header.clone()]),
            (right.clone(), vec![right_header.clone()]),
            (left_header.clone(), Vec::new()),
            (right_header.clone(), Vec::new()),
        ]);
        let declarations = HashMap::from_iter([
            (left_header.clone(), BTreeSet::from([left_collision])),
            (right_header.clone(), BTreeSet::from([right_collision])),
        ]);
        let roots = HashSet::from_iter([left.clone(), right.clone()]);
        let VisibilityData {
            visible_by_file, ..
        } = build_visibility_data(
            &roots,
            None,
            |file| adjacency.get(file).cloned().unwrap_or_default(),
            |file| declarations.get(file).cloned().unwrap_or_default(),
        );
        let visibility = visibility_index(visible_by_file);
        let candidate_sources = |file: &ProjectFile| {
            visibility
                .visible_identifier_candidates(file, "Collision")
                .map(|candidate| candidate.source().clone())
                .collect::<HashSet<_>>()
        };

        assert_eq!(candidate_sources(&left), HashSet::from_iter([left_header]));
        assert_eq!(
            candidate_sources(&right),
            HashSet::from_iter([right_header])
        );
    }

    fn visibility_index(
        visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    ) -> VisibilityIndex {
        VisibilityIndex {
            visible_by_identifier: build_visible_identifier_index(&visible_by_file),
            visible_by_file,
            visible_source_files_by_root: HashMap::default(),
            alias_cells: Mutex::new(HashMap::default()),
            alias_source_parse_counts: Mutex::new(HashMap::default()),
            field_type_facts: Mutex::new(HashMap::default()),
            structured_alias_targets: Mutex::new(HashMap::default()),
            qualified_candidate_inspections: AtomicUsize::new(0),
        }
    }

    #[test]
    fn qualified_type_lookup_inspects_only_exact_fqn_candidates() {
        const UNRELATED_DECLARATIONS: usize = 256;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let target_a_file = ProjectFile::new(root.clone(), "include/target_a.h");
        let target_b_file = ProjectFile::new(root.clone(), "include/target_b.h");
        let target_a = CodeUnit::new(target_a_file, CodeUnitType::Class, "perf", "Exact");
        let target_b = CodeUnit::new(target_b_file, CodeUnitType::Class, "perf", "Exact");
        let same_fqn_function = CodeUnit::with_signature(
            ProjectFile::new(root.clone(), "include/function.h"),
            CodeUnitType::Function,
            "perf",
            "Exact",
            Some("void Exact()".to_string()),
            false,
        );
        let alias = CodeUnit::with_signature(
            ProjectFile::new(root.clone(), "include/alias.h"),
            CodeUnitType::Field,
            "perf",
            "Alias",
            Some("using Alias = Exact;".to_string()),
            false,
        );
        let global = CodeUnit::new(
            ProjectFile::new(root.clone(), "include/global.h"),
            CodeUnitType::Class,
            "",
            "Global",
        );
        let hidden_same_fqn = CodeUnit::new(
            ProjectFile::new(root.clone(), "hidden/target.h"),
            CodeUnitType::Class,
            "perf",
            "Exact",
        );

        let mut visible = HashSet::default();
        for index in 0..UNRELATED_DECLARATIONS {
            visible.insert(CodeUnit::new(
                ProjectFile::new(root.clone(), format!("include/unrelated_{index}.h")),
                CodeUnitType::Class,
                format!("unrelated{index}"),
                format!("Type{index}"),
            ));
        }
        visible.extend([
            target_a.clone(),
            target_b.clone(),
            same_fqn_function.clone(),
            alias.clone(),
            global.clone(),
        ]);
        let visible_by_file = HashMap::from_iter([
            (consumer.clone(), visible.clone()),
            (alias.source().clone(), visible),
        ]);
        let visibility = visibility_index(visible_by_file);

        visibility.reset_qualified_candidate_inspections();
        let candidates = visibility.type_candidates(&consumer, "perf::Exact");
        let inspected = visibility.qualified_candidate_inspections();
        assert_eq!(
            candidates.len(),
            2,
            "qualified type candidates: {candidates:#?}"
        );
        assert!(candidates.contains(&&target_a));
        assert!(candidates.contains(&&target_b));
        assert!(!candidates.contains(&&hidden_same_fqn));
        let raw_type_candidates = visibility.type_name_candidates(&consumer, "perf::Exact");
        assert_eq!(raw_type_candidates.len(), 3);
        assert!(raw_type_candidates.contains(&&same_fqn_function));
        assert_eq!(
            visibility.named_candidates_for_normalized(
                &consumer,
                "perf::Exact",
                TargetKind::FreeFunction
            ),
            vec![&same_fqn_function],
            "target-kind filtering must distinguish a same-FQN free function from types"
        );
        assert_eq!(
            visibility.resolve_type(&consumer, "::Global"),
            Some(global),
            "a leading global qualifier must still resolve the visible global type"
        );
        assert_eq!(
            visibility.resolve_type(&consumer, "perf::Alias"),
            Some(alias.clone()),
            "a namespace-qualified alias must remain a type candidate"
        );
        assert_eq!(
            visibility.alias_target(&alias).map(|unit| unit.fq_name()),
            Some("perf.Exact".to_string()),
            "a qualified namespace alias must resolve its namespace-relative target"
        );
        assert_eq!(
            inspected, 3,
            "qualified lookup should inspect only the two visible type declarations and the same-FQN non-type declaration"
        );
    }

    #[test]
    fn qualified_lookup_uses_the_final_cpp_scope_component_verbatim() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let header = ProjectFile::new(root, "include/types.h");
        let nested = CodeUnit::new(header.clone(), CodeUnitType::Class, "ns", "Outer$Inner");
        let constructor = CodeUnit::with_signature(
            header.clone(),
            CodeUnitType::Function,
            "ns",
            "Widget.Widget",
            Some("Widget()".to_string()),
            false,
        );
        let arrow = CodeUnit::with_signature(
            header.clone(),
            CodeUnitType::Function,
            "ns",
            "Widget.operator->",
            Some("Widget* operator->()".to_string()),
            false,
        );
        let destructor = CodeUnit::with_signature(
            header,
            CodeUnitType::Function,
            "ns",
            "Widget.~Widget",
            Some("~Widget()".to_string()),
            false,
        );
        let visible_by_file = HashMap::from_iter([(
            consumer.clone(),
            HashSet::from_iter([
                nested.clone(),
                constructor.clone(),
                arrow.clone(),
                destructor.clone(),
            ]),
        )]);
        let visibility = visibility_index(visible_by_file);

        assert_eq!(
            visibility.candidate_units(&consumer, "ns::Outer::Inner", TargetKind::Type),
            vec![&nested]
        );
        assert_eq!(
            visibility.resolve_type(&consumer, "ns::Outer::Inner<int>"),
            Some(nested),
            "template arguments must be removed before selecting the final identifier bucket"
        );
        assert_eq!(
            visibility.candidate_units(&consumer, "ns::Widget::Widget", TargetKind::Constructor),
            vec![&constructor]
        );
        assert_eq!(
            visibility.candidate_units(&consumer, "ns::Widget::operator->", TargetKind::Method),
            vec![&arrow],
            "operator-> must not be reduced with terminal_name-style punctuation splitting"
        );
        assert_eq!(
            visibility.candidate_units(&consumer, "ns::Widget::~Widget", TargetKind::Method),
            vec![&destructor]
        );
        assert!(
            visibility
                .candidate_units(&consumer, "::", TargetKind::Type)
                .is_empty(),
            "a degenerate qualified name must fail closed"
        );
    }

    #[test]
    fn owner_candidate_collapse_prefers_one_full_and_rejects_unknown_or_duplicate_full() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let forward = CodeUnit::new(
            ProjectFile::new(root.clone(), "forward.h"),
            CodeUnitType::Class,
            "demo",
            "Widget",
        );
        let full = CodeUnit::new(
            ProjectFile::new(root.clone(), "full.h"),
            CodeUnitType::Class,
            "demo",
            "Widget",
        );
        let duplicate = CodeUnit::new(
            ProjectFile::new(root, "duplicate.h"),
            CodeUnitType::Class,
            "demo",
            "Widget",
        );

        assert!(matches!(
            collapse_owner_candidates(
                [
                    (forward, CppClassDeclarationStrength::Forward),
                    (full.clone(), CppClassDeclarationStrength::Full),
                ]
                .into_iter()
            ),
            DirectOwnerResolution::UniqueFull(owner) if owner == full
        ));
        assert!(matches!(
            collapse_owner_candidates(
                [(full.clone(), CppClassDeclarationStrength::Unknown)].into_iter()
            ),
            DirectOwnerResolution::Ambiguous
        ));
        assert!(matches!(
            collapse_owner_candidates(
                [
                    (full, CppClassDeclarationStrength::Full),
                    (duplicate, CppClassDeclarationStrength::Full),
                ]
                .into_iter()
            ),
            DirectOwnerResolution::Ambiguous
        ));
    }
}
