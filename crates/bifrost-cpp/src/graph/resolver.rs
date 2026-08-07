use crate::call_match::{
    CppArgType, cpp_signature_param_types, cpp_split_top_level_commas, normalize_cpp_type_name,
};
use crate::declarations::{
    cpp_export_macro_token, cpp_field_declaration_linkage, cpp_template_term, node_text,
    normalize_cpp_whitespace, recovered_exported_class_has_body,
};
use crate::graph::CppGraphSource;
use crate::graph::extractor::ScanCtx;
use crate::graph_support::CppSource;
use crate::imports::{
    IncludeTargetIndex, include_paths as cpp_include_paths, resolve_include_targets_with_index,
};
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CodeUnitType, CppFieldLinkage, CppTemplateExpression, CppTemplateMetadata,
    CppTemplateParameterMetadata, CppTemplateTerm,
};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::tree_walk::node_for_exact_range;
use brokk_bifrost_core::analyzer::usages::common::same_node;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::borrow::Cow;
#[cfg(any(test, feature = "test-support"))]
use std::cell::Cell;
use std::collections::BTreeSet;
use std::hash::Hash;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::ThreadId;
use tree_sitter::{Node, Parser, Tree};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Type,
    Constructor,
    FreeFunction,
    Method,
    GlobalField,
    MemberField,
}

pub enum LexicalTypeResolution {
    Resolved {
        unit: CodeUnit,
        components: Vec<String>,
        candidates: Vec<CodeUnit>,
    },
    Ambiguous,
    Missing,
}

#[derive(Clone, Copy)]
enum TypeCandidateResolution<'a> {
    Canonical,
    PreserveAlias,
    PreserveTarget(&'a CodeUnit),
}

pub enum LexicalCallableValueResolution {
    Type(CodeUnit),
    FreeFunction(CodeUnit),
    Ambiguous,
    Missing,
}

pub enum UsingEnumMemberResolution {
    Resolved { owner: CodeUnit, member: CodeUnit },
    Ambiguous,
    Missing,
}

pub enum NamespaceValueResolution {
    Resolved,
    Ambiguous,
    Missing,
}

pub fn resolve_namespace_value(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
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

pub(crate) struct ScopedUsingEnumOwners {
    scopes: Vec<Vec<CodeUnit>>,
}

/// Same-file class and namespace imports collected by the targeted scanner's AST prepass.
/// Cross-file and inherited class imports are deliberately not inferred without persisted
/// evidence; a missing imported enumerator therefore remains unproven rather than being
/// misresolved.
pub(crate) struct SemanticUsingEnumOwners {
    class_imports: HashMap<CodeUnit, Vec<CodeUnit>>,
    namespace_imports: HashMap<Vec<String>, Vec<(usize, CodeUnit)>>,
}

pub(crate) enum SemanticUsingEnumMemberResolution {
    Class(UsingEnumMemberResolution),
    Namespace(UsingEnumMemberResolution),
    Missing,
}

impl SemanticUsingEnumOwners {
    pub(crate) fn new() -> Self {
        Self {
            class_imports: HashMap::default(),
            namespace_imports: HashMap::default(),
        }
    }

    pub fn import_class(&mut self, class: CodeUnit, enum_owner: CodeUnit) {
        let imports = self.class_imports.entry(class).or_default();
        if !imports
            .iter()
            .any(|existing| same_visible_symbol(existing, &enum_owner))
        {
            imports.push(enum_owner);
        }
    }

    pub fn import_namespace(
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

    pub fn resolve_member(
        &self,
        visibility: &VisibilityIndex<'_>,
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
    visibility: &VisibilityIndex<'_>,
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
    pub(crate) fn new() -> Self {
        Self {
            scopes: vec![Vec::new()],
        }
    }

    pub fn enter_scope(&mut self) {
        self.scopes.push(Vec::new());
    }

    pub fn exit_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    pub fn import(&mut self, owner: CodeUnit) {
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

    pub fn resolve_member(
        &self,
        visibility: &VisibilityIndex<'_>,
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

#[derive(Clone)]
pub struct TargetSpec {
    pub target: CodeUnit,
    pub kind: TargetKind,
    pub owner: Option<CodeUnit>,
    pub member_name: String,
    pub callable_arity: Option<CallableArity>,
    pub activated_callable_arities: Vec<ActivatedCallableArity>,
    pub param_types: Option<Vec<String>>,
    pub enum_owner_kind: EnumOwnerKind,
    pub owner_is_forward_declaration: bool,
}

#[derive(Clone, Copy)]
pub struct ActivatedCallableArity {
    pub activation_byte: usize,
    pub arity: CallableArity,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct TypeScanKey {
    target: LogicalSymbolKey,
    member_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
pub enum EnumOwnerKind {
    Scoped,
    Unscoped,
    NonEnum,
}

impl TargetSpec {
    pub fn type_scan_key(&self) -> Option<TypeScanKey> {
        (self.kind == TargetKind::Type).then(|| TypeScanKey {
            target: logical_symbol_key(&self.target),
            member_name: self.member_name.clone(),
        })
    }

    pub fn from_target(analyzer: &CppGraphSource<'_>, target: &CodeUnit) -> Option<Self> {
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
            let owner_resolution = type_owner_resolution(analyzer, target)
                .or_else(|| target_forward_owner_resolution(analyzer, target));
            let owner_is_forward_declaration = owner_resolution
                .as_ref()
                .is_some_and(|owner| owner.is_forward_declaration);
            let owner = owner_resolution.map(|owner| owner.unit);
            let kind = if owner.as_ref().is_some_and(|owner| {
                target.identifier() == owner.identifier()
                    || analyzer
                        .cpp
                        .and_then(|cpp| cpp.template_metadata(owner))
                        .is_some_and(|metadata| metadata.primary_name == target.identifier())
            }) {
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

    pub fn with_visible_callable_arities<'a>(
        &'a self,
        analyzer: &CppGraphSource<'_>,
        cpp: &dyn CppSource,
        visibility: &VisibilityIndex<'_>,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
    ) -> Cow<'a, Self> {
        let macro_parameter_arity =
            visibility.callable_parameter_macro_arity(&self.target, self.target.signature());
        let activated_callable_arities =
            visibility.callable_arities_for_target(analyzer, cpp, file, prepared, self);
        if macro_parameter_arity.is_none() && activated_callable_arities.is_empty() {
            return Cow::Borrowed(self);
        }
        let mut effective = self.clone();
        if let Some(macro_parameter_arity) = macro_parameter_arity {
            effective.callable_arity = Some(macro_parameter_arity);
        }
        effective.activated_callable_arities = activated_callable_arities;
        Cow::Owned(effective)
    }

    pub fn callable_arity_at(&self, byte: usize) -> Option<CallableArity> {
        let base = self.callable_arity?;
        Some(
            self.activated_callable_arities
                .iter()
                .filter(|candidate| candidate.activation_byte <= byte)
                .fold(base, |arity, candidate| {
                    merge_compatible_callable_arities(arity, candidate.arity).unwrap_or(arity)
                }),
        )
    }

    pub fn new(
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
            activated_callable_arities: Vec::new(),
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

fn classify_enum_owner(analyzer: &CppGraphSource<'_>, owner: &CodeUnit) -> EnumOwnerKind {
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
pub struct CppScanBinding {
    pub unit: Option<CodeUnit>,
    pub type_name: Option<String>,
    pub indirection: i32,
}

impl CppScanBinding {
    pub fn from_unit(unit: CodeUnit, indirection: i32) -> Self {
        Self {
            type_name: Some(cpp_name_for(&unit)),
            unit: Some(unit),
            indirection,
        }
    }

    pub fn from_type_name(type_name: String, unit: Option<CodeUnit>, indirection: i32) -> Self {
        Self {
            type_name: Some(type_name),
            unit,
            indirection,
        }
    }

    pub fn as_arg_type(&self) -> Option<CppArgType> {
        let name = self
            .type_name
            .clone()
            .or_else(|| self.unit.as_ref().map(cpp_name_for))?;
        Some(CppArgType {
            name,
            unit: self.unit.clone(),
            indirection: self.indirection,
            pointee_const: false,
        })
    }
}

type AliasCell = Arc<OnceLock<Box<[CppAlias]>>>;
type VisibleParserAliasTargetNamesCell = Arc<OnceLock<HashMap<String, HashSet<String>>>>;
pub type OrdinaryTypeImportCell = Arc<EffectiveUsingIndex>;
pub type MacroEventCell = Arc<OnceLock<Box<[MacroEvent]>>>;
type MacroIncludeProtectionCell = Arc<OnceLock<MacroIncludeProtection>>;
pub type MacroEnvironmentCursorCell = Arc<Mutex<MacroEnvironmentCursor>>;
type MacroReplacementCache = HashMap<(ProjectFile, usize), Arc<ParsedMacroReplacement>>;

#[derive(Clone, Default)]
pub struct MacroEnvironment {
    bindings: HashMap<String, MacroBinding>,
    unknown_names: bool,
    applied_pragma_once_files: HashSet<ProjectFile>,
    maybe_applied_pragma_once_files: HashSet<ProjectFile>,
}

#[derive(Default)]
pub struct MacroEnvironmentCursor {
    frontier: usize,
    environment: Arc<MacroEnvironment>,
}

impl MacroEnvironment {
    fn binding(&self, name: &str) -> Option<&MacroBinding> {
        self.bindings.get(name)
    }

    fn may_bind(&self, name: &str) -> bool {
        self.bindings.contains_key(name) || self.unknown_names
    }

    fn insert(&mut self, name: String, binding: MacroBinding) {
        self.bindings.insert(name, binding);
    }

    fn remove(&mut self, name: &str) {
        self.bindings.remove(name);
    }

    fn mark_unknown_names(&mut self, source: &ProjectFile, byte: usize) {
        for binding in self.bindings.values_mut() {
            *binding = MacroBinding::ambiguous(source, byte);
        }
        self.unknown_names = true;
    }
}

#[derive(Clone)]
pub enum EffectiveUsingTarget {
    Ordinary {
        name: String,
        target_components: Vec<String>,
        global: bool,
    },
    Namespace {
        namespace_components: Vec<String>,
        global: bool,
    },
}

#[derive(Clone)]
pub struct OrdinaryTypeImport {
    pub target: EffectiveUsingTarget,
    pub source: ProjectFile,
    pub declaration_byte: usize,
    pub scope_start: usize,
    pub scope_end: usize,
    pub scope_depth: usize,
    pub lexical_depth: usize,
    pub declaration_namespace: Vec<String>,
    pub namespace_scope: Option<Vec<String>>,
    pub resolved_target_components: Option<Vec<String>>,
    pub required_guards: HashSet<PreprocessorGuard>,
}

#[derive(Clone)]
pub struct ConditionalIncludeProjection {
    pub activation_byte: usize,
    pub required_guards: HashSet<PreprocessorGuard>,
}

#[derive(Default)]
pub struct SourceUsingIndex {
    pub ordinary_by_name: HashMap<String, Vec<OrdinaryTypeImport>>,
    pub directives: Vec<OrdinaryTypeImport>,
}

#[derive(Default)]
pub struct ProjectUsingIndex {
    pub ordinary_by_name: HashMap<String, Vec<OrdinaryTypeImport>>,
    pub directives: Vec<OrdinaryTypeImport>,
}

type EffectiveUsingProjectionCell = Arc<OnceLock<Arc<[OrdinaryTypeImport]>>>;

pub struct EffectiveUsingIndex {
    projected_by_name: Mutex<HashMap<String, EffectiveUsingProjectionCell>>,
}

impl EffectiveUsingIndex {
    fn new(_root: ProjectFile) -> Self {
        Self {
            projected_by_name: Mutex::new(HashMap::default()),
        }
    }

    pub fn projection_cell(&self, name: &str) -> EffectiveUsingProjectionCell {
        self.projected_by_name
            .lock()
            .expect("C++ effective-using projection cache poisoned")
            .entry(name.to_string())
            .or_default()
            .clone()
    }
}

pub enum OrdinaryTypeImportResolution {
    Resolved {
        target: CodeUnit,
        target_components: Vec<String>,
        lexical_depth: usize,
        is_direct: bool,
    },
    Ambiguous {
        lexical_depth: usize,
    },
    Missing,
}

type CallableReferenceSpecCell = Arc<OnceLock<Option<TargetSpec>>>;
type ConditionalIncludeProjectionCache =
    HashMap<(ProjectFile, ProjectFile), Arc<[ConditionalIncludeProjection]>>;
type VisibleParserAliasNameSetCell = Arc<OnceLock<HashSet<String>>>;
type IndexedStructuralClassScopeCache = HashMap<(ProjectFile, usize, usize), Option<Vec<String>>>;
type IndexedEnclosingOwnerScopeCache = HashMap<(ProjectFile, usize, usize), Option<Vec<String>>>;

/// Per-query C++ visibility facts.
///
/// The analyzer is *borrowed*, never cloned: `TreeSitterAnalyzer::clone` gives
/// the clone a fresh, empty `QueryReadCache` on purpose (clones cross
/// generations and overlays, where another generation's hydrated states would
/// be wrong). An index that owned a clone would therefore see an inactive read
/// cache for every `prepared_syntax` call it makes, re-reading and re-parsing
/// the same source from the store once per candidate instead of once per query
/// — the #1175 blow-up, where one scan re-parsed a 4.8 MB generated header
/// tens of thousands of times.
pub struct VisibilityIndex<'a> {
    cpp: &'a dyn CppSource,
    pub visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    visible_by_identifier: HashMap<ProjectFile, HashMap<String, Vec<CodeUnit>>>,
    global_field_internal_linkage: HashMap<CodeUnit, bool>,
    visible_source_files_by_root: HashMap<ProjectFile, HashSet<ProjectFile>>,
    alias_cells: Mutex<HashMap<ProjectFile, AliasCell>>,
    visible_parser_alias_name_sets: RwLock<HashMap<ProjectFile, VisibleParserAliasNameSetCell>>,
    visible_parser_alias_target_names:
        Mutex<HashMap<ProjectFile, VisibleParserAliasTargetNamesCell>>,
    ordinary_type_import_cells: Mutex<HashMap<ProjectFile, OrdinaryTypeImportCell>>,
    project_using_index: OnceLock<ProjectUsingIndex>,
    callable_reference_specs:
        Mutex<HashMap<(ProjectFile, LogicalSymbolKey), CallableReferenceSpecCell>>,
    include_activation_cells: Mutex<HashMap<(ProjectFile, ProjectFile), Option<usize>>>,
    conditional_include_projection_cells: Mutex<ConditionalIncludeProjectionCache>,
    #[cfg(any(test, feature = "test-support"))]
    include_activation_build_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    using_donor_activation_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    using_namespace_lookup_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    using_name_candidate_inspection_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    using_source_index_walk_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    callable_reference_spec_build_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    alias_source_parse_counts: Mutex<HashMap<ProjectFile, usize>>,
    #[cfg(any(test, feature = "test-support"))]
    visible_parser_alias_name_set_build_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    visible_parser_alias_target_names_build_count: AtomicUsize,
    field_type_facts: Mutex<HashMap<CodeUnit, Option<DeclaredFieldTypeFact>>>,
    structured_alias_targets: Mutex<HashMap<CodeUnit, Option<StructuredAliasTarget>>>,
    indexed_structural_class_scopes: Mutex<IndexedStructuralClassScopeCache>,
    indexed_enclosing_owner_scopes: Mutex<IndexedEnclosingOwnerScopeCache>,
    precise_parent_cache: Mutex<HashMap<CodeUnit, Option<CodeUnit>>>,
    macro_event_cells: Mutex<HashMap<ProjectFile, MacroEventCell>>,
    pub macro_include_protection_cells: Mutex<HashMap<ProjectFile, MacroIncludeProtectionCell>>,
    // A forward cursor is useful only while its caller visits one source in byte order. The
    // authoritative differential shares this index across target workers, whose frontiers can
    // interleave arbitrarily, so sharing one cursor per file would serialize the include replay
    // and repeatedly reset it. Keep one bounded cursor per participating worker instead; the
    // immutable event and parse caches above remain shared.
    pub macro_environment_cursors:
        Mutex<HashMap<(ProjectFile, ThreadId), MacroEnvironmentCursorCell>>,
    macro_replacements: Mutex<MacroReplacementCache>,
    callable_parameter_macro_arities: Mutex<HashMap<(ProjectFile, String), Option<CallableArity>>>,
    #[cfg(any(test, feature = "test-support"))]
    pub macro_replacement_parse_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    pub macro_event_application_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    pub macro_environment_copy_count: AtomicUsize,
    cpp_template_metadata: HashMap<CodeUnit, CppTemplateMetadata>,
    cpp_template_families: HashMap<String, Vec<CodeUnit>>,
    #[cfg(any(test, feature = "test-support"))]
    qualified_candidate_inspections: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    target_preserving_type_resolution_count: AtomicUsize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PreprocessorGuard {
    Defined(String),
    Undefined(String),
    Expression(String),
    NegatedExpression(String),
    Constant(bool),
}

impl PreprocessorGuard {
    fn negated(&self) -> Self {
        match self {
            Self::Defined(name) => Self::Undefined(name.clone()),
            Self::Undefined(name) => Self::Defined(name.clone()),
            Self::Expression(expression) => Self::NegatedExpression(expression.clone()),
            Self::NegatedExpression(expression) => Self::Expression(expression.clone()),
            Self::Constant(value) => Self::Constant(!value),
        }
    }

    fn may_depend_on_macro(&self, macro_name: &str) -> bool {
        match self {
            Self::Defined(name) | Self::Undefined(name) => name == macro_name,
            // The expression has already been isolated structurally by
            // tree-sitter, but its full preprocessor semantics are outside the
            // analyzer's guard model. Any macro mutation can therefore change
            // its truth value.
            Self::Expression(_) | Self::NegatedExpression(_) => true,
            Self::Constant(_) => false,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum MacroDefinition {
    Object {
        replacement: String,
    },
    Function {
        parameters: Vec<String>,
        replacement: String,
    },
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacroIncludeProtection {
    MacroGuard(String),
    PragmaOnce,
    None,
}

enum ParsedMacroReplacement {
    Parsed { source: String, tree: Tree },
    Unsupported,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacroBinding {
    source: ProjectFile,
    declaration_byte: usize,
    definition: MacroDefinition,
    exact: bool,
}

impl MacroBinding {
    fn ambiguous(source: &ProjectFile, declaration_byte: usize) -> Self {
        Self {
            source: source.clone(),
            declaration_byte,
            definition: MacroDefinition::Unsupported,
            exact: false,
        }
    }

    fn is_exact(&self) -> bool {
        self.exact
    }
}

#[derive(Clone)]
pub enum MacroEvent {
    Define {
        name: String,
        binding: MacroBinding,
        byte: usize,
        conditional: bool,
    },
    Undef {
        name: String,
        byte: usize,
        conditional: bool,
    },
    Include {
        targets: Vec<ProjectFile>,
        byte: usize,
        conditional: bool,
    },
    Invalidate {
        byte: usize,
    },
}

impl MacroEvent {
    pub fn byte(&self) -> usize {
        match self {
            Self::Define { byte, .. }
            | Self::Undef { byte, .. }
            | Self::Include { byte, .. }
            | Self::Invalidate { byte } => *byte,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallArityEvidence {
    Exact(usize),
    Unknown,
}

impl CallArityEvidence {
    pub fn exact(self) -> Option<usize> {
        match self {
            Self::Exact(arity) => Some(arity),
            Self::Unknown => None,
        }
    }

    pub fn accepts(self, expected: CallableArity) -> Option<bool> {
        self.exact().map(|arity| expected.accepts(arity))
    }
}

#[derive(Clone)]
struct DeclaredFieldTypeFact {
    type_text: String,
    indirection: i32,
    template_arguments: Option<Vec<CppTemplateExpression>>,
}

#[derive(Clone)]
enum StructuredAliasTarget {
    Builtin,
    Named {
        components: Vec<String>,
        global: bool,
        arguments: Option<Vec<CppTemplateExpression>>,
    },
}

struct CppAlias {
    name: String,
    target: String,
    namespace: Option<String>,
}

type ReceiverResolver<'a> = dyn for<'tree> Fn(Node<'tree>, &str) -> Vec<CodeUnit> + 'a;

/// Why template-argument resolution failed. Definition diagnostics render
/// each mode differently; graph scans only care that the resolution is
/// unproven and match `Err(_)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppTemplateResolutionError {
    /// A template alias expansion revisited `alias`.
    AliasCycle { alias: CodeUnit },
    /// The explicit arguments do not bind to the declared template parameters.
    ArgumentBinding,
    /// Bound arguments do not substitute into the alias target's arguments.
    Substitution,
    /// No visible primary template declaration could be selected and
    /// reconciled for the specialization family.
    PrimarySelection,
    /// More than one applicable specialization remains and none is strictly
    /// more specialized than every other candidate.
    AmbiguousSpecialization { candidates: Vec<CodeUnit> },
}

/// The ambiguity candidates, deduplicated to one representative per visible
/// symbol so a diagnostic lists each contender once.
fn distinct_visible_symbols<'u>(units: impl Iterator<Item = &'u CodeUnit>) -> Vec<CodeUnit> {
    let mut distinct: Vec<CodeUnit> = Vec::new();
    for unit in units {
        if !distinct
            .iter()
            .any(|existing| same_visible_symbol(existing, unit))
        {
            distinct.push(unit.clone());
        }
    }
    distinct
}

impl<'a> VisibilityIndex<'a> {
    pub fn cpp(&self) -> &'a dyn CppSource {
        self.cpp
    }

    /// A [`VisibilityIndex`] over a caller-supplied visible-declaration map,
    /// bypassing the include-closure walk [`Self::build`] performs.
    ///
    /// The resolver's own unit tests drive the type-resolution paths against a
    /// hand-written visibility table; they live in `brokk-bifrost-analysis`
    /// because they need a real `CppAnalyzer`, so the struct literal they used
    /// to write inline is here instead of thirty-three public fields.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_visible_files_for_test(
        cpp: &'a dyn CppSource,
        visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    ) -> Self {
        let visible_source_files_by_root = visible_by_file
            .iter()
            .map(|(file, visible)| {
                (
                    file.clone(),
                    visible
                        .iter()
                        .map(|unit| unit.source().clone())
                        .chain(std::iter::once(file.clone()))
                        .collect(),
                )
            })
            .collect();
        let mut global_field_internal_linkage = HashMap::default();
        Self {
            cpp,
            visible_by_identifier: build_visible_identifier_index(
                &CppGraphSource::from_source(cpp),
                &visible_by_file,
                &visible_source_files_by_root,
                &mut global_field_internal_linkage,
            ),
            global_field_internal_linkage,
            visible_by_file,
            visible_source_files_by_root,
            alias_cells: Mutex::new(HashMap::default()),
            visible_parser_alias_name_sets: RwLock::new(HashMap::default()),
            visible_parser_alias_target_names: Mutex::new(HashMap::default()),
            ordinary_type_import_cells: Mutex::new(HashMap::default()),
            project_using_index: OnceLock::new(),
            callable_reference_specs: Mutex::new(HashMap::default()),
            include_activation_cells: Mutex::new(HashMap::default()),
            conditional_include_projection_cells: Mutex::new(HashMap::default()),
            include_activation_build_count: AtomicUsize::new(0),
            using_donor_activation_count: AtomicUsize::new(0),
            using_namespace_lookup_count: AtomicUsize::new(0),
            using_name_candidate_inspection_count: AtomicUsize::new(0),
            using_source_index_walk_count: AtomicUsize::new(0),
            callable_reference_spec_build_count: AtomicUsize::new(0),
            alias_source_parse_counts: Mutex::new(HashMap::default()),
            visible_parser_alias_name_set_build_count: AtomicUsize::new(0),
            visible_parser_alias_target_names_build_count: AtomicUsize::new(0),
            field_type_facts: Mutex::new(HashMap::default()),
            structured_alias_targets: Mutex::new(HashMap::default()),
            indexed_structural_class_scopes: Mutex::new(HashMap::default()),
            indexed_enclosing_owner_scopes: Mutex::new(HashMap::default()),
            precise_parent_cache: Mutex::new(HashMap::default()),
            macro_event_cells: Mutex::new(HashMap::default()),
            macro_include_protection_cells: Mutex::new(HashMap::default()),
            macro_environment_cursors: Mutex::new(HashMap::default()),
            macro_replacements: Mutex::new(HashMap::default()),
            callable_parameter_macro_arities: Mutex::new(HashMap::default()),
            macro_replacement_parse_count: AtomicUsize::new(0),
            macro_event_application_count: AtomicUsize::new(0),
            macro_environment_copy_count: AtomicUsize::new(0),
            cpp_template_metadata: HashMap::default(),
            cpp_template_families: HashMap::default(),
            qualified_candidate_inspections: AtomicUsize::new(0),
            target_preserving_type_resolution_count: AtomicUsize::new(0),
        }
    }

    /// The index's own C++ source, in the dispatching-analyzer shape.
    ///
    /// Four resolution paths reach the workspace through the C++ analyzer they
    /// already hold rather than through the analyzer the query was issued
    /// against; before the move they passed `&CppAnalyzer` straight into a
    /// `&dyn IAnalyzer` parameter. See [`CppGraphSource::from_source`].
    fn cpp_source(&self) -> CppGraphSource<'a> {
        CppGraphSource::from_source(self.cpp)
    }

    pub fn build(
        cpp: &'a dyn CppSource,
        analyzer: &CppGraphSource<'_>,
        roots: &HashSet<ProjectFile>,
    ) -> Self {
        Self::build_with_cancellation(cpp, analyzer, roots, None)
    }

    pub fn build_with_cancellation(
        cpp: &'a dyn CppSource,
        analyzer: &CppGraphSource<'_>,
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
        let mut global_field_internal_linkage = HashMap::default();
        let visible_by_identifier = build_visible_identifier_index(
            analyzer,
            &visible_by_file,
            &visible_source_files_by_root,
            &mut global_field_internal_linkage,
        );
        let mut cpp_template_metadata = HashMap::default();
        for unit in visible_by_file
            .values()
            .flatten()
            .filter(|unit| unit.is_class())
        {
            if cpp_template_metadata.contains_key(unit) {
                continue;
            }
            if let Some(metadata) = cpp.template_metadata(unit) {
                cpp_template_metadata.insert(unit.clone(), metadata);
            }
        }
        let mut cpp_template_families: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for (unit, metadata) in &cpp_template_metadata {
            cpp_template_families
                .entry(metadata.primary_fq_name.clone())
                .or_default()
                .push(unit.clone());
        }
        Self {
            cpp,
            visible_by_file,
            visible_by_identifier,
            global_field_internal_linkage,
            visible_source_files_by_root,
            alias_cells: Mutex::new(HashMap::default()),
            visible_parser_alias_name_sets: RwLock::new(HashMap::default()),
            visible_parser_alias_target_names: Mutex::new(HashMap::default()),
            ordinary_type_import_cells: Mutex::new(HashMap::default()),
            project_using_index: OnceLock::new(),
            callable_reference_specs: Mutex::new(HashMap::default()),
            include_activation_cells: Mutex::new(HashMap::default()),
            conditional_include_projection_cells: Mutex::new(HashMap::default()),
            #[cfg(any(test, feature = "test-support"))]
            include_activation_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            using_donor_activation_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            using_namespace_lookup_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            using_name_candidate_inspection_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            using_source_index_walk_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            callable_reference_spec_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            alias_source_parse_counts: Mutex::new(HashMap::default()),
            #[cfg(any(test, feature = "test-support"))]
            visible_parser_alias_name_set_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            visible_parser_alias_target_names_build_count: AtomicUsize::new(0),
            field_type_facts: Mutex::new(HashMap::default()),
            structured_alias_targets: Mutex::new(HashMap::default()),
            indexed_structural_class_scopes: Mutex::new(HashMap::default()),
            indexed_enclosing_owner_scopes: Mutex::new(HashMap::default()),
            precise_parent_cache: Mutex::new(HashMap::default()),
            macro_event_cells: Mutex::new(HashMap::default()),
            macro_include_protection_cells: Mutex::new(HashMap::default()),
            macro_environment_cursors: Mutex::new(HashMap::default()),
            macro_replacements: Mutex::new(HashMap::default()),
            callable_parameter_macro_arities: Mutex::new(HashMap::default()),
            #[cfg(any(test, feature = "test-support"))]
            macro_replacement_parse_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            macro_event_application_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            macro_environment_copy_count: AtomicUsize::new(0),
            cpp_template_metadata,
            cpp_template_families,
            #[cfg(any(test, feature = "test-support"))]
            qualified_candidate_inspections: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            target_preserving_type_resolution_count: AtomicUsize::new(0),
        }
    }

    pub fn is_visible(&self, file: &ProjectFile, target: &CodeUnit) -> bool {
        if file == target.source() {
            return true;
        }
        if self.global_field_has_internal_linkage(target) {
            return self
                .visible_source_files_by_root
                .get(file)
                .is_some_and(|sources| sources.contains(target.source()));
        }
        self.visible_by_file
            .get(file)
            .is_some_and(|visible| visible.iter().any(|unit| same_visible_symbol(unit, target)))
    }

    fn global_field_has_internal_linkage(&self, unit: &CodeUnit) -> bool {
        self.global_field_internal_linkage
            .get(unit)
            .copied()
            .unwrap_or_else(|| cpp_global_field_has_internal_linkage(&self.cpp_source(), unit))
    }

    pub fn call_arity_evidence(
        &self,
        file: &ProjectFile,
        call: Node<'_>,
        source: &str,
    ) -> CallArityEvidence {
        let Some(arguments) = call
            .child_by_field_name("arguments")
            .or_else(|| call.child_by_field_name("parameters"))
            .or_else(|| call.child_by_field_name("value"))
            .or_else(|| first_named_child_of_kind(call, "argument_list"))
            .or_else(|| first_named_child_of_kind(call, "initializer_list"))
        else {
            return CallArityEvidence::Exact(0);
        };
        let arguments = argument_children(arguments).collect::<Vec<_>>();
        if arguments
            .iter()
            .all(|argument| !argument_shape_may_change_arity(*argument))
        {
            return CallArityEvidence::Exact(arguments.len());
        }
        let environment = self.macro_environment(file, call.start_byte());
        let mut stack = Vec::new();
        let mut total = 0usize;
        for argument in arguments {
            if !macro_expansion_shape_is_safe(argument, source, &[], &environment) {
                return CallArityEvidence::Unknown;
            }
            let CallArityEvidence::Exact(spread) =
                self.argument_arity_evidence(argument, source, &environment, &mut stack)
            else {
                return CallArityEvidence::Unknown;
            };
            total += spread;
        }
        CallArityEvidence::Exact(total)
    }

    fn argument_arity_evidence(
        &self,
        argument: Node<'_>,
        source: &str,
        environment: &MacroEnvironment,
        stack: &mut Vec<(ProjectFile, usize)>,
    ) -> CallArityEvidence {
        let (name, invocation_arguments, function_like) = match argument.kind() {
            "identifier" => (node_text(argument, source), None, false),
            "call_expression" => {
                let Some(function) = argument.child_by_field_name("function") else {
                    return CallArityEvidence::Exact(1);
                };
                if function.kind() != "identifier" {
                    return CallArityEvidence::Exact(1);
                }
                let Some(arguments) = argument.child_by_field_name("arguments") else {
                    return CallArityEvidence::Exact(1);
                };
                (node_text(function, source), Some(arguments), true)
            }
            _ => return CallArityEvidence::Exact(1),
        };
        let Some(binding) = environment.binding(name) else {
            return if environment.unknown_names {
                CallArityEvidence::Unknown
            } else {
                CallArityEvidence::Exact(1)
            };
        };
        match (&binding.definition, invocation_arguments, function_like) {
            (MacroDefinition::Object { replacement }, None, false) => self
                .replacement_arity_evidence(
                    replacement,
                    &[],
                    &[],
                    source,
                    environment,
                    stack,
                    binding,
                ),
            (
                MacroDefinition::Function {
                    parameters,
                    replacement,
                },
                Some(arguments),
                true,
            ) => {
                let actuals = argument_children(arguments).collect::<Vec<_>>();
                if actuals.len() != parameters.len() {
                    CallArityEvidence::Unknown
                } else {
                    self.replacement_arity_evidence(
                        replacement,
                        parameters,
                        &actuals,
                        source,
                        environment,
                        stack,
                        binding,
                    )
                }
            }
            (MacroDefinition::Function { .. }, None, false) => CallArityEvidence::Exact(1),
            _ => CallArityEvidence::Unknown,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn replacement_arity_evidence(
        &self,
        replacement: &str,
        parameters: &[String],
        actuals: &[Node<'_>],
        actual_source: &str,
        environment: &MacroEnvironment,
        stack: &mut Vec<(ProjectFile, usize)>,
        binding: &MacroBinding,
    ) -> CallArityEvidence {
        let identity = (binding.source.clone(), binding.declaration_byte);
        if stack.contains(&identity) || replacement.trim().is_empty() {
            return CallArityEvidence::Unknown;
        }
        stack.push(identity);
        let parsed = self.parsed_macro_replacement(binding, replacement);
        let evidence = (|| {
            let ParsedMacroReplacement::Parsed {
                source: sentinel,
                tree,
            } = parsed.as_ref()
            else {
                return None;
            };
            let call = first_descendant_of_kind(tree.root_node(), "call_expression")?;
            let arguments = call.child_by_field_name("arguments")?;
            let mut total = 0usize;
            for argument in argument_children(arguments) {
                if !macro_expansion_shape_is_safe(argument, sentinel, parameters, environment) {
                    return None;
                }
                if argument.kind() == "identifier"
                    && let Some(parameter_index) = parameters
                        .iter()
                        .position(|parameter| parameter == node_text(argument, sentinel))
                {
                    if !macro_expansion_shape_is_safe(
                        actuals[parameter_index],
                        actual_source,
                        &[],
                        environment,
                    ) {
                        return None;
                    }
                    let CallArityEvidence::Exact(spread) = self.argument_arity_evidence(
                        actuals[parameter_index],
                        actual_source,
                        environment,
                        stack,
                    ) else {
                        return None;
                    };
                    total += spread;
                    continue;
                }
                let CallArityEvidence::Exact(spread) =
                    self.argument_arity_evidence(argument, sentinel, environment, stack)
                else {
                    return None;
                };
                total += spread;
            }
            Some(CallArityEvidence::Exact(total))
        })()
        .unwrap_or(CallArityEvidence::Unknown);
        stack.pop();
        evidence
    }

    fn parsed_macro_replacement(
        &self,
        binding: &MacroBinding,
        replacement: &str,
    ) -> Arc<ParsedMacroReplacement> {
        let key = (binding.source.clone(), binding.declaration_byte);
        let mut cache = self
            .macro_replacements
            .lock()
            .expect("C++ macro replacement cache poisoned");
        if let Some(parsed) = cache.get(&key) {
            return Arc::clone(parsed);
        }
        #[cfg(any(test, feature = "test-support"))]
        self.macro_replacement_parse_count
            .fetch_add(1, Ordering::Relaxed);
        let source =
            format!("void __bifrost_macro_arity() {{ __bifrost_macro_call({replacement}); }}");
        let mut parser = Parser::new();
        let parsed = parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .ok()
            .and_then(|()| parser.parse(&source, None))
            .filter(|tree| !tree.root_node().has_error())
            .map_or(ParsedMacroReplacement::Unsupported, |tree| {
                ParsedMacroReplacement::Parsed { source, tree }
            });
        let parsed = Arc::new(parsed);
        cache.insert(key, Arc::clone(&parsed));
        parsed
    }

    fn decode_macro_definition(node: Node<'_>, source: &str) -> MacroDefinition {
        let Some(value) = node.child_by_field_name("value") else {
            return MacroDefinition::Unsupported;
        };
        let replacement = node_text(value, source).to_string();
        if node.kind() == "preproc_def" {
            return MacroDefinition::Object { replacement };
        }
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return MacroDefinition::Unsupported;
        };
        if (0..parameters.child_count()).any(|index| {
            parameters
                .child(index)
                .is_some_and(|child| child.kind() == "...")
        }) {
            return MacroDefinition::Unsupported;
        }
        let parameters = (0..parameters.named_child_count())
            .filter_map(|index| parameters.named_child(index))
            .map(|parameter| node_text(parameter, source).to_string())
            .collect();
        MacroDefinition::Function {
            parameters,
            replacement,
        }
    }

    pub fn macro_event_cell(&self, file: &ProjectFile) -> MacroEventCell {
        self.macro_event_cells
            .lock()
            .expect("C++ macro event cache poisoned")
            .entry(file.clone())
            .or_default()
            .clone()
    }

    pub fn macro_environment_cursor_cell(&self, file: &ProjectFile) -> MacroEnvironmentCursorCell {
        let key = (file.clone(), std::thread::current().id());
        self.macro_environment_cursors
            .lock()
            .expect("C++ macro environment cursor cache poisoned")
            .entry(key)
            .or_default()
            .clone()
    }

    pub fn macro_environment(
        &self,
        file: &ProjectFile,
        before_byte: usize,
    ) -> Arc<MacroEnvironment> {
        let cell = self.macro_event_cell(file);
        let events = cell.get_or_init(|| self.collect_macro_events(file).into_boxed_slice());
        let frontier = events.partition_point(|event| event.byte() < before_byte);
        let cursor_cell = self.macro_environment_cursor_cell(file);
        let mut cursor = cursor_cell
            .lock()
            .expect("C++ macro environment cursor poisoned");
        if frontier < cursor.frontier {
            *cursor = MacroEnvironmentCursor::default();
        }
        if frontier > cursor.frontier {
            #[cfg(any(test, feature = "test-support"))]
            if Arc::strong_count(&cursor.environment) > 1 {
                self.macro_environment_copy_count
                    .fetch_add(1, Ordering::Relaxed);
            }
            let start = cursor.frontier;
            let environment = Arc::make_mut(&mut cursor.environment);
            let mut include_stack = HashSet::from_iter([file.clone()]);
            for event in &events[start..frontier] {
                self.apply_macro_event(file, event, environment, &mut include_stack);
            }
            cursor.frontier = frontier;
        }
        Arc::clone(&cursor.environment)
    }

    pub fn object_macro_replacement_at(
        &self,
        file: &ProjectFile,
        name: &str,
        before_byte: usize,
    ) -> Option<String> {
        let environment = self.macro_environment(file, before_byte);
        let binding = environment.binding(name)?;
        if !binding.exact {
            return None;
        }
        match &binding.definition {
            MacroDefinition::Object { replacement } => Some(replacement.clone()),
            MacroDefinition::Function { .. } | MacroDefinition::Unsupported => None,
        }
    }

    fn apply_macro_events(
        &self,
        file: &ProjectFile,
        before_byte: Option<usize>,
        environment: &mut MacroEnvironment,
        include_stack: &mut HashSet<ProjectFile>,
    ) {
        if !include_stack.insert(file.clone()) {
            return;
        }
        if self.cpp.prepared_syntax(file).is_none() {
            environment.mark_unknown_names(file, before_byte.unwrap_or_default());
            include_stack.remove(file);
            return;
        }
        match self.macro_include_protection(file) {
            MacroIncludeProtection::MacroGuard(guard) => match environment.binding(&guard) {
                Some(binding) if binding.is_exact() => {
                    include_stack.remove(file);
                    return;
                }
                Some(_) | None if environment.unknown_names => {
                    let mut ambiguous_seen = HashSet::default();
                    self.mark_macro_events_ambiguous(
                        file,
                        environment,
                        &mut ambiguous_seen,
                        file,
                        before_byte.unwrap_or_default(),
                    );
                    include_stack.remove(file);
                    return;
                }
                Some(_) => {
                    let mut ambiguous_seen = HashSet::default();
                    self.mark_macro_events_ambiguous(
                        file,
                        environment,
                        &mut ambiguous_seen,
                        file,
                        before_byte.unwrap_or_default(),
                    );
                    include_stack.remove(file);
                    return;
                }
                None => {}
            },
            MacroIncludeProtection::PragmaOnce => {
                if !environment.applied_pragma_once_files.insert(file.clone()) {
                    include_stack.remove(file);
                    return;
                }
                if environment.maybe_applied_pragma_once_files.remove(file) {
                    // A prior conditional include may already have consumed the pragma-once
                    // header. This unconditional include guarantees it is consumed now, but
                    // cannot prove whether its events occur before or after intervening local
                    // macro changes, so preserve the union as ambiguous.
                    let mut ambiguous_seen = HashSet::default();
                    environment.applied_pragma_once_files.remove(file);
                    self.mark_macro_events_ambiguous(
                        file,
                        environment,
                        &mut ambiguous_seen,
                        file,
                        before_byte.unwrap_or_default(),
                    );
                    environment.maybe_applied_pragma_once_files.remove(file);
                    environment.applied_pragma_once_files.insert(file.clone());
                    include_stack.remove(file);
                    return;
                }
            }
            MacroIncludeProtection::None => {}
        }
        let cell = self.macro_event_cell(file);
        let events = cell.get_or_init(|| self.collect_macro_events(file).into_boxed_slice());
        for event in events {
            if before_byte.is_some_and(|limit| event.byte() >= limit) {
                break;
            }
            self.apply_macro_event(file, event, environment, include_stack);
        }
        include_stack.remove(file);
    }

    fn apply_macro_event(
        &self,
        file: &ProjectFile,
        event: &MacroEvent,
        environment: &mut MacroEnvironment,
        include_stack: &mut HashSet<ProjectFile>,
    ) {
        #[cfg(any(test, feature = "test-support"))]
        self.macro_event_application_count
            .fetch_add(1, Ordering::Relaxed);
        match event {
            MacroEvent::Define {
                name,
                binding,
                conditional,
                byte,
            } => {
                environment.insert(
                    name.clone(),
                    if *conditional {
                        MacroBinding::ambiguous(file, *byte)
                    } else {
                        binding.clone()
                    },
                );
            }
            MacroEvent::Undef {
                name,
                conditional,
                byte,
            } => {
                if *conditional {
                    if environment.binding(name).is_some() {
                        environment.insert(name.clone(), MacroBinding::ambiguous(file, *byte));
                    }
                } else {
                    environment.remove(name);
                }
            }
            MacroEvent::Include {
                targets,
                conditional,
                byte,
            } => {
                if targets.is_empty() {
                    environment.mark_unknown_names(file, *byte);
                    return;
                }
                if *conditional || targets.len() > 1 {
                    let mut ambiguous_seen = HashSet::default();
                    for target in targets {
                        self.mark_macro_events_ambiguous(
                            target,
                            environment,
                            &mut ambiguous_seen,
                            file,
                            *byte,
                        );
                    }
                } else if let Some(target) = targets.first() {
                    self.apply_macro_events(target, None, environment, include_stack);
                }
            }
            MacroEvent::Invalidate { byte } => {
                for binding in environment.bindings.values_mut() {
                    *binding = MacroBinding::ambiguous(file, *byte);
                }
            }
        }
    }

    fn mark_macro_events_ambiguous(
        &self,
        file: &ProjectFile,
        environment: &mut MacroEnvironment,
        include_stack: &mut HashSet<ProjectFile>,
        conditional_file: &ProjectFile,
        conditional_byte: usize,
    ) {
        if !include_stack.insert(file.clone()) {
            return;
        }
        if self.cpp.prepared_syntax(file).is_none() {
            environment.mark_unknown_names(conditional_file, conditional_byte);
            return;
        }
        match self.macro_include_protection(file) {
            MacroIncludeProtection::MacroGuard(guard) => {
                if environment
                    .binding(&guard)
                    .is_some_and(MacroBinding::is_exact)
                {
                    return;
                }
            }
            MacroIncludeProtection::PragmaOnce => {
                if environment.applied_pragma_once_files.contains(file) {
                    return;
                }
                environment
                    .maybe_applied_pragma_once_files
                    .insert(file.clone());
            }
            MacroIncludeProtection::None => {}
        }
        let cell = self.macro_event_cell(file);
        let events = cell.get_or_init(|| self.collect_macro_events(file).into_boxed_slice());
        for event in events {
            #[cfg(any(test, feature = "test-support"))]
            self.macro_event_application_count
                .fetch_add(1, Ordering::Relaxed);
            match event {
                MacroEvent::Define { name, .. } => {
                    environment.insert(
                        name.clone(),
                        MacroBinding::ambiguous(conditional_file, conditional_byte),
                    );
                }
                MacroEvent::Undef { name, .. } => {
                    if environment.binding(name).is_some() {
                        environment.insert(
                            name.clone(),
                            MacroBinding::ambiguous(conditional_file, conditional_byte),
                        );
                    }
                }
                MacroEvent::Include { targets, .. } => {
                    if targets.is_empty() {
                        environment.mark_unknown_names(conditional_file, conditional_byte);
                        continue;
                    }
                    for target in targets {
                        self.mark_macro_events_ambiguous(
                            target,
                            environment,
                            include_stack,
                            conditional_file,
                            conditional_byte,
                        );
                    }
                }
                MacroEvent::Invalidate { .. } => {
                    for binding in environment.bindings.values_mut() {
                        *binding = MacroBinding::ambiguous(conditional_file, conditional_byte);
                    }
                }
            }
        }
    }

    pub fn macro_include_protection(&self, file: &ProjectFile) -> MacroIncludeProtection {
        let cell = self
            .macro_include_protection_cells
            .lock()
            .expect("C++ include protection cache poisoned")
            .entry(file.clone())
            .or_default()
            .clone();
        cell.get_or_init(|| {
            self.cpp
                .prepared_syntax(file)
                .map_or(MacroIncludeProtection::None, |prepared| {
                    top_level_macro_include_protection(
                        prepared.tree().root_node(),
                        prepared.source(),
                    )
                })
        })
        .clone()
    }

    fn collect_macro_events(&self, file: &ProjectFile) -> Vec<MacroEvent> {
        let Some(prepared) = self.cpp.prepared_syntax(file) else {
            return Vec::new();
        };
        let source = prepared.source();
        let mut events = Vec::new();
        let mut stack = vec![prepared.tree().root_node()];
        while let Some(node) = stack.pop() {
            let conditional = has_preprocessor_conditional_ancestor(node, source);
            match node.kind() {
                "preproc_def" | "preproc_function_def" => {
                    let Some(name) = node.child_by_field_name("name") else {
                        continue;
                    };
                    let name = node_text(name, source).to_string();
                    events.push(MacroEvent::Define {
                        name,
                        binding: MacroBinding {
                            source: file.clone(),
                            declaration_byte: node.start_byte(),
                            definition: Self::decode_macro_definition(node, source),
                            exact: true,
                        },
                        byte: node.start_byte(),
                        conditional,
                    });
                    continue;
                }
                "preproc_include" => {
                    let Some(path) = node.child_by_field_name("path") else {
                        events.push(MacroEvent::Include {
                            targets: Vec::new(),
                            byte: node.start_byte(),
                            conditional,
                        });
                        continue;
                    };
                    let targets =
                        structured_include_path(path, source).map_or_else(Vec::new, |path| {
                            resolve_include_targets_with_index(
                                file,
                                path,
                                self.cpp.include_target_index(),
                            )
                        });
                    // An unresolved angle-bracket include crosses into an external system
                    // boundary that is absent from the source index. It must not poison all
                    // later local macro evidence. Quoted/project-local and computed includes,
                    // by contrast, may hide indexed macro state and therefore fail closed.
                    if targets.is_empty() && path.kind() == "system_lib_string" {
                        continue;
                    }
                    events.push(MacroEvent::Include {
                        targets,
                        byte: node.start_byte(),
                        conditional,
                    });
                    continue;
                }
                "preproc_call" => {
                    let Some(directive) = node.child_by_field_name("directive") else {
                        continue;
                    };
                    if node_text(directive, source) != "#undef" {
                        continue;
                    }
                    let name = node
                        .child_by_field_name("argument")
                        .and_then(|argument| parse_preproc_identifier(node_text(argument, source)));
                    if let Some(name) = name {
                        events.push(MacroEvent::Undef {
                            name,
                            byte: node.start_byte(),
                            conditional,
                        });
                    } else {
                        events.push(MacroEvent::Invalidate {
                            byte: node.start_byte(),
                        });
                    }
                    continue;
                }
                _ => {}
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        events.sort_by_key(MacroEvent::byte);
        events
    }

    pub fn ordinary_type_import_cell(&self, file: &ProjectFile) -> OrdinaryTypeImportCell {
        self.ordinary_type_import_cells
            .lock()
            .expect("C++ ordinary type import cache poisoned")
            .entry(file.clone())
            .or_insert_with(|| Arc::new(EffectiveUsingIndex::new(file.clone())))
            .clone()
    }

    pub fn project_using_index(
        &self,
        build: impl FnOnce() -> ProjectUsingIndex,
    ) -> &ProjectUsingIndex {
        self.project_using_index.get_or_init(build)
    }

    pub fn all_visible_source_files(&self) -> Vec<ProjectFile> {
        let mut files = self
            .visible_source_files_by_root
            .values()
            .flatten()
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        files.sort_by(|left, right| left.rel_path().cmp(right.rel_path()));
        files
    }

    pub fn source_is_visible(&self, root: &ProjectFile, source: &ProjectFile) -> bool {
        self.visible_source_files_by_root
            .get(root)
            .is_some_and(|files| files.contains(source))
    }

    fn visible_parser_alias_name_is_visible(&self, file: &ProjectFile, name: &str) -> bool {
        let cached = self
            .visible_parser_alias_name_sets
            .read()
            .expect("visible parser alias-name cache poisoned")
            .get(file)
            .cloned();
        let cell = if let Some(cached) = cached {
            cached
        } else {
            let mut cells = self
                .visible_parser_alias_name_sets
                .write()
                .expect("visible parser alias-name cache poisoned");
            Arc::clone(
                cells
                    .entry(file.clone())
                    .or_insert_with(|| Arc::new(OnceLock::new())),
            )
        };
        cell.get_or_init(|| {
            #[cfg(any(test, feature = "test-support"))]
            self.visible_parser_alias_name_set_build_count
                .fetch_add(1, Ordering::Relaxed);
            let mut names = HashSet::default();
            let visible_files = self
                .visible_source_files_by_root
                .get(file)
                .cloned()
                .unwrap_or_else(|| HashSet::from_iter([file.clone()]));
            for visible_file in visible_files {
                let aliases = {
                    let mut cells = self.alias_cells.lock().expect("alias cell map lock");
                    Arc::clone(
                        cells
                            .entry(visible_file.clone())
                            .or_insert_with(|| Arc::new(OnceLock::new())),
                    )
                };
                for alias in aliases
                    .get_or_init(|| {
                        #[cfg(any(test, feature = "test-support"))]
                        {
                            *self
                                .alias_source_parse_counts
                                .lock()
                                .expect("alias source parse count lock")
                                .entry(visible_file.clone())
                                .or_default() += 1;
                        }
                        aliases_from_prepared_source(self.cpp, &visible_file).into_boxed_slice()
                    })
                    .iter()
                {
                    names.insert(alias.name.clone());
                }
            }
            names
        })
        .contains(name)
    }

    fn visible_parser_alias_names_for_target(
        &self,
        file: &ProjectFile,
        target: &CodeUnit,
    ) -> HashSet<String> {
        let cell = {
            let mut cells = self
                .visible_parser_alias_target_names
                .lock()
                .expect("visible parser alias-target cache poisoned");
            Arc::clone(
                cells
                    .entry(file.clone())
                    .or_insert_with(|| Arc::new(OnceLock::new())),
            )
        };
        let target_name = cpp_name_for(target);
        cell.get_or_init(|| {
            #[cfg(any(test, feature = "test-support"))]
            self.visible_parser_alias_target_names_build_count
                .fetch_add(1, Ordering::Relaxed);
            let visible_files = self
                .visible_source_files_by_root
                .get(file)
                .cloned()
                .unwrap_or_else(|| HashSet::from_iter([file.clone()]));
            let mut names_by_target = HashMap::<String, HashSet<String>>::default();
            for visible_file in visible_files {
                let aliases = {
                    let mut cells = self.alias_cells.lock().expect("alias cell map lock");
                    Arc::clone(
                        cells
                            .entry(visible_file.clone())
                            .or_insert_with(|| Arc::new(OnceLock::new())),
                    )
                };
                for alias in aliases
                    .get_or_init(|| {
                        #[cfg(any(test, feature = "test-support"))]
                        {
                            *self
                                .alias_source_parse_counts
                                .lock()
                                .expect("alias source parse count lock")
                                .entry(visible_file.clone())
                                .or_default() += 1;
                        }
                        aliases_from_prepared_source(self.cpp, &visible_file).into_boxed_slice()
                    })
                    .iter()
                {
                    for target_name in parser_alias_target_names(alias) {
                        names_by_target
                            .entry(target_name)
                            .or_default()
                            .insert(alias.name.clone());
                    }
                }
            }
            names_by_target
        })
        .get(&target_name)
        .cloned()
        .unwrap_or_default()
    }

    fn callable_arities_for_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        cpp: &dyn CppSource,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        spec: &TargetSpec,
    ) -> Vec<ActivatedCallableArity> {
        let Some(signature) = spec.target.signature() else {
            return Vec::new();
        };
        let Some(candidates) = self
            .visible_by_identifier
            .get(file)
            .and_then(|by_name| by_name.get(&spec.member_name))
        else {
            return Vec::new();
        };
        let differing_candidates = candidates
            .iter()
            .filter(|candidate| {
                candidate.is_function()
                    && candidate.fq_name() == spec.target.fq_name()
                    && candidate.signature() == Some(signature)
            })
            .filter_map(|candidate| {
                analyzer
                    .signature_metadata(candidate)
                    .into_iter()
                    .find_map(|metadata| metadata.callable_arity())
                    .filter(|arity| Some(*arity) != spec.callable_arity)
                    .map(|arity| (candidate, arity))
            })
            .collect::<Vec<_>>();
        if differing_candidates.is_empty() {
            return Vec::new();
        }
        let mut arities = Vec::with_capacity(differing_candidates.len());
        for (candidate, candidate_arity) in differing_candidates {
            let declaration_activation = if candidate.source() == file {
                callable_declaration_activation_in_file(analyzer, prepared, candidate, file)
            } else {
                cpp.prepared_syntax(candidate.source()).and_then(|syntax| {
                    callable_declaration_activation_in_file(
                        analyzer,
                        syntax.as_ref(),
                        candidate,
                        file,
                    )
                })
            };
            let Some(declaration_activation) = declaration_activation else {
                continue;
            };
            let activation_byte = if candidate.source() == file {
                Some(declaration_activation)
            } else {
                self.include_activation_for_source(cpp, file, prepared, candidate.source())
            };
            if let Some(activation_byte) = activation_byte {
                arities.push(ActivatedCallableArity {
                    activation_byte,
                    arity: candidate_arity,
                });
            }
        }
        arities
    }

    fn callable_parameter_macro_arity(
        &self,
        target: &CodeUnit,
        signature: Option<&str>,
    ) -> Option<CallableArity> {
        let parameter_types = cpp_signature_param_types(signature?)?;
        let [macro_name] = parameter_types.as_slice() else {
            return None;
        };
        if macro_name.is_empty()
            || !macro_name
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        {
            return None;
        }
        let cache_key = (target.source().clone(), macro_name.clone());
        if let Some(cached) = self
            .callable_parameter_macro_arities
            .lock()
            .expect("C++ callable parameter-macro arity cache poisoned")
            .get(&cache_key)
            .copied()
        {
            return cached;
        }
        let mut visible_files = HashSet::default();
        collect_include_closure(
            &self.cpp_source(),
            self.cpp.include_target_index(),
            target.source(),
            &mut visible_files,
            None,
        );
        let mut arities = Vec::new();
        for visible_file in visible_files {
            let cell = self.macro_event_cell(&visible_file);
            for event in
                cell.get_or_init(|| self.collect_macro_events(&visible_file).into_boxed_slice())
            {
                let MacroEvent::Define { name, binding, .. } = event else {
                    continue;
                };
                if name != macro_name {
                    continue;
                }
                let MacroDefinition::Object { replacement } = &binding.definition else {
                    continue;
                };
                let Some(arity) = parse_macro_parameter_list_arity(replacement) else {
                    continue;
                };
                if !arities.contains(&arity) {
                    arities.push(arity);
                }
            }
        }
        let resolved = (|| {
            let required = arities
                .iter()
                .filter_map(|arity| (0..=arity.total()).find(|count| arity.accepts(*count)))
                .min()?;
            let total = arities.iter().map(|arity| arity.total()).max()?;
            let repeated = arities
                .iter()
                .any(|arity| arity.accepts(arity.total().saturating_add(1)));
            // Preprocessor conditions can leave more than one object-like parameter
            // bundle active in the target header's include closure. Preserve their
            // conservative callable envelope instead of choosing whichever definition
            // happened to be visited first.
            Some(CallableArity::new(required, total, repeated))
        })();
        self.callable_parameter_macro_arities
            .lock()
            .expect("C++ callable parameter-macro arity cache poisoned")
            .insert(cache_key, resolved);
        resolved
    }

    pub fn include_activation_for_source(
        &self,
        cpp: &dyn CppSource,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        donor_source: &ProjectFile,
    ) -> Option<usize> {
        let key = (file.clone(), donor_source.clone());
        if let Some(cached) = self
            .include_activation_cells
            .lock()
            .expect("C++ include activation cache poisoned")
            .get(&key)
            .copied()
        {
            return cached;
        }
        #[cfg(any(test, feature = "test-support"))]
        self.include_activation_build_count
            .fetch_add(1, Ordering::Relaxed);
        let activation = find_include_activation(cpp, file, prepared, donor_source);
        let mut cells = self
            .include_activation_cells
            .lock()
            .expect("C++ include activation cache poisoned");
        *cells.entry(key).or_insert(activation)
    }

    pub fn conditional_include_projections_for_source(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        donor_source: &ProjectFile,
    ) -> Arc<[ConditionalIncludeProjection]> {
        let key = (file.clone(), donor_source.clone());
        if let Some(cached) = self
            .conditional_include_projection_cells
            .lock()
            .expect("C++ conditional include projection cache poisoned")
            .get(&key)
            .cloned()
        {
            return cached;
        }
        let projections: Arc<[ConditionalIncludeProjection]> =
            find_conditional_include_projections(self.cpp, file, prepared, donor_source).into();
        self.conditional_include_projection_cells
            .lock()
            .expect("C++ conditional include projection cache poisoned")
            .entry(key)
            .or_insert_with(|| Arc::clone(&projections))
            .clone()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn include_activation_build_count_for_test(&self) -> usize {
        self.include_activation_build_count.load(Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn note_using_donor_activation_for_test(&self) {
        self.using_donor_activation_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub fn note_using_donor_activation_for_test(&self) {}

    #[cfg(any(test, feature = "test-support"))]
    pub fn note_using_namespace_lookup_for_test(&self) {
        self.using_namespace_lookup_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub fn note_using_namespace_lookup_for_test(&self) {}

    #[cfg(any(test, feature = "test-support"))]
    pub fn note_using_name_candidate_inspection_for_test(&self) {
        self.using_name_candidate_inspection_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub fn note_using_name_candidate_inspection_for_test(&self) {}

    #[cfg(any(test, feature = "test-support"))]
    pub fn note_using_source_index_walk_for_test(&self) {
        self.using_source_index_walk_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub fn note_using_source_index_walk_for_test(&self) {}

    #[cfg(any(test, feature = "test-support"))]
    pub fn using_work_counts_for_test(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.using_source_index_walk_count.load(Ordering::Relaxed),
            self.using_donor_activation_count.load(Ordering::Relaxed),
            self.using_namespace_lookup_count.load(Ordering::Relaxed),
            self.callable_reference_spec_build_count
                .load(Ordering::Relaxed),
            self.using_name_candidate_inspection_count
                .load(Ordering::Relaxed),
        )
    }

    pub fn is_physically_visible(&self, file: &ProjectFile, target: &CodeUnit) -> bool {
        file == target.source()
            || self
                .visible_by_file
                .get(file)
                .is_some_and(|visible| visible.contains(target))
    }

    pub fn declaration_visible_at(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        declaration: &CodeUnit,
        reference_byte: usize,
    ) -> bool {
        self.visible_identifier_candidates(file, declaration.identifier())
            .filter(|candidate| {
                same_logical_symbol(candidate, declaration)
                    || flattened_macro_namespace_declaration_matches(
                        analyzer,
                        self.cpp,
                        file,
                        candidate,
                        declaration,
                        reference_byte,
                    )
            })
            .any(|candidate| {
                self.physical_declaration_visible_at(analyzer, file, candidate, reference_byte)
            })
    }

    pub fn callable_arity_at_reference(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference_byte: usize,
    ) -> Option<CallableArity> {
        let key = (file.clone(), logical_symbol_key(candidate));
        let cell = self
            .callable_reference_specs
            .lock()
            .expect("C++ callable reference-spec cache poisoned")
            .entry(key)
            .or_default()
            .clone();
        let spec = cell.get_or_init(|| {
            let prepared = self.cpp.prepared_syntax(file)?;
            let spec = TargetSpec::from_target(analyzer, candidate)?;
            let spec = spec
                .with_visible_callable_arities(analyzer, self.cpp, self, file, prepared.as_ref())
                .into_owned();
            #[cfg(any(test, feature = "test-support"))]
            self.callable_reference_spec_build_count
                .fetch_add(1, Ordering::Relaxed);
            Some(spec)
        });
        spec.as_ref()?.callable_arity_at(reference_byte)
    }

    fn physical_declaration_visible_at(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        declaration: &CodeUnit,
        reference_byte: usize,
    ) -> bool {
        let Some(prepared) = self.cpp.prepared_syntax(file) else {
            return false;
        };
        if declaration.source() == file {
            return callable_declaration_activation_in_file(
                analyzer,
                prepared.as_ref(),
                declaration,
                file,
            )
            .is_some_and(|activation| activation < reference_byte);
        }
        let Some(donor_syntax) = self.cpp.prepared_syntax(declaration.source()) else {
            return false;
        };
        if callable_declaration_activation_in_file(
            analyzer,
            donor_syntax.as_ref(),
            declaration,
            file,
        )
        .is_none()
        {
            return false;
        }
        self.include_activation_for_source(self.cpp, file, prepared.as_ref(), declaration.source())
            .is_some_and(|activation| activation < reference_byte)
    }

    pub fn external_type_candidate_visible_at(
        &self,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference_byte: usize,
    ) -> bool {
        if candidate.source() == file {
            return true;
        }
        let Some(prepared) = self.cpp.prepared_syntax(file) else {
            return false;
        };
        self.visible_identifier_candidates(file, candidate.identifier())
            .filter(|peer| same_logical_symbol(candidate, peer))
            .any(|peer| {
                peer.source() == file
                    || self
                        .include_activation_for_source(
                            self.cpp,
                            file,
                            prepared.as_ref(),
                            peer.source(),
                        )
                        .is_some_and(|activation| activation <= reference_byte)
            })
    }

    pub fn external_type_declaration_visible_at(
        &self,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference_byte: usize,
    ) -> bool {
        if candidate.source() == file {
            return true;
        }
        let Some(prepared) = self.cpp.prepared_syntax(file) else {
            return false;
        };
        self.include_activation_for_source(self.cpp, file, prepared.as_ref(), candidate.source())
            .is_some_and(|activation| activation <= reference_byte)
    }

    pub fn external_type_candidate_visible_in_context(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference: Node<'_>,
    ) -> bool {
        let Some(prepared) = self.cpp.prepared_syntax(file) else {
            return false;
        };
        let reference_guards = preprocessor_guard_environment(reference, prepared.source());

        let directly_visible = self
            .visible_identifier_candidates(file, candidate.identifier())
            .filter(|peer| same_logical_symbol(candidate, peer))
            .any(|peer| {
                declaration_guard_requirements(analyzer, self.cpp, peer)
                    .into_iter()
                    .any(|(declaration_byte, declaration_guards)| {
                        if peer.source() == file {
                            return declaration_byte < reference.start_byte()
                                && guard_requirements_hold_at_reference(
                                    &declaration_guards,
                                    reference_guards.as_ref(),
                                )
                                && self.preprocessor_guards_stable_between(
                                    file,
                                    declaration_byte,
                                    reference.start_byte(),
                                    &declaration_guards,
                                );
                        }
                        if self
                            .include_activation_for_source(
                                self.cpp,
                                file,
                                prepared.as_ref(),
                                peer.source(),
                            )
                            .is_some_and(|activation| {
                                activation <= reference.start_byte()
                                    && guard_requirements_hold_at_reference(
                                        &declaration_guards,
                                        reference_guards.as_ref(),
                                    )
                                    && self.preprocessor_guards_stable_between(
                                        file,
                                        0,
                                        reference.start_byte(),
                                        &declaration_guards,
                                    )
                            })
                        {
                            return true;
                        }
                        self.conditional_include_projections_for_source(
                            file,
                            prepared.as_ref(),
                            peer.source(),
                        )
                        .iter()
                        .any(|projection| {
                            let Some(required_guards) = merge_preprocessor_guards(
                                &projection.required_guards,
                                &declaration_guards,
                            ) else {
                                return false;
                            };
                            projection.activation_byte <= reference.start_byte()
                                && guard_requirements_hold_at_reference(
                                    &required_guards,
                                    reference_guards.as_ref(),
                                )
                                && self.preprocessor_guards_stable_between(
                                    file,
                                    0,
                                    reference.start_byte(),
                                    &required_guards,
                                )
                        })
                    })
            });
        let complementary = self
            .visible_identifier_candidates(file, candidate.identifier())
            .filter(|peer| {
                peer.kind() == candidate.kind()
                    && peer.fq_name() == candidate.fq_name()
                    && peer.source() == candidate.source()
            })
            .collect::<Vec<_>>();
        // A completed #if/#else family declares the shared source-level name
        // before this reference. A later macro mutation cannot revoke that
        // declaration. The family gate below rejects declarations split across
        // separate conditional blocks, where mutation can change coverage.
        let candidate_branch_compatible = reference_guards.as_ref().is_some_and(|active| {
            declaration_guard_requirements(analyzer, self.cpp, candidate)
                .iter()
                .any(|(_, required)| merge_preprocessor_guards(required, active).is_some())
        });
        let complementary_visible = candidate_branch_compatible
            && self.complementary_same_fqn_type_declarations(analyzer, &complementary, candidate)
            && if candidate.source() == file {
                declaration_guard_requirements(analyzer, self.cpp, candidate)
                    .iter()
                    .any(|(declaration_byte, _)| *declaration_byte < reference.start_byte())
            } else {
                self.include_activation_for_source(
                    self.cpp,
                    file,
                    prepared.as_ref(),
                    candidate.source(),
                )
                .is_some_and(|activation| activation <= reference.start_byte())
            };
        directly_visible || complementary_visible
    }

    pub fn is_exhaustive_same_fqn_type_declaration_family(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
    ) -> bool {
        let candidates = self
            .visible_identifier_candidates(file, candidate.identifier())
            .filter(|peer| {
                peer.kind() == candidate.kind()
                    && peer.fq_name() == candidate.fq_name()
                    && peer.source() == candidate.source()
            })
            .collect::<Vec<_>>();
        self.complementary_same_fqn_type_declarations(analyzer, &candidates, candidate)
    }

    /// Prove a nested type alias used as a dependent member-pointer owner when
    /// its owning class has mutually-exclusive declarations.  A common C++11
    /// compatibility shape provides the owning class in one preprocessor
    /// branch and aliases it to a standard-library type in the other branch;
    /// the nested fallback alias is therefore not itself active in every
    /// branch even though the qualified owner API is.
    ///
    /// This is deliberately narrower than ordinary type visibility.  The
    /// caller has already recovered a member-pointer owner path from the CST;
    /// this helper additionally requires the target's structured parent to
    /// match that path, physical source visibility, and exact preprocessor
    /// guard agreement with the parent declaration.  Only then may the
    /// parent's direct/complementary same-FQN visibility stand in for the
    /// nested terminal's active-branch check.
    pub fn dependent_member_pointer_alias_visible_in_context(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
        owner_components: &[String],
        reference: Node<'_>,
    ) -> bool {
        if !analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(candidate))
        {
            return false;
        }
        let Some((terminal, owner_prefix)) = owner_components.split_last() else {
            return false;
        };
        if terminal != candidate.identifier()
            || canonical_cpp_scope_components(candidate) != owner_components
        {
            return false;
        }
        let Some(expected_parent_fq_name) =
            brokk_bifrost_core::analyzer::default_parent_fq_name(candidate)
        else {
            return false;
        };
        let Some(parent_anchor) = type_owner_of(analyzer, candidate) else {
            return false;
        };
        if parent_anchor.fq_name() != expected_parent_fq_name.as_str()
            || parent_anchor.source() != candidate.source()
            || canonical_cpp_scope_components(&parent_anchor) != owner_prefix
        {
            return false;
        }

        // The ordinary path already handles unguarded aliases (and preserves
        // same-file declaration ordering).  This fallback is only for a
        // physically visible declaration whose guard is the owning branch's
        // guard, so reject a same-file declaration that appears after the
        // reference before considering guard compatibility.
        if !self.external_type_candidate_visible_at(file, candidate, reference.start_byte())
            || candidate.source() == file
                && !analyzer
                    .ranges(candidate)
                    .iter()
                    .any(|range| range.start_byte < reference.start_byte())
        {
            return false;
        }

        let candidate_guards = declaration_guard_requirements(analyzer, self.cpp, candidate);
        if candidate_guards.is_empty() {
            return false;
        }
        let same_guard_sets =
            |left: &[(usize, HashSet<PreprocessorGuard>)],
             right: &[(usize, HashSet<PreprocessorGuard>)]| {
                left.iter().all(|(_, left_guards)| {
                    right
                        .iter()
                        .any(|(_, right_guards)| left_guards == right_guards)
                })
            };
        let parent_candidates = self
            .visible_identifier_candidates(file, parent_anchor.identifier())
            .filter(|peer| {
                peer.kind() == parent_anchor.kind()
                    && peer.fq_name() == expected_parent_fq_name.as_str()
                    && peer.source() == parent_anchor.source()
                    && canonical_cpp_scope_components(peer) == owner_prefix
            })
            .filter_map(|peer| {
                let parent_guards = declaration_guard_requirements(analyzer, self.cpp, peer);
                (candidate_guards.len() == parent_guards.len()
                    && same_guard_sets(&candidate_guards, &parent_guards)
                    && same_guard_sets(&parent_guards, &candidate_guards))
                .then(|| (peer.clone(), parent_guards))
            })
            .collect::<Vec<_>>();
        let [(parent, _parent_guards)] = parent_candidates.as_slice() else {
            return false;
        };

        let Some(prepared) = self.cpp.prepared_syntax(file) else {
            return false;
        };
        let Some(reference_guards) = preprocessor_guard_environment(reference, prepared.source())
        else {
            return false;
        };
        // An external header selects its declaration branch before the
        // reference file is parsed. Require compatible reference guards, but
        // do not test the header's guard expression for stability in the
        // reference file. Same-file aliases still require that stability.
        if !candidate_guards.iter().any(|(_, target_guards)| {
            merge_preprocessor_guards(target_guards, &reference_guards).is_some()
                && (candidate.source() != file
                    || self.preprocessor_guards_stable_between(
                        file,
                        0,
                        reference.start_byte(),
                        target_guards,
                    ))
        }) {
            return false;
        }

        self.external_type_candidate_visible_in_context(analyzer, file, parent, reference)
    }

    /// Check a type candidate's preprocessor/import context without imposing
    /// ordinary declaration-before-reference ordering for same-file peers.
    ///
    /// C++ class scope makes member names visible throughout the complete
    /// class, including a trailing return type that appears before the member
    /// alias declaration in source order. Callers must first prove that the
    /// reference is inside the candidate's indexed class owner; this helper
    /// only relaxes the byte-order predicate while retaining guard and include
    /// activation checks.
    pub fn external_type_candidate_guard_compatible_in_context(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference: Node<'_>,
    ) -> bool {
        let Some(prepared) = self.cpp.prepared_syntax(file) else {
            return false;
        };
        let reference_guards = preprocessor_guard_environment(reference, prepared.source());

        self.visible_identifier_candidates(file, candidate.identifier())
            .filter(|peer| same_logical_symbol(candidate, peer))
            .any(|peer| {
                declaration_guard_requirements(analyzer, self.cpp, peer)
                    .into_iter()
                    .any(|(declaration_byte, declaration_guards)| {
                        if peer.source() == file {
                            let (start, end) = if declaration_byte <= reference.start_byte() {
                                (declaration_byte, reference.start_byte())
                            } else {
                                (reference.start_byte(), declaration_byte)
                            };
                            return guard_requirements_hold_at_reference(
                                &declaration_guards,
                                reference_guards.as_ref(),
                            ) && self.preprocessor_guards_stable_between(
                                file,
                                start,
                                end,
                                &declaration_guards,
                            );
                        }
                        if self
                            .include_activation_for_source(
                                self.cpp,
                                file,
                                prepared.as_ref(),
                                peer.source(),
                            )
                            .is_some_and(|activation| {
                                activation <= reference.start_byte()
                                    && guard_requirements_hold_at_reference(
                                        &declaration_guards,
                                        reference_guards.as_ref(),
                                    )
                                    && self.preprocessor_guards_stable_between(
                                        file,
                                        0,
                                        reference.start_byte(),
                                        &declaration_guards,
                                    )
                            })
                        {
                            return true;
                        }
                        self.conditional_include_projections_for_source(
                            file,
                            prepared.as_ref(),
                            peer.source(),
                        )
                        .iter()
                        .any(|projection| {
                            let Some(required_guards) = merge_preprocessor_guards(
                                &projection.required_guards,
                                &declaration_guards,
                            ) else {
                                return false;
                            };
                            projection.activation_byte <= reference.start_byte()
                                && guard_requirements_hold_at_reference(
                                    &required_guards,
                                    reference_guards.as_ref(),
                                )
                                && self.preprocessor_guards_stable_between(
                                    file,
                                    0,
                                    reference.start_byte(),
                                    &required_guards,
                                )
                        })
                    })
            })
    }

    pub fn type_candidate_may_be_visible_before_reference(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference_byte: usize,
    ) -> bool {
        let Some(prepared) = self.cpp.prepared_syntax(file) else {
            return false;
        };
        let root = prepared.tree().root_node();
        let end_byte = reference_byte
            .saturating_add(1)
            .min(prepared.source().len());
        let Some(reference) = root.descendant_for_byte_range(reference_byte, end_byte) else {
            return false;
        };
        self.external_type_candidate_visible_in_context(analyzer, file, candidate, reference)
    }

    pub fn preprocessor_guards_stable_between(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        guards: &HashSet<PreprocessorGuard>,
    ) -> bool {
        if guards.is_empty() || start_byte >= end_byte {
            return true;
        }
        let cell = self.macro_event_cell(file);
        let events = cell.get_or_init(|| self.collect_macro_events(file).into_boxed_slice());
        let mut visited = HashSet::from_iter([file.clone()]);
        !events.iter().any(|event| {
            event.byte() >= start_byte
                && event.byte() < end_byte
                && self.macro_event_may_mutate_guards(event, guards, &mut visited)
        })
    }

    fn macro_event_may_mutate_guards(
        &self,
        event: &MacroEvent,
        guards: &HashSet<PreprocessorGuard>,
        visited: &mut HashSet<ProjectFile>,
    ) -> bool {
        match event {
            MacroEvent::Define { name, .. } | MacroEvent::Undef { name, .. } => {
                guards.iter().any(|guard| guard.may_depend_on_macro(name))
            }
            MacroEvent::Include { targets, .. } => {
                targets.is_empty()
                    || targets
                        .iter()
                        .any(|target| self.source_may_mutate_guards(target, guards, visited))
            }
            MacroEvent::Invalidate { .. } => true,
        }
    }

    fn source_may_mutate_guards(
        &self,
        file: &ProjectFile,
        guards: &HashSet<PreprocessorGuard>,
        visited: &mut HashSet<ProjectFile>,
    ) -> bool {
        if !visited.insert(file.clone()) {
            return false;
        }
        let cell = self.macro_event_cell(file);
        let events = cell.get_or_init(|| self.collect_macro_events(file).into_boxed_slice());
        events
            .iter()
            .any(|event| self.macro_event_may_mutate_guards(event, guards, visited))
    }

    pub fn resolve_type(&self, file: &ProjectFile, raw_name: &str) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        self.type_candidates(file, &normalized)
            .into_iter()
            .next()
            .cloned()
    }

    pub fn resolve_type_node_result(
        &self,
        file: &ProjectFile,
        node: Node<'_>,
        source: &str,
    ) -> std::result::Result<Option<CodeUnit>, CppTemplateResolutionError> {
        let Some(primary) = self.resolve_type_node_primary(file, node, source) else {
            return Ok(None);
        };
        let Some(arguments) = cpp_template_reference_arguments(node, source) else {
            return Ok(Some(primary));
        };
        self.resolve_template_arguments(file, primary, &arguments)
            .map(Some)
    }

    pub fn resolve_type_node_primary(
        &self,
        file: &ProjectFile,
        node: Node<'_>,
        source: &str,
    ) -> Option<CodeUnit> {
        let components = cpp_type_name_components(node, source)?;
        self.resolve_type(file, &components.join("::"))
    }

    pub fn resolve_template_arguments(
        &self,
        file: &ProjectFile,
        primary: CodeUnit,
        arguments: &[CppTemplateExpression],
    ) -> std::result::Result<CodeUnit, CppTemplateResolutionError> {
        self.resolve_template_arguments_inner(file, primary, arguments, &mut HashSet::default())
    }

    fn resolve_template_arguments_inner(
        &self,
        file: &ProjectFile,
        primary: CodeUnit,
        arguments: &[CppTemplateExpression],
        seen_aliases: &mut HashSet<CodeUnit>,
    ) -> std::result::Result<CodeUnit, CppTemplateResolutionError> {
        if let Some(metadata) = self.cpp_template_metadata.get(&primary)
            && let Some(alias_target) = &metadata.alias_target
        {
            if !seen_aliases.insert(primary.clone()) {
                return Err(CppTemplateResolutionError::AliasCycle { alias: primary });
            }
            let (_, bindings) = cpp_bind_template_arguments(&metadata.parameters, arguments)
                .ok_or(CppTemplateResolutionError::ArgumentBinding)?;
            let target_name = alias_target.components.join("::");
            let target_primary = if alias_target.global {
                unique_logical_type_candidate(self.type_candidates(file, &target_name))
            } else {
                self.resolve_unique_type_for_declaration(file, &primary, &target_name)
            };
            let Some(target_primary) = target_primary else {
                // A dependent or external RHS cannot be canonicalized from the
                // indexed graph. Preserve the alias's direct identity instead
                // of inventing a target from its source spelling.
                return Ok(primary);
            };
            let Some(target_arguments) = &alias_target.arguments else {
                return Ok(target_primary);
            };
            let target_arguments = cpp_substitute_template_arguments(target_arguments, &bindings)
                .ok_or(CppTemplateResolutionError::Substitution)?;
            return self.resolve_template_arguments_inner(
                file,
                target_primary,
                &target_arguments,
                seen_aliases,
            );
        }

        let primary_fq_name = self
            .cpp_template_metadata
            .get(&primary)
            .map(|metadata| metadata.primary_fq_name.clone())
            .unwrap_or_else(|| primary.fq_name());
        let has_specialization_metadata = self
            .cpp_template_families
            .get(&primary_fq_name)
            .is_some_and(|family| family.iter().any(|unit| self.is_visible(file, unit)));
        if !has_specialization_metadata {
            return Ok(primary);
        }
        self.select_template_specialization(file, &primary, arguments)
    }

    fn select_template_specialization(
        &self,
        file: &ProjectFile,
        resolved: &CodeUnit,
        explicit_arguments: &[CppTemplateExpression],
    ) -> std::result::Result<CodeUnit, CppTemplateResolutionError> {
        let primary_fq_name = self
            .cpp_template_metadata
            .get(resolved)
            .map(|metadata| metadata.primary_fq_name.clone())
            .unwrap_or_else(|| resolved.fq_name());
        let family = self
            .cpp_template_families
            .get(&primary_fq_name)
            .ok_or(CppTemplateResolutionError::PrimarySelection)?;
        let primary_candidates = family
            .iter()
            .filter_map(|unit| {
                let metadata = self.cpp_template_metadata.get(unit)?;
                (metadata.specialization_arguments.is_empty() && self.is_visible(file, unit))
                    .then_some((unit, metadata))
            })
            .collect::<Vec<_>>();
        let primary_unit = primary_candidates
            .iter()
            .find_map(|(unit, _)| (*unit == resolved).then_some(*unit))
            .or_else(|| {
                primary_candidates
                    .iter()
                    .map(|(unit, _)| *unit)
                    .min_by_key(|unit| {
                        (
                            unit.source().to_string(),
                            unit.signature().unwrap_or_default(),
                        )
                    })
            })
            .ok_or(CppTemplateResolutionError::PrimarySelection)?;
        let primary_parameters =
            cpp_reconcile_primary_template_parameters(&primary_candidates, primary_unit)
                .ok_or(CppTemplateResolutionError::PrimarySelection)?;
        let (expanded, _) = cpp_bind_template_arguments(&primary_parameters, explicit_arguments)
            .ok_or(CppTemplateResolutionError::ArgumentBinding)?;

        let mut applicable = Vec::new();
        for unit in family {
            let Some(metadata) = self.cpp_template_metadata.get(unit) else {
                continue;
            };
            if metadata.specialization_arguments.is_empty() || !self.is_visible(file, unit) {
                continue;
            }
            if !cpp_specialization_matches(metadata, &expanded) {
                continue;
            }
            applicable.push((unit, metadata));
        }
        if applicable.is_empty() {
            return Ok(primary_unit.clone());
        }

        // A scalar constraint count cannot represent C++ partial ordering:
        // e.g. `<T*, U>` and `<T, int>` are incomparable for `<int*, int>`.
        // Select only a logical candidate whose structural pattern is strictly
        // more specialized than every other distinct applicable candidate.
        let winners = applicable
            .iter()
            .filter(|(candidate, candidate_metadata)| {
                applicable.iter().all(|(other, other_metadata)| {
                    same_visible_symbol(candidate, other)
                        || cpp_specialization_more_specialized(candidate_metadata, other_metadata)
                })
            })
            .copied()
            .collect::<Vec<_>>();
        let Some((selected, _)) = winners.first() else {
            // Mutually incomparable applicable candidates: every one of them
            // is a live contender.
            return Err(CppTemplateResolutionError::AmbiguousSpecialization {
                candidates: distinct_visible_symbols(applicable.iter().map(|(unit, _)| *unit)),
            });
        };
        if winners
            .iter()
            .any(|(unit, _)| !same_visible_symbol(unit, selected))
        {
            return Err(CppTemplateResolutionError::AmbiguousSpecialization {
                candidates: distinct_visible_symbols(winners.iter().map(|(unit, _)| *unit)),
            });
        }
        Ok((*selected).clone())
    }

    pub fn resolve_type_components_lexically(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
    ) -> LexicalTypeResolution {
        self.resolve_type_components_lexically_inner(
            analyzer,
            file,
            components,
            global,
            lexical_scope,
            TypeCandidateResolution::Canonical,
        )
    }

    pub fn resolve_type_components_lexically_for_forward(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
    ) -> LexicalTypeResolution {
        self.resolve_type_components_lexically_inner(
            analyzer,
            file,
            components,
            global,
            lexical_scope,
            TypeCandidateResolution::PreserveAlias,
        )
    }

    pub fn resolve_type_components_lexically_for_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
        target: &CodeUnit,
    ) -> LexicalTypeResolution {
        #[cfg(any(test, feature = "test-support"))]
        self.target_preserving_type_resolution_count
            .fetch_add(1, Ordering::Relaxed);
        self.resolve_type_components_lexically_inner(
            analyzer,
            file,
            components,
            global,
            lexical_scope,
            TypeCandidateResolution::PreserveTarget(target),
        )
    }

    pub fn coarse_unqualified_type_reference_may_resolve(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> bool {
        if name.is_empty() {
            return true;
        }
        self.visible_identifier_candidates(file, name)
            .any(|candidate| candidate.kind() == CodeUnitType::Class || is_type_alias(candidate))
            || self.visible_parser_alias_name_is_visible(file, name)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn structured_type_reference_may_resolve_to_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
        target: &CodeUnit,
    ) -> bool {
        if components.is_empty() {
            return true;
        }
        let Some(terminal) = components.last() else {
            return true;
        };
        let parser_alias_visible = self.visible_parser_alias_name_is_visible(file, terminal);
        if parser_alias_visible
            && self.parser_alias_resolves_to_type(analyzer, file, terminal, target)
        {
            return true;
        }
        let qualified_tiers = lexical_component_tiers(components, global, lexical_scope)
            .map(|qualified| qualified.join("::"))
            .collect::<Vec<_>>();
        let target_name = cpp_name_for(target);
        if qualified_tiers
            .iter()
            .any(|qualified| qualified == &target_name)
        {
            return true;
        }

        let mut saw_shape_candidate = parser_alias_visible;
        for candidate in self.visible_identifier_candidates(file, terminal) {
            if candidate.kind() != CodeUnitType::Class && !declared_type_alias(analyzer, candidate)
            {
                continue;
            }
            let candidate_name = cpp_name_for(candidate);
            let shape_matches = if global || components.len() > 1 {
                qualified_tiers
                    .iter()
                    .any(|qualified| qualified == &candidate_name)
            } else {
                true
            };
            if !shape_matches {
                continue;
            }
            saw_shape_candidate = true;
            if same_visible_symbol(candidate, target)
                || self.compatible_primary_template_redeclarations(candidate, target)
                || (declared_type_alias(analyzer, candidate)
                    && self.alias_candidate_may_preserve_target(analyzer, file, candidate, target))
            {
                return true;
            }
        }

        !saw_shape_candidate
    }

    pub fn target_preserving_reference_namespace(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        identifier: &str,
        target: &CodeUnit,
    ) -> Option<Vec<String>> {
        let mut namespace = None;
        for candidate in self.visible_identifier_candidates(file, identifier) {
            if candidate.kind() != CodeUnitType::Class && !declared_type_alias(analyzer, candidate)
            {
                continue;
            }
            if !(same_visible_symbol(candidate, target)
                || self.compatible_primary_template_redeclarations(candidate, target)
                || declared_type_alias(analyzer, candidate)
                    && self.structured_alias_primary_preserves_target(
                        analyzer, file, candidate, target,
                    ))
            {
                continue;
            }
            if namespace
                .as_ref()
                .is_some_and(|existing| existing != candidate.package_name())
            {
                return None;
            }
            namespace = Some(candidate.package_name().to_string());
        }
        let namespace = namespace?;
        Some(
            brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
                brokk_bifrost_core::analyzer::Language::Cpp,
                &namespace,
            ),
        )
    }

    pub fn resolve_imported_type_candidate(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        target: &CodeUnit,
        target_components: &[String],
        direct_target: Option<&CodeUnit>,
        preserve_alias: bool,
    ) -> LexicalTypeResolution {
        let candidates = [target];
        let resolution = if preserve_alias {
            TypeCandidateResolution::PreserveAlias
        } else {
            direct_target.map_or(
                TypeCandidateResolution::Canonical,
                TypeCandidateResolution::PreserveTarget,
            )
        };
        let Some(unit) = self.resolve_type_candidates(analyzer, file, &candidates, resolution)
        else {
            return LexicalTypeResolution::Ambiguous;
        };
        LexicalTypeResolution::Resolved {
            unit,
            components: target_components.to_vec(),
            candidates: vec![target.clone()],
        }
    }

    fn resolve_type_components_lexically_inner(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
        resolution: TypeCandidateResolution<'_>,
    ) -> LexicalTypeResolution {
        if components.is_empty() {
            return LexicalTypeResolution::Missing;
        }
        // A C++ class injects its own name into the class scope.  The indexed
        // FqName for that declaration is the class path itself (for example,
        // `n::raw_hash_set`), not a synthetic child named
        // `n::raw_hash_set::raw_hash_set`.  Ordinary lexical tiers append the
        // requested identifier to every scope component, so they cannot
        // represent that injected binding when the enclosing class is the
        // closest scope.  Recover the binding from the structured class path
        // before allowing lookup to fall through to an outer same-spelled
        // declaration.
        let mut injected = self.resolve_injected_class_name(
            analyzer,
            file,
            components,
            global,
            lexical_scope,
            resolution,
        );
        for (tier_index, qualified) in
            lexical_component_tiers(components, global, lexical_scope).enumerate()
        {
            let prefix_len = qualified.len().saturating_sub(components.len());
            if injected
                .as_ref()
                .is_some_and(|(owner_len, _)| prefix_len < *owner_len)
            {
                return injected
                    .take()
                    .expect("injected class resolution was just present")
                    .1;
            }
            let qualified_name = qualified.join("::");
            let candidates = self
                .type_candidates(file, &qualified_name)
                .into_iter()
                .filter(|candidate| canonical_cpp_name_matches(candidate, &qualified_name))
                .collect::<Vec<_>>();
            if candidates.is_empty() {
                if tier_index == 0 && !global && components.len() == 1 {
                    match self.resolve_inherited_type_for_lexical_scope(
                        analyzer,
                        file,
                        lexical_scope,
                        &components[0],
                        resolution,
                    ) {
                        LexicalTypeResolution::Missing => {}
                        inherited => return inherited,
                    }
                }
                continue;
            }
            let unit = self.resolve_type_candidates(analyzer, file, &candidates, resolution);
            let Some(unit) = unit else {
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

    fn resolve_injected_class_name(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        components: &[String],
        global: bool,
        lexical_scope: &[String],
        resolution: TypeCandidateResolution<'_>,
    ) -> Option<(usize, LexicalTypeResolution)> {
        if global
            || components.len() != 1
            || file.rel_path().extension().is_some_and(|ext| ext == "c")
            || matches!(resolution, TypeCandidateResolution::PreserveTarget(target) if !target.is_class())
        {
            return None;
        }
        let name = components.first()?;
        let mut matches: Vec<&CodeUnit> = Vec::new();
        let mut owner_len = 0;
        for candidate in self.visible_identifier_candidates(file, name) {
            if !candidate.is_class()
                || declared_type_alias(analyzer, candidate)
                || candidate.identifier() != name
            {
                continue;
            }
            let candidate_scope = canonical_cpp_scope_components(candidate);
            if candidate_scope.len() > lexical_scope.len()
                || !lexical_scope.starts_with(&candidate_scope)
                || candidate_scope.last().is_none_or(|last| last != name)
            {
                continue;
            }
            if candidate_scope.len() > owner_len {
                owner_len = candidate_scope.len();
                matches.clear();
            }
            if candidate_scope.len() == owner_len
                && !matches
                    .iter()
                    .any(|existing| same_logical_symbol(existing, candidate))
            {
                matches.push(candidate);
            }
        }
        if matches.is_empty() {
            return None;
        }
        // A same-named class at the current lexical boundary is already
        // represented by the ordinary namespace/class tier.  The injected
        // recovery is only needed when lookup is occurring inside a nested
        // class, where the enclosing class name is injected across that
        // additional class boundary.  Keeping this boundary strict avoids
        // treating qualified receiver/static-qualifier context as an
        // injected-name reference.
        if owner_len >= lexical_scope.len() {
            return None;
        }
        let owner_components = lexical_scope[..owner_len].to_vec();
        let resolved = self.resolve_type_candidates(analyzer, file, &matches, resolution);
        let resolution = resolved.map_or(LexicalTypeResolution::Ambiguous, |unit| {
            LexicalTypeResolution::Resolved {
                unit,
                components: owner_components,
                candidates: matches.into_iter().cloned().collect(),
            }
        });
        Some((owner_len, resolution))
    }

    fn resolve_inherited_type_for_lexical_scope(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        lexical_scope: &[String],
        name: &str,
        resolution: TypeCandidateResolution<'_>,
    ) -> LexicalTypeResolution {
        let Some(hierarchy) = analyzer.type_hierarchy_provider() else {
            return LexicalTypeResolution::Missing;
        };
        let lexical_owner_name = lexical_scope.join("::");
        if lexical_owner_name.is_empty() {
            return LexicalTypeResolution::Missing;
        }
        let owner_candidates = self
            .type_candidates(file, &lexical_owner_name)
            .into_iter()
            .filter(|candidate| {
                canonical_cpp_name_matches(candidate, &lexical_owner_name)
                    && !declared_type_alias(analyzer, candidate)
            })
            .collect::<Vec<_>>();
        if owner_candidates.is_empty() {
            return LexicalTypeResolution::Missing;
        }
        let Some(lexical_owner) = unique_logical_type_candidate(owner_candidates) else {
            return LexicalTypeResolution::Ambiguous;
        };

        let mut frontier = hierarchy.get_direct_ancestors(&lexical_owner);
        let mut visited_owners = HashSet::default();
        while !frontier.is_empty() {
            let mut level_matches: Vec<(CodeUnit, Vec<CodeUnit>)> = Vec::new();
            let mut next_frontier = Vec::new();
            for owner in frontier {
                if !visited_owners.insert(owner.fq_name()) {
                    continue;
                }
                let qualified_name = format!("{}::{name}", cpp_name_for(&owner));
                let candidates = self
                    .type_candidates(file, &qualified_name)
                    .into_iter()
                    .filter(|candidate| canonical_cpp_name_matches(candidate, &qualified_name))
                    .collect::<Vec<_>>();
                if candidates.is_empty() {
                    for ancestor in hierarchy.get_direct_ancestors(&owner) {
                        if !next_frontier
                            .iter()
                            .any(|existing: &CodeUnit| existing.fq_name() == ancestor.fq_name())
                        {
                            next_frontier.push(ancestor);
                        }
                    }
                    continue;
                }
                let Some(unit) =
                    self.resolve_type_candidates(analyzer, file, &candidates, resolution)
                else {
                    return LexicalTypeResolution::Ambiguous;
                };
                level_matches.push((unit, candidates.into_iter().cloned().collect::<Vec<_>>()));
            }
            if let Some((unit, candidates)) = level_matches.first().cloned() {
                let Some(first_declaration) = candidates.first() else {
                    return LexicalTypeResolution::Ambiguous;
                };
                if !level_matches.iter().all(|(_, declarations)| {
                    declarations
                        .iter()
                        .all(|declaration| same_logical_symbol(first_declaration, declaration))
                }) {
                    return LexicalTypeResolution::Ambiguous;
                }
                let mut components = lexical_scope.to_vec();
                components.push(name.to_string());
                return LexicalTypeResolution::Resolved {
                    unit,
                    components,
                    candidates,
                };
            }
            frontier = next_frontier;
        }
        LexicalTypeResolution::Missing
    }

    fn resolve_type_candidates(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidates: &[&CodeUnit],
        resolution: TypeCandidateResolution<'_>,
    ) -> Option<CodeUnit> {
        match resolution {
            TypeCandidateResolution::Canonical => {
                self.unique_canonical_type_candidate(analyzer, file, candidates)
            }
            TypeCandidateResolution::PreserveAlias => {
                unique_type_candidate_preserving_alias(analyzer, candidates)
            }
            TypeCandidateResolution::PreserveTarget(target) => {
                self.unique_type_candidate_preserving_target(analyzer, file, candidates, target)
            }
        }
    }

    pub fn resolve_callable_value_components_lexically(
        &self,
        analyzer: &CppGraphSource<'_>,
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
                .filter(|candidate| canonical_cpp_name_matches(candidate, &owner_name))
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
                    canonical_cpp_name_matches(candidate, &callable_name)
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
        analyzer: &CppGraphSource<'_>,
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

    pub fn canonical_type_unit(
        &self,
        analyzer: &CppGraphSource<'_>,
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

    pub fn canonical_visible_full_type_unit(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        unit: &CodeUnit,
    ) -> Option<CodeUnit> {
        let canonical = self.canonical_type_unit(analyzer, visible_from, unit)?;
        if cpp_class_declaration_strength(analyzer, &canonical)
            != CppClassDeclarationStrength::Forward
        {
            return Some(canonical);
        }
        let mut full = Vec::new();
        for candidate in self
            .visible_identifier_candidates(visible_from, canonical.identifier())
            .filter(|candidate| {
                candidate.is_class()
                    && candidate.fq_name() == canonical.fq_name()
                    && cpp_class_declaration_strength(analyzer, candidate)
                        == CppClassDeclarationStrength::Full
            })
        {
            if !full.iter().any(|existing| same_symbol(existing, candidate)) {
                full.push(candidate.clone());
            }
        }
        match full.len() {
            0 => Some(canonical),
            1 => full.pop(),
            _ => None,
        }
    }

    fn resolve_structured_alias_target(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        target: &StructuredAliasTarget,
    ) -> Option<CodeUnit> {
        let primary = self.resolve_structured_alias_primary(visible_from, declaration, target)?;
        let StructuredAliasTarget::Named { arguments, .. } = target else {
            return None;
        };
        match arguments {
            Some(arguments) => self
                .resolve_template_arguments(visible_from, primary, arguments)
                .ok(),
            None => Some(primary),
        }
    }

    fn resolve_structured_alias_primary(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        target: &StructuredAliasTarget,
    ) -> Option<CodeUnit> {
        let StructuredAliasTarget::Named {
            components, global, ..
        } = target
        else {
            return None;
        };
        let qualified = components.join("::");
        if *global {
            unique_logical_type_candidate(self.type_candidates(visible_from, &qualified))
        } else {
            self.resolve_unique_type_for_declaration(visible_from, declaration, &qualified)
        }
    }

    pub fn structured_alias_primary_preserves_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        candidate: &CodeUnit,
        target: &CodeUnit,
    ) -> bool {
        let mut current = candidate.clone();
        let mut seen = HashSet::default();
        let mut matched_target = false;
        loop {
            if same_visible_symbol(&current, target)
                || self.compatible_primary_template_redeclarations(&current, target)
            {
                matched_target = true;
            }
            if !seen.insert(current.clone()) {
                return false;
            }
            let Some(alias_target) = self.structured_alias_target(analyzer, &current) else {
                return matched_target;
            };
            if matches!(alias_target, StructuredAliasTarget::Builtin) {
                return matched_target;
            };
            let Some(primary) =
                self.resolve_structured_alias_primary(visible_from, &current, &alias_target)
            else {
                // A dependent member target such as `Detector<T>::type`
                // cannot be reduced to an indexed primary, but a preceding
                // structured alias hop may already have proven the requested
                // alias identity. Cycles still resolve a primary and are
                // rejected by `seen` above.
                return matched_target;
            };
            current = primary;
        }
    }

    pub fn structured_class_alias_resolves_to_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        alias: &CodeUnit,
        target: &CodeUnit,
    ) -> bool {
        let Some(owner) = type_owner_of(analyzer, alias).filter(CodeUnit::is_class) else {
            return false;
        };
        let Some(alias_target) = self.structured_alias_target(analyzer, alias) else {
            return false;
        };
        let StructuredAliasTarget::Named {
            components, global, ..
        } = &alias_target
        else {
            return false;
        };
        let lexical_scope = canonical_cpp_scope_components(&owner);
        match self.resolve_type_components_lexically_for_target(
            analyzer,
            visible_from,
            components,
            *global,
            &lexical_scope,
            target,
        ) {
            LexicalTypeResolution::Resolved {
                unit, candidates, ..
            } => {
                same_visible_symbol(&unit, target)
                    || self.same_template_member_identity(analyzer, &unit, target)
                    || candidates.iter().any(|candidate| {
                        same_visible_symbol(candidate, target)
                            || self.same_template_member_identity(analyzer, candidate, target)
                    })
            }
            LexicalTypeResolution::Ambiguous | LexicalTypeResolution::Missing => {
                self.structured_alias_primary_preserves_target(
                    analyzer,
                    visible_from,
                    alias,
                    target,
                ) || self.flattened_macro_namespace_alias_target_matches(
                    analyzer,
                    visible_from,
                    alias,
                    &alias_target,
                    target,
                )
            }
        }
    }

    fn flattened_macro_namespace_alias_target_matches(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        alias: &CodeUnit,
        alias_target: &StructuredAliasTarget,
        target: &CodeUnit,
    ) -> bool {
        let StructuredAliasTarget::Named {
            components,
            global: false,
            arguments: None,
        } = alias_target
        else {
            return false;
        };
        let Some((target_name, namespace_components)) = components.split_last() else {
            return false;
        };
        if namespace_components.is_empty()
            || target_name != target.identifier()
            || alias.source() != target.source()
            || alias.source() != visible_from
            || !target.is_class()
            || declared_type_alias(analyzer, target)
        {
            return false;
        }
        if self
            .resolve_structured_alias_target(visible_from, alias, alias_target)
            .is_some()
        {
            return false;
        }

        let alias_ranges = analyzer.ranges(alias);
        let target_ranges = analyzer.ranges(target);
        if alias_ranges.is_empty() || target_ranges.is_empty() {
            return false;
        }
        let alias_start = alias_ranges
            .iter()
            .map(|range| range.start_byte)
            .min()
            .expect("non-empty alias ranges have a minimum");
        let Some(prepared) = self.cpp.prepared_syntax(target.source()) else {
            return false;
        };
        let root = prepared.tree().root_node();
        let has_matching_declaration = target_ranges
            .iter()
            .filter(|range| range.end_byte <= alias_start)
            .filter_map(|range| node_for_exact_range(root, range))
            .any(|node| {
                flattened_macro_namespace_components(node, prepared.source())
                    .is_some_and(|recovered| recovered == namespace_components)
            });
        if !has_matching_declaration {
            return false;
        }

        let alias_guards = declaration_guard_requirements(analyzer, self.cpp, alias);
        let target_guards = declaration_guard_requirements(analyzer, self.cpp, target);
        guard_requirement_sets_match(&alias_guards, &target_guards)
    }

    pub fn template_alias_arguments_preserve_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        alias: &CodeUnit,
        arguments: &[CppTemplateExpression],
        target: &CodeUnit,
    ) -> bool {
        let Some(metadata) = self.cpp_template_metadata.get(alias) else {
            return false;
        };
        if metadata.alias_target.is_none()
            || cpp_bind_template_arguments(&metadata.parameters, arguments).is_none()
        {
            return false;
        }
        self.structured_alias_primary_preserves_target(analyzer, visible_from, alias, target)
    }

    pub fn is_primary_template(&self, unit: &CodeUnit) -> bool {
        self.cpp_template_metadata
            .get(unit)
            .is_some_and(|metadata| metadata.specialization_arguments.is_empty())
    }

    pub fn is_template_specialization(&self, unit: &CodeUnit) -> bool {
        self.cpp_template_metadata
            .get(unit)
            .is_some_and(|metadata| !metadata.specialization_arguments.is_empty())
    }

    pub fn same_template_owner_identity(&self, left: &CodeUnit, right: &CodeUnit) -> bool {
        same_visible_symbol(left, right)
            || self.compatible_primary_template_redeclarations(left, right)
    }

    pub fn same_template_member_identity(
        &self,
        analyzer: &CppGraphSource<'_>,
        left: &CodeUnit,
        right: &CodeUnit,
    ) -> bool {
        if same_visible_symbol(left, right) {
            return true;
        }
        if left.kind() != right.kind()
            || left.identifier() != right.identifier()
            || left.signature() != right.signature()
        {
            return false;
        }
        let (Some(left_owner), Some(right_owner)) =
            (analyzer.parent_of(left), analyzer.parent_of(right))
        else {
            return false;
        };
        left_owner.is_class()
            && right_owner.is_class()
            && self.same_template_owner_identity(&left_owner, &right_owner)
    }

    fn unique_canonical_type_candidate(
        &self,
        analyzer: &CppGraphSource<'_>,
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

    pub fn unique_type_candidate_preserving_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        candidates: &[&CodeUnit],
        target: &CodeUnit,
    ) -> Option<CodeUnit> {
        // C++ headers often expose one logical type through mutually exclusive
        // physical declarations, for example a class in the fallback branch
        // and a `using` alias to the standard-library type in the configured
        // branch. The index intentionally retains both declarations so forward
        // lookup can report each target. Preserve the requested target when
        // that is the only ambiguity: every candidate has the same type kind,
        // exact canonical FQN, and source file, and the requested declaration
        // itself is one of the physical candidates. Do not merge same-named
        // declarations from different files or namespaces; those remain
        // ambiguous and fail closed below.
        if self.alternate_same_fqn_type_declarations(analyzer, candidates, target) {
            return Some(target.clone());
        }
        let mut resolved_candidates = Vec::new();
        for candidate in candidates {
            let resolved =
                self.type_candidate_preserving_target(analyzer, visible_from, candidate, target)?;
            if resolved_candidates
                .iter()
                .any(|existing| same_visible_symbol(existing, &resolved))
            {
                continue;
            }
            resolved_candidates.push(resolved);
            if resolved_candidates.len() > 1 {
                return None;
            }
        }
        resolved_candidates.pop()
    }

    pub fn alternate_same_fqn_type_declarations(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidates: &[&CodeUnit],
        target: &CodeUnit,
    ) -> bool {
        let Some(first) = candidates.first() else {
            return false;
        };
        let same_api = first.kind() == target.kind()
            && first.fq_name() == target.fq_name()
            && first.source() == target.source()
            && candidates.iter().all(|candidate| {
                candidate.kind() == target.kind()
                    && candidate.fq_name() == target.fq_name()
                    && candidate.source() == target.source()
            })
            && candidates
                .iter()
                .any(|candidate| same_symbol(candidate, target))
            && candidates
                .iter()
                .any(|candidate| !same_logical_symbol(candidate, target));
        if !same_api {
            return false;
        }

        let requirements = candidates
            .iter()
            .map(|candidate| declaration_guard_requirements(analyzer, self.cpp, candidate))
            .collect::<Vec<_>>();
        requirements.len() > 1
            && requirements
                .iter()
                .all(|requirement| !requirement.is_empty())
            && requirements.iter().enumerate().all(|(index, left)| {
                requirements[index + 1..].iter().all(|right| {
                    left.iter().all(|(_, left_guards)| {
                        right.iter().all(|(_, right_guards)| {
                            merge_preprocessor_guards(left_guards, right_guards).is_none()
                        })
                    })
                })
            })
    }

    fn preprocessor_guard_terms_cover_all_paths(terms: &[HashSet<PreprocessorGuard>]) -> bool {
        let mut pending = vec![terms.to_vec()];
        while let Some(branch_terms) = pending.pop() {
            let mut normalized = Vec::new();
            let mut covers_branch = false;
            for term in branch_terms {
                if term.iter().any(|guard| term.contains(&guard.negated())) {
                    continue;
                }
                if term.is_empty() {
                    covers_branch = true;
                    break;
                }
                if !normalized.iter().any(|existing| existing == &term) {
                    normalized.push(term);
                }
            }
            if covers_branch {
                continue;
            }
            let Some(split_guard) = normalized
                .iter()
                .flat_map(|term| term.iter())
                .next()
                .cloned()
            else {
                return false;
            };
            let negated_guard = split_guard.negated();
            let mut when_defined = Vec::new();
            let mut when_undefined = Vec::new();
            for term in normalized {
                if term.contains(&negated_guard) {
                    // This term cannot hold when `split_guard` is true.
                } else if term.contains(&split_guard) {
                    let mut reduced = term.clone();
                    reduced.remove(&split_guard);
                    when_defined.push(reduced);
                } else {
                    when_defined.push(term.clone());
                }
                if term.contains(&split_guard) {
                    // This term cannot hold when `split_guard` is false.
                } else if term.contains(&negated_guard) {
                    let mut reduced = term;
                    reduced.remove(&negated_guard);
                    when_undefined.push(reduced);
                } else {
                    when_undefined.push(term);
                }
            }
            pending.push(when_defined);
            pending.push(when_undefined);
        }
        true
    }

    fn declarations_share_exhaustive_conditional_family(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidates: &[&CodeUnit],
    ) -> bool {
        // Guard terms alone cannot distinguish one #if family from separate
        // blocks whose macros changed between declarations. Require every
        // physical range to belong to one syntax-tree family with a terminal
        // #else before the terms can prove branch coverage.
        let mut family_range = None;
        for candidate in candidates {
            let Some(prepared) = self.cpp.prepared_syntax(candidate.source()) else {
                return false;
            };
            let root = prepared.tree().root_node();
            let mut candidate_family = None;
            for range in analyzer.ranges(candidate) {
                let Some(node) = root.descendant_for_byte_range(range.start_byte, range.end_byte)
                else {
                    return false;
                };
                let Some(family) = preprocessor_conditional_family_for_declaration(node) else {
                    return false;
                };
                let key = (family.start_byte(), family.end_byte());
                if candidate_family.is_some_and(|existing| existing != key) {
                    return false;
                }
                candidate_family = Some(key);
            }
            let Some(candidate_family) = candidate_family else {
                return false;
            };
            if family_range.is_some_and(|existing| existing != candidate_family) {
                return false;
            }
            family_range = Some(candidate_family);
        }
        family_range.is_some()
    }

    pub fn complementary_same_fqn_type_declarations(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidates: &[&CodeUnit],
        target: &CodeUnit,
    ) -> bool {
        if candidates.len() < 2
            || !self.alternate_same_fqn_type_declarations(analyzer, candidates, target)
            || !self.declarations_share_exhaustive_conditional_family(analyzer, candidates)
        {
            return false;
        }
        let requirements = candidates
            .iter()
            .map(|candidate| declaration_guard_requirements(analyzer, self.cpp, candidate))
            .collect::<Vec<_>>();
        let terms = requirements
            .into_iter()
            .flat_map(|ranges| ranges.into_iter().map(|(_, guards)| guards))
            .collect::<Vec<_>>();
        Self::preprocessor_guard_terms_cover_all_paths(&terms)
    }

    fn type_candidate_preserving_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        candidate: &CodeUnit,
        target: &CodeUnit,
    ) -> Option<CodeUnit> {
        let mut current = candidate.clone();
        let mut matched_target = same_visible_symbol(&current, target)
            || self.compatible_primary_template_redeclarations(&current, target);
        let mut seen = HashSet::default();
        loop {
            if !seen.insert(current.clone()) {
                return None;
            }
            let Some(alias_target) = self.structured_alias_target(analyzer, &current) else {
                return matched_target
                    .then(|| target.clone())
                    .or_else(|| current.is_class().then_some(current));
            };
            if self.flattened_macro_namespace_alias_target_matches(
                analyzer,
                visible_from,
                &current,
                &alias_target,
                target,
            ) {
                return Some(target.clone());
            }
            if matches!(alias_target, StructuredAliasTarget::Builtin) {
                return matched_target
                    .then(|| target.clone())
                    .or_else(|| current.is_class().then_some(current));
            }
            // A non-template alias can name a template alias with explicit
            // arguments (for example, `using Result = Expected<int>`).  When
            // the requested target is that alias's primary declaration, keep
            // the primary identity before expanding the RHS arguments.  The
            // expansion would otherwise canonicalize through the underlying
            // implementation type and lose the target spelling used by the
            // forward resolver.
            if !self.cpp_template_metadata.contains_key(&current)
                && let Some(primary) =
                    self.resolve_structured_alias_primary(visible_from, &current, &alias_target)
                && (same_visible_symbol(&primary, target)
                    || self.compatible_primary_template_redeclarations(&primary, target))
            {
                return Some(target.clone());
            }
            if same_visible_symbol(&current, target) {
                return Some(target.clone());
            }
            if self.cpp_template_metadata.contains_key(&current) {
                return None;
            }
            let Some(next) =
                self.resolve_structured_alias_target(visible_from, &current, &alias_target)
            else {
                return matched_target.then(|| target.clone());
            };
            current = next;
            matched_target |= same_visible_symbol(&current, target)
                || self.compatible_primary_template_redeclarations(&current, target);
        }
    }

    fn compatible_primary_template_redeclarations(
        &self,
        left: &CodeUnit,
        right: &CodeUnit,
    ) -> bool {
        let (Some(left_metadata), Some(right_metadata)) = (
            self.cpp_template_metadata.get(left),
            self.cpp_template_metadata.get(right),
        ) else {
            return false;
        };
        left_metadata.primary_fq_name == right_metadata.primary_fq_name
            && left_metadata.specialization_arguments.is_empty()
            && right_metadata.specialization_arguments.is_empty()
            && cpp_reconcile_primary_template_parameters(
                &[(left, left_metadata), (right, right_metadata)],
                right,
            )
            .is_some()
    }

    fn alias_candidate_may_preserve_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        candidate: &CodeUnit,
        target: &CodeUnit,
    ) -> bool {
        let mut current = candidate.clone();
        let mut seen = HashSet::default();
        loop {
            if same_visible_symbol(&current, target)
                || self.compatible_primary_template_redeclarations(&current, target)
            {
                return true;
            }
            if self.cpp_template_metadata.contains_key(&current) {
                return true;
            }
            let Some(alias_target) = self.structured_alias_target(analyzer, &current) else {
                return false;
            };
            let StructuredAliasTarget::Named {
                components,
                global,
                arguments,
            } = alias_target
            else {
                return false;
            };
            if arguments.is_some() || !seen.insert(current.clone()) {
                return true;
            }
            let qualified = components.join("::");
            let next = if global {
                unique_logical_type_candidate(self.type_candidates(visible_from, &qualified))
            } else {
                self.resolve_unique_type_for_declaration(visible_from, &current, &qualified)
            };
            let Some(next) = next else {
                return true;
            };
            current = next;
        }
    }

    fn resolve_unique_type_for_declaration(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        if let Some(namespace) = cpp_namespace_for(declaration) {
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

    pub fn resolves_to_type(
        &self,
        analyzer: &CppGraphSource<'_>,
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
        let Some(resolved) =
            self.unique_type_candidate_preserving_target(analyzer, file, &candidates, target)
        else {
            return false;
        };
        same_symbol(&resolved, target) || same_visible_symbol(&resolved, target)
    }

    pub fn alias_target(&self, alias: &CodeUnit) -> Option<CodeUnit> {
        let raw_target = type_alias_target_text(alias)?;
        let resolved = self.resolve_type_for_declaration(alias.source(), alias, raw_target)?;
        match resolved.kind() {
            CodeUnitType::Class => Some(resolved),
            _ if is_type_alias(&resolved) => self.alias_target(&resolved),
            _ => None,
        }
    }

    pub fn canonical_type_for_reference(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        let resolved = self.resolve_type(file, raw_name)?;
        self.alias_target(&resolved).or(Some(resolved))
    }

    pub fn parser_alias_resolves_to_type(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        raw_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let Some(alias_name) = normalize_reference_name(raw_name) else {
            return false;
        };
        let Some(cpp) = analyzer.cpp else {
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
        cpp: &dyn CppSource,
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
            #[cfg(any(test, feature = "test-support"))]
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

    #[cfg(any(test, feature = "test-support"))]
    pub fn visible_source_files_for_test(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        self.visible_source_files_by_root
            .get(file)
            .cloned()
            .unwrap_or_else(|| HashSet::from_iter([file.clone()]))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn alias_source_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.alias_source_parse_counts
            .lock()
            .expect("alias source parse count lock")
            .get(file)
            .copied()
            .unwrap_or(0)
    }

    pub fn resolve_named(
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

    pub fn contains_named_symbol(
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

    pub fn named_candidates(
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

    pub fn resolve_known_non_target(
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

    pub fn resolve_call_return_binding(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        raw_name: &str,
        arity: usize,
        lexical_namespace: Option<&str>,
        direct_type: Option<&CodeUnit>,
    ) -> Option<CppScanBinding> {
        let normalized = normalize_reference_name(raw_name)?;
        let mut candidates = Vec::new();
        for function in
            self.named_candidates_for_normalized(file, &normalized, TargetKind::FreeFunction)
        {
            if cpp_callable_arity(analyzer, function).accepts(arity)
                && !direct_type.is_some_and(|direct_type| {
                    self.callable_is_constructor_declaration(analyzer, function)
                        && type_owner_of(analyzer, function)
                            .is_some_and(|owner| same_visible_symbol(&owner, direct_type))
                })
            {
                candidates.push(function.clone());
            }
        }
        candidates = nearest_namespace_candidates(candidates, &normalized, lexical_namespace);
        unanimous_return_binding(analyzer, self, file, &candidates)
    }

    pub fn resolve_call_return_binding_without_arity(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        raw_name: &str,
        lexical_namespace: Option<&str>,
        direct_type: Option<&CodeUnit>,
    ) -> (bool, Option<CppScanBinding>) {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return (false, None);
        };
        let mut candidates = self
            .named_candidates_for_normalized(file, &normalized, TargetKind::FreeFunction)
            .into_iter()
            .filter(|function| {
                function.is_function()
                    && !direct_type.is_some_and(|direct_type| {
                        self.callable_is_constructor_declaration(analyzer, function)
                            && type_owner_of(analyzer, function)
                                .is_some_and(|owner| same_visible_symbol(&owner, direct_type))
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        candidates = nearest_namespace_candidates(candidates, &normalized, lexical_namespace);
        let has_candidates = !candidates.is_empty();
        (
            has_candidates,
            unanimous_return_binding(analyzer, self, file, &candidates),
        )
    }

    pub fn visible_identifier_candidates<'b>(
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

    /// Return terminal reference names that can denote `target` from `file`.
    ///
    /// The indexed candidate table covers ordinary declarations and aliases;
    /// parser-only aliases are read through their per-file cells so this path
    /// never reparses a source that has already been inspected by the visibility
    /// index.
    pub fn visible_type_reference_component_names_for_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        target: &CodeUnit,
    ) -> HashSet<String> {
        let mut names = HashSet::from_iter([target.identifier().to_string()]);
        if let Some(metadata) = self.cpp_template_metadata.get(target) {
            names.insert(metadata.primary_name.clone());
        }

        if let Some(by_identifier) = self.visible_by_identifier.get(file) {
            for (identifier, candidates) in by_identifier {
                if candidates.iter().any(|candidate| {
                    (candidate.is_class()
                        && (same_visible_symbol(candidate, target)
                            || self.compatible_primary_template_redeclarations(candidate, target)))
                        || (declared_type_alias(analyzer, candidate)
                            && self.alias_candidate_may_preserve_target(
                                analyzer, file, candidate, target,
                            ))
                }) {
                    names.insert(identifier.clone());
                }
            }
        }

        names.extend(self.visible_parser_alias_names_for_target(file, target));

        names
    }

    pub fn indexed_structural_class_scope(
        &self,
        file: &ProjectFile,
        class: Node<'_>,
        source: &str,
    ) -> Option<Vec<String>> {
        let key = (file.clone(), class.start_byte(), class.end_byte());
        if let Some(cached) = self
            .indexed_structural_class_scopes
            .lock()
            .expect("C++ indexed structural-class scope cache poisoned")
            .get(&key)
            .cloned()
        {
            return cached;
        }
        let resolved = (|| {
            let name = class.child_by_field_name("name")?;
            let identifier = if name.kind() == "template_type" {
                node_text(name.child_by_field_name("name")?, source).to_string()
            } else {
                let mut components = Vec::new();
                append_cpp_name_components(name, source, &mut components)?;
                components.last()?.clone()
            };
            let visible = self
                .visible_identifier_candidates(file, &identifier)
                .cloned()
                .collect::<Vec<_>>();
            let mut visible = visible;
            for candidate in
                self.visible_by_file
                    .get(file)
                    .into_iter()
                    .flatten()
                    .filter(|candidate| {
                        self.cpp_template_metadata
                            .get(candidate)
                            .is_some_and(|metadata| metadata.primary_name == identifier)
                    })
            {
                if !visible
                    .iter()
                    .any(|existing| same_logical_symbol(existing, candidate))
                {
                    visible.push(candidate.clone());
                }
            }
            // Built once per call rather than per candidate; `cpp_source` rebuilds
            // the five-field source from the same `self.cpp` on every call.
            let cpp_source = self.cpp_source();
            let candidates = visible
                .iter()
                .filter(|candidate| {
                    candidate.source() == file
                        && candidate.is_class()
                        && !declared_type_alias(&cpp_source, candidate)
                        && self.cpp.ranges(candidate).iter().any(|range| {
                            range.start_byte <= class.start_byte()
                                && class.end_byte() <= range.end_byte
                        })
                })
                .collect::<Vec<_>>();
            let owner = if name.kind() == "template_type" {
                let expected = normalize_cpp_whitespace(node_text(name, source));
                let interner = brokk_bifrost_core::analyzer::fq_name::segment_interner();
                let exact = candidates
                    .iter()
                    .copied()
                    .filter(|candidate| {
                        candidate
                            .fq()
                            .segments()
                            .iter()
                            .rev()
                            .find_map(|&segment| {
                                let (text, kind) = interner.resolve(segment);
                                matches!(
                                    kind,
                                    brokk_bifrost_core::analyzer::fq_name::SegmentKind::Type
                                        | brokk_bifrost_core::analyzer::fq_name::SegmentKind::Nested
                                )
                                .then_some(text)
                            })
                            .is_some_and(|text| text == expected)
                    })
                    .collect::<Vec<_>>();
                unique_logical_type_candidate(exact)
                    .or_else(|| unique_logical_type_candidate(candidates.clone()))?
            } else {
                unique_logical_type_candidate(candidates)?
            };
            Some(canonical_cpp_scope_components(&owner))
        })();
        self.indexed_structural_class_scopes
            .lock()
            .expect("C++ indexed structural-class scope cache poisoned")
            .insert(key, resolved.clone());
        resolved
    }

    pub fn indexed_enclosing_owner_scope(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        node: Node<'_>,
    ) -> Option<Vec<String>> {
        let anchor = std::iter::successors(Some(node), |current| current.parent())
            .find(|current| {
                matches!(
                    current.kind(),
                    "function_definition"
                        | "class_specifier"
                        | "struct_specifier"
                        | "union_specifier"
                )
            })
            .unwrap_or(node);
        let key = (file.clone(), anchor.start_byte(), anchor.end_byte());
        if let Some(cached) = self
            .indexed_enclosing_owner_scopes
            .lock()
            .expect("C++ indexed enclosing-owner scope cache poisoned")
            .get(&key)
            .cloned()
        {
            return cached;
        }
        let resolved = (|| {
            let range = Range {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            };
            let start = analyzer.enclosing_code_unit(file, &range)?;
            let owner = brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain(
                start,
                |unit| self.cached_precise_parent_of(analyzer, unit),
            )
            .find(|unit| {
                unit.is_class()
                    && !analyzer
                        .type_alias_provider()
                        .is_some_and(|provider| provider.is_type_alias(unit))
            })?;
            Some(canonical_cpp_scope_components(&owner))
        })();
        self.indexed_enclosing_owner_scopes
            .lock()
            .expect("C++ indexed enclosing-owner scope cache poisoned")
            .insert(key, resolved.clone());
        resolved
    }

    fn cached_precise_parent_of(
        &self,
        analyzer: &CppGraphSource<'_>,
        code_unit: &CodeUnit,
    ) -> Option<CodeUnit> {
        if let Some(cached) = self
            .precise_parent_cache
            .lock()
            .expect("C++ precise-parent cache poisoned")
            .get(code_unit)
            .cloned()
        {
            return cached;
        }
        let resolved = precise_parent_resolution(analyzer, code_unit).map(|owner| owner.unit);
        self.precise_parent_cache
            .lock()
            .expect("C++ precise-parent cache poisoned")
            .insert(code_unit.clone(), resolved.clone());
        resolved
    }

    pub fn callable_is_constructor_declaration(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidate: &CodeUnit,
    ) -> bool {
        if !candidate.is_function() {
            return false;
        }
        let Some(prepared) = self.cpp.prepared_syntax(candidate.source()) else {
            return false;
        };
        let root = prepared.tree().root_node();
        let candidate_ranges = analyzer.ranges(candidate);
        let enclosed_by_matching_type = candidate_ranges.iter().any(|range| {
            let mut current = root
                .descendant_for_byte_range(range.start_byte, range.end_byte)
                .and_then(|node| node.parent());
            while let Some(node) = current {
                if matches!(
                    node.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier"
                ) {
                    return node
                        .child_by_field_name("name")
                        .map(|name| terminal_name(node_text(name, prepared.source())))
                        .is_some_and(|name| name == candidate.identifier());
                }
                current = node.parent();
            }
            false
        });
        if enclosed_by_matching_type {
            return true;
        }
        let indexed_containment = analyzer
            .declarations(candidate.source())
            .into_iter()
            .filter(|unit| unit.is_class() && unit.identifier() == candidate.identifier())
            .any(|owner| {
                analyzer.ranges(&owner).iter().any(|owner_range| {
                    candidate_ranges.iter().any(|candidate_range| {
                        owner_range.start_byte <= candidate_range.start_byte
                            && candidate_range.end_byte <= owner_range.end_byte
                    })
                })
            });
        if indexed_containment {
            return true;
        }
        let metadata = analyzer.signature_metadata(candidate);
        !metadata.is_empty()
            && metadata
                .iter()
                .all(|signature| signature.return_type_text().is_none())
    }

    pub fn type_name_candidates<'b>(
        &'b self,
        file: &ProjectFile,
        normalized: &str,
    ) -> Vec<&'b CodeUnit> {
        self.candidate_units(file, normalized, TargetKind::Type)
    }

    pub fn visible_members_for_owner_name<'b>(
        &'b self,
        file: &ProjectFile,
        owner: &CodeUnit,
        name: &str,
    ) -> Vec<&'b CodeUnit> {
        self.visible_identifier_candidates(file, name)
            .filter(|unit| {
                // Structured owner pop on the unit's own `fq()` (shared with
                // `CodeUnitIndex::parent_of`), not a re-split of its rendered fqn
                // string.
                brokk_bifrost_core::analyzer::default_parent_fq_name(unit)
                    .is_some_and(|parent| parent == owner.fq_name())
            })
            .collect()
    }

    pub fn visible_member_for_owner_name(
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
        analyzer: &CppGraphSource<'_>,
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
        analyzer: &CppGraphSource<'_>,
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

    pub fn type_candidates<'b>(
        &'b self,
        file: &ProjectFile,
        normalized: &str,
    ) -> Vec<&'b CodeUnit> {
        let mut candidates = self
            .candidate_units(file, normalized, TargetKind::Type)
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class || is_type_alias(unit))
            .collect::<Vec<_>>();
        dedup_unit_refs(&mut candidates);
        candidates
    }

    pub fn named_candidates_for_normalized<'b>(
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

    pub fn candidate_units<'b>(
        &'b self,
        file: &ProjectFile,
        normalized: &str,
        kind: TargetKind,
    ) -> Vec<&'b CodeUnit> {
        if normalized.contains("::") {
            // `normalized` comes from `normalize_cpp_reference_text`, which
            // truncates at the first `(`/`{`/`<`, leaving a plain `::`-joined
            // qualified-id with no embedded `.`/`/`/`\` and operator tokens
            // kept intact by the shared splitter's operator merge — the same
            // domain `cpp_reference_fqn_candidates` below already parses with
            // the shared splitter. Re-tokenizing and taking the last segment
            // reproduces `rsplit("::").find(non-empty)`'s terminal-component
            // scan exactly.
            let Some(identifier) = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
                brokk_bifrost_core::analyzer::Language::Cpp,
                normalized,
            )
            .pop() else {
                return Vec::new();
            };
            let fqns = cpp_reference_fqn_candidates(normalized, kind);
            return self
                .visible_identifier_candidates(file, &identifier)
                .filter(|unit| {
                    #[cfg(any(test, feature = "test-support"))]
                    self.qualified_candidate_inspections
                        .fetch_add(1, Ordering::Relaxed);
                    fqns.iter().any(|fqn| unit.fq_name() == *fqn)
                        || canonical_cpp_name_matches(unit, normalized)
                })
                .collect();
        }
        self.visible_identifier_candidates(file, normalized)
            .collect()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_qualified_candidate_inspections(&self) {
        self.qualified_candidate_inspections
            .store(0, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn qualified_candidate_inspections(&self) -> usize {
        self.qualified_candidate_inspections.load(Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_target_preserving_type_resolution_count(&self) {
        self.target_preserving_type_resolution_count
            .store(0, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn target_preserving_type_resolution_count(&self) -> usize {
        self.target_preserving_type_resolution_count
            .load(Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn visible_parser_alias_name_set_build_count(&self) -> usize {
        self.visible_parser_alias_name_set_build_count
            .load(Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn visible_parser_alias_target_names_build_count(&self) -> usize {
        self.visible_parser_alias_target_names_build_count
            .load(Ordering::Relaxed)
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

pub struct VisibilityData {
    pub visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    pub visible_source_files_by_root: HashMap<ProjectFile, HashSet<ProjectFile>>,
}

pub fn build_visibility_data<F, D>(
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

pub enum VisibleMemberResolution {
    Callable(Vec<CodeUnit>),
    NonCallable,
    AmbiguousKind,
    Missing,
}

#[derive(Clone)]
pub enum EnclosingMemberOwnerResolution {
    Owner(CodeUnit),
    Ambiguous,
    Missing,
}

pub fn resolve_declaring_member_owner(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    receiver_owner: &CodeUnit,
    member_name: &str,
) -> EnclosingMemberOwnerResolution {
    let Some(hierarchy) = analyzer.type_hierarchy_provider() else {
        return EnclosingMemberOwnerResolution::Missing;
    };
    let Some(receiver_owner) =
        visibility.canonical_visible_full_type_unit(analyzer, file, receiver_owner)
    else {
        return EnclosingMemberOwnerResolution::Ambiguous;
    };
    let resolve_level = |frontier: &[CodeUnit]| {
        let mut member_owners = Vec::new();
        for raw_owner in frontier {
            let Some(owner) =
                visibility.canonical_visible_full_type_unit(analyzer, file, raw_owner)
            else {
                return EnclosingMemberOwnerResolution::Ambiguous;
            };
            for member in visibility.visible_members_for_owner_name(file, &owner, member_name) {
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
    // The first declaration on each structured base path hides deeper names,
    // regardless of whether its callable overload is applicable at a particular
    // call site. Applicability is checked only after this owner is established.
    let direct = resolve_level(std::slice::from_ref(&receiver_owner));
    if !matches!(direct, EnclosingMemberOwnerResolution::Missing) {
        return direct;
    }
    let mut stack = hierarchy.get_direct_ancestors(&receiver_owner);
    let mut propagated_counts: HashMap<CodeUnit, u8> = HashMap::default();
    let mut path_matches = Vec::new();
    while let Some(raw_owner) = stack.pop() {
        let Some(owner) = visibility.canonical_visible_full_type_unit(analyzer, file, &raw_owner)
        else {
            return EnclosingMemberOwnerResolution::Ambiguous;
        };
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

pub fn lexical_component_tiers<'a>(
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

pub fn build_visible_identifier_index(
    analyzer: &CppGraphSource<'_>,
    visible_by_file: &HashMap<ProjectFile, HashSet<CodeUnit>>,
    visible_source_files_by_root: &HashMap<ProjectFile, HashSet<ProjectFile>>,
    global_field_internal_linkage: &mut HashMap<CodeUnit, bool>,
) -> HashMap<ProjectFile, HashMap<String, Vec<CodeUnit>>> {
    let mut out = HashMap::default();
    for (file, visible) in visible_by_file {
        let mut by_identifier: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for unit in visible {
            if unit.is_field()
                && !visible_source_files_by_root
                    .get(file)
                    .is_some_and(|sources| sources.contains(unit.source()))
                && cpp_global_field_has_internal_linkage_cached(
                    analyzer,
                    global_field_internal_linkage,
                    unit,
                )
            {
                continue;
            }
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

pub fn cpp_reference_fqn_candidates(reference: &str, kind: TargetKind) -> Vec<String> {
    // Same domain as `candidate_units` above: `reference` is a plain
    // `::`-joined qualified-id with operator tokens kept intact by the shared
    // splitter's operator merge.
    let parts = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
        brokk_bifrost_core::analyzer::Language::Cpp,
        reference,
    );
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

pub fn infer_cpp_initializer_type(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    infer_cpp_initializer_binding(analyzer, visibility, file, source, node, None)
        .and_then(|binding| binding.unit)
}

pub fn infer_cpp_initializer_binding(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
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
            let direct_type_binding = visibility
                .resolve_type(file, function_text)
                .map(|unit| CppScanBinding::from_unit(unit, 0));
            if function.kind() == "template_function" && direct_type_binding.is_some() {
                let lexical_namespace = enclosing_namespace_context(node, source);
                let arity = visibility.call_arity_evidence(file, node, source).exact();
                if let Some(arity) = arity
                    && let Some(binding) = visibility.resolve_call_return_binding(
                        analyzer,
                        file,
                        function_text,
                        arity,
                        lexical_namespace.as_deref(),
                        direct_type_binding
                            .as_ref()
                            .and_then(|binding| binding.unit.as_ref()),
                    )
                {
                    return Some(binding);
                }
                let (has_callable, callable_binding) = visibility
                    .resolve_call_return_binding_without_arity(
                        analyzer,
                        file,
                        function_text,
                        lexical_namespace.as_deref(),
                        direct_type_binding
                            .as_ref()
                            .and_then(|binding| binding.unit.as_ref()),
                    );
                if let Some(binding) = callable_binding {
                    return Some(binding);
                }
                if has_callable {
                    return None;
                }
                return direct_type_binding;
            }
            let arity = visibility.call_arity_evidence(file, node, source).exact()?;
            let direct_type_binding_for_call = direct_type_binding.clone();
            resolve_static_method_call_return_binding(
                analyzer, visibility, file, source, function, arity,
            )
            .or(direct_type_binding)
            .or_else(|| {
                visibility.resolve_call_return_binding(
                    analyzer,
                    file,
                    function_text,
                    arity,
                    enclosing_namespace_context(node, source).as_deref(),
                    direct_type_binding_for_call
                        .as_ref()
                        .and_then(|binding| binding.unit.as_ref()),
                )
            })
            .or_else(|| {
                resolve_field_method_call_return_binding(
                    analyzer,
                    visibility,
                    file,
                    source,
                    function,
                    arity,
                    receiver_resolver,
                )
            })
        }),
        _ => None,
    }
}

fn resolve_static_method_call_return_binding(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    arity: usize,
) -> Option<CppScanBinding> {
    if function.kind() != "qualified_identifier" {
        return None;
    }
    let qualified = normalize_cpp_reference_text(node_text(function, source));
    // A C++ qualified-id is `::`-joined with no embedded delimiters in any
    // single component (the shared splitter's operator-token merge keeps
    // `operator+`-style names intact), so re-tokenizing with the shared
    // structured splitter and peeling the terminal segment reproduces
    // `rsplit_once("::")`'s (owner, member) split exactly — same shape as
    // `cpp_out_of_line_function_owner`'s `qualified` split above.
    let parts = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
        brokk_bifrost_core::analyzer::Language::Cpp,
        &qualified,
    );
    let (owner_text, member_name) = match parts.split_last() {
        Some((member, owner_parts)) if !owner_parts.is_empty() => {
            (owner_parts.join("::"), member.clone())
        }
        _ => {
            let scope = function.child_by_field_name("scope")?;
            let name = function.child_by_field_name("name")?;
            (
                node_text(scope, source).to_string(),
                node_text(name, source).to_string(),
            )
        }
    };
    let owner = visibility.resolve_type(file, &owner_text)?;
    let candidates = visibility
        .visible_members_for_owner_name(file, &owner, &member_name)
        .into_iter()
        .filter(|unit| unit.is_function() && cpp_callable_arity(analyzer, unit).accepts(arity))
        .cloned()
        .collect::<Vec<_>>();
    unanimous_return_binding(analyzer, visibility, file, &candidates)
}

fn resolve_field_method_call_return_binding(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
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
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
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
            let indirection = crate::call_match::cpp_type_text_pointer_depth(&return_text);
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

fn aliases_from_prepared_source(cpp: &dyn CppSource, file: &ProjectFile) -> Vec<CppAlias> {
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

pub fn collect_include_closure(
    analyzer: &CppGraphSource<'_>,
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

pub fn signature_arity(signature: Option<&str>) -> usize {
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

fn parse_macro_parameter_list_arity(replacement: &str) -> Option<CallableArity> {
    let source = format!("void __bifrost_macro_parameters({replacement});");
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(&source, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let declaration = root.named_child(0)?;
    let declarator = declaration.child_by_field_name("declarator")?;
    let parameters = declarator.child_by_field_name("parameters")?;
    let mut required = 0;
    let mut total = 0;
    let mut repeated = false;
    let mut cursor = parameters.walk();
    for parameter in parameters.children(&mut cursor) {
        match parameter.kind() {
            "parameter_declaration" => {
                if parameter.child_by_field_name("declarator").is_none()
                    && parameter
                        .child_by_field_name("type")
                        .is_some_and(|type_node| node_text(type_node, &source).trim() == "void")
                {
                    continue;
                }
                required += 1;
                total += 1;
            }
            "optional_parameter_declaration" => total += 1,
            "variadic_parameter" | "variadic_parameter_declaration" | "..." => {
                repeated = true;
            }
            _ => {}
        }
    }
    Some(CallableArity::new(required, total, repeated))
}

pub fn cpp_callable_arity(analyzer: &CppGraphSource<'_>, unit: &CodeUnit) -> CallableArity {
    analyzer
        .signature_metadata(unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| CallableArity::exact(signature_arity(unit.signature())))
}

fn merge_compatible_callable_arities(
    left: CallableArity,
    right: CallableArity,
) -> Option<CallableArity> {
    let total = left.total();
    let left_repeated = left.accepts(total.saturating_add(1));
    let right_repeated = right.accepts(right.total().saturating_add(1));
    if total != right.total() || left_repeated != right_repeated {
        return None;
    }
    let required = (0..=total).find(|arity| left.accepts(*arity) || right.accepts(*arity))?;
    Some(CallableArity::new(required, total, left_repeated))
}

fn find_include_activation(
    cpp: &dyn CppSource,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    donor_source: &ProjectFile,
) -> Option<usize> {
    let include_targets = cpp.include_target_index();
    let mut direct_includes = Vec::new();
    let mut nodes = vec![prepared.tree().root_node()];
    while let Some(node) = nodes.pop() {
        if node.kind() == "preproc_include" {
            if callable_preprocessor_context_is_visible_for_reference(node, prepared.source(), file)
            {
                let raw = normalize_cpp_whitespace(node_text(node, prepared.source()));
                for include in cpp_include_paths(std::slice::from_ref(&raw)) {
                    if let Some(target) = unique_include_target(resolve_include_targets_with_index(
                        file,
                        &include,
                        include_targets,
                    )) {
                        direct_includes.push((node.end_byte(), target));
                    }
                }
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                nodes.push(child);
            }
        }
    }
    direct_includes.sort_by_key(|(activation, _)| *activation);
    let mut known_missing = HashSet::default();
    direct_includes
        .into_iter()
        .find(|(_, direct)| {
            unconditional_include_reaches(
                cpp,
                include_targets,
                direct,
                donor_source,
                file,
                &mut known_missing,
            )
        })
        .map(|(activation, _)| activation)
}

fn find_conditional_include_projections(
    cpp: &dyn CppSource,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    donor_source: &ProjectFile,
) -> Vec<ConditionalIncludeProjection> {
    let include_targets = cpp.include_target_index();
    let mut projections = Vec::new();
    let mut nodes = vec![prepared.tree().root_node()];
    while let Some(node) = nodes.pop() {
        if node.kind() == "preproc_include" {
            let Some(required_guards) = preprocessor_guard_environment(node, prepared.source())
            else {
                continue;
            };
            let raw = normalize_cpp_whitespace(node_text(node, prepared.source()));
            for include in cpp_include_paths(std::slice::from_ref(&raw)) {
                let Some(target) = unique_include_target(resolve_include_targets_with_index(
                    file,
                    &include,
                    include_targets,
                )) else {
                    continue;
                };
                let paths = conditional_include_requirement_paths(
                    cpp,
                    &target,
                    donor_source,
                    required_guards.clone(),
                );
                for required_guards in paths {
                    if !projections
                        .iter()
                        .any(|projection: &ConditionalIncludeProjection| {
                            projection.activation_byte == node.end_byte()
                                && projection.required_guards == required_guards
                        })
                    {
                        projections.push(ConditionalIncludeProjection {
                            activation_byte: node.end_byte(),
                            required_guards,
                        });
                    }
                }
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                nodes.push(child);
            }
        }
    }
    projections.sort_by_key(|projection| projection.activation_byte);
    projections
}

fn conditional_include_requirement_paths(
    cpp: &dyn CppSource,
    first: &ProjectFile,
    donor_source: &ProjectFile,
    required_guards: HashSet<PreprocessorGuard>,
) -> Vec<HashSet<PreprocessorGuard>> {
    let include_targets = cpp.include_target_index();
    let mut paths = Vec::new();
    let mut stack = vec![(
        first.clone(),
        required_guards,
        HashSet::from_iter([first.clone()]),
    )];
    while let Some((file, required_guards, visited)) = stack.pop() {
        if file == *donor_source {
            if !paths.contains(&required_guards) {
                paths.push(required_guards);
            }
            continue;
        }
        let Some(prepared) = cpp.prepared_syntax(&file) else {
            continue;
        };
        let mut nodes = vec![prepared.tree().root_node()];
        while let Some(node) = nodes.pop() {
            if node.kind() == "preproc_include" {
                let Some(include_guards) = preprocessor_guard_environment(node, prepared.source())
                else {
                    continue;
                };
                let Some(path_guards) =
                    merge_preprocessor_guards(&required_guards, &include_guards)
                else {
                    continue;
                };
                let raw = normalize_cpp_whitespace(node_text(node, prepared.source()));
                for include in cpp_include_paths(std::slice::from_ref(&raw)) {
                    let Some(target) = unique_include_target(resolve_include_targets_with_index(
                        &file,
                        &include,
                        include_targets,
                    )) else {
                        continue;
                    };
                    if visited.contains(&target) {
                        continue;
                    }
                    let mut next_visited = visited.clone();
                    next_visited.insert(target.clone());
                    stack.push((target, path_guards.clone(), next_visited));
                }
                continue;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    nodes.push(child);
                }
            }
        }
    }
    paths
}

fn unconditional_include_reaches(
    cpp: &dyn CppSource,
    include_targets: &IncludeTargetIndex,
    first: &ProjectFile,
    donor_source: &ProjectFile,
    reference_file: &ProjectFile,
    known_missing: &mut HashSet<ProjectFile>,
) -> bool {
    if first == donor_source {
        return true;
    }
    if known_missing.contains(first) {
        return false;
    }
    let reference_is_c = reference_file
        .rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("c");
    if let Some(reaches) =
        cpp.cached_unconditional_include_reachability(first, donor_source, reference_is_c)
    {
        return reaches;
    }
    let mut visited = HashSet::default();
    let mut files = vec![first.clone()];
    while let Some(file) = files.pop() {
        if file == *donor_source {
            cpp.cache_unconditional_include_reachability(first, donor_source, reference_is_c, true);
            return true;
        }
        if known_missing.contains(&file) || !visited.insert(file.clone()) {
            continue;
        }
        let Some(prepared) = cpp.prepared_syntax(&file) else {
            continue;
        };
        let mut nodes = vec![prepared.tree().root_node()];
        while let Some(node) = nodes.pop() {
            if node.kind() == "preproc_include" {
                if callable_preprocessor_context_is_visible_for_reference(
                    node,
                    prepared.source(),
                    reference_file,
                ) {
                    let raw = normalize_cpp_whitespace(node_text(node, prepared.source()));
                    for include in cpp_include_paths(std::slice::from_ref(&raw)) {
                        if let Some(target) = unique_include_target(
                            resolve_include_targets_with_index(&file, &include, include_targets),
                        ) {
                            files.push(target);
                        }
                    }
                }
                continue;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    nodes.push(child);
                }
            }
        }
    }
    known_missing.extend(visited);
    cpp.cache_unconditional_include_reachability(first, donor_source, reference_is_c, false);
    false
}

fn declaration_guard_requirements(
    analyzer: &CppGraphSource<'_>,
    cpp: &dyn CppSource,
    candidate: &CodeUnit,
) -> Vec<(usize, HashSet<PreprocessorGuard>)> {
    let Some(prepared) = cpp.prepared_syntax(candidate.source()) else {
        return Vec::new();
    };
    let root = prepared.tree().root_node();
    analyzer
        .ranges(candidate)
        .into_iter()
        .filter_map(|range| {
            root.descendant_for_byte_range(range.start_byte, range.end_byte)
                .and_then(|node| preprocessor_guard_environment(node, prepared.source()))
                // A class name is injected into its own body at the declaration's
                // introduction point, not after the complete class range. Using
                // the start also preserves normal before/after ordering for aliases.
                .map(|required| (range.start_byte, required))
        })
        .collect()
}

fn guard_requirements_hold_at_reference(
    required: &HashSet<PreprocessorGuard>,
    reference: Option<&HashSet<PreprocessorGuard>>,
) -> bool {
    reference.is_some_and(|active| required.is_subset(active))
}

fn preprocessor_conditional_family_for_declaration(node: Node<'_>) -> Option<Node<'_>> {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if is_preprocessor_conditional(current) {
            let family = preprocessor_conditional_family_root(current);
            if preprocessor_conditional_family_has_terminal_else(family) {
                return Some(family);
            }
        }
        ancestor = current.parent();
    }
    None
}

fn preprocessor_conditional_family_root(mut conditional: Node<'_>) -> Node<'_> {
    while let Some(parent) = conditional.parent() {
        let is_alternative = parent
            .child_by_field_name("alternative")
            .is_some_and(|alternative| {
                alternative.start_byte() == conditional.start_byte()
                    && alternative.end_byte() == conditional.end_byte()
            });
        if !is_alternative {
            break;
        }
        conditional = parent;
    }
    conditional
}

fn preprocessor_conditional_family_has_terminal_else(mut conditional: Node<'_>) -> bool {
    loop {
        let Some(alternative) = conditional.child_by_field_name("alternative") else {
            return false;
        };
        match alternative.kind() {
            "preproc_else" => return true,
            "preproc_elif" => conditional = alternative,
            _ => return false,
        }
    }
}

pub fn preprocessor_guard_environment(
    node: Node<'_>,
    source: &str,
) -> Option<HashSet<PreprocessorGuard>> {
    let mut guards = HashSet::default();
    let mut ancestor = node.parent();
    while let Some(conditional) = ancestor {
        if matches!(
            conditional.kind(),
            "preproc_if" | "preproc_ifdef" | "preproc_elif"
        ) && !is_file_covering_include_guard(conditional, source)
        {
            let guard = preprocessor_guard_for_descendant(conditional, node, source)?;
            match guard {
                PreprocessorGuard::Constant(true) => {
                    ancestor = conditional.parent();
                    continue;
                }
                PreprocessorGuard::Constant(false) => return None,
                _ => {}
            }
            if guards.contains(&guard.negated()) {
                return None;
            }
            guards.insert(guard);
        }
        ancestor = conditional.parent();
    }
    Some(guards)
}

fn preprocessor_guard_for_descendant(
    conditional: Node<'_>,
    descendant: Node<'_>,
    source: &str,
) -> Option<PreprocessorGuard> {
    let mut guard = simple_preprocessor_guard(conditional, source)?;
    if conditional
        .child_by_field_name("alternative")
        .is_some_and(|alternative| {
            alternative.start_byte() <= descendant.start_byte()
                && descendant.end_byte() <= alternative.end_byte()
        })
    {
        let alternative = conditional.child_by_field_name("alternative")?;
        // Tree-sitter nests an `#elif` chain in each `alternative` field. A
        // descendant in any later branch must first exclude the parent branch,
        // then collect the nested `preproc_elif` guard from its own ancestor.
        if !matches!(alternative.kind(), "preproc_else" | "preproc_elif") {
            return None;
        }
        guard = guard.negated();
    }
    Some(guard)
}

pub fn merge_preprocessor_guards(
    left: &HashSet<PreprocessorGuard>,
    right: &HashSet<PreprocessorGuard>,
) -> Option<HashSet<PreprocessorGuard>> {
    let mut merged = left.clone();
    for guard in right {
        if merged.contains(&guard.negated()) {
            return None;
        }
        merged.insert(guard.clone());
    }
    Some(merged)
}

fn simple_preprocessor_guard(conditional: Node<'_>, source: &str) -> Option<PreprocessorGuard> {
    if conditional.kind() == "preproc_ifdef" {
        let name = conditional.child_by_field_name("name")?;
        let name = node_text(name, source).to_string();
        return match conditional.child(0)?.kind() {
            "#ifdef" => Some(PreprocessorGuard::Defined(name)),
            "#ifndef" => Some(PreprocessorGuard::Undefined(name)),
            _ => None,
        };
    }
    let condition = conditional.child_by_field_name("condition")?;
    simple_preprocessor_expression_guard(condition, source).or_else(|| {
        Some(PreprocessorGuard::Expression(normalize_cpp_whitespace(
            node_text(condition, source),
        )))
    })
}

fn simple_preprocessor_expression_guard(
    expression: Node<'_>,
    source: &str,
) -> Option<PreprocessorGuard> {
    match expression.kind() {
        "number_literal" => match node_text(expression, source).trim() {
            "0" => Some(PreprocessorGuard::Constant(false)),
            "1" => Some(PreprocessorGuard::Constant(true)),
            _ => None,
        },
        "preproc_defined" => {
            let identifier = (0..expression.named_child_count())
                .filter_map(|index| expression.named_child(index))
                .find(|child| child.kind() == "identifier")?;
            Some(PreprocessorGuard::Defined(
                node_text(identifier, source).to_string(),
            ))
        }
        "unary_expression"
            if expression
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "!") =>
        {
            simple_preprocessor_expression_guard(
                expression.child_by_field_name("argument")?,
                source,
            )
            .map(|guard| guard.negated())
        }
        "parenthesized_expression" => (0..expression.named_child_count())
            .filter_map(|index| expression.named_child(index))
            .next()
            .and_then(|child| simple_preprocessor_expression_guard(child, source)),
        _ => None,
    }
}

fn unique_include_target(mut targets: Vec<ProjectFile>) -> Option<ProjectFile> {
    if targets.len() == 1 {
        targets.pop()
    } else {
        None
    }
}

fn callable_declaration_activation_in_file(
    analyzer: &CppGraphSource<'_>,
    prepared: &PreparedSyntaxTree,
    candidate: &CodeUnit,
    reference_file: &ProjectFile,
) -> Option<usize> {
    let root = prepared.tree().root_node();
    analyzer
        .ranges(candidate)
        .into_iter()
        .filter_map(|range| {
            let mut declaration =
                root.descendant_for_byte_range(range.start_byte, range.end_byte)?;
            while !matches!(
                declaration.kind(),
                "declaration" | "field_declaration" | "function_definition"
            ) {
                declaration = declaration.parent()?;
            }
            let mut ancestor = declaration.parent();
            while let Some(node) = ancestor {
                // An export macro between `class` and its name can make
                // tree-sitter recover the class body as the compound body of
                // a synthetic function_definition.  A member declaration in
                // that body is still namespace/class scoped; do not discard
                // its declaration activation merely because the malformed
                // wrapper looks callable.
                if node.kind() == "function_definition"
                    && crate::declarations::is_recovered_exported_class_container(
                        node,
                        prepared.source(),
                    )
                {
                    ancestor = node.parent();
                    continue;
                }
                if node.kind() == "compound_statement"
                    && node.parent().is_some_and(|parent| {
                        crate::declarations::is_recovered_exported_class_container(
                            parent,
                            prepared.source(),
                        )
                    })
                {
                    ancestor = node.parent().and_then(|parent| parent.parent());
                    continue;
                }
                if matches!(
                    node.kind(),
                    "compound_statement" | "function_definition" | "lambda_expression"
                ) {
                    return None;
                }
                ancestor = node.parent();
            }
            callable_preprocessor_context_is_visible_for_reference(
                declaration,
                prepared.source(),
                reference_file,
            )
            .then_some(declaration.end_byte())
        })
        .min()
}

fn callable_preprocessor_context_is_visible_for_reference(
    node: Node<'_>,
    source: &str,
    reference_file: &ProjectFile,
) -> bool {
    let reference_is_c = reference_file
        .rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("c");
    let mut ancestor = node.parent();
    while let Some(conditional) = ancestor {
        if matches!(conditional.kind(), "preproc_if" | "preproc_ifdef")
            && !is_file_covering_include_guard(conditional, source)
            && !is_split_cpp_language_linkage_wrapper(conditional, node, source)
        {
            let Some(guard) = preprocessor_guard_for_descendant(conditional, node, source) else {
                return false;
            };
            match guard {
                PreprocessorGuard::Constant(true) => {}
                PreprocessorGuard::Constant(false) => return false,
                PreprocessorGuard::Defined(name) if name == "__cplusplus" => {
                    if reference_is_c {
                        return false;
                    }
                }
                PreprocessorGuard::Undefined(name) if name == "__cplusplus" => {
                    if !reference_is_c {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        ancestor = conditional.parent();
    }
    true
}

fn flattened_macro_namespace_declaration_matches(
    analyzer: &CppGraphSource<'_>,
    cpp: &dyn CppSource,
    reference_file: &ProjectFile,
    visible_declaration: &CodeUnit,
    qualified_candidate: &CodeUnit,
    reference_byte: usize,
) -> bool {
    // Namespace-opening macros can leave tree-sitter unable to retain the
    // namespace owner after a later recovery point. In that shape the forward
    // declaration is indexed at translation-unit scope, while the definition
    // still has its qualified owner. Require all surviving structural evidence
    // before treating the declaration as activation for that definition.
    if visible_declaration.kind() != qualified_candidate.kind()
        || visible_declaration.identifier() != qualified_candidate.identifier()
        || visible_declaration.signature() != qualified_candidate.signature()
        || !visible_declaration.package_name().is_empty()
        || qualified_candidate.package_name().is_empty()
    {
        return false;
    }

    let Some(prepared) = cpp.prepared_syntax(visible_declaration.source()) else {
        return false;
    };
    let root = prepared.tree().root_node();
    let closing_brace_limit = if visible_declaration.source() == reference_file {
        reference_byte
    } else {
        usize::MAX
    };

    analyzer
        .ranges(visible_declaration)
        .into_iter()
        .any(|range| {
            let Some(mut declaration) =
                root.descendant_for_byte_range(range.start_byte, range.end_byte)
            else {
                return false;
            };
            while !matches!(
                declaration.kind(),
                "declaration" | "field_declaration" | "function_definition"
            ) {
                let Some(parent) = declaration.parent() else {
                    return false;
                };
                declaration = parent;
            }
            if declaration
                .parent()
                .is_none_or(|parent| parent.kind() != "translation_unit")
                || !macro_displaced_cpp_return_type(declaration, prepared.source())
            {
                return false;
            }

            let mut cursor = root.walk();
            root.named_children(&mut cursor).any(|sibling| {
                sibling.start_byte() >= declaration.end_byte()
                    && sibling.start_byte() < closing_brace_limit
                    && direct_unmatched_closing_brace(sibling)
            })
        })
}

fn flattened_macro_namespace_components(
    declaration: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    flattened_macro_function_namespace_components(declaration, source)
        .or_else(|| flattened_macro_error_namespace_components(declaration, source))
}

fn flattened_macro_function_namespace_components(
    declaration: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    let body = declaration
        .parent()
        .filter(|parent| parent.kind() == "compound_statement")?;
    let function = body
        .parent()
        .filter(|parent| parent.kind() == "function_definition" && parent.has_error())?;
    if function.child_by_field_name("body") != Some(body) {
        return None;
    }
    let mut cursor = function.walk();
    let prefix = function
        .named_children(&mut cursor)
        .take_while(|child| child.start_byte() < body.start_byte())
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let begin_index = prefix.iter().rposition(|child| {
        flattened_macro_sentinel_name(*child, source)
            .is_some_and(|name| name.ends_with("NAMESPACE_BEGIN"))
    })?;
    let mut identifiers = Vec::new();
    let mut stack = prefix[begin_index + 1..]
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    while let Some(current) = stack.pop() {
        if let Some(identifier) = direct_cpp_identifier_name(current, source) {
            identifiers.push(identifier);
            continue;
        }
        let mut cursor = current.walk();
        let children = current.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    let [keyword, namespace_name] = identifiers.as_slice() else {
        return None;
    };
    if keyword != "namespace" || namespace_name.is_empty() || cpp_export_macro_token(namespace_name)
    {
        return None;
    }
    let mut next = function.next_named_sibling();
    let next = loop {
        let candidate = next?;
        next = candidate.next_named_sibling();
        if candidate.kind() != "comment" {
            break candidate;
        }
    };
    if !flattened_macro_sentinel_name(next, source)
        .is_some_and(|name| name.ends_with("NAMESPACE_END"))
    {
        return None;
    }
    let mut components = enclosing_namespace_components(declaration, source)?;
    components.push(namespace_name.clone());
    Some(components)
}

fn flattened_macro_error_namespace_components(
    declaration: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    let parent = declaration
        .parent()
        .filter(|parent| parent.kind() == "ERROR" && parent.has_error())?;
    let mut cursor = parent.walk();
    let siblings = parent.named_children(&mut cursor).collect::<Vec<_>>();
    let declaration_index = siblings
        .iter()
        .position(|candidate| same_node(*candidate, declaration))?;
    let begin_index = (0..declaration_index).rev().find(|index| {
        flattened_macro_sentinel_name(siblings[*index], source)
            .is_some_and(|name| name.ends_with("NAMESPACE_BEGIN"))
    })?;

    let significant = siblings[begin_index + 1..declaration_index]
        .iter()
        .copied()
        .filter(|node| node.kind() != "comment")
        .collect::<Vec<_>>();
    let [namespace_keyword, namespace_name, ..] = significant.as_slice() else {
        return None;
    };
    if direct_cpp_identifier_name(*namespace_keyword, source).as_deref() != Some("namespace") {
        return None;
    }
    let namespace_name = flattened_macro_namespace_name(*namespace_name, source)?;
    if significant[2..].iter().any(|node| {
        flattened_macro_sentinel_name(*node, source).is_some_and(|name| {
            name.ends_with("NAMESPACE_BEGIN") || name.ends_with("NAMESPACE_END")
        })
    }) {
        return None;
    }

    let mut saw_namespace_close = false;
    for sibling in siblings.iter().skip(declaration_index + 1).copied() {
        if sibling.kind() == "comment" {
            continue;
        }
        if !saw_namespace_close {
            if direct_unmatched_closing_brace(sibling) {
                saw_namespace_close = true;
                continue;
            }
            if flattened_macro_sentinel_name(sibling, source).is_some() {
                return None;
            }
            continue;
        }
        if !flattened_macro_sentinel_name(sibling, source)
            .is_some_and(|name| name.ends_with("NAMESPACE_END"))
        {
            return None;
        }
        let mut components = enclosing_namespace_components(declaration, source)?;
        components.push(namespace_name);
        return Some(components);
    }
    None
}

fn flattened_macro_sentinel_name(node: Node<'_>, source: &str) -> Option<String> {
    let candidate = direct_cpp_identifier_name(node, source).or_else(|| {
        node.child_by_field_name("type")
            .and_then(|type_node| direct_cpp_identifier_name(type_node, source))
    })?;
    (cpp_export_macro_token(&candidate)
        && (candidate.ends_with("NAMESPACE_BEGIN") || candidate.ends_with("NAMESPACE_END")))
    .then_some(candidate)
}

fn flattened_macro_namespace_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "ERROR" || node.named_child_count() != 1 {
        return None;
    }
    let name = direct_cpp_identifier_name(node.named_child(0)?, source)?;
    (!cpp_export_macro_token(&name)).then_some(name)
}

fn direct_cpp_identifier_name(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(
        node.kind(),
        "identifier" | "namespace_identifier" | "type_identifier"
    ) {
        return None;
    }
    let name = normalize_cpp_whitespace(node_text(node, source));
    (!name.is_empty()).then_some(name)
}

fn guard_requirement_sets_match(
    left: &[(usize, HashSet<PreprocessorGuard>)],
    right: &[(usize, HashSet<PreprocessorGuard>)],
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(_, left_guards)| {
            right
                .iter()
                .any(|(_, right_guards)| left_guards == right_guards)
        })
        && right.iter().all(|(_, right_guards)| {
            left.iter()
                .any(|(_, left_guards)| right_guards == left_guards)
        })
}

fn macro_displaced_cpp_return_type(declaration: Node<'_>, source: &str) -> bool {
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return false;
    };
    let type_name = normalize_cpp_whitespace(node_text(type_node, source));
    !type_name.is_empty()
        && type_name
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        && (0..declaration.named_child_count()).any(|index| {
            declaration
                .named_child(index)
                .is_some_and(|child| child.kind() == "ERROR")
        })
}

fn direct_unmatched_closing_brace(node: Node<'_>) -> bool {
    node.kind() == "ERROR"
        && (0..node.child_count())
            .any(|index| node.child(index).is_some_and(|child| child.kind() == "}"))
}

pub fn callable_preprocessor_context_is_visible(node: Node<'_>, source: &str) -> bool {
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        if is_preprocessor_conditional(parent)
            && !is_file_covering_include_guard(parent, source)
            && !is_split_cpp_language_linkage_wrapper(parent, node, source)
        {
            return false;
        }
        ancestor = parent.parent();
    }
    true
}

fn is_split_cpp_language_linkage_wrapper(
    conditional: Node<'_>,
    descendant: Node<'_>,
    source: &str,
) -> bool {
    if conditional.kind() != "preproc_ifdef"
        || conditional.child_by_field_name("alternative").is_some()
        || conditional
            .child_by_field_name("name")
            .is_none_or(|name| node_text(name, source) != "__cplusplus")
    {
        return false;
    }
    let mut current = descendant.parent();
    let linkage = loop {
        let Some(node) = current else {
            return false;
        };
        if node == conditional {
            return false;
        }
        if node.kind() == "linkage_specification" {
            break node;
        }
        current = node.parent();
    };
    if linkage
        .child_by_field_name("value")
        .is_none_or(|value| node_text(value, source) != "\"C\"")
    {
        return false;
    }
    let Some(body) = linkage.child_by_field_name("body") else {
        return false;
    };
    let closes_opening_branch = (0..body.named_child_count())
        .filter_map(|index| body.named_child(index))
        .take_while(|child| child.end_byte() <= descendant.start_byte())
        .any(|child| {
            child.kind() == "preproc_call"
                && child
                    .child_by_field_name("directive")
                    .is_some_and(|directive| node_text(directive, source) == "#endif")
        });
    let reopens_for_closing_brace = (0..body.named_child_count())
        .filter_map(|index| body.named_child(index))
        .skip_while(|child| child.start_byte() < descendant.end_byte())
        .any(|child| {
            child.kind() == "preproc_ifdef"
                && child
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == "__cplusplus")
                && (0..child.child_count()).any(|index| {
                    child
                        .child(index)
                        .is_some_and(|token| token.kind() == "#endif" && token.is_missing())
                })
        });
    closes_opening_branch && reopens_for_closing_brace
}

pub fn call_arity(node: Node<'_>) -> usize {
    node.child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("parameters"))
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| first_named_child_of_kind(node, "argument_list"))
        .or_else(|| first_named_child_of_kind(node, "initializer_list"))
        .map(|args| argument_children(args).count())
        .unwrap_or(0)
}

pub fn argument_children<'tree>(node: Node<'tree>) -> impl Iterator<Item = Node<'tree>> {
    let recovered_block_arguments = recovered_block_literal_arguments(node);
    (0..node.child_count())
        .filter_map(move |index| node.child(index))
        .filter(|child| child.is_named() && !child.is_extra())
        .flat_map(move |child| {
            if let Some((raw, left, right)) = recovered_block_arguments
                && child == raw
            {
                [Some(left), Some(right)]
            } else {
                [Some(child), None]
            }
        })
        .flatten()
}

fn recovered_block_literal_arguments<'tree>(
    arguments: Node<'tree>,
) -> Option<(Node<'tree>, Node<'tree>, Node<'tree>)> {
    if arguments.kind() != "argument_list" {
        return None;
    }
    let mut raw_arguments = (0..arguments.child_count())
        .filter_map(|index| arguments.child(index))
        .filter(|child| child.is_named() && !child.is_extra());
    let raw = raw_arguments.next()?;
    if raw_arguments.next().is_some() || raw.kind() != "binary_expression" {
        return None;
    }

    let left = raw.child_by_field_name("left")?;
    if left.is_missing() || left.start_byte() == left.end_byte() {
        return None;
    }
    let right = raw.child_by_field_name("right")?;
    if right.kind() != "compound_literal_expression"
        || right.is_missing()
        || right
            .child_by_field_name("type")
            .is_none_or(|node| node.kind() != "type_descriptor" || node.is_missing())
        || right
            .child_by_field_name("value")
            .is_none_or(|node| node.kind() != "initializer_list" || node.is_missing())
    {
        return None;
    }
    let has_intervening_error = (0..raw.child_count())
        .filter_map(|index| raw.child(index))
        .any(|child| {
            child.kind() == "ERROR"
                && !child.is_missing()
                && child.start_byte() >= left.end_byte()
                && child.end_byte() <= right.start_byte()
        });
    has_intervening_error.then_some((raw, left, right))
}

pub fn constructor_type_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "new_expression" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0)),
        "compound_literal_expression" => node.child_by_field_name("type"),
        "call_expression" => node.child_by_field_name("function"),
        _ => None,
    }
}

pub fn field_initializer_constructs_target(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    // A qualified name in a constructor initializer denotes a base
    // subobject constructor (`namespace::Base(args)`), not a member field.  The
    // field-initializer grammar exposes the qualified name as one structured
    // `qualified_identifier`; resolve its owner through the same lexical type
    // machinery used for ordinary C++ type references before considering the
    // initializer a hit.  This keeps an unrelated `namespace::Other(...)`, a
    // qualified non-constructor member, and an unresolved owner out of the
    // target constructor's inverse usage set.
    if first_named_child_of_kind(node, "qualified_identifier").is_some() {
        return qualified_base_initializer_constructs_target(node, ctx, owner);
    }
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

fn qualified_base_initializer_constructs_target(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(qualified) = first_named_child_of_kind(node, "qualified_identifier") else {
        return false;
    };
    let Some(components) = cpp_type_name_components(qualified, ctx.source) else {
        return false;
    };
    let Some(lexical_scope) = enclosing_namespace_components(node, ctx.source) else {
        return false;
    };
    let resolves_target = |components: &[String]| {
        matches!(
            ctx.visibility.resolve_type_components_lexically_for_target(
                &ctx.analyzer,
                ctx.file,
                components,
                is_globally_qualified_cpp_name(qualified),
                &lexical_scope,
                owner,
            ),
            LexicalTypeResolution::Resolved { unit, .. }
                if same_visible_symbol(&unit, owner)
        )
    };
    if resolves_target(&components) {
        return true;
    }

    // Some real-world code spells a base mem-initializer as
    // `Base::Base(args)`. In that structured path the final component repeats
    // the constructor name; resolve the preceding type path. The terminal
    // identity check prevents an arbitrary qualified member from taking this
    // route.
    components
        .last()
        .is_some_and(|terminal| terminal == owner.identifier())
        && resolves_target(&components[..components.len() - 1])
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

pub fn field_declared_binding(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
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
    let resolved = match (resolved, fact.template_arguments.as_deref()) {
        (Some(primary), Some(arguments)) => visibility
            .resolve_template_arguments(visible_from, primary, arguments)
            .ok(),
        (resolved, None) => resolved,
        (None, Some(_)) => None,
    };
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

fn unique_type_candidate_preserving_alias(
    analyzer: &CppGraphSource<'_>,
    candidates: &[&CodeUnit],
) -> Option<CodeUnit> {
    let first = *candidates.first()?;
    if declared_type_alias(analyzer, first) {
        return candidates
            .iter()
            .all(|candidate| {
                declared_type_alias(analyzer, candidate) && same_logical_symbol(first, candidate)
            })
            .then(|| first.clone());
    }
    candidates
        .iter()
        .all(|candidate| {
            !declared_type_alias(analyzer, candidate)
                && candidate.kind() == first.kind()
                && candidate.fq_name() == first.fq_name()
        })
        .then(|| first.clone())
}

fn declared_type_alias(analyzer: &CppGraphSource<'_>, unit: &CodeUnit) -> bool {
    is_type_alias(unit)
        || analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(unit))
}

pub fn field_declared_type_binding(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    visible_from: &ProjectFile,
    field: &CodeUnit,
) -> Option<(String, Option<CodeUnit>, i32)> {
    let fact = visibility.field_declared_type_fact(analyzer, field)?;
    let normalized = normalize_field_type_text(&fact.type_text);
    let primary = visibility.resolve_unique_canonical_type_for_declaration(
        analyzer,
        visible_from,
        field,
        &normalized,
    );
    let resolved = match (primary, fact.template_arguments.as_deref()) {
        (Some(primary), Some(arguments)) => visibility
            .resolve_template_arguments(visible_from, primary, arguments)
            .ok(),
        (resolved, None) => resolved,
        (None, Some(_)) => None,
    };
    Some((normalized, resolved, fact.indirection))
}

fn decode_field_declared_type_fact(
    analyzer: &CppGraphSource<'_>,
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
                template_arguments: cpp_template_reference_arguments(type_node, &declaration),
            });
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

fn decode_structured_alias_target(
    analyzer: &CppGraphSource<'_>,
    unit: &CodeUnit,
) -> Option<StructuredAliasTarget> {
    analyzer
        .get_source(unit, false)
        .and_then(|declaration| decode_structured_alias_target_source(unit, &declaration, true))
        .or_else(|| {
            let signature = unit.signature()?;
            decode_structured_alias_target_source(unit, signature, false)
        })
}

fn decode_structured_alias_target_source(
    unit: &CodeUnit,
    declaration: &str,
    require_top_level: bool,
) -> Option<StructuredAliasTarget> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(declaration, None)?;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let type_node = match node.kind() {
            "type_definition" => {
                if require_top_level
                    && node
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
                        extract_typedef_declarator_name(declarator, declaration)
                            .is_some_and(|name| name == unit.identifier())
                    });
                declares_unit.then(|| node.child_by_field_name("type"))??
            }
            "alias_declaration" => {
                if require_top_level
                    && node
                        .parent()
                        .is_none_or(|parent| parent.kind() != "translation_unit")
                {
                    let mut cursor = node.walk();
                    stack.extend(node.named_children(&mut cursor));
                    continue;
                }
                let name = node.child_by_field_name("name")?;
                (node_text(name, declaration) == unit.identifier())
                    .then(|| node.child_by_field_name("type"))??
            }
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
                continue;
            }
        };
        return structured_alias_type_target(type_node, declaration);
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
    let arguments = cpp_template_reference_arguments(type_node, source);
    (!components.is_empty()).then_some(StructuredAliasTarget::Named {
        components,
        global,
        arguments,
    })
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
        .resolves_to_type(&ctx.analyzer, ctx.file, declaration, owner)
        || field_type_prefix(declaration, unit.identifier()).is_some_and(|type_text| {
            let normalized = normalize_field_type_text(type_text);
            ctx.visibility
                .resolves_to_type(&ctx.analyzer, ctx.file, type_text, owner)
                || ctx.visibility.resolves_to_type(
                    &ctx.analyzer,
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

pub fn declaration_mentions_type(node: Node<'_>, ctx: &ScanCtx<'_>, owner: &CodeUnit) -> bool {
    let Some(type_node) = node.child_by_field_name("type") else {
        return false;
    };
    ctx.visibility.resolves_to_type(
        &ctx.analyzer,
        ctx.file,
        node_text(type_node, ctx.source),
        owner,
    )
}

pub fn declaration_is_object_construction_candidate(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
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

pub fn declaration_constructor_arity(node: Node<'_>, _ctx: &ScanCtx<'_>) -> usize {
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
        "argument_list" | "initializer_list" => argument_children(value).count(),
        "compound_literal_expression" => call_arity(value),
        _ => 1,
    }
}

fn declaration_declarator_arity(node: Node<'_>) -> usize {
    if let Some(parameters) = node.child_by_field_name("parameters") {
        return argument_children(parameters).count();
    }
    node.child_by_field_name("declarator")
        .map(declaration_declarator_arity)
        .unwrap_or(0)
}

fn first_named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn first_descendant_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            return Some(node);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

fn argument_shape_may_change_arity(node: Node<'_>) -> bool {
    if node.kind() == "identifier" {
        return true;
    }
    if node.kind() == "parenthesized_expression" {
        return false;
    }
    if node.kind() == "call_expression" {
        return node
            .child_by_field_name("function")
            .is_some_and(|function| function.kind() == "identifier");
    }
    let mut stack = vec![node];
    while let Some(descendant) = stack.pop() {
        if descendant != node && descendant.kind() == "parenthesized_expression" {
            continue;
        }
        if descendant.kind() == "identifier" {
            return true;
        }
        if descendant.kind() == "call_expression" {
            if descendant
                .child_by_field_name("function")
                .is_some_and(|function| function.kind() == "identifier")
            {
                return true;
            }
            continue;
        }
        for index in (0..descendant.named_child_count()).rev() {
            if let Some(child) = descendant.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn macro_expansion_shape_is_safe(
    node: Node<'_>,
    source: &str,
    parameters: &[String],
    environment: &MacroEnvironment,
) -> bool {
    if matches!(node.kind(), "identifier" | "parenthesized_expression") {
        return true;
    }
    if node.kind() == "call_expression" {
        let Some(function) = node.child_by_field_name("function") else {
            return true;
        };
        if function.kind() != "identifier" {
            return true;
        }
        let function_name = node_text(function, source);
        if parameters
            .iter()
            .any(|parameter| parameter == function_name)
        {
            return false;
        }
        if !environment.may_bind(function_name) {
            return true;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return false;
        };
        return argument_children(arguments).all(|argument| {
            if argument.kind() == "identifier"
                && parameters
                    .iter()
                    .any(|parameter| parameter == node_text(argument, source))
            {
                return false;
            }
            macro_expansion_shape_is_safe(argument, source, parameters, environment)
        });
    }
    let mut stack = vec![node];
    while let Some(descendant) = stack.pop() {
        if descendant != node {
            if descendant.kind() == "parenthesized_expression" {
                continue;
            }
            if descendant.kind() == "call_expression" {
                let expands = descendant
                    .child_by_field_name("function")
                    .filter(|function| function.kind() == "identifier")
                    .is_some_and(|function| environment.may_bind(node_text(function, source)));
                if expands {
                    return false;
                }
                continue;
            }
        }
        if descendant.kind() == "identifier" {
            let identifier = node_text(descendant, source);
            if parameters.iter().any(|parameter| parameter == identifier)
                || environment.may_bind(identifier)
            {
                return false;
            }
        }
        for index in (0..descendant.named_child_count()).rev() {
            if let Some(child) = descendant.named_child(index) {
                stack.push(child);
            }
        }
    }
    true
}

fn structured_include_path<'a>(path: Node<'_>, source: &'a str) -> Option<&'a str> {
    let text = node_text(path, source);
    match path.kind() {
        "string_literal" => text.strip_prefix('"')?.strip_suffix('"'),
        "system_lib_string" => text.strip_prefix('<')?.strip_suffix('>'),
        _ => None,
    }
}

fn has_preprocessor_conditional_ancestor(mut node: Node<'_>, source: &str) -> bool {
    while let Some(parent) = node.parent() {
        if is_preprocessor_conditional(parent) && !is_file_covering_include_guard(parent, source) {
            return true;
        }
        node = parent;
    }
    false
}

fn is_preprocessor_conditional(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "preproc_if"
            | "preproc_ifdef"
            | "preproc_ifndef"
            | "preproc_elif"
            | "preproc_elifdef"
            | "preproc_else"
    )
}

fn is_file_covering_include_guard(node: Node<'_>, source: &str) -> bool {
    node.parent()
        .filter(|parent| parent.kind() == "translation_unit")
        .is_some_and(|root| top_level_canonical_include_guard_name(root, source).is_some())
        && is_canonical_include_guard(node, source)
}

fn is_canonical_include_guard(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "preproc_ifdef"
        || node
            .child(0)
            .is_none_or(|directive| directive.kind() != "#ifndef")
        || node.child_by_field_name("alternative").is_some()
    {
        return false;
    }
    let Some(guard_name) = node.child_by_field_name("name") else {
        return false;
    };
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| *child != guard_name && child.kind() != "comment")
        .filter(|child| child.kind() == "preproc_def")
        .and_then(|definition| definition.child_by_field_name("name"))
        .is_some_and(|defined_name| {
            node_text(defined_name, source) == node_text(guard_name, source)
        })
}

fn top_level_canonical_include_guard_name(root: Node<'_>, source: &str) -> Option<String> {
    let mut guard = None;
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if child.kind() == "comment" || is_pragma_once(child, source) {
            continue;
        }
        if guard.is_none() && is_canonical_include_guard(child, source) {
            guard = Some(child);
        } else {
            return None;
        }
    }
    guard
        .and_then(|guard: Node<'_>| guard.child_by_field_name("name"))
        .map(|name| node_text(name, source).to_string())
}

fn top_level_macro_include_protection(root: Node<'_>, source: &str) -> MacroIncludeProtection {
    if (0..root.named_child_count())
        .filter_map(|index| root.named_child(index))
        .any(|child| is_pragma_once(child, source))
    {
        return MacroIncludeProtection::PragmaOnce;
    }
    top_level_canonical_include_guard_name(root, source)
        .map(MacroIncludeProtection::MacroGuard)
        .unwrap_or(MacroIncludeProtection::None)
}

fn is_pragma_once(node: Node<'_>, source: &str) -> bool {
    node.kind() == "preproc_call"
        && node
            .child_by_field_name("directive")
            .is_some_and(|directive| node_text(directive, source) == "#pragma")
        && node
            .child_by_field_name("argument")
            .is_some_and(|argument| node_text(argument, source).trim() == "once")
}

fn parse_preproc_identifier(argument: &str) -> Option<String> {
    let sentinel = format!("void __bifrost_undef() {{ {argument}; }}");
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(&sentinel, None)?;
    if tree.root_node().has_error() {
        return None;
    }
    let statement = first_descendant_of_kind(tree.root_node(), "expression_statement")?;
    let identifier = statement.named_child(0)?;
    (identifier.kind() == "identifier" && statement.named_child_count() == 1)
        .then(|| node_text(identifier, &sentinel).to_string())
}

pub fn extract_variable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" => {
            let name = node_text(node, source).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        "abstract_array_declarator"
        | "abstract_function_declarator"
        | "abstract_parenthesized_declarator"
        | "abstract_pointer_declarator"
        | "abstract_reference_declarator" => None,
        "function_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .and_then(|child| extract_variable_name(child, source)),
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))
            .and_then(|child| extract_variable_name(child, source)),
    }
}

pub fn is_declarator_node(node: Node<'_>) -> bool {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredDeclaratorTypeContext {
    Declaration,
    FunctionDefinition,
}

/// Recognize a real type displaced into a qualified declarator by parser
/// recovery.
///
/// Tree-sitter parses `API Result *make(Arg);` as if `API` were the declared
/// type and `Result` were the scope of a qualified declarator with a missing
/// `::`. The same recovery occurs for macro-prefixed definitions and extern
/// variables. Keep this intentionally structural: the recovered scope must
/// have the grammar's missing separator, the qualified node must occupy the
/// declaration's declarator chain, a separate nonempty type must occupy the
/// normal type field, and the recovered name must unwrap to a real declarator
/// name.
pub fn recovered_macro_decorated_declarator_type(
    node: Node<'_>,
) -> Option<RecoveredDeclaratorTypeContext> {
    recovered_macro_decorated_type_node(node).map(|(_, context)| context)
}

/// Return the declaration/function `type` displaced by a macro-shaped
/// qualified declarator, together with the enclosing declaration context.
/// Callers use the macro scope only as structural admission evidence; the
/// returned node is the real type reference to resolve and record.
pub fn recovered_macro_decorated_type_node(
    node: Node<'_>,
) -> Option<(Node<'_>, RecoveredDeclaratorTypeContext)> {
    if node.kind() != "namespace_identifier" || node.is_missing() {
        return None;
    }
    let qualified = node.parent()?;
    if qualified.kind() != "qualified_identifier"
        || qualified.child_by_field_name("scope") != Some(node)
        || !(0..qualified.child_count())
            .filter_map(|index| qualified.child(index))
            .any(|child| child.kind() == "::" && child.is_missing())
    {
        return None;
    }
    if !concrete_recovered_declarator_name(qualified.child_by_field_name("name")?) {
        return None;
    }

    let (declaration, context) = recovered_declarator_container(qualified)?;
    let type_node = declaration
        .child_by_field_name("type")
        .filter(|type_node| {
            *type_node != qualified
                && !type_node.is_missing()
                && type_node.start_byte() != type_node.end_byte()
        })?;
    Some((type_node, context))
}

fn recovered_declarator_container(
    mut declarator: Node<'_>,
) -> Option<(Node<'_>, RecoveredDeclaratorTypeContext)> {
    loop {
        let parent = declarator.parent()?;
        if parent.kind() == "init_declarator" && has_field_child(parent, "declarator", declarator) {
            return Some((
                parent
                    .parent()
                    .filter(|declaration| declaration.kind() == "declaration")?,
                RecoveredDeclaratorTypeContext::Declaration,
            ));
        }
        if parent.kind() == "declaration" && has_field_child(parent, "declarator", declarator) {
            return Some((parent, RecoveredDeclaratorTypeContext::Declaration));
        }
        if parent.kind() == "function_definition"
            && has_field_child(parent, "declarator", declarator)
        {
            return Some((parent, RecoveredDeclaratorTypeContext::FunctionDefinition));
        }
        if !matches!(
            parent.kind(),
            "array_declarator"
                | "function_declarator"
                | "parenthesized_declarator"
                | "pointer_declarator"
                | "pointer_type_declarator"
                | "reference_declarator"
        ) || !has_field_child(parent, "declarator", declarator)
        {
            return None;
        }
        declarator = parent;
    }
}

fn has_field_child(parent: Node<'_>, field: &str, target: Node<'_>) -> bool {
    let mut cursor = parent.walk();
    parent
        .children_by_field_name(field, &mut cursor)
        .any(|child| child == target)
}

fn concrete_recovered_declarator_name(mut node: Node<'_>) -> bool {
    loop {
        if node.is_missing() || node.start_byte() == node.end_byte() {
            return false;
        }
        match node.kind() {
            "identifier" | "field_identifier" | "type_identifier" => return true,
            "array_declarator"
            | "function_declarator"
            | "parenthesized_declarator"
            | "pointer_declarator"
            | "pointer_type_declarator"
            | "reference_declarator" => {
                let Some(declarator) = node.child_by_field_name("declarator") else {
                    return false;
                };
                node = declarator;
            }
            _ => return false,
        }
    }
}

/// Aggregate-owner proof for a structurally recognized designated initializer.
pub enum DesignatedInitializerOwner {
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
pub fn designated_initializer_owner(
    visibility: &VisibilityIndex<'_>,
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
        || !crate::structural::is_recovered_designator_init_declarator(init_declarator)
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
    visibility: &VisibilityIndex<'_>,
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
    visibility: &VisibilityIndex<'_>,
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
    visibility: &VisibilityIndex<'_>,
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

pub fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
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

pub fn constructor_style_local_declaration<T: Clone + Eq + Hash>(
    visibility: &VisibilityIndex<'_>,
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
        && bindings.is_shadowed(text)
}

pub fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent
        .child_by_field_name("name")
        .is_some_and(|name| same_node(name, node))
    {
        if matches!(
            parent.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
        ) {
            return cpp_tag_specifier_declares_name(parent);
        }
        if matches!(
            parent.kind(),
            "namespace_definition"
                | "namespace_alias_definition"
                | "alias_declaration"
                | "enumerator"
        ) {
            return true;
        }
    }

    let mut current = Some(parent);
    while let Some(ancestor) = current {
        let type_definition = ancestor.kind() == "type_definition";
        let mut declarator_cursor = ancestor.walk();
        if ancestor
            .children_by_field_name("declarator", &mut declarator_cursor)
            .any(|declarator| declarator_name_path_contains(declarator, node, type_definition))
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

/// Whether a parameter declaration belongs to the callable scope whose body can
/// contain references to it.
///
/// Error recovery can wrap a macro-decorated class body in a synthetic outer
/// `function_definition`. Merely finding any callable ancestor would then leak
/// parameters from member prototypes into later member bodies. Require the
/// parameter to be inside that definition's own declarator instead.
pub fn parameter_belongs_to_callable_scope(parameter: Node<'_>) -> bool {
    let mut current = parameter.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "lambda_expression" {
            return ancestor
                .child_by_field_name("declarator")
                .is_some_and(|declarator| {
                    declarator.start_byte() <= parameter.start_byte()
                        && parameter.end_byte() <= declarator.end_byte()
                });
        }
        if ancestor.kind() == "function_definition" {
            return ancestor
                .child_by_field_name("declarator")
                .is_some_and(|declarator| {
                    declarator.start_byte() <= parameter.start_byte()
                        && parameter.end_byte() <= declarator.end_byte()
                });
        }
        current = ancestor.parent();
    }
    false
}

fn cpp_tag_specifier_declares_name(specifier: Node<'_>) -> bool {
    if specifier.child_by_field_name("body").is_some() {
        return true;
    }
    let mut current = specifier.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "type_descriptor"
            | "parameter_declaration"
            | "optional_parameter_declaration"
            | "template_argument_list"
            | "cast_expression" => return false,
            "declaration" | "field_declaration" => {
                let mut cursor = ancestor.walk();
                return ancestor
                    .children_by_field_name("declarator", &mut cursor)
                    .next()
                    .is_none();
            }
            "translation_unit" => return true,
            _ => current = ancestor.parent(),
        }
    }
    false
}

pub fn declarator_name_node(node: Node<'_>) -> Option<Node<'_>> {
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
pub fn is_nested_type_node(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "qualified_identifier" | "scoped_type_identifier" | "template_type"
        )
    })
}

pub struct OutOfLineMemberDefinitionOwners<'tree> {
    pub owners: Vec<(Node<'tree>, CodeUnit)>,
    innermost: Option<(Node<'tree>, CodeUnit)>,
}

impl OutOfLineMemberDefinitionOwners<'_> {
    pub fn innermost(&self) -> Option<(Node<'_>, &CodeUnit)> {
        self.innermost.as_ref().map(|(node, owner)| (*node, owner))
    }
}

pub struct QualifiedOwnerComponents<'tree> {
    pub nodes: Vec<Node<'tree>>,
    pub names: Vec<String>,
    pub global: bool,
}

pub fn qualified_owner_components<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<QualifiedOwnerComponents<'tree>> {
    let mut nodes = cpp_name_component_nodes(node)?;
    nodes.pop()?;
    if nodes.is_empty() {
        return None;
    }
    let names = nodes
        .iter()
        .map(|component| node_text(*component, source).to_string())
        .collect();
    Some(QualifiedOwnerComponents {
        nodes,
        names,
        global: is_globally_qualified_cpp_name(node),
    })
}

/// Return the terminal type-name occurrence in an out-of-line destructor
/// declarator such as `endpoint::~endpoint`.  Unlike an ordinary terminal
/// method name, this identifier is a second reference to the owner type.
pub fn out_of_line_destructor_type_reference(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "qualified_identifier" {
        return None;
    }
    let destructor = node.child_by_field_name("name")?;
    if destructor.kind() != "destructor_name" {
        return None;
    }
    (0..destructor.named_child_count())
        .filter_map(|index| destructor.named_child(index))
        .find(|child| matches!(child.kind(), "identifier" | "type_identifier"))
}

pub fn out_of_line_member_definition_owner<'tree>(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
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
    let qualified = qualified_owner_components(node, source)?;
    let lexical_scope = enclosing_namespace_components(node, source)?;
    let mut owners = Vec::new();
    let mut innermost = None;

    for component_count in 1..=qualified.names.len() {
        if let LexicalTypeResolution::Resolved { unit, .. } = visibility
            .resolve_type_components_lexically(
                analyzer,
                file,
                &qualified.names[..component_count],
                qualified.global,
                &lexical_scope,
            )
            && !owners
                .iter()
                .any(|(_, existing)| same_visible_symbol(existing, &unit))
        {
            if component_count == qualified.names.len() {
                innermost = Some((qualified.nodes[component_count - 1], unit.clone()));
            }
            owners.push((qualified.nodes[component_count - 1], unit));
        }
    }

    // The C++ analyzer has already reconciled an indexed out-of-line callable
    // against the include-visible class table. Consult that canonical owner
    // chain only when ordinary lexical lookup could not recover the innermost
    // owner.  A one-segment qualifier is safe here only when the enclosing
    // indexed callable has an authoritative class owner and the parser's
    // namespace path is a (possibly sparse) subsequence of that owner path.
    // The latter is what lets macro-wrapped namespace sentinels recover a
    // missing `time_internal`/`cord_internal` component without guessing an
    // unrelated short name.
    if innermost.is_none() {
        let indexed_owner_components = visibility
            .indexed_enclosing_owner_scope(analyzer, file, node)
            .or_else(|| {
                // Retain the legacy rendered-name fallback for the existing
                // multi-segment path when an enclosing owner chain is not
                // available (for example, cache-loaded units without parent
                // links).  One-segment recovery must stay canonical-only.
                if qualified.names.len() <= 1 {
                    return None;
                }
                let range = Range {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    start_line: node.start_position().row,
                    end_line: node.end_position().row,
                };
                let start = analyzer.enclosing_code_unit(file, &range)?;
                let mut components = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
                    brokk_bifrost_core::analyzer::Language::Cpp,
                    &cpp_name_for(&start),
                );
                components.pop();
                Some(components)
            });
        if let Some(indexed_owner_components) = indexed_owner_components
            && indexed_owner_components.len() > qualified.names.len()
            && indexed_owner_components.ends_with(&qualified.names)
            && indexed_namespace_path_is_recoverable(
                &lexical_scope,
                &indexed_owner_components,
            )
            // A globally-qualified one-segment owner is an explicit request
            // for the top-level binding; do not reinterpret it as a missing
            // namespace component.  Existing multi-segment global lookups
            // retain their historical indexed recovery.
            && (qualified.names.len() > 1 || !qualified.global)
        {
            let namespace_count = indexed_owner_components.len() - qualified.names.len();
            for component_count in 1..=qualified.names.len() {
                let expected = &indexed_owner_components[..namespace_count + component_count];
                let owner_node = qualified.nodes[component_count - 1];
                for owner in visibility
                    .visible_identifier_candidates(file, &qualified.names[component_count - 1])
                    .filter(|candidate| candidate.is_class())
                    .filter(|candidate| {
                        canonical_cpp_scope_components(candidate) == expected
                            && visibility.external_type_candidate_visible_in_context(
                                analyzer, file, candidate, node,
                            )
                    })
                {
                    if component_count == qualified.names.len() && innermost.is_none() {
                        innermost = Some((owner_node, owner.clone()));
                    }
                    if !owners
                        .iter()
                        .any(|(_, existing)| same_symbol(existing, owner))
                    {
                        owners.push((owner_node, owner.clone()));
                    }
                }
            }
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

pub fn append_cpp_name_components(
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

pub fn cpp_type_name_components(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut components = Vec::new();
    append_cpp_name_components(node, source, &mut components)?;
    Some(components)
}

pub fn cpp_template_reference_arguments(
    mut node: Node<'_>,
    source: &str,
) -> Option<Vec<CppTemplateExpression>> {
    loop {
        match node.kind() {
            "template_type" | "template_function" => {
                let arguments = node.child_by_field_name("arguments")?;
                let mut cursor = arguments.walk();
                return Some(
                    arguments
                        .named_children(&mut cursor)
                        .filter(|argument| !argument.is_extra() && argument.kind() != "comment")
                        .map(|argument| CppTemplateExpression {
                            text: normalize_cpp_whitespace(node_text(argument, source)),
                            term: cpp_template_term(argument, source, &[]),
                        })
                        .collect(),
                );
            }
            "qualified_identifier" | "scoped_type_identifier" | "type_descriptor" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("type"))?;
            }
            _ => return None,
        }
    }
}

fn cpp_reconcile_primary_template_parameters(
    candidates: &[(&CodeUnit, &CppTemplateMetadata)],
    preferred: &CodeUnit,
) -> Option<Vec<CppTemplateParameterMetadata>> {
    let canonical = candidates
        .iter()
        .find_map(|(unit, metadata)| (*unit == preferred).then_some(*metadata))?;
    let mut merged = canonical
        .parameters
        .iter()
        .map(|parameter| CppTemplateParameterMetadata {
            name: parameter.name.clone(),
            kind: parameter.kind,
            variadic: parameter.variadic,
            default: None,
        })
        .collect::<Vec<_>>();

    for (_, metadata) in candidates {
        if metadata.parameters.len() != merged.len() {
            return None;
        }
        let rename_bindings = metadata
            .parameters
            .iter()
            .zip(&merged)
            .map(|(parameter, canonical)| {
                (
                    parameter.name.clone(),
                    CppTemplateTerm::Parameter(canonical.name.clone()),
                )
            })
            .collect::<HashMap<_, _>>();
        for ((parameter, canonical), merged_parameter) in metadata
            .parameters
            .iter()
            .zip(&canonical.parameters)
            .zip(&mut merged)
        {
            if parameter.kind != canonical.kind || parameter.variadic != canonical.variadic {
                return None;
            }
            let Some(default) = &parameter.default else {
                continue;
            };
            let normalized_term = cpp_substitute_template_term(&default.term, &rename_bindings)?;
            if let Some(existing) = &merged_parameter.default {
                if !cpp_template_terms_equal(&existing.term, &normalized_term) {
                    return None;
                }
            } else {
                merged_parameter.default = Some(CppTemplateExpression {
                    text: default.text.clone(),
                    term: normalized_term,
                });
            }
        }
    }
    Some(merged)
}

pub fn cpp_bind_template_arguments(
    parameters: &[CppTemplateParameterMetadata],
    explicit_arguments: &[CppTemplateExpression],
) -> Option<(Vec<CppTemplateExpression>, HashMap<String, CppTemplateTerm>)> {
    let variadic_index = parameters.iter().position(|parameter| parameter.variadic);
    if variadic_index.is_some_and(|index| {
        index + 1 != parameters.len()
            || parameters[index + 1..]
                .iter()
                .any(|parameter| parameter.variadic)
    }) {
        return None;
    }
    let fixed_count = variadic_index.unwrap_or(parameters.len());
    if variadic_index.is_none() && explicit_arguments.len() > fixed_count {
        return None;
    }
    let explicit_fixed_count = explicit_arguments.len().min(fixed_count);
    let mut expanded = explicit_arguments[..explicit_fixed_count]
        .iter()
        .map(cpp_clone_template_expression_iterative)
        .collect::<Vec<_>>();
    let mut bindings = HashMap::default();
    for (parameter, argument) in parameters[..explicit_fixed_count].iter().zip(&expanded) {
        bindings.insert(
            parameter.name.clone(),
            cpp_clone_template_term_iterative(&argument.term),
        );
    }
    for parameter in &parameters[explicit_fixed_count..fixed_count] {
        let default = parameter.default.as_ref()?;
        let term = cpp_substitute_template_term(&default.term, &bindings)?;
        bindings.insert(parameter.name.clone(), term.clone());
        expanded.push(CppTemplateExpression {
            text: default.text.clone(),
            term,
        });
    }
    if let Some(index) = variadic_index {
        let packed_arguments = &explicit_arguments[explicit_fixed_count..];
        expanded.extend(
            packed_arguments
                .iter()
                .map(cpp_clone_template_expression_iterative),
        );
        bindings.insert(
            parameters[index].name.clone(),
            CppTemplateTerm::Node {
                kind: "parameter_pack".to_string(),
                children: packed_arguments
                    .iter()
                    .map(|argument| cpp_clone_template_term_iterative(&argument.term))
                    .collect(),
            },
        );
    }
    Some((expanded, bindings))
}

fn cpp_specialization_matches(
    metadata: &CppTemplateMetadata,
    arguments: &[CppTemplateExpression],
) -> bool {
    if metadata.specialization_arguments.len() != arguments.len() {
        return false;
    }
    let parameter_names = metadata
        .parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect::<HashSet<_>>();
    let mut bindings: HashMap<String, CppTemplateTerm> = HashMap::default();
    for (pattern, argument) in metadata.specialization_arguments.iter().zip(arguments) {
        if !cpp_unify_template_term(
            &pattern.term,
            &argument.term,
            &parameter_names,
            &mut bindings,
        ) {
            return false;
        }
    }
    true
}

fn cpp_specialization_more_specialized(
    candidate: &CppTemplateMetadata,
    other: &CppTemplateMetadata,
) -> bool {
    cpp_specialization_pattern_accepts(other, candidate)
        && !cpp_specialization_pattern_accepts(candidate, other)
}

fn cpp_specialization_pattern_accepts(
    broader: &CppTemplateMetadata,
    narrower: &CppTemplateMetadata,
) -> bool {
    if broader.specialization_arguments.len() != narrower.specialization_arguments.len() {
        return false;
    }
    let parameter_names = broader
        .parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect::<HashSet<_>>();
    let mut bindings: HashMap<String, CppTemplateTerm> = HashMap::default();
    broader
        .specialization_arguments
        .iter()
        .zip(&narrower.specialization_arguments)
        .all(|(pattern, argument)| {
            cpp_unify_template_term(
                &pattern.term,
                &argument.term,
                &parameter_names,
                &mut bindings,
            )
        })
}

pub fn cpp_substitute_template_term(
    term: &CppTemplateTerm,
    bindings: &HashMap<String, CppTemplateTerm>,
) -> Option<CppTemplateTerm> {
    enum Work<'a> {
        Visit(&'a CppTemplateTerm),
        Build { kind: String, child_count: usize },
    }

    let mut work = vec![Work::Visit(term)];
    let mut substituted = Vec::new();
    while let Some(next) = work.pop() {
        match next {
            Work::Visit(CppTemplateTerm::Parameter(name)) => {
                substituted.push(cpp_clone_template_term_iterative(bindings.get(name)?));
            }
            Work::Visit(CppTemplateTerm::Atom { kind, text }) => {
                substituted.push(CppTemplateTerm::Atom {
                    kind: kind.clone(),
                    text: text.clone(),
                });
            }
            Work::Visit(CppTemplateTerm::Node { kind, children }) => {
                work.push(Work::Build {
                    kind: kind.clone(),
                    child_count: children.len(),
                });
                work.extend(children.iter().rev().map(Work::Visit));
            }
            Work::Build { kind, child_count } => {
                let children = substituted.split_off(substituted.len() - child_count);
                substituted.push(CppTemplateTerm::Node { kind, children });
            }
        }
    }
    substituted.pop()
}

pub fn cpp_substitute_template_arguments(
    arguments: &[CppTemplateExpression],
    bindings: &HashMap<String, CppTemplateTerm>,
) -> Option<Vec<CppTemplateExpression>> {
    let mut substituted = Vec::new();
    for argument in arguments {
        let CppTemplateTerm::Node { kind, children } = &argument.term else {
            substituted.push(CppTemplateExpression {
                text: argument.text.clone(),
                term: cpp_substitute_template_term(&argument.term, bindings)?,
            });
            continue;
        };
        if kind != "parameter_pack_expansion" {
            substituted.push(CppTemplateExpression {
                text: argument.text.clone(),
                term: cpp_substitute_template_term(&argument.term, bindings)?,
            });
            continue;
        }
        let [pattern, CppTemplateTerm::Atom { text: ellipsis, .. }] = children.as_slice() else {
            return None;
        };
        if ellipsis != "..." {
            return None;
        }

        let mut pack_names = Vec::new();
        let mut work = vec![pattern];
        while let Some(term) = work.pop() {
            match term {
                CppTemplateTerm::Parameter(name)
                    if matches!(
                        bindings.get(name),
                        Some(CppTemplateTerm::Node { kind, .. }) if kind == "parameter_pack"
                    ) =>
                {
                    if !pack_names.contains(name) {
                        pack_names.push(name.clone());
                    }
                }
                CppTemplateTerm::Node { children, .. } => work.extend(children),
                CppTemplateTerm::Parameter(_) | CppTemplateTerm::Atom { .. } => {}
            }
        }
        let first_pack = pack_names.first()?;
        let CppTemplateTerm::Node {
            children: first_elements,
            ..
        } = bindings.get(first_pack)?
        else {
            return None;
        };
        let pack_len = first_elements.len();
        for pack_name in &pack_names {
            let CppTemplateTerm::Node { children, .. } = bindings.get(pack_name)? else {
                return None;
            };
            if children.len() != pack_len {
                return None;
            }
        }
        for index in 0..pack_len {
            let mut element_bindings = bindings.clone();
            for pack_name in &pack_names {
                let CppTemplateTerm::Node { children, .. } = bindings.get(pack_name)? else {
                    return None;
                };
                element_bindings.insert(
                    pack_name.clone(),
                    cpp_clone_template_term_iterative(&children[index]),
                );
            }
            substituted.push(CppTemplateExpression {
                text: argument.text.clone(),
                term: cpp_substitute_template_term(pattern, &element_bindings)?,
            });
        }
    }
    Some(substituted)
}

fn cpp_clone_template_term_iterative(term: &CppTemplateTerm) -> CppTemplateTerm {
    enum Work<'a> {
        Visit(&'a CppTemplateTerm),
        Build { kind: String, child_count: usize },
    }

    let mut work = vec![Work::Visit(term)];
    let mut cloned = Vec::new();
    while let Some(next) = work.pop() {
        match next {
            Work::Visit(CppTemplateTerm::Parameter(name)) => {
                cloned.push(CppTemplateTerm::Parameter(name.clone()));
            }
            Work::Visit(CppTemplateTerm::Atom { kind, text }) => {
                cloned.push(CppTemplateTerm::Atom {
                    kind: kind.clone(),
                    text: text.clone(),
                });
            }
            Work::Visit(CppTemplateTerm::Node { kind, children }) => {
                work.push(Work::Build {
                    kind: kind.clone(),
                    child_count: children.len(),
                });
                work.extend(children.iter().rev().map(Work::Visit));
            }
            Work::Build { kind, child_count } => {
                let children = cloned.split_off(cloned.len() - child_count);
                cloned.push(CppTemplateTerm::Node { kind, children });
            }
        }
    }
    cloned
        .pop()
        .expect("template term traversal emits one root")
}

fn cpp_clone_template_expression_iterative(
    expression: &CppTemplateExpression,
) -> CppTemplateExpression {
    CppTemplateExpression {
        text: expression.text.clone(),
        term: cpp_clone_template_term_iterative(&expression.term),
    }
}

pub fn cpp_unify_template_term(
    pattern: &CppTemplateTerm,
    argument: &CppTemplateTerm,
    parameters: &HashSet<&str>,
    bindings: &mut HashMap<String, CppTemplateTerm>,
) -> bool {
    let mut work = vec![(pattern, argument)];
    while let Some((pattern, argument)) = work.pop() {
        match pattern {
            CppTemplateTerm::Parameter(name) if parameters.contains(name.as_str()) => {
                if let Some(bound) = bindings.get(name) {
                    if !cpp_template_terms_equal(bound, argument) {
                        return false;
                    }
                } else {
                    bindings.insert(name.clone(), cpp_clone_template_term_iterative(argument));
                }
            }
            CppTemplateTerm::Atom {
                kind: pattern_kind,
                text: pattern_text,
            } => {
                if !matches!(
                    argument,
                    CppTemplateTerm::Atom { kind, text }
                        if kind == pattern_kind && text == pattern_text
                ) {
                    return false;
                }
            }
            CppTemplateTerm::Node {
                kind: pattern_kind,
                children: pattern_children,
            } => {
                let CppTemplateTerm::Node { kind, children } = argument else {
                    return false;
                };
                if kind != pattern_kind || children.len() != pattern_children.len() {
                    return false;
                }
                work.extend(pattern_children.iter().zip(children).rev());
            }
            CppTemplateTerm::Parameter(_) => return false,
        }
    }
    true
}

fn cpp_template_terms_equal(left: &CppTemplateTerm, right: &CppTemplateTerm) -> bool {
    let mut work = vec![(left, right)];
    while let Some((left, right)) = work.pop() {
        match (left, right) {
            (CppTemplateTerm::Parameter(left), CppTemplateTerm::Parameter(right)) => {
                if left != right {
                    return false;
                }
            }
            (
                CppTemplateTerm::Atom {
                    kind: left_kind,
                    text: left_text,
                },
                CppTemplateTerm::Atom {
                    kind: right_kind,
                    text: right_text,
                },
            ) => {
                if left_kind != right_kind || left_text != right_text {
                    return false;
                }
            }
            (
                CppTemplateTerm::Node {
                    kind: left_kind,
                    children: left_children,
                },
                CppTemplateTerm::Node {
                    kind: right_kind,
                    children: right_children,
                },
            ) => {
                if left_kind != right_kind || left_children.len() != right_children.len() {
                    return false;
                }
                work.extend(left_children.iter().zip(right_children).rev());
            }
            _ => return false,
        }
    }
    true
}

pub fn cpp_name_component_nodes(node: Node<'_>) -> Option<Vec<Node<'_>>> {
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

pub fn is_globally_qualified_cpp_name(node: Node<'_>) -> bool {
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

/// Whether a parser-derived namespace path can be reconciled with an indexed
/// owner scope without inventing an unrelated short-name binding.
///
/// Macro namespace sentinels can make tree-sitter omit one or more namespace
/// definitions from the ancestor chain.  Preserve the order of every
/// namespace that did survive parsing, but allow indexed components between
/// them.  An empty path is deliberately rejected: a one-segment owner at the
/// translation-unit root is not evidence of a malformed namespace.
fn indexed_namespace_path_is_recoverable(
    lexical_scope: &[String],
    indexed_owner_scope: &[String],
) -> bool {
    if lexical_scope.is_empty() || lexical_scope.len() >= indexed_owner_scope.len() {
        return false;
    }
    let mut indexed = indexed_owner_scope.iter();
    lexical_scope
        .iter()
        .all(|component| indexed.any(|candidate| candidate == component))
}

pub fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

/// Return the terminal identifier represented by a callable or type callee.
///
/// Qualified, scoped, template, and field wrappers are traversed through their
/// grammar fields so both function calls and type constructions emit the token
/// that names the referenced declaration.
pub fn function_terminal_node(mut node: Node<'_>) -> Node<'_> {
    loop {
        let next = match node.kind() {
            "qualified_identifier"
            | "scoped_identifier"
            | "template_function"
            | "template_type" => node.child_by_field_name("name"),
            "field_expression" => node.child_by_field_name("field"),
            _ => None,
        };
        let Some(next) = next else {
            return node;
        };
        node = next;
    }
}

/// Whether `node` is part of a call's callee expression, walking only through
/// the grammar wrappers that can structurally contain that callee.
pub fn is_call_callee_node(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "call_expression" => {
                return parent
                    .child_by_field_name("function")
                    .or_else(|| parent.named_child(0))
                    == Some(node);
            }
            "qualified_identifier"
            | "scoped_identifier"
            | "template_function"
            | "template_type"
            | "field_expression" => node = parent,
            _ => return false,
        }
    }
    false
}

pub fn type_reference_hit_node<'tree, T: Clone + Eq + Hash>(
    node: Node<'tree>,
    file: &ProjectFile,
    source: &str,
    bindings: &LocalInferenceEngine<T>,
) -> Node<'tree> {
    if is_call_callee_node(node) {
        return function_terminal_node(node);
    }
    if file.rel_path().extension().is_some_and(|ext| ext == "c") {
        return node;
    }
    let mut current = node;
    let declaration = loop {
        let Some(parent) = current.parent() else {
            return node;
        };
        if parent.kind() == "declaration" {
            break parent;
        }
        if matches!(
            parent.kind(),
            "compound_statement" | "function_definition" | "lambda_expression"
        ) {
            return node;
        }
        current = parent;
    };
    let Some(_type_node) = declaration.child_by_field_name("type").filter(|type_node| {
        type_node.start_byte() <= node.start_byte() && node.end_byte() <= type_node.end_byte()
    }) else {
        return node;
    };
    let mut cursor = declaration.walk();
    let constructs_object = declaration.named_children(&mut cursor).any(|child| {
        if child.kind() == "init_declarator" {
            return child.child_by_field_name("value").is_some()
                || first_named_child_of_kind(child, "initializer_list").is_some()
                || first_named_child_of_kind(child, "compound_literal_expression").is_some();
        }
        let declarator = if is_declarator_node(child) {
            Some(child)
        } else {
            None
        };
        declarator.is_some_and(|declarator| {
            declarator.kind() == "function_declarator"
                && has_ancestor_kind(declarator, "compound_statement")
                && declarator
                    .child_by_field_name("declarator")
                    .is_some_and(|name| name.kind() == "identifier")
                && declarator
                    .child_by_field_name("parameters")
                    .is_some_and(|parameters| {
                        constructor_parameters_look_like_expressions(parameters, source, bindings)
                    })
        })
    });
    if constructs_object {
        function_terminal_node(node)
    } else {
        node
    }
}

pub fn normalize_type_text(value: &str) -> String {
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

pub fn normalize_reference_name(value: &str) -> Option<String> {
    let normalized = normalize_cpp_reference_text(value);
    (!normalized.is_empty()).then_some(normalized)
}

pub fn normalize_cpp_reference_text(value: &str) -> String {
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

pub fn cpp_name_for(unit: &CodeUnit) -> String {
    let short = unit.short_name().replace(['.', '$'], "::");
    if unit.package_name().is_empty() {
        short
    } else {
        format!("{}::{}", unit.package_name(), short)
    }
}

/// Render an indexed C++ qualified name from its authoritative FqName
/// segments. Unlike the legacy `cpp_name_for` renderer, this preserves dots
/// that belong to a template argument (for example `Args...`).
fn canonical_cpp_name_from_fq(unit: &CodeUnit) -> Option<String> {
    let fq = unit.fq();
    if fq.is_empty() {
        return None;
    }
    let interner = brokk_bifrost_core::analyzer::fq_name::segment_interner();
    Some(
        fq.segments()
            .iter()
            .map(|&segment| interner.resolve(segment).0)
            .collect::<Vec<_>>()
            .join("::"),
    )
}

fn canonical_cpp_name_matches(unit: &CodeUnit, expected: &str) -> bool {
    canonical_cpp_name_from_fq(unit).as_deref() == Some(expected)
        || unit.fq().is_empty() && cpp_name_for(unit) == expected
}

/// Return the indexed C++ owner scope without reparsing its rendered name.
///
/// Template spellings are opaque within an indexed `FqName` segment.  In
/// particular, the ellipsis in a parameter pack (`Args...`) is part of the
/// `AtomicHook<...>` type segment; feeding the legacy all-`::` rendering back
/// through `parse_symbol_path` would mistake those dots for component
/// separators.  Cache-loaded/legacy units may still have an empty structured
/// name, so retain the parser only as that explicit fallback.
pub fn canonical_cpp_scope_components(unit: &CodeUnit) -> Vec<String> {
    let fq = unit.fq();
    if !fq.is_empty() {
        let interner = brokk_bifrost_core::analyzer::fq_name::segment_interner();
        let scope = fq
            .segments()
            .iter()
            .filter_map(|&segment| {
                let (text, kind) = interner.resolve(segment);
                matches!(
                    kind,
                    brokk_bifrost_core::analyzer::fq_name::SegmentKind::Package
                        | brokk_bifrost_core::analyzer::fq_name::SegmentKind::Type
                        | brokk_bifrost_core::analyzer::fq_name::SegmentKind::Nested
                )
                .then(|| text.to_string())
            })
            .collect();
        return scope;
    }
    brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
        brokk_bifrost_core::analyzer::Language::Cpp,
        &cpp_name_for(unit),
    )
}

// fqname-M4: the second stage splits on the individual chars '.', '-', '>'
// (not the substring "->"), which deliberately reduces an `operator->`-style
// terminal segment to an empty tail rather than keeping it intact; the shared
// structured splitter's cpp operator-token merge would keep `operator->`
// whole instead, changing this function's result — `name_matches_callable`'s
// `expected.starts_with("operator")` fallback exists specifically to
// compensate for that reduction, and a pinned regression test
// (`operator-> must not be reduced with terminal_name-style punctuation
// splitting`) asserts today's char-class behavior. Not equivalence-provable;
// revisit alongside that pinned test if it is ever relaxed.
pub fn terminal_name(value: &str) -> &str {
    value
        .rsplit("::")
        .next()
        .unwrap_or(value)
        .rsplit(['.', '-', '>'])
        .next()
        .unwrap_or(value)
        .trim()
}

pub fn name_matches_terminal(value: &str, expected: &str) -> bool {
    terminal_name(&normalize_cpp_reference_text(value)) == expected
}

pub fn name_matches_callable(value: &str, expected: &str) -> bool {
    name_matches_terminal(value, expected)
        || expected.starts_with("operator")
            && terminal_name(&normalize_cpp_reference_text(value)) == "operator"
}

pub fn name_mentions(value: &str, expected: &str) -> bool {
    normalize_cpp_reference_text(value)
        .split("::")
        .any(|part| part == expected)
}

pub fn reference_matches_unit(reference: &str, unit: &CodeUnit) -> bool {
    let cpp_name = cpp_name_for(unit);
    if reference.contains("::") {
        return reference == cpp_name;
    }
    reference == cpp_name
        || terminal_name(reference) == unit.identifier()
            && (unit.package_name().is_empty() || reference == unit.identifier())
}

pub fn matches_kind_for_lookup(unit: &CodeUnit, kind: TargetKind) -> bool {
    match kind {
        TargetKind::Type
        | TargetKind::Constructor
        | TargetKind::Method
        | TargetKind::MemberField => true,
        TargetKind::FreeFunction => unit.is_function(),
        TargetKind::GlobalField => unit.is_field(),
    }
}

pub fn is_type_alias(unit: &CodeUnit) -> bool {
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

fn parser_alias_target_names(alias: &CppAlias) -> Vec<String> {
    let normalized = normalize_cpp_reference_text(alias.target.trim().trim_end_matches(';'));
    if normalized.contains("::") {
        return vec![normalized];
    }
    alias
        .namespace
        .as_deref()
        .map(namespace_prefixes)
        .map(|prefixes| {
            prefixes
                .into_iter()
                .map(|prefix| format!("{prefix}::{normalized}"))
                .collect()
        })
        .unwrap_or_else(|| vec![normalized])
}

/// The declared return type text of a C++ function unit, with leading declaration specifiers
/// stripped, e.g. `T*` for `T* operator->()`.
pub fn cpp_function_return_type_text(
    analyzer: &CppGraphSource<'_>,
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

fn cpp_function_signature_text(
    analyzer: &CppGraphSource<'_>,
    function: &CodeUnit,
) -> Option<String> {
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

pub fn cpp_namespace_for(unit: &CodeUnit) -> Option<String> {
    // fqname-M4: `cpp_name_for` is a bespoke all-`::` rendering of the unit's
    // name (it replaces every `.`/`$` in `short_name` with `::`), which is NOT
    // the same string `default_parent_fq_name`/`fq().parent()` would render:
    // the structured `FqName`'s native cpp display deliberately keeps `.` (not
    // `::`) between a trailing `Package` segment and a following `Type`
    // segment (see `separator` in `fq_name.rs`, landed for issue #1163), so
    // popping the unit's own `fq()` segment would NOT reproduce this
    // fully-`::`-joined string. Left as a split on the locally-built
    // all-colon string rather than the unit's structured name.
    cpp_name_for(unit).rsplit_once("::").map(|(namespace, _)| {
        namespace
            .strip_prefix("anonymous_namespace::")
            .unwrap_or(namespace)
            .to_string()
    })
}

fn namespace_prefixes(namespace: &str) -> Vec<String> {
    // `namespace` is built by `cpp_name_for`/`cpp_namespace_for` with every
    // non-`::` separator already converted to `::`, so re-tokenizing it with
    // the shared structured splitter and progressively popping the last
    // component reproduces the `rsplit_once("::")` outward walk exactly (same
    // shape as `cpp_qualifier_lookup_tiers`'s namespace-chain walk).
    let mut parts = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
        brokk_bifrost_core::analyzer::Language::Cpp,
        namespace,
    );
    let mut prefixes = Vec::new();
    while !parts.is_empty() {
        prefixes.push(parts.join("::"));
        parts.pop();
    }
    prefixes
}

fn nearest_namespace_candidates(
    candidates: Vec<CodeUnit>,
    normalized: &str,
    lexical_namespace: Option<&str>,
) -> Vec<CodeUnit> {
    if normalized.contains("::") {
        return candidates;
    }
    if let Some(namespace) = lexical_namespace {
        for prefix in namespace_prefixes(namespace) {
            let scoped = candidates
                .iter()
                .filter(|function| cpp_namespace_for(function).as_deref() == Some(prefix.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            if !scoped.is_empty() {
                return scoped;
            }
        }
    }
    candidates
        .into_iter()
        .filter(|function| cpp_namespace_for(function).is_none_or(|namespace| namespace.is_empty()))
        .collect()
}

pub fn enclosing_namespace_context(node: Node<'_>, source: &str) -> Option<String> {
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
pub fn type_owner_of(analyzer: &CppGraphSource<'_>, code_unit: &CodeUnit) -> Option<CodeUnit> {
    type_owner_resolution(analyzer, code_unit).map(|owner| owner.unit)
}

fn type_owner_resolution(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
) -> Option<ResolvedTypeOwner> {
    precise_parent_resolution(analyzer, code_unit).filter(|owner| !owner.unit.is_module())
}

/// Recover method identity for an indexed out-of-line definition when the
/// analyzer has retained only its unique include-visible class forward
/// declaration. This is deliberately target-only: canonical declaration
/// resolution must continue to prefer the callable definition rather than
/// replacing it with the forward owner.
fn target_forward_owner_resolution(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
) -> Option<ResolvedTypeOwner> {
    if !code_unit.is_function() {
        return None;
    }
    let interner = brokk_bifrost_core::analyzer::fq_name::segment_interner();
    let owner_fqn = code_unit.fq().parent()?.display(interner);
    let cpp = analyzer.cpp?;
    let mut visible_files = HashSet::default();
    collect_include_closure(
        analyzer,
        cpp.include_target_index(),
        code_unit.source(),
        &mut visible_files,
        None,
    );
    let mut forward = None;
    for candidate in analyzer
        .global_usage_definition_index()
        .fqn(&owner_fqn)
        .into_iter()
        .filter(|candidate| candidate.is_class() && visible_files.contains(candidate.source()))
    {
        match cpp_class_declaration_strength(analyzer, candidate) {
            CppClassDeclarationStrength::Forward if forward.is_none() => {
                forward = Some(candidate.clone());
            }
            CppClassDeclarationStrength::Forward
            | CppClassDeclarationStrength::Full
            | CppClassDeclarationStrength::Unknown => return None,
        }
    }
    forward.map(|unit| ResolvedTypeOwner {
        unit,
        is_forward_declaration: true,
    })
}

pub fn precise_parent_of(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    visibility.cached_precise_parent_of(analyzer, code_unit)
}

fn precise_parent_resolution(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
) -> Option<ResolvedTypeOwner> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(cpp) = analyzer.cpp {
        cpp.record_cpp_parent_resolution_for_test();
    }
    if let Some(unit) = exact_structural_type_parent(analyzer, code_unit) {
        return Some(ResolvedTypeOwner {
            unit,
            is_forward_declaration: false,
        });
    }
    let fallback = analyzer.parent_of(code_unit);
    // fqname-M4: `owner_name` is used both bare (passed standalone to the
    // owner-resolution calls below) and manually recombined with
    // `package_name()` a few lines down, so this needs the package-less
    // `short_name` owner specifically; `default_parent_fq_name`/`fq.parent()`
    // would render the package-qualified owner instead, changing both uses.
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
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    if !code_unit.is_function() && !code_unit.is_field() {
        return None;
    }
    let encoded_owner = code_unit.short_name().rsplit_once('.')?.0; // fqname-M4: package-less short_name owner used as an encoded key; fq.parent() would render the `::`-headed package-qualified owner
    let cpp = analyzer.cpp?;
    let parent = cpp.structural_parent_of(code_unit)?;
    (!parent.is_module()
        && parent.source() == code_unit.source()
        && parent.package_name() == code_unit.package_name()
        && parent.short_name() == encoded_owner)
        .then_some(parent)
}

fn same_source_owner(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
    owner_fqn: &str,
    owner_name: &str,
) -> DirectOwnerResolution {
    let candidates = analyzer
        .global_usage_definition_index()
        .fqn(owner_fqn)
        .into_iter()
        .filter(|candidate| {
            candidate.is_class()
                && candidate.source() == code_unit.source()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
        })
        .collect::<Vec<_>>();
    let candidates = prefer_member_declaring_owners(analyzer, code_unit, candidates);
    classify_direct_owner_candidates(analyzer, candidates.into_iter())
}

fn visible_full_cpp_owner(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
    owner_fqn: &str,
    owner_name: &str,
) -> FullOwnerResolution {
    let Some(cpp) = analyzer.cpp else {
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
        .fqn(owner_fqn)
        .into_iter()
        .filter(|candidate| {
            candidate.is_class()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
                && visible_files.contains(candidate.source())
        })
        .collect::<Vec<_>>();
    let candidates = prefer_member_declaring_owners(analyzer, code_unit, candidates);
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

pub enum DirectOwnerResolution {
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
pub enum CppClassDeclarationStrength {
    Full,
    Forward,
    Unknown,
}

fn directly_included_owner(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
    owner_fqn: &str,
    owner_name: &str,
) -> DirectOwnerResolution {
    let Some(cpp) = analyzer.cpp else {
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
        .fqn(owner_fqn)
        .into_iter()
        .filter(|candidate| {
            candidate.is_class()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
                && direct_includes.contains(candidate.source())
        })
        .collect::<Vec<_>>();
    let candidates = prefer_member_declaring_owners(analyzer, code_unit, candidates);
    classify_direct_owner_candidates(analyzer, candidates.into_iter())
}

fn prefer_member_declaring_owners<'a>(
    analyzer: &CppGraphSource<'_>,
    member: &CodeUnit,
    candidates: Vec<&'a CodeUnit>,
) -> Vec<&'a CodeUnit> {
    let matching = candidates
        .iter()
        .copied()
        .filter(|owner| owner_declares_member(analyzer, owner, member))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        candidates
    } else {
        matching
    }
}

fn owner_declares_member(
    analyzer: &CppGraphSource<'_>,
    owner: &CodeUnit,
    member: &CodeUnit,
) -> bool {
    analyzer.direct_children(owner).into_iter().any(|child| {
        child.kind() == member.kind()
            && child.identifier() == member.identifier()
            && child.signature() == member.signature()
    })
}

fn classify_direct_owner_candidates<'a>(
    analyzer: &CppGraphSource<'_>,
    candidates: impl Iterator<Item = &'a CodeUnit>,
) -> DirectOwnerResolution {
    collapse_owner_candidates(candidates.map(|candidate| {
        (
            candidate.clone(),
            cpp_class_declaration_strength(analyzer, candidate),
        )
    }))
}

pub fn collapse_owner_candidates(
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

pub fn cpp_class_declaration_strength(
    analyzer: &CppGraphSource<'_>,
    candidate: &CodeUnit,
) -> CppClassDeclarationStrength {
    if let Some(prepared) = analyzer
        .cpp
        .and_then(|cpp| cpp.prepared_syntax(candidate.source()))
    {
        return cpp_class_declaration_strength_in_tree(
            analyzer,
            candidate,
            prepared.source(),
            prepared.tree().root_node(),
        );
    }
    let Some(source) = analyzer.indexed_source(candidate.source()) else {
        return CppClassDeclarationStrength::Unknown;
    };
    #[cfg(any(test, feature = "test-support"))]
    if let Some(cpp) = analyzer.cpp {
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
    cpp_class_declaration_strength_in_tree(analyzer, candidate, &source, tree.root_node())
}

fn cpp_class_declaration_strength_in_tree(
    analyzer: &CppGraphSource<'_>,
    candidate: &CodeUnit,
    source: &str,
    root: Node<'_>,
) -> CppClassDeclarationStrength {
    let ranges = analyzer.ranges(candidate);
    let mut saw_forward = false;
    for range in ranges {
        let mut stack = vec![root];
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
                    recovered_exported_class_has_body(node, source, candidate.identifier())
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

pub fn visible_owner_from_member_name(ctx: &ScanCtx<'_>, code_unit: &CodeUnit) -> Option<CodeUnit> {
    // fqname-M4: `owner_name` is used both bare and manually recombined with
    // `package_name()` below (same package-less short_name owner shape as
    // `precise_parent_resolution` above); `default_parent_fq_name` would
    // render the package-qualified owner instead, changing both uses.
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
        .fqn(&owner_fqn)
        .into_iter()
        .find(|candidate| {
            candidate.is_class()
                && ctx.visibility.is_visible(ctx.file, candidate)
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
        })
        .cloned()
}

pub fn same_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
        && left.source() == right.source()
}

pub fn same_visible_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    same_symbol(left, right) || same_logical_symbol(left, right)
}

pub fn same_visible_global_field_symbol(
    analyzer: &CppGraphSource<'_>,
    internal_linkage_cache: &mut HashMap<CodeUnit, bool>,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    if same_symbol(left, right) {
        return true;
    }
    if !same_logical_symbol(left, right) {
        return false;
    }
    if cpp_global_field_has_internal_linkage_cached(analyzer, internal_linkage_cache, left)
        || cpp_global_field_has_internal_linkage_cached(analyzer, internal_linkage_cache, right)
    {
        left.source() == right.source()
    } else {
        true
    }
}

fn cpp_global_field_has_internal_linkage_cached(
    analyzer: &CppGraphSource<'_>,
    cache: &mut HashMap<CodeUnit, bool>,
    candidate: &CodeUnit,
) -> bool {
    if let Some(internal) = cache.get(candidate) {
        return *internal;
    }
    #[cfg(any(test, feature = "test-support"))]
    note_cpp_global_field_internal_linkage_classification_for_test();
    let internal = cpp_global_field_has_internal_linkage(analyzer, candidate);
    cache.insert(candidate.clone(), internal);
    internal
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CPP_GLOBAL_FIELD_INTERNAL_LINKAGE_CLASSIFICATIONS_FOR_TEST: Cell<usize> = const { Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
fn note_cpp_global_field_internal_linkage_classification_for_test() {
    CPP_GLOBAL_FIELD_INTERNAL_LINKAGE_CLASSIFICATIONS_FOR_TEST.with(|count| {
        count.set(count.get() + 1);
    });
}

#[cfg(any(test, feature = "test-support"))]
pub fn with_cpp_global_field_internal_linkage_classification_counter_for_test<T>(
    body: impl FnOnce() -> T,
) -> (T, usize) {
    CPP_GLOBAL_FIELD_INTERNAL_LINKAGE_CLASSIFICATIONS_FOR_TEST.with(|count| {
        count.set(0);
        let result = body();
        let observed = count.get();
        count.set(0);
        (result, observed)
    })
}

pub fn same_logical_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
}

pub fn cpp_global_field_has_internal_linkage(
    analyzer: &CppGraphSource<'_>,
    candidate: &CodeUnit,
) -> bool {
    if !candidate.is_field() || candidate.short_name().contains('.') {
        return false;
    }
    let Some(local_linkage) = cpp_global_field_declaration_linkage(analyzer, candidate) else {
        return false;
    };
    match local_linkage {
        CppFieldLinkage::Internal => true,
        CppFieldLinkage::External => false,
        CppFieldLinkage::InternalUnlessExternalPeer => {
            !cpp_global_field_linkage_peers(analyzer, candidate)
                .filter_map(|peer| cpp_global_field_declaration_linkage(analyzer, peer))
                .any(|linkage| matches!(linkage, CppFieldLinkage::External))
        }
    }
}

fn cpp_global_field_linkage_peers<'a>(
    analyzer: &CppGraphSource<'a>,
    candidate: &'a CodeUnit,
) -> impl Iterator<Item = &'a CodeUnit> + 'a {
    // These peers are returned to the caller, so they must borrow the analyzer
    // for `'a` rather than a handle that dies with this call. `fqn` reads the
    // shards directly for exactly that reason.
    let fq_name = candidate.fq_name();
    analyzer
        .global_usage_definition_index()
        .fqn(&fq_name)
        .into_iter()
        .filter(move |peer| {
            if *peer == candidate {
                return false;
            }
            #[cfg(any(test, feature = "test-support"))]
            note_cpp_global_field_linkage_peer_inspection_for_test();
            same_logical_symbol(peer, candidate)
        })
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CPP_GLOBAL_FIELD_LINKAGE_PEER_INSPECTIONS_FOR_TEST: Cell<usize> = const { Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
fn note_cpp_global_field_linkage_peer_inspection_for_test() {
    CPP_GLOBAL_FIELD_LINKAGE_PEER_INSPECTIONS_FOR_TEST.with(|count| {
        count.set(count.get() + 1);
    });
}

#[cfg(any(test, feature = "test-support"))]
pub fn with_cpp_global_field_linkage_peer_inspection_counter_for_test<T>(
    body: impl FnOnce() -> T,
) -> (T, usize) {
    CPP_GLOBAL_FIELD_LINKAGE_PEER_INSPECTIONS_FOR_TEST.with(|count| {
        count.set(0);
        let result = body();
        let observed = count.get();
        count.set(0);
        (result, observed)
    })
}

fn cpp_global_field_declaration_linkage(
    analyzer: &CppGraphSource<'_>,
    candidate: &CodeUnit,
) -> Option<CppFieldLinkage> {
    if let Some(linkage) = analyzer.cpp_field_linkage(candidate) {
        return Some(linkage);
    }
    let cpp = analyzer.cpp?;
    if let Some(prepared) = cpp.prepared_syntax(candidate.source()) {
        return cpp_global_field_declaration_linkage_in_tree(
            analyzer,
            candidate,
            prepared.source(),
            prepared.tree().root_node(),
        );
    }
    let source = analyzer.indexed_source(candidate.source())?;
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return None;
    }
    let tree = parser.parse(&source, None)?;
    cpp_global_field_declaration_linkage_in_tree(analyzer, candidate, &source, tree.root_node())
}

fn cpp_global_field_declaration_linkage_in_tree(
    analyzer: &CppGraphSource<'_>,
    candidate: &CodeUnit,
    source: &str,
    root: Node<'_>,
) -> Option<CppFieldLinkage> {
    analyzer.ranges(candidate).iter().find_map(|range| {
        node_for_exact_range(root, range)
            .and_then(enclosing_cpp_field_declaration)
            .map(|declaration| cpp_field_declaration_linkage(declaration, source))
    })
}

fn enclosing_cpp_field_declaration(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(node.kind(), "declaration" | "field_declaration") {
            return Some(node);
        }
        node = node.parent()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_enum_flattened_namespace(source: &str) -> Option<Vec<String>> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ fixture tree");
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "enum_specifier" {
                return flattened_macro_namespace_components(node, source);
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            stack.extend(children.into_iter().rev());
        }
        None
    }

    #[test]
    fn flattened_namespace_scope_requires_a_complete_sentinel_envelope() {
        let complete = r#"NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
enum class value_t { null };
}
NLOHMANN_JSON_NAMESPACE_END
NLOHMANN_JSON_NAMESPACE_BEGIN
namespace next
{
struct next_type {};
}
NLOHMANN_JSON_NAMESPACE_END
"#;
        assert_eq!(
            first_enum_flattened_namespace(complete),
            Some(vec!["detail".to_string()])
        );

        let stale_end = format!("NLOHMANN_JSON_NAMESPACE_END\n{complete}");
        assert_eq!(
            first_enum_flattened_namespace(&stale_end),
            Some(vec!["detail".to_string()]),
            "a stale end marker before the begin marker must not replace the intended namespace"
        );

        let incomplete = r#"NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
enum class value_t { null };
}
struct next_type {};
"#;
        assert_eq!(first_enum_flattened_namespace(incomplete), None);
    }
}
